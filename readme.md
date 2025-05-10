# AI-Powered Multi-STI Fuzzer for Zero-Day Discovery

A next-generation **Multi-STI** (Server‑Side Template Injection) fuzzer that leverages **AI** expansion, **browser-based crawling**, and **WAF-evasion techniques** to unearth injection bugs in over **fifteen different** template engines. Designed for comprehensive coverage of both classic and **newly discovered** template injection attack vectors.

---

## 1. Multi-STI Coverage

This tool detects and exploits **six major classes** of template injection vulnerabilities:

1. **SSTI (Server-Side Template Injection)** – *“The usual approach”*  
   - Targets widely used engines like **Jinja2**, **Mustache**, **Handlebars**, **Twig**, **Freemarker**, **Velocity**, etc.  
   - Often involves injecting malicious expressions (e.g., `{{7*7}}`) to force code execution, variable leakage, or command injection.  
   - Classic and well-documented, but still one of the most common categories of injections found in real-world apps.

2. **BSTI (Bytecode-Level Template Injection)** – *new*  
   - Exploits the **lower-level bytecode or compiled structures** of certain template engines (particularly in Java or Python).  
   - Attackers can **rewrite or corrupt bytecode tables**, alter class hierarchies, or bypass standard injection filters by directly referencing internal classes or method offsets.  
   - Example: leveraging Python’s `__class__.__mro__` or Java’s `MethodHandle`/`MethodType` constructs to run arbitrary commands at the JVM or CPython layer.

3. **MSTI (Macro-Level Template Injection)** – *new*  
   - Focuses on **macro or function-level constructs** within template languages like **Thymeleaf**, **Jinja2**, or **Nunjucks**.  
   - Attackers define or override **macros**—small reusable template blocks—to embed malicious logic.  
   - Can be used to leak server-side data, or chain injection at the macro level by passing unexpected arguments or hooking into the template’s built-in macro expansions.

4. **ASTI (AST-Level Template Injection)** – *new*  
   - Manipulates the **Abstract Syntax Tree (AST)** of the templating engine or the underlying language.  
   - Injected code can create or modify AST nodes before final code generation, often bypassing typical lexical or syntactic filters.  
   - Allows for advanced exploitation, such as **compiling new code** on the fly, altering control flow, or redefining fundamental language operations.

5. **FSTI (Filter-Pipeline Template Injection)** – *new*  
   - Targets **filter or pipe chains** in template syntax (e.g., `{{ something|filter1|filter2 }}` in Jinja2 or Twig).  
   - By injecting filters or chaining them in unexpected ways, attackers might gain code execution, file read access, or parameter tampering.  
   - Useful in frameworks that heavily rely on filters, allowing pivot from benign transformations to malicious code or commands.

6. **GSTI (Global Context Template Injection)** – *new*  
   - Focuses on the **global namespace** or environment used by the template engine, such as Python’s `globals()` or Java’s `System` classes.  
   - Attackers can override global variables, **rebind built‑in functions** (e.g., turning `eval` into `os.system`), or manipulate system-wide modules.  
   - Particularly powerful where frameworks trust global variables or handle environment contexts insecurely.

---

## 2. Hybrid Crawler

- **Static HTML parsing** with BeautifulSoup to collect forms and links from raw HTML.  
- **Dynamic browser replay** via Playwright, capturing every XHR, `fetch()`, GraphQL call, and single-page app transitions.  
- **Click‑through support** for popular SPA frameworks (React, Angular, Vue, Svelte, Next/Nuxt, etc.), unveiling hidden or lazy-loaded endpoints.

---

## 3. Broad Template‑Engine Coverage

- Scans more than **15+ template engines** in a single run:
  - **Jinja2**, **Twig**, **Freemarker**, **Velocity**, **Go‑tmpl**, **Thymeleaf**, **Mustache**, **Handlebars**, **ERB**, **Razor**, **JSP‑EL**, **Liquid**, **Dust**, plus **classic Apache/nginx SSI (SSIT)**, and more.
- Automatically tailors payloads and injection strategies to each engine’s **unique syntax and escape rules**.

---

## 4. Extensive Payload Library

- Ships with **150+** built-in probes:
  - **Quote‑less Jinja2** primitives, Freemarker/Velocity `ProcessBuilder` RCE  
  - **SSI** `<!--#exec cmd="..."-->` vectors  
  - Blind **timing** payloads  
  - Memory/stack introspection in advanced engines
- **Optional AI-driven expansion** via Microsoft CodeBERT (if installed) for fresh, previously unseen payload variants.

---

## 5. Stealth and Evasion Techniques

- Multi-layer **encodings**: single/double URL‑encode, hex escapes (`\x..`), **null‑byte** injections.  
- **Comment cloaking** (`<!-- payload -->`), string splitting and concatenation to foil naive signature checks.  
- **Random header spoofing** (`User‑Agent`, `X‑Forwarded‑For`, `Referer`, etc.) to blend in with normal traffic.  
- Configurable **adaptive jitter** between requests to avoid WAF rate-limiting or detection based on request velocity.

---

## 6. Blind Exfiltration

- Out-of-band DNS beacons (e.g. `ping sstiXXXX.dnslog.cn`) for detection in **non-reflective** injection scenarios.  
- Even if the response is sanitized or offers no direct echo, the **DNS callback** proves the injection succeeded.

---

## 7. Concurrency and Scale

- User‑tunable **thread pool** (`--threads`, default = 18) to speed up or slow down scans.  
- **Crawl depth** limit (`--max-pages`) to avoid infinite loops on sites with deep links.  
- **Disable browser** mode (`--no-browser`) for quicker scanning when advanced JavaScript coverage isn’t required.

---

## 8. Smart Root-URL Handling

- Accepts bare domains (e.g., `example.com` or `test.internal`) and attempts **HTTPS** first, then falls back to **HTTP** if needed.  
- Ensures coverage even if the site is misconfigured or behind a reverse proxy.

---

## 9. Clean, Organized Reporting

- Outputs to a **Markdown log** file (`ssti_results.md`) with each finding summarized in one line, like:  
