## SSTI AI Fuzzer

- **Hybrid crawler**
  - Static HTML parsing with BeautifulSoup.
  - Dynamic browser replay with Playwright that captures every XHR, fetch and GraphQL call.
  - Click‑through support for SPA routers (Angular, React, Vue, Svelte, Next/Nuxt, etc.) to reveal hidden API endpoints.

- **Broad template‑engine coverage**
  - Scans more than 15+ engines in a single run: Jinja2, Twig, Freemarker, Velocity, Go‑tmpl, Thymeleaf, Handlebars, Mustache, ERB, Razor, JSP‑EL, Liquid, Dust and classic Apache / nginx SSI (SSIT).

- **Extensive payload library**
  - Ships with 150‑plus probes.
  - Includes quote‑less Jinja primitives, Freemarker / Velocity arithmetic and `ProcessBuilder` RCE, SSI `<!--#exec cmd="..."-->` vectors, blind timing payloads and more.
  - Optional AI‑driven expansion through Microsoft CodeBERT when the model is available.

- **Stealth and evasion features**
  - Multiple encoding layers: single and double URL‑encode, hexadecimal, null‑byte.
  - Comment cloaking, quote splitting and string concatenation to avoid signature filters.
  - Randomised header spoofing (`User‑Agent`, `X‑Forwarded‑For`, `Origin`, `Referer`).
  - Adaptive jitter between requests to slip past WAF rate limits.

- **Blind exfiltration**
  - Out‑of‑band DNS beacon payloads (`ping sstiXXXX.dnslog.cn`) for cases where nothing is reflected in the response.

- **Concurrency and scale controls**
  - User‑tunable thread pool (default 18).
  - Crawl‑depth cap (`--max-pages`) and option to disable the browser layer (`--no-browser`) for lightweight reconnaissance.

- **Smart root‑URL handling**
  - Accepts bare domains and automatically tests HTTPS first, then HTTP.

- **Readable output**
  - Writes a Markdown log (`ssti_results.md`) with compact one‑line findings: `mode • URL • parameter → payload`.

---

## Compare with basic SSTI fuzzer

- Handles SPA and JavaScript‑heavy sites through Playwright network interception instead of stopping at static HTML.
- Fires more than 150 payloads.
- Uses AI unlike fixed word‑lists in typical tools.
- Supports over fifteen template engines (including SSI); basic tools usually target at most three.
- Provides blind out‑of‑band and timing‑based probes in addition to simple reflection checks.
- Adds multiple evasion layers—double URL‑encoding, hex, null‑byte, comment cloaking—beyond the single URL‑encoding seen in simpler tools.
- Spoofs headers randomly, mimicking real traffic instead of using static values.
- Runs fully threaded for speed; some scripts run serially or with limited concurrency.
- Produces a clean, deduplicated Markdown report rather than unstructured console output.
- Offers flexible CLI flags (`--threads`, `--no-browser`, `--max-pages`, `--debug`) instead of hard‑coded settings.

Provides full‑stack, WAF‑aware, browser‑assisted coverage that uncovers endpoints and vulnerabilities ordinary SSTI fuzzers never reach.
