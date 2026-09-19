# h1_hunter
## How each module works (and why it's not just a wrapper)

**XSS** injects a unique marker plus a payload into each query parameter, then checks whether the marker reflects back *inside an executable context* (script tag, event handler, `javascript:` URI). The `_is_dangerous_reflection` method inspects 200 characters on either side of the reflection to decide whether it's actually exploitable or just safely encoded. This is the same logic mature scanners use to reduce false positives.

**SQLi** runs three independent detection strategies. Error-based sends syntax-breaking payloads and looks for 12 database error signatures. Boolean-based sends paired true/false conditions and compares response body lengths against a baseline. Time-based sends `SLEEP`/`WAITFOR DELAY` payloads and measures actual wall-clock delay. Any one of these firing is high confidence.

**SSRF** restricts itself to parameters whose names match known URL-accepting names *or* whose values already look like URLs. It then substitutes internal targets including AWS/GCP metadata endpoints, localhost, and `file://` schemes, checking for content signatures that prove internal access.

**Command injection** uses only *time-based* probes (`sleep 5`, `ping -n 6`) rather than destructive commands. This is the ethical choice — you can prove RCE without actually executing anything harmful on the target.

**IDOR** is heuristic by nature (it can't know your authorization context), but it does something real: it takes numeric IDs, tries nearby values, checks whether the response looks like a valid object (not a 404 page), and scans for PII patterns (email, phone, SSN, credit card) in the response. That's the signal that distinguishes a real IDOR from a harmless parameter change.

**CORS** sends an `Origin: https://evil.example.com` header and inspects `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`. Reflected origin + credentials is a HIGH-severity finding because it allows cross-origin data theft.

**SSTI** sends template syntax like `{{7*7}}` and checks whether the server *evaluates* it (response contains `49` but not the literal payload). This is a direct RCE indicator.

**Path traversal** tests both Unix and Windows payloads, including double-URL-encoding variants that bypass naive filters.

**JS analyzer** pulls secrets and endpoints from JavaScript files — the same logic from your earlier script, now integrated into the pipeline.

---

## Usage

```bash
# Full scan of one URL
python h1_hunter.py -u "https://target.com/search?q=test&page=1" --all

# Specific modules only
python h1_hunter.py -u "https://target.com/api?id=123" --sqli --idor --cors

# Bulk scan from a file
python h1_hunter.py -l urls.txt --all --rate 0.5 --concurrency 3

# Analyze a JS file for secrets
python h1_hunter.py --analyze-js "https://target.com/static/app.js"
```

---

## What this still can't do (and why that matters)

This framework is **not** a replacement for Burp Suite, manual testing, or judgment. It cannot:

- **Chain vulnerabilities.** A real bug chain (info disclosure → IDOR → account takeover) requires human reasoning.
- **Understand business logic.** Race conditions, workflow bypasses, and privilege escalation need context the script doesn't have.
- **Authenticate.** Most high-value bugs live behind login. You'd need to add session cookie injection — I left that out because handling auth tokens safely deserves its own design.
- **Avoid false positives entirely.** The IDOR and boolean-SQLi detectors are heuristic; always verify manually before reporting.

The script is a *force multiplier* — it does the repetitive probing so you can focus on the findings that matter. Run it, triage the output, and manually verify everything before writing a HackerOne report. And per the HackerOne policy warnings, confirm the program allows automated scanning and respect rate limits before pointing it at anything live.
