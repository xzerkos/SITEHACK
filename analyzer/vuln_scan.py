import re
import time
from urllib.parse import urlsplit

import requests

UA = "Mozilla/5.0 (compatible; ScopeBreaker/1.0)"
SQL_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{4,}|PostgreSQL.*ERROR|SQLite.*error|Unclosed quotation)",
    re.I,
)
NOSQL_MARKERS = re.compile(r"(MongoError|E11000|Cast to ObjectId|BSONTypeError|Cannot read prop.*of undefined.*findOne)", re.I)
CMDI_MARKERS = re.compile(r"(uid=\d+|gid=\d+|www-data|root:.*:0:0:|nt authority|SYSTEM\s+PROFILE)", re.I)
LFI_MARKERS = re.compile(r"(root:x:0:0:|\[extensions\]|\[fonts\]|PD9waHA)", re.I)

XSS_MARK = "sbx9q7"
SSTI_PAYLOADS = ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>")
SSTI_MARK = "49"
TRAVERSAL_PAYLOADS = ("../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd")
CMDI_PAYLOADS = (";id", "|id", "`id`", "$(id)", "&& id")
NOSQL_PAYLOADS = (
    ("$ne", {"$ne": ""}),
    ("$gt", {"$gt": ""}),
    ("[$ne]", None),
)


def _req(method: str, url: str, params=None, data=None, json=None, timeout: float = 8.0, allow_redirects: bool = True):
    try:
        return requests.request(method, url, params=params, data=data, json=json,
                                timeout=timeout, headers={"User-Agent": UA},
                                allow_redirects=allow_redirects)
    except Exception:
        return None


def _join(base: str, action: str) -> str:
    if action.startswith("http"):
        return action
    return base.rstrip("/") + "/" + action.lstrip("/")


def _form_inputs(form: dict) -> list[str]:
    return [i["name"] for i in form.get("inputs", []) if i.get("name")]


def _submit(form: dict, url: str, payload: dict):
    if form["method"] == "POST":
        return _req("POST", url, data=payload)
    return _req("GET", url, params=payload)


def probe_sql_injection(base_url: str, forms: list[dict], delay: float = 0.4) -> list[dict]:
    out = []
    for f in forms[:5]:
        action = _join(base_url, f["action"])
        for inp in _form_inputs(f)[:3]:
            baseline = _submit(f, action, {inp: "1"})
            probe = _submit(f, action, {inp: "1'"})
            if not baseline or not probe:
                continue
            if baseline.status_code >= 400:
                time.sleep(delay); continue
            diff_code = baseline.status_code != probe.status_code
            diff_len = abs(len(baseline.text) - len(probe.text)) > 200
            err_hit = bool(SQL_ERRORS.search(probe.text))
            if err_hit or (diff_code and diff_len):
                out.append({"type": "SQLi", "target": f"{action} [{inp}]",
                            "evidence": "error-match" if err_hit else "response-delta"})
            time.sleep(delay)
    return out


def probe_nosql(base_url: str, forms: list[dict], delay: float = 0.4) -> list[dict]:
    out = []
    for f in forms[:5]:
        action = _join(base_url, f["action"])
        for inp in _form_inputs(f)[:3]:
            baseline = _submit(f, action, {inp: "1"})
            if not baseline or baseline.status_code >= 400:
                time.sleep(delay); continue
            for label, obj in NOSQL_PAYLOADS:
                if obj is None:
                    probe = _submit(f, action, {f"{inp}[$ne]": "1"})
                else:
                    probe = _req("POST", action, json={inp: obj}) if f["method"] == "POST" else \
                            _req("GET", action, params={inp: str(obj)})
                if not probe:
                    continue
                if probe.status_code in (403, 406, 429):
                    continue
                if NOSQL_MARKERS.search(probe.text):
                    out.append({"type": "NoSQLi", "target": f"{action} [{inp}]", "evidence": f"payload={label}"})
                    break
                if abs(len(probe.text) - len(baseline.text)) > 300 and probe.status_code != baseline.status_code:
                    out.append({"type": "NoSQLi?", "target": f"{action} [{inp}]", "evidence": f"payload={label} response-delta"})
                    break
            time.sleep(delay)
    return out


def probe_cmdi(base_url: str, forms: list[dict], delay: float = 0.4) -> list[dict]:
    out = []
    for f in forms[:5]:
        action = _join(base_url, f["action"])
        for inp in _form_inputs(f)[:3]:
            baseline = _submit(f, action, {inp: "test"})
            if not baseline or baseline.status_code >= 400:
                time.sleep(delay); continue
            for payload in CMDI_PAYLOADS:
                probe = _submit(f, action, {inp: payload})
                if not probe or probe.status_code in (403, 406, 429):
                    continue
                if CMDI_MARKERS.search(probe.text) and not CMDI_MARKERS.search(baseline.text):
                    out.append({"type": "Command injection", "target": f"{action} [{inp}]",
                                "evidence": f"payload={payload}"})
                    break
            time.sleep(delay)
    return out


def probe_lfi(base_url: str, forms: list[dict], delay: float = 0.4) -> list[dict]:
    out = []
    for f in forms[:5]:
        action = _join(base_url, f["action"])
        for inp in _form_inputs(f)[:3]:
            baseline = _submit(f, action, {inp: "index"})
            if not baseline or baseline.status_code >= 400:
                time.sleep(delay); continue
            for payload in TRAVERSAL_PAYLOADS:
                probe = _submit(f, action, {inp: payload})
                if not probe or probe.status_code in (403, 406, 429):
                    continue
                if LFI_MARKERS.search(probe.text) and not LFI_MARKERS.search(baseline.text):
                    out.append({"type": "LFI", "target": f"{action} [{inp}]", "evidence": f"payload={payload}"})
                    break
            time.sleep(delay)
    return out


def probe_xss(base_url: str, forms: list[dict], delay: float = 0.4) -> list[dict]:
    out = []
    payload = f"<{XSS_MARK}>"
    for f in forms[:5]:
        action = _join(base_url, f["action"])
        for inp in _form_inputs(f)[:3]:
            r = _submit(f, action, {inp: payload})
            if r and payload in r.text:
                out.append({"type": "XSS(Reflected)", "target": f"{action} [{inp}]", "evidence": "unescaped-echo"})
            time.sleep(delay)
    return out


def probe_ssti(base_url: str, forms: list[dict], delay: float = 0.4) -> list[dict]:
    out = []
    for f in forms[:5]:
        action = _join(base_url, f["action"])
        for inp in _form_inputs(f)[:3]:
            baseline = _submit(f, action, {inp: "x"})
            if not baseline or baseline.status_code >= 400:
                time.sleep(delay); continue
            for payload in SSTI_PAYLOADS:
                r = _submit(f, action, {inp: payload})
                if r and SSTI_MARK in r.text and SSTI_MARK not in baseline.text:
                    out.append({"type": "SSTI", "target": f"{action} [{inp}]",
                                "evidence": f"payload={payload} -> '{SSTI_MARK}'"})
                    break
            time.sleep(delay)
    return out


def probe_csrf(base_url: str, forms: list[dict]) -> list[dict]:
    out = []
    token_rx = re.compile(r"(csrf|xsrf|authenticity|__RequestVerificationToken)", re.I)
    for f in forms:
        if f["method"] != "POST":
            continue
        names = " ".join(_form_inputs(f))
        if not token_rx.search(names):
            out.append({"type": "CSRF", "target": _join(base_url, f["action"]),
                        "evidence": "POST-form без csrf-токена"})
    return out


def probe_open_redirect(base_url: str, forms: list[dict], delay: float = 0.4) -> list[dict]:
    out = []
    base_host = urlsplit(base_url).netloc
    probe_url = "http://example.com/"
    for f in forms[:5]:
        action = _join(base_url, f["action"])
        for inp in _form_inputs(f)[:3]:
            r = _req("GET", action, params={inp: probe_url}, allow_redirects=False)
            if r and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if loc and urlsplit(loc).netloc and urlsplit(loc).netloc != base_host:
                    out.append({"type": "Open redirect", "target": f"{action} [{inp}]",
                                "evidence": f"Location={loc}"})
            time.sleep(delay)
    return out


def probe_security_headers(base_url: str) -> list[dict]:
    r = _req("GET", base_url)
    if not r:
        return []
    out = []
    required = {
        "Strict-Transport-Security": "HSTS отсутствует",
        "Content-Security-Policy": "CSP отсутствует (XSS-риск)",
        "X-Frame-Options": "X-Frame-Options отсутствует (clickjacking)",
        "X-Content-Type-Options": "X-Content-Type-Options отсутствует (MIME sniffing)",
        "Referrer-Policy": "Referrer-Policy отсутствует",
        "Permissions-Policy": "Permissions-Policy отсутствует",
    }
    for h, msg in required.items():
        if not r.headers.get(h):
            out.append({"type": "Header", "target": h, "evidence": msg})
    return out


def probe_http_methods(base_url: str) -> list[dict]:
    out = []
    r = _req("OPTIONS", base_url)
    if not r:
        return out
    allow = r.headers.get("Allow", "")
    tokens = {t.strip().upper() for t in allow.split(",") if t.strip()}
    for risky in ("PUT", "DELETE", "TRACE"):
        if risky in tokens:
            out.append({"type": "HTTP method", "target": risky,
                        "evidence": f"Allow: {allow[:120]}"})
    return out


def probe_rate_limit(base_url: str, hits: int = 5) -> list[dict]:
    codes = []
    for _ in range(hits):
        r = _req("GET", base_url)
        if not r:
            return []
        codes.append(r.status_code)
        if r.headers.get("Retry-After"):
            return []
        time.sleep(0.1)
    if all(c == 200 for c in codes):
        return [{"type": "Rate limit", "target": base_url,
                 "evidence": f"{hits} GET подряд без 429/Retry-After"}]
    return []


def probe_bot_protection(base_url: str) -> dict:
    r = _req("GET", base_url)
    headers = r.headers if r else {}
    has_captcha = bool(r and re.search(r"(g-recaptcha|hcaptcha|turnstile|cf-chl)", r.text, re.I))
    rate_limit = headers.get("X-RateLimit-Limit") or headers.get("Retry-After")
    waf = (headers.get("Server", "") + " " + headers.get("CF-Ray", "")).strip()
    sec_headers = {k: headers.get(k) for k in (
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
    )}
    return {
        "captcha": has_captcha,
        "rate_limit": bool(rate_limit),
        "waf_hint": waf,
        "security_headers": sec_headers,
    }


def probe_all(base_url: str, forms: list[dict], progress=None) -> tuple[list[dict], dict]:
    stages = [
        ("sql", lambda: probe_sql_injection(base_url, forms)),
        ("nosql", lambda: probe_nosql(base_url, forms)),
        ("cmdi", lambda: probe_cmdi(base_url, forms)),
        ("lfi", lambda: probe_lfi(base_url, forms)),
        ("xss", lambda: probe_xss(base_url, forms)),
        ("ssti", lambda: probe_ssti(base_url, forms)),
        ("csrf", lambda: probe_csrf(base_url, forms)),
        ("redir", lambda: probe_open_redirect(base_url, forms)),
        ("headers", lambda: probe_security_headers(base_url)),
        ("methods", lambda: probe_http_methods(base_url)),
        ("ratelimit", lambda: probe_rate_limit(base_url)),
    ]
    findings = []
    for i, (name, fn) in enumerate(stages, 1):
        findings.extend(fn())
        if progress:
            progress((i / len(stages)) * 100, f"vuln:{name}")
    bot = probe_bot_protection(base_url)
    return findings, bot