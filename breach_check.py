def _hudsonrock(domain: str) -> list[dict]:
    out = []
    try:
        r = requests.get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
            params={"domain": domain}, timeout=15,
            headers={"User-Agent": UA},
        )
        if r.status_code != 200:
            return out
        j = r.json()
        total = j.get("total", 0)
        if not total:
            return out
        sev = "CRITICAL" if j.get("employees", 0) >= 10 else (
            "HIGH" if j.get("employees", 0) >= 1 else (
                "MEDIUM" if j.get("users", 0) >= 1 else "INFO"
            )
        )
        urls = [u.get("url") for u in (j.get("data", {}).get("employees_urls") or [])][:5]
        families = [f.get("_key") for f in (j.get("data", {}).get("stealer_families") or [])]
        out.append({
            "source": "hudsonrock",
            "title": f"stealer logs: total={total} employees={j.get('employees',0)} users={j.get('users',0)} third_parties={j.get('third_parties',0)}",
            "url": "https://cavalier.hudsonrock.com",
            "reason": f"severity={sev}; stealers={','.join(families) or 'n/a'}; sample_urls={'; '.join(u for u in urls if u) or 'n/a'} (free tier, redacted)",
        })
        time.sleep(1.0)
    except Exception:
        pass
    return out


def _hibp_domain(domain: str) -> list[dict]:
    key = os.getenv("HIBP_KEY")
    if not key:
        return []
    out = []
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            headers={"User-Agent": UA, "hibp-api-key": key}, timeout=15,
        )
        if r.status_code != 200:
            return out
        j = r.json()
        out.append({
            "source": "hibp",
            "title": f"breacheddomain: {len(j)} aliases affected",
            "url": f"https://haveibeenpwned.com/DomainSearch?domain={domain}",
            "reason": "; ".join(list(j.keys())[:10]),
        })
    except Exception:
        pass
    return out