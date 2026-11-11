import requests

UA = "Mozilla/5.0 (compatible; ScopeBreaker/1.0)"

PATHS = [
    "/.git/config", "/.env", "/.env.bak", "/backup.zip", "/backup.tar.gz",
    "/wp-config.php.bak", "/config.php.bak", "/phpmyadmin/", "/adminer.php",
    "/actuator", "/actuator/env", "/debug", "/server-status", "/.DS_Store",
    "/admin/", "/robots.txt", "/sitemap.xml",
]


def scan(base_url: str, delay: float = 0.4) -> list[dict]:
    import time
    root = base_url.rstrip("/")
    out = []
    for p in PATHS:
        try:
            r = requests.get(root + p, timeout=6, headers={"User-Agent": UA}, allow_redirects=False)
            if r.status_code in (200, 401, 403) and p not in ("/robots.txt", "/sitemap.xml"):
                out.append({"path": p, "status": r.status_code, "len": len(r.content)})
            elif r.status_code == 200 and p in ("/robots.txt", "/sitemap.xml"):
                out.append({"path": p, "status": 200, "len": len(r.content)})
        except Exception:
            pass
        time.sleep(delay)
    return out