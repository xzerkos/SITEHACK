import os
import sys

from researcher.banner import show_banner, prompt_domain
from researcher.whois_lookup import lookup
from researcher.breach_check import check as breach_check
from researcher.crawler import crawl, as_tree
from analyzer.role_map import map_roles
from analyzer.vuln_scan import probe_all
from analyzer.exposure_scan import scan as exposure_scan
from analyzer.report import write as write_report

BAR_WIDTH = 40


def progress_bar(percent: float, label: str = ""):
    percent = max(0.0, min(100.0, percent))
    filled = int((percent / 100.0) * BAR_WIDTH)
    bar = "#" * filled + "-" * (BAR_WIDTH - filled)
    sys.stdout.write(f"\r  [{bar}] {percent:5.1f}%  {label:<18}")
    sys.stdout.flush()


def scan(domain: str):
    print()
    progress_bar(0, "init")
    info = lookup(domain)
    if not info:
        progress_bar(100, "whois")
        print()
        print("domain does not exist")
        return None
    progress_bar(12, "whois")

    breaches = breach_check(domain, progress=lambda p, l: progress_bar(12 + p * 0.28, l))
    progress_bar(40, "breach")

    site = crawl(domain, max_pages=60, depth=2,
                 progress=lambda p, l: progress_bar(40 + p * 0.25, l))
    progress_bar(65, "crawl")

    roles = map_roles(list(site["pages"].keys()))
    progress_bar(70, "roles")

    vulns, bot = probe_all(site["root"], site["forms"],
                           progress=lambda p, l: progress_bar(70 + p * 0.20, l))
    progress_bar(90, "vuln")

    exposure = exposure_scan(site["root"])
    progress_bar(96, "exposure")

    tree = as_tree(site)
    payload = {
        "scanned_at": info.get("scanned_at"),
        "whois": info,
        "breaches": breaches,
        "tree": tree,
        "roles": roles,
        "vulns": vulns,
        "bot": bot,
        "exposure": exposure,
        "api_hints": site.get("api_hints", []),
    }
    progress_bar(100, "report")
    print()
    return payload


def render(payload: dict, domain: str):
    whois = payload["whois"]

    print()
    print("[ WHOIS / DNS ]")
    for k in ("ip", "owner", "registrar", "created", "expires", "nameservers", "status"):
        v = whois.get(k)
        if v:
            print(f"  {k:<10}: {v}")

    print()
    print("[ BREACH ]")
    if not payload["breaches"]:
        print("  Взломов связанной с данном сайтом не найдено")
    else:
        print(f"  Найдено ({len(payload['breaches'])}) взломов которые связаны с сайтом")
        for i, b in enumerate(payload["breaches"], 1):
            print(f"  {i}. [{b['source']}] {b['title']}")
            print(f"     {b['url']}")
            if b.get("reason"):
                print(f"     причина: {b['reason'][:160]}")

    print()
    print("[ STRUCTURE ]")
    print(payload["tree"])

    print()
    print("[ API HINTS ]")
    if payload.get("api_hints"):
        for a in payload["api_hints"]:
            print(f"  {a}")
    else:
        print("  (не найдено)")

    print()
    print("[ ROLES ]")
    for path, role in payload["roles"]:
        print(f"  {path} - {role}")

    print()
    print("[ VULNS / SURFACE ]")
    if payload["vulns"]:
        for f in payload["vulns"]:
            print(f"  {f['type']:<20} {f['target']}  ({f['evidence']})")
    else:
        print("  активные пробы инъекций/XSS/SSTI/traversal не дали сигнала")

    bp = payload["bot"]
    print(f"  captcha={bp['captcha']}  rate_limit={bp['rate_limit']}  waf='{bp['waf_hint']}'")
    for k, v in (bp["security_headers"] or {}).items():
        print(f"  {k}: {v}")

    print()
    print("[ EXPOSURE ]")
    if payload["exposure"]:
        for e in payload["exposure"]:
            print(f"  {e['path']}  ->  {e['status']}  ({e['len']}b)")
    else:
        print("  открытых артефактов не найдено")

    path = write_report(domain, payload)
    print()
    print(f"report saved: {os.path.abspath(path)}")


def main():
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        show_banner()
        domain = prompt_domain()
        if not domain:
            continue
        try:
            payload = scan(domain)
            if payload is not None:
                render(payload, domain)
        except KeyboardInterrupt:
            print()
            return
        except Exception as e:
            print(f"scan error: {e}")
        print()
        input("> Press Enter to return to the menu...")


if __name__ == "__main__":
    main()