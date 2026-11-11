import os
import time


def write(domain: str, payload: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join("reports", f"scan_{domain}_{ts}.txt")
    lines = []
    lines.append(f"SCOPEBREAKER report :: {domain}")
    lines.append(f"generated: {payload.get('scanned_at')}")
    lines.append("=" * 72)
    lines.append("\n[WHOIS / DNS]")
    for k, v in (payload.get("whois") or {}).items():
        lines.append(f"  {k}: {v}")
    lines.append("\n[BREACH / INCIDENTS]")
    breaches = payload.get("breaches") or []
    if not breaches:
        lines.append("Взломов связанной с данном сайтом не найдено")
    else:
        lines.append(f"Найдено ({len(breaches)}) взломов которые связаны с сайтом")
        for i, b in enumerate(breaches, 1):
            lines.append(f"  {i}. [{b['source']}] {b['title']}")
            lines.append(f"     url: {b['url']}")
            lines.append(f"     reason: {b['reason']}")
    lines.append("\n[STRUCTURE]")
    lines.append(payload.get("tree") or "  (no pages)")
    lines.append("\n[ROLES]")
    for p, role in payload.get("roles") or []:
        lines.append(f"  {p} - {role}")
    lines.append("\n[VULNERABILITIES]")
    for f in payload.get("vulns") or []:
        lines.append(f"  {f['type']} :: {f['target']} :: {f['evidence']}")
    if not payload.get("vulns"):
        lines.append("  surface probes: не выявили")
    lines.append("\n[BOT PROTECTION]")
    bp = payload.get("bot") or {}
    lines.append(f"  captcha: {bp.get('captcha')}")
    lines.append(f"  rate_limit: {bp.get('rate_limit')}")
    lines.append(f"  waf_hint: {bp.get('waf_hint')}")
    for k, v in (bp.get("security_headers") or {}).items():
        lines.append(f"  {k}: {v}")
    lines.append("\n[EXPOSURE]")
    for e in payload.get("exposure") or []:
        lines.append(f"  {e['path']} :: {e['status']} :: {e['len']}b")
    if not payload.get("exposure"):
        lines.append("ничего подозрительного не открыто")
    lines.append("\n" + "=" * 72)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path