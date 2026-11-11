import socket
from datetime import datetime

import dns.resolver
import requests
import whois

UA = "Mozilla/5.0 (compatible; ScopeBreaker/1.0)"


def _rdap(domain: str) -> dict:
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=8, headers={"User-Agent": UA})
        if r.status_code != 200:
            return {}
        j = r.json()
        out = {}
        for ev in j.get("events", []):
            if ev.get("eventAction") == "registration":
                out["created"] = ev.get("eventDate")
            if ev.get("eventAction") == "expiration":
                out["expires"] = ev.get("eventDate")
        for ent in j.get("entities", []):
            roles = ent.get("roles", [])
            vcard = ent.get("vcardArray", [None, []])
            name = None
            for item in vcard[1] if len(vcard) > 1 else []:
                if item[0] == "fn":
                    name = item[3]
            if "registrar" in roles:
                out["registrar"] = name
            if "registrant" in roles:
                out["owner"] = name
        return out
    except Exception:
        return {}


def _dns(domain: str) -> dict:
    res = {}
    try:
        res["ip"] = socket.gethostbyname(domain)
    except Exception:
        res["ip"] = None
    for rtype in ("NS", "MX", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            res[rtype.lower()] = [str(a).strip('"') for a in answers]
        except Exception:
            res[rtype.lower()] = []
    return res


def lookup(domain: str) -> dict | None:
    info = {"domain": domain}
    try:
        w = whois.whois(domain)
        if not w or not (w.domain_name or w.registrar):
            raise ValueError("empty whois")
        info["registrar"] = w.registrar
        info["owner"] = w.get("org") or w.get("name")
        info["created"] = str(w.creation_date)
        info["expires"] = str(w.expiration_date)
        info["nameservers"] = w.name_servers
        info["status"] = w.status
    except Exception:
        info.update(_rdap(domain))
        if not (info.get("registrar") or info.get("created")):
            return None
    info.update(_dns(domain))
    info["scanned_at"] = datetime.utcnow().isoformat() + "Z"
    return info