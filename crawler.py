import re
import socket
import time
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import PurePosixPath
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

UA = "Mozilla/5.0 (compatible; ScopeBreaker/1.0)"
FILE_RX = re.compile(r"\.\w{1,6}$")
BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
JS_PATH_RX = re.compile(r"""["'`](/[a-zA-Z0-9_\-/\.]{2,80})["'`]""")
JS_FETCH_RX = re.compile(r"""(?:fetch|axios\.(?:get|post)|\.open)\s*\(\s*["'`]([^"'`]+)["'`]""")
SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|mp3|pdf|zip|gz|tar)$", re.I)
API_HINT_RX = re.compile(r"/(api|graphql|v\d+|rest|rpc)/", re.I)
SEED_PATHS = ("/.well-known/security.txt", "/admin/", "/login", "/api/", "/robots.txt", "/sitemap.xml")


def _safe_name(name: str) -> str:
    return BAD_CHARS.sub("_", name)[:120]


def _fetch(url: str, timeout: float = 8.0, method: str = "GET", data=None):
    try:
        return requests.request(method, url, timeout=timeout, data=data,
                                headers={"User-Agent": UA}, allow_redirects=True)
    except Exception:
        return None


def _robots_sitemap(root: str, host: str) -> list[str]:
    extra = []
    r = _fetch(root.rstrip("/") + "/robots.txt", timeout=6)
    if r and r.status_code == 200 and "text" in r.headers.get("content-type", ""):
        for line in r.text.splitlines():
            low = line.lower()
            if low.startswith(("sitemap:", "disallow:")):
                p = line.split(":", 1)[1].strip()
                if not p or p == "/":
                    continue
                if p.startswith("http"):
                    if urlsplit(p).netloc == host:
                        extra.append(p)
                else:
                    extra.append(urljoin(root, p))
    r = _fetch(root.rstrip("/") + "/sitemap.xml", timeout=6)
    if r and r.status_code == 200 and "xml" in r.headers.get("content-type", ""):
        try:
            tree = ET.fromstring(r.content)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in tree.findall(".//sm:loc", ns)[:200]:
                if loc.text and urlsplit(loc.text).netloc == host:
                    extra.append(loc.text)
        except ET.ParseError:
            pass
    return extra


def _js_links(html: str, base: str) -> list[str]:
    out = []
    for rx in (JS_PATH_RX, JS_FETCH_RX):
        for m in rx.findall(html):
            full = urljoin(base, m)
            if SKIP_EXT.search(urlsplit(full).path):
                continue
            out.append(full)
    return out


def crawl(base: str, max_pages: int = 60, depth: int = 2, delay: float = 0.15, progress=None) -> dict:
    root = base if base.startswith("http") else f"https://{base}"
    host = urlsplit(root).netloc
    seen = set()
    q = deque([(root, 0)])
    for sp in SEED_PATHS:
        q.append((root.rstrip("/") + sp, 0))
    for u in _robots_sitemap(root, host):
        if u not in seen:
            q.append((u, 0))

    pages = {}
    scripts = set()
    forms = []
    api_hints = set()

    while q and len(seen) < max_pages:
        url, d = q.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            r = _fetch(url)
            if not r or "text/html" not in r.headers.get("content-type", ""):
                pages[url] = {"links": [], "status": r.status_code if r else None}
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            links = []
            for a in soup.find_all("a", href=True):
                href = a["href"].split("#")[0].split("?")[0]
                full = urljoin(url, href)
                sp = urlsplit(full)
                if sp.netloc != host or sp.scheme not in ("http", "https"):
                    continue
                if SKIP_EXT.search(sp.path):
                    continue
                links.append(full)
                if API_HINT_RX.search(sp.path):
                    api_hints.add(full)
                if d < depth and full not in seen:
                    q.append((full, d + 1))
            for s in soup.find_all("script", src=True):
                scripts.add(s["src"])
            for s in soup.find_all("script"):
                if s.string:
                    for js_link in _js_links(s.string, url):
                        if js_link not in seen and urlsplit(js_link).netloc == host:
                            q.append((js_link, d + 1))
            for f in soup.find_all("form"):
                action = f.get("action", url)
                method = (f.get("method") or "get").upper()
                enctype = f.get("enctype", "application/x-www-form-urlencoded")
                inputs = []
                for tag in f.find_all(["input", "textarea", "select"]):
                    n = tag.get("name")
                    if not n:
                        continue
                    inputs.append({
                        "name": n,
                        "type": tag.get("type", tag.name),
                    })
                forms.append({
                    "action": action,
                    "method": method,
                    "enctype": enctype,
                    "inputs": inputs,
                })
            pages[url] = {"links": links, "status": r.status_code}
        except Exception:
            pages[url] = {"links": [], "status": None}
        if progress:
            progress(min(99.0, (len(seen) / max_pages) * 100), f"crawl:{len(seen)}")
        time.sleep(delay)

    return {
        "root": root,
        "host": host,
        "pages": pages,
        "scripts": sorted(scripts),
        "forms": forms,
        "api_hints": sorted(api_hints),
    }


def as_tree(data: dict) -> str:
    host = data.get("host") or urlsplit(data["root"]).netloc
    tree = {}
    for url in data["pages"]:
        path = urlsplit(url).path or "/"
        parts = [p for p in PurePosixPath(path).parts if p and p != "/"]
        node = tree
        for p in parts:
            node = node.setdefault(_safe_name(p), {})
    lines = [f"-/  ({host})"]

    def walk(node, prefix):
        for name, child in sorted(node.items()):
            if not name:
                continue
            is_file = bool(FILE_RX.search(name))
            marker = "-- " if is_file else "-/ "
            lines.append(f"{prefix}{marker}{name}")
            if child:
                walk(child, prefix + ("   " if is_file else "|  "))

    walk(tree, "  ")
    return "\n".join(lines)