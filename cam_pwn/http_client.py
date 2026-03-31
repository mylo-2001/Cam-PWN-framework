"""
Shared HTTP session with optional Tor/proxy from config.
Use for CVE checks, Shodan (if proxy supported), and other outbound requests.
"""

from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cam_pwn.config import get


def get_proxies() -> Optional[Dict[str, str]]:
    """
    Return proxies dict for requests (e.g. {"http": "socks5://127.0.0.1:9050", "https": "..."}).
    Set in config: proxy.http, proxy.https or proxy.url for both.
    """
    cfg = get("proxy") or {}
    if not cfg:
        return None
    url = cfg.get("url")
    if url:
        return {"http": url, "https": url}
    out = {}
    if cfg.get("http"):
        out["http"] = cfg["http"]
    if cfg.get("https"):
        out["https"] = cfg["https"]
    return out if out else None


def session(timeout: int = 8, use_proxy: bool = True) -> requests.Session:
    """Build requests.Session with retries and optional proxy from config."""
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"})
    retries = Retry(total=2, backoff_factor=0.5)
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    if use_proxy:
        proxies = get_proxies()
        if proxies:
            s.proxies.update(proxies)
    return s
