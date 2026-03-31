"""
Network utilities: local IP(s), public IP (for discovery context).
"""

import socket
from typing import List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


def get_local_ips() -> List[str]:
    """Return list of local IPv4 addresses (excluding loopback)."""
    out = []
    if PSUTIL_AVAILABLE:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if getattr(addr, "family", None) == socket.AF_INET:
                    a = getattr(addr, "address", None) or getattr(addr, "addr", None)
                    if a and not a.startswith("127."):
                        out.append(a)
    if not out:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            out.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return list(dict.fromkeys(out))


def get_public_ip(timeout: float = 5.0) -> Optional[str]:
    """Fetch public (outbound) IP via external service."""
    urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    try:
        import urllib.request
        req = urllib.request.Request(urls[0], headers={"User-Agent": "CamPWN/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8").strip()
    except Exception:
        pass
    for url in urls[1:]:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "CamPWN/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8").strip()
        except Exception:
            continue
    return None
