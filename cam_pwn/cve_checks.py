"""
CVE checks for IP cameras. Hikvision, Dahua, and others.
Uses shared HTTP session with optional Tor/proxy from config.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import requests

from cam_pwn.config import get
from cam_pwn.http_client import session as http_session

logger = logging.getLogger(__name__)

# CVE-2017-7921: Hikvision auth bypass
CVE_2017_7921_SNAPSHOT = "/ISAPI/System/Video/inputs/channels/1/snapshot"
CVE_2017_7921_PATHS = ["/ISAPI/Security/userCheck", "/Security/users"]


def _session(timeout: int = 8) -> requests.Session:
    return http_session(timeout=timeout)


def _timeout() -> int:
    return int(get("stealth.request_timeout", 8) or 8)


def check_cve_2017_7921(ip: str, port: int = 80, use_ssl: bool = False) -> Tuple[bool, Optional[dict]]:
    """CVE-2017-7921 (Hikvision authentication bypass)."""
    base = f"{'https' if use_ssl else 'http'}://{ip}:{port}"
    t = _timeout()
    try:
        url = base + CVE_2017_7921_SNAPSHOT
        r = _session().get(url, timeout=t)
        if r.status_code == 200 and len(r.content) > 100:
            if r.headers.get("Content-Type", "").startswith("image/"):
                return True, {"snapshot_url": url}
            if b"\xff\xd8\xff" in r.content[:10] or b"\x89PNG" in r.content[:10]:
                return True, {"snapshot_url": url}
        for path in CVE_2017_7921_PATHS:
            r = _session().get(base + path, timeout=t)
            if r.status_code == 200 and ("userName" in r.text or "username" in r.text.lower()):
                return True, {"path": path}
    except Exception as e:
        logger.debug("CVE-2017-7921 %s:%s: %s", ip, port, e)
    return False, None


def check_cve_2018_9995(ip: str, port: int = 80, use_ssl: bool = False) -> Tuple[bool, Optional[dict]]:
    """CVE-2018-9995 (Dahua / TVT NVR auth bypass via cookie)."""
    base = f"{'https' if use_ssl else 'http'}://{ip}:{port}"
    try:
        # Request with Type cookie can leak device type / bypass auth on some versions
        r = _session().get(
            base + "/",
            cookies={"uid": "admin"},
            timeout=_timeout(),
        )
        if r.status_code == 200:
            # Some vulnerable devices return 200 with sensitive info in body when using specific cookies
            if "Dahua" in r.text or "dahua" in r.text or "NVR" in r.text:
                # Additional check: try common Dahua path without auth
                r2 = _session().get(base + "/cgi-bin/magicBox.cgi?action=getDeviceType", timeout=5)
                if r2.status_code == 200 and len(r2.text) > 0:
                    return True, {"device_info": r2.text[:200]}
    except Exception as e:
        logger.debug("CVE-2018-9995 %s:%s: %s", ip, port, e)
    return False, None


def check_cve_2021_36260(ip: str, port: int = 80, use_ssl: bool = False) -> Tuple[bool, Optional[dict]]:
    """CVE-2021-36260 (Hikvision RCE – vulnerable /SDK/webLanguage endpoint)."""
    base = f"{'https' if use_ssl else 'http'}://{ip}:{port}"
    try:
        # Vulnerable devices respond to this endpoint; we only probe, no payload
        r = _session().get(base + "/SDK/webLanguage", timeout=_timeout())
        if r.status_code == 200 and len(r.content) > 0:
            # Presence of endpoint suggests potentially vulnerable firmware
            return True, {"endpoint": "/SDK/webLanguage", "note": "endpoint present"}
    except Exception as e:
        logger.debug("CVE-2021-36260 %s:%s: %s", ip, port, e)
    return False, None


def check_cve_2020_25078(ip: str, port: int = 80, use_ssl: bool = False) -> Tuple[bool, Optional[dict]]:
    """CVE-2020-25078 (Dahua NVR/camera – command injection in time params)."""
    base = f"{'https' if use_ssl else 'http'}://{ip}:{port}"
    try:
        # Check for vulnerable endpoint; we do not send malicious payload
        r = _session().get(base + "/RPC2_Login", timeout=_timeout())
        if r.status_code in (200, 401, 404):
            # Device may be affected; real check would need auth
            if "Dahua" in r.text or "RPC2" in r.text or r.status_code == 401:
                return True, {"note": "RPC2_Login present"}
    except Exception as e:
        logger.debug("CVE-2020-25078 %s:%s: %s", ip, port, e)
    return False, None


CVE_CHECKS = {
    "CVE-2017-7921": check_cve_2017_7921,
    "CVE-2018-9995": check_cve_2018_9995,
    "CVE-2021-36260": check_cve_2021_36260,
    "CVE-2020-25078": check_cve_2020_25078,
}


def run_cve_checks(ip: str, port: int = 80, cves: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run selected CVE checks. Returns dict of CVE -> {vulnerable, info/error}."""
    cves = cves or list(CVE_CHECKS.keys())
    results = {}
    for cve_id in cves:
        if cve_id not in CVE_CHECKS:
            continue
        try:
            ok, info = CVE_CHECKS[cve_id](ip, port)
            results[cve_id] = {"vulnerable": ok, "info": info}
        except Exception as e:
            results[cve_id] = {"vulnerable": False, "error": str(e)}
    return results
