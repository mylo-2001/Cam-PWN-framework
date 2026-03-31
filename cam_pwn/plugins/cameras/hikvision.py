"""Hikvision camera plugin: fingerprinting and CVE-2017-7921."""

import logging
from typing import Any, Dict, Optional

import requests

from cam_pwn.cve_checks import check_cve_2017_7921

logger = logging.getLogger(__name__)


def scan(ip: str, port: int = 80, **kwargs) -> Dict[str, Any]:
    """Fingerprint Hikvision and check CVE-2017-7921."""
    result = {"camera_type": "hikvision", "vulnerable": False, "cves": []}
    base = f"http://{ip}:{port}"
    try:
        r = requests.get(f"{base}/", timeout=5)
        if "hikvision" in r.text.lower() or "Hikvision" in r.text:
            result["identified"] = True
        vuln, info = check_cve_2017_7921(ip, port)
        if vuln:
            result["vulnerable"] = True
            result["cves"].append("CVE-2017-7921")
            result["info"] = info
    except Exception as e:
        result["error"] = str(e)
    return result
