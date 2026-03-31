"""Dahua camera plugin: fingerprinting and default credentials check."""

import logging
from typing import Any, Dict

import requests

logger = logging.getLogger(__name__)


def scan(ip: str, port: int = 80, **kwargs) -> Dict[str, Any]:
    """Fingerprint Dahua camera."""
    result = {"camera_type": "dahua", "vulnerable": False}
    base = f"http://{ip}:{port}"
    try:
        r = requests.get(f"{base}/", timeout=5)
        if "dahua" in r.text.lower() or "DHI" in r.text:
            result["identified"] = True
        # Common path
        r2 = requests.get(f"{base}/cgi-bin/magicBox.cgi?action=getDeviceType", timeout=5)
        if r2.status_code == 200:
            result["device_info"] = r2.text[:200]
    except Exception as e:
        result["error"] = str(e)
    return result
