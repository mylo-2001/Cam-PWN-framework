"""Foscam camera plugin: fingerprinting."""

import logging
from typing import Any, Dict

import requests

logger = logging.getLogger(__name__)


def scan(ip: str, port: int = 80, **kwargs) -> Dict[str, Any]:
    """Fingerprint Foscam camera."""
    result = {"camera_type": "foscam", "vulnerable": False}
    base = f"http://{ip}:{port}"
    try:
        r = requests.get(f"{base}/", timeout=5)
        if "foscam" in r.text.lower() or "Foscam" in r.text:
            result["identified"] = True
    except Exception as e:
        result["error"] = str(e)
    return result
