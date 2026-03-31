"""
Integration with Burp Suite and OWASP ZAP: send vulnerable endpoints for scanning.
"""

import logging
from typing import List, Optional

from cam_pwn.config import get, get_current_project
from cam_pwn.db.models import Camera, get_session, init_db

logger = logging.getLogger(__name__)


def _burp_proxy() -> Optional[str]:
    if not get("integrations.burp.enabled", False):
        return None
    return get("integrations.burp.proxy", "http://127.0.0.1:8080")


def send_to_burp(camera_ids: Optional[List[int]] = None, project: Optional[str] = None) -> int:
    """
    Send vulnerable camera URLs to Burp by issuing requests through Burp proxy.
    project filters by Camera.project.
    """
    proxy = _burp_proxy()
    if not proxy:
        return 0
    init_db()
    session = get_session()
    q = session.query(Camera)
    if camera_ids:
        q = q.filter(Camera.id.in_(camera_ids))
    if project is not None:
        q = q.filter(Camera.project == project)
    count = 0
    try:
        import requests
        for c in q:
            base = f"http://{c.ip}:{c.port or 80}"
            try:
                requests.get(base + "/", proxies={"http": proxy, "https": proxy}, timeout=5)
                count += 1
            except Exception as e:
                logger.debug("Burp send %s failed: %s", base, e)
    finally:
        session.close()
    return count


def send_to_zap(camera_ids: Optional[List[int]] = None, project: Optional[str] = None) -> int:
    """
    Add URLs to ZAP for passive/active scanning via ZAP API.
    project filters by Camera.project.
    """
    if not get("integrations.zap.enabled", False):
        return 0
    base_url = get("integrations.zap.base_url", "http://127.0.0.1:8080").rstrip("/")
    api_key = get("integrations.zap.api_key", "")
    init_db()
    session = get_session()
    q = session.query(Camera)
    if camera_ids:
        q = q.filter(Camera.id.in_(camera_ids))
    if project is not None:
        q = q.filter(Camera.project == project)
    count = 0
    try:
        import requests
        for c in q:
            url = f"http://{c.ip}:{c.port or 80}/"
            try:
                r = requests.get(
                    f"{base_url}/JSON/core/action/accessUrl/",
                    params={"url": url, "apikey": api_key},
                    timeout=5,
                )
                if r.status_code == 200:
                    count += 1
            except Exception as e:
                logger.debug("ZAP send %s failed: %s", url, e)
    finally:
        session.close()
    return count
