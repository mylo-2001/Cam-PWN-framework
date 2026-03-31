"""
Health check: ping cameras from DB to see which are still alive.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from cam_pwn.config import get, get_current_project
from cam_pwn.db.models import Camera, get_session, init_db

TIMEOUT = 3


def _ping_one(ip: str, port: int, timeout: float) -> Tuple[str, int, bool]:
    """Probe IP:port. Returns (ip, port, alive)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return (ip, port, r == 0)
    except Exception:
        return (ip, port, False)


def health_check_cameras(
    camera_ids: Optional[List[int]] = None,
    project: Optional[str] = None,
    max_workers: int = 50,
) -> Dict[str, Any]:
    """Ping cameras in DB. Returns {alive: [(ip,port),...], dead: [(ip,port),...], total}."""
    init_db()
    session = get_session()
    q = session.query(Camera)
    if camera_ids:
        q = q.filter(Camera.id.in_(camera_ids))
    if project is not None:
        q = q.filter(Camera.project == project)
    cameras = [(c.ip, c.port or 80) for c in q]
    session.close()

    timeout = float(get("stealth.request_timeout", 8) or 8)
    alive = []
    dead = []
    seen = set()
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_ping_one, ip, port, min(timeout, TIMEOUT)): (ip, port) for ip, port in cameras}
        for fut in as_completed(futures):
            ip, port, ok = fut.result()
            key = (ip, port)
            if key in seen:
                continue
            seen.add(key)
            if ok:
                alive.append(key)
            else:
                dead.append(key)
    return {"alive": alive, "dead": dead, "total": len(cameras)}
