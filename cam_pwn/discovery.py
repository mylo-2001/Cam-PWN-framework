"""
Local network discovery: find IP cameras on the same network.
Uses ARP scan / port scan on common camera ports.
"""

import ipaddress
import logging
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Set, Tuple

from cam_pwn.config import get
from cam_pwn.db.models import Camera, get_session, init_db, ScanResult
from cam_pwn.network_utils import get_local_ips, get_public_ip

logger = logging.getLogger(__name__)

# Common camera ports
CAMERA_PORTS = [80, 443, 554, 8080, 8443, 8554, 8888, 37777, 34567]


def get_local_networks() -> List[Tuple[str, str]]:
    """Return list of (network_cidr, interface) for local IPs."""
    try:
        import psutil
    except ImportError:
        return []
    result = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                try:
                    net = ipaddress.ip_network(f"{addr.address}/24", strict=False)
                    result.append((str(net), name))
                except Exception:
                    pass
    return result


def _scan_port(ip: str, port: int, timeout: float = 1.5) -> Optional[dict]:
    """Probe one IP:port. Returns minimal banner if open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        if r != 0:
            return None
        # Optional: GET / for HTTP to get Server/title (uses proxy from config if set)
        if port in (80, 443, 8080, 8888):
            try:
                from cam_pwn.http_client import session as http_session
                proto = "https" if port in (443, 8443) else "http"
                r = http_session().get(f"{proto}://{ip}:{port}/", timeout=3)
                data = r.text[:4096] if r.text else ""
                if "hikvision" in data.lower() or "dahua" in data.lower() or "foscam" in data.lower() or "axis" in data.lower() or "ipcam" in data.lower():
                    return {"ip": ip, "port": port, "banner": data[:500]}
            except Exception:
                pass
        return {"ip": ip, "port": port}
    except Exception:
        return None


def discover_local(
    networks: Optional[List[str]] = None,
    ports: Optional[List[int]] = None,
    max_workers: int = 50,
) -> List[dict]:
    """
    Scan local network(s) for open camera ports.
    networks: list of CIDR e.g. ['192.168.1.0/24']. If None, use local interfaces.
    """
    ports = ports or get("bruteforce.rtsp_ports", [554, 8554]) + get("bruteforce.http_ports", [80, 8080, 8888])
    ports = list(dict.fromkeys(ports))

    if not networks:
        nets = get_local_networks()
        networks = [n[0] for n in nets] if nets else []
    if not networks:
        logger.warning("No local networks to scan")
        return []

    all_ips: Set[str] = set()
    for cidr in networks:
        try:
            for ip in ipaddress.ip_network(cidr, strict=False).hosts():
                all_ips.add(str(ip))
        except Exception as e:
            logger.debug("Skip network %s: %s", cidr, e)

    found: List[dict] = []
    timeout = get("bruteforce.timeout", 5) or 2

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {}
        for ip in all_ips:
            for port in ports:
                futures[ex.submit(_scan_port, ip, port, min(timeout, 2))] = (ip, port)
        for fut in as_completed(futures):
            try:
                r = fut.result()
                if r:
                    found.append(r)
            except Exception as e:
                logger.debug("Scan task error: %s", e)

    # Dedupe by ip
    by_ip: dict = {}
    for f in found:
        by_ip.setdefault(f["ip"], []).append(f["port"])
    result = [{"ip": ip, "ports": ports} for ip, ports in sorted(by_ip.items())]
    return result


def discover_and_store(
    networks: Optional[List[str]] = None,
    max_workers: int = 50,
) -> int:
    """Run local discovery and insert new cameras into DB. Returns count added."""
    from cam_pwn.config import get_current_project
    init_db()
    session = get_session()
    project = get_current_project()
    added = 0
    try:
        for hit in discover_local(networks=networks, max_workers=max_workers):
            ip = hit["ip"]
            ports = hit.get("ports", [])
            rtsp_port = 554 if 554 in ports else (8554 if 8554 in ports else None)
            http_port = next((p for p in [80, 8080, 8888, 443] if p in ports), (ports[0] if ports else 80))
            existing = session.query(Camera).filter(Camera.ip == ip).first()
            if existing:
                continue
            cam = Camera(
                project=project,
                ip=ip,
                port=http_port,
                rtsp_port=rtsp_port or 554,
                protocol="http",
                product="Unknown (local scan)",
            )
            session.add(cam)
            session.flush()  # so cam.id is set
            session.add(ScanResult(camera_id=cam.id, scan_type="local_scan", result=str(hit), success=True))
            added += 1
        session.commit()
    except Exception as e:
        session.rollback()
        logger.exception("discover_and_store failed: %s", e)
        raise
    finally:
        session.close()
    return added
