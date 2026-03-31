"""
Auto-start Metasploit RPC daemon (msfrpcd) if not running.
Target: Linux / Kali. Finds msfrpcd and starts it in background.
"""

import logging
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from cam_pwn.config import get

logger = logging.getLogger(__name__)

PORT = 55553
HOST = "127.0.0.1"
WAIT_SEC = 8


def _port_open(host: str = HOST, port: int = PORT) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        r = s.connect_ex((host, port))
        s.close()
        return r == 0
    except Exception:
        return False


# Kali / Linux paths for msfrpcd (framework is Linux-first)
KALI_MSFRPCD_PATHS = [
    "/usr/bin/msfrpcd",           # Kali, apt install metasploit-framework
    "/opt/metasploit-framework/msfrpcd",
    "/opt/metasploit/app/msfrpcd",
    "/usr/share/metasploit-framework/msfrpcd",
    "/usr/local/bin/msfrpcd",
]


def _find_msfrpcd() -> Optional[str]:
    """Find msfrpcd executable. Kali/Linux first (primary platform)."""
    custom = get("exploitation.msfrpcd_path") or os.environ.get("CAM_PWN_MSFRPCD_PATH")
    if custom and os.path.isfile(custom):
        return custom
    # Linux / Kali: common paths + PATH
    for p in KALI_MSFRPCD_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    exe = shutil.which("msfrpcd")
    if exe:
        return exe
    # Windows (fallback)
    if sys.platform == "win32":
        for p in [
            r"C:\metasploit-framework\bin\msfrpcd.bat",
            r"C:\Metasploit\bin\msfrpcd.bat",
        ]:
            if os.path.isfile(p):
                return p
    return None


def start_msfrpcd(
    password: Optional[str] = None,
    host: str = HOST,
    port: int = PORT,
) -> bool:
    """
    Start msfrpcd in background if not already running.
    Returns True if msfrpcd is reachable after call (was already running or started successfully).
    """
    if _port_open(host, port):
        return True
    password = password or get("exploitation.metasploit_rpc_pass") or os.environ.get("CAM_PWN_MSF_PASS")
    if not password:
        logger.warning("No MSF password in config or CAM_PWN_MSF_PASS. Set exploitation.metasploit_rpc_pass in config.yaml")
        return False
    exe = _find_msfrpcd()
    if not exe:
        logger.warning("msfrpcd not found. Install Metasploit Framework or add it to PATH.")
        return False
    cmd = [exe, "-P", password, "-S", "-a", host, "-p", str(port)]
    try:
        kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if sys.platform == "win32":
            cf = getattr(subprocess, "CREATE_NO_WINDOW", None)
            if cf is not None:
                kw["creationflags"] = cf
        else:
            kw["start_new_session"] = True
        subprocess.Popen(cmd, **kw)
        for _ in range(WAIT_SEC):
            time.sleep(1)
            if _port_open(host, port):
                return True
    except Exception as e:
        logger.warning("Failed to start msfrpcd: %s", e)
    return False


def ensure_msfrpcd_running() -> bool:
    """If msfrpcd not running, try to start it. Returns True if reachable."""
    host = get("exploitation.metasploit_rpc_host", HOST)
    port = int(get("exploitation.metasploit_rpc_port", PORT))
    if _port_open(host, port):
        return True
    return start_msfrpcd(host=host, port=port)
