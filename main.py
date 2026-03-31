#!/usr/bin/env python3
"""
Cam-PWN: IP Camera Penetration Testing Framework

Usage:
  python main.py discover --local              # Find cameras on local network
  python main.py shodan --query "port:554"     # Shodan search and store
  python main.py cve --all                     # Run CVE checks on all in DB
  python main.py brute --rtsp                  # RTSP brute-force on DB cameras
  python main.py exploit --name rfi            # Run exploit (e.g. rfi) on all
  python main.py report --output report.html   # Generate HTML report
  python main.py stats                         # Show statistics dashboard
  python main.py burp                          # Send targets to Burp
  python main.py zap                           # Send targets to ZAP

Use only on systems you are authorized to test.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# Ensure package is on path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cam_pwn import __version__
from cam_pwn.config import load_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("cam_pwn")


def cmd_discover(args):
    from cam_pwn.discovery import discover_and_store
    from cam_pwn.network_utils import get_local_ips, get_public_ip
    local_ips = get_local_ips()
    public_ip = get_public_ip()
    if local_ips:
        log.info("Your local IP(s): %s", ", ".join(local_ips))
    if public_ip:
        log.info("Your public IP: %s", public_ip)
    n = discover_and_store(networks=args.network, max_workers=args.workers)
    log.info("Discovered and stored %d new cameras", n)


def cmd_shodan(args):
    from cam_pwn.shodan_client import ShodanClient
    from cam_pwn.config import get
    api_key = os.environ.get("CAM_PWN_SHODAN_KEY") or get("shodan.api_key")
    if not api_key:
        log.error("Set CAM_PWN_SHODAN_KEY or shodan.api_key in config")
        return 1
    client = ShodanClient(api_key)
    queries = args.query if args.query else None
    if isinstance(queries, str):
        queries = [queries]
    n = client.search_and_store(queries=queries, country=args.country, limit_per_query=args.limit)
    log.info("Shodan: stored %d new cameras", n)
    return 0


def cmd_cve(args):
    from cam_pwn.mass_exploit import mass_cve_scan
    results = mass_cve_scan(camera_ids=args.id, max_workers=args.workers)
    vuln = [r for r in results if r.get("vulns")]
    log.info("CVE scan: %d cameras with vulns", len(vuln))
    for r in vuln:
        log.info("  %s %s", r.get("ip"), r.get("vulns"))


def cmd_brute(args):
    from cam_pwn.rtsp_bruteforce import run_rtsp_bruteforce_on_db
    n = run_rtsp_bruteforce_on_db(camera_ids=args.id, wordlist_path=args.wordlist)
    log.info("RTSP brute: %d cameras with new credentials", n)


def cmd_exploit(args):
    from cam_pwn.mass_exploit import mass_exploit
    results = mass_exploit(args.name, camera_ids=args.id, max_workers=args.workers)
    ok = [r for r in results if r.get("success")]
    log.info("Exploit %s: %d successful", args.name, len(ok))


def cmd_report(args):
    from cam_pwn.reporting import generate_html_report
    path = generate_html_report(output_path=args.output, camera_ids=args.id, title=args.title)
    log.info("Report written to %s", path)


def cmd_stats(args):
    from cam_pwn.reporting import get_statistics
    s = get_statistics()
    log.info("Total cameras: %d", s["total"])
    log.info("By country: %s", s.get("by_country"))
    log.info("By product: %s", s.get("by_product"))
    log.info("Honeypots (flagged): %d", s.get("honeypot_count", 0))


def cmd_burp(args):
    from cam_pwn.integrations import send_to_burp
    n = send_to_burp(camera_ids=args.id)
    log.info("Sent %d URLs to Burp", n)


def cmd_zap(args):
    from cam_pwn.integrations import send_to_zap
    n = send_to_zap(camera_ids=args.id)
    log.info("Sent %d URLs to ZAP", n)


def main():
    parser = argparse.ArgumentParser(description="Cam-PWN IP Camera Penetration Testing Framework")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", help="Command")

    # discover
    p = sub.add_parser("discover", help="Discover cameras on local network")
    p.add_argument("--local", action="store_true", help="Use local interface networks")
    p.add_argument("--network", nargs="*", help="CIDR(s) e.g. 192.168.1.0/24")
    p.add_argument("--workers", type=int, default=50)
    p.set_defaults(func=cmd_discover)

    # shodan
    p = sub.add_parser("shodan", help="Shodan search and store in SQLite")
    p.add_argument("--query", nargs="*", help="Shodan query (default: camera queries)")
    p.add_argument("--country", type=str, help="Country code filter")
    p.add_argument("--limit", type=int, default=1000)
    p.set_defaults(func=cmd_shodan)

    # cve
    p = sub.add_parser("cve", help="Run CVE checks on cameras")
    p.add_argument("--id", type=int, nargs="*", help="Camera IDs (default: all)")
    p.add_argument("--workers", type=int, default=20)
    p.set_defaults(func=cmd_cve)

    # brute
    p = sub.add_parser("brute", help="RTSP/HTTP brute-force")
    p.add_argument("--rtsp", action="store_true", help="RTSP brute (default)")
    p.add_argument("--id", type=int, nargs="*")
    p.add_argument("--wordlist", type=str, help="Path to wordlist (user:pass or pass per line)")
    p.set_defaults(func=cmd_brute)

    # exploit
    p = sub.add_parser("exploit", help="Run exploit on cameras")
    p.add_argument("--name", type=str, required=True, help="e.g. rfi, rtsp_buffer_overflow")
    p.add_argument("--id", type=int, nargs="*")
    p.add_argument("--workers", type=int, default=10)
    p.set_defaults(func=cmd_exploit)

    # report
    p = sub.add_parser("report", help="Generate HTML report with map")
    p.add_argument("--output", type=str)
    p.add_argument("--id", type=int, nargs="*")
    p.add_argument("--title", type=str, default="IP Camera Assessment")
    p.set_defaults(func=cmd_report)

    # stats
    p = sub.add_parser("stats", help="Statistics dashboard")
    p.set_defaults(func=cmd_stats)

    # burp / zap
    p = sub.add_parser("burp", help="Send vulnerable URLs to Burp Suite")
    p.add_argument("--id", type=int, nargs="*")
    p.set_defaults(func=cmd_burp)
    p = sub.add_parser("zap", help="Send vulnerable URLs to OWASP ZAP")
    p.add_argument("--id", type=int, nargs="*")
    p.set_defaults(func=cmd_zap)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0
    try:
        args.func(args)
    except Exception as e:
        log.exception("%s", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
