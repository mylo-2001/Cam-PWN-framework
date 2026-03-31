"""
HTML reporting with maps (Leaflet), statistics, and optional PDF/PGP.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cam_pwn.config import get
from cam_pwn.kali_paths import get_reports_dir
from cam_pwn.db.models import Camera, get_session, init_db

logger = logging.getLogger(__name__)

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False


REPORT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cam-PWN Report - {{ title }}</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    body { font-family: system-ui, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
    h1 { color: #e94560; }
    .stats { display: flex; flex-wrap: wrap; gap: 16px; margin: 20px 0; }
    .stat { background: #16213e; padding: 16px; border-radius: 8px; min-width: 140px; }
    .stat span { font-size: 24px; color: #0f3460; font-weight: bold; }
    #map { height: 500px; border-radius: 8px; margin: 20px 0; }
    table { border-collapse: collapse; width: 100%; margin: 20px 0; }
    th, td { border: 1px solid #0f3460; padding: 8px; text-align: left; }
    th { background: #16213e; }
    tr:nth-child(even) { background: #1a1a2e; }
    .vuln { color: #e94560; }
    .rtsp { font-size: 12px; word-break: break-all; }
    a { color: #0f3460; }
  </style>
</head>
<body>
  <h1>Cam-PWN Vulnerability Report</h1>
  <p>Generated: {{ generated_at }}</p>
  <h2>Statistics</h2>
  <div class="stats">
    <div class="stat">Total cameras <span>{{ total }}</span></div>
    <div class="stat">With vulnerabilities <span>{{ with_vulns }}</span></div>
    <div class="stat">With credentials <span>{{ with_creds }}</span></div>
    <div class="stat">Countries <span>{{ countries|length }}</span></div>
    <div class="stat">Honeypots (flagged) <span>{{ honeypots }}</span></div>
  </div>
  <h2>Map</h2>
  <div id="map"></div>
  <h2>Cameras</h2>
  <table>
    <thead>
      <tr>
        <th>IP:Port</th>
        <th>Country</th>
        <th>Product</th>
        <th>Vulns</th>
        <th>Risk</th>
        <th>Honeypot</th>
        <th>Web UI</th>
        <th>RTSP</th>
        <th>Payloads (by CVE)</th>
      </tr>
    </thead>
    <tbody>
      {{ table_rows | safe }}
    </tbody>
  </table>
  <script>
    var map = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '&copy; OSM' }).addTo(map);
    var markers = {{ markers_json }};
    markers.forEach(function(m) {
      if (m.lat != null && m.lon != null) {
        L.marker([m.lat, m.lon]).addTo(map).bindPopup(m.ip + ' ' + (m.product || ''));
      }
    });
  </script>
</body>
</html>
"""


def _get_stats(session, project: Optional[str] = None) -> Dict[str, Any]:
    q = session.query(Camera)
    if project is not None:
        q = q.filter(Camera.project == project)
    cameras = q.all()
    total = len(cameras)
    with_vulns = sum(1 for c in cameras if c.vulns and json.loads(c.vulns))
    with_creds = sum(1 for c in cameras if c.credentials and json.loads(c.credentials))
    countries = list({c.country for c in cameras if c.country})
    honeypots = sum(1 for c in cameras if c.is_honeypot)
    return {
        "total": total,
        "with_vulns": with_vulns,
        "with_creds": with_creds,
        "countries": countries,
        "honeypots": honeypots,
    }


def generate_html_report(
    output_path: Optional[str] = None,
    camera_ids: Optional[List[int]] = None,
    title: str = "IP Camera Assessment",
    project: Optional[str] = None,
) -> str:
    """Generate HTML report with map and stats. project filters by Camera.project."""
    init_db()
    session = get_session()
    q = session.query(Camera)
    if camera_ids:
        q = q.filter(Camera.id.in_(camera_ids))
    if project is not None:
        q = q.filter(Camera.project == project)
    cameras = []
    for c in q:
        cameras.append({
            "ip": c.ip,
            "port": c.port or 80,
            "country": c.country,
            "product": c.product,
            "vulns": json.loads(c.vulns) if c.vulns else [],
            "rtsp_url": c.rtsp_url,
            "lat": c.lat,
            "lon": c.lon,
            "risk_score": c.risk_score,
            "honeypot_score": c.honeypot_score,
            "is_honeypot": c.is_honeypot,
        })
    stats = _get_stats(session, project=project)
    session.close()

    from cam_pwn.payloads import build_native_tiles_for_vulns

    markers_json = json.dumps([{"ip": c["ip"], "lat": c.get("lat"), "lon": c.get("lon"), "product": c.get("product")} for c in cameras])
    rows = ""
    for c in cameras:
        vulns = ", ".join(c["vulns"]) if c["vulns"] else "-"
        risk = c.get("risk_score") if c.get("risk_score") is not None else ""
        hp_score = c.get("honeypot_score") if c.get("honeypot_score") is not None else ""
        hp_label = ""
        if c.get("is_honeypot"):
            hp_label = "YES"
        elif hp_score:
            hp_label = f"{hp_score:.2f}"
        http_url = f'http://{c["ip"]}:{c["port"]}/'
        http_link = f'<a href="{http_url}" target="_blank">HTTP</a>'
        rtsp = f'<a href="{c["rtsp_url"]}" target="_blank">RTSP</a>' if c.get("rtsp_url") else "-"
        tiles = build_native_tiles_for_vulns(c["vulns"], c["ip"], c["port"], use_ssl=False)
        payload_links = " ".join(
            f'<a href="{t["url"]}" target="_blank">{t["name"]}</a>' for t in tiles[:5]
        ) if tiles else "-"
        rows += (
            f'<tr>'
            f'<td>{c["ip"]}:{c["port"]}</td>'
            f'<td>{c.get("country") or "-"}</td>'
            f'<td>{c.get("product") or "-"}</td>'
            f'<td class="vuln">{vulns}</td>'
            f'<td>{risk if risk is not None else ""}</td>'
            f'<td>{hp_label}</td>'
            f'<td class="rtsp">{http_link}</td>'
            f'<td class="rtsp">{rtsp}</td>'
            f'<td class="rtsp">{payload_links}</td>'
            f'</tr>'
        )
    ctx = {
        "title": title,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "cameras": cameras,
        "markers_json": markers_json,
        "table_rows": rows,
        **stats,
    }
    if JINJA_AVAILABLE:
        env = Environment(autoescape=select_autoescape())
        t = env.from_string(REPORT_HTML_TEMPLATE)
        html = t.render(**ctx)
    else:
        html = REPORT_HTML_TEMPLATE.replace("{{ title }}", title)
        html = html.replace("{{ generated_at }}", ctx["generated_at"])
        html = html.replace("{{ total }}", str(stats["total"]))
        html = html.replace("{{ with_vulns }}", str(stats["with_vulns"]))
        html = html.replace("{{ with_creds }}", str(stats["with_creds"]))
        html = html.replace("{{ countries|length }}", str(len(stats["countries"])))
        html = html.replace("{{ honeypots }}", str(stats["honeypots"]))
        html = html.replace("{{ markers_json }}", markers_json)
        html = html.replace("{{ table_rows | safe }}", rows)

    out = output_path or Path(get_reports_dir()) / f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    if get("reporting.pgp_encrypt_reports") and get("reporting.pgp_recipient"):
        from cam_pwn.crypto_utils import pgp_encrypt_file
        pgp_encrypt_file(str(out), get("reporting.pgp_recipient"))
    return str(out)


def export_report_to_pdf(
    html_path: Optional[str] = None,
    output_path: Optional[str] = None,
    project: Optional[str] = None,
    title: str = "IP Camera Assessment",
) -> Optional[str]:
    """
    Generate HTML report (if html_path not given) then export to PDF via WeasyPrint.
    Returns path to PDF or None if WeasyPrint not available.
    """
    if not html_path:
        html_path = generate_html_report(
            output_path=None, camera_ids=None, title=title, project=project
        )
    try:
        from weasyprint import HTML
        out = output_path or str(
            Path(html_path).with_suffix(".pdf")
        )
        HTML(filename=html_path).write_pdf(out)
        return out
    except Exception as e:
        logger.warning("PDF export failed (install weasyprint?): %s", e)
        return None


def get_statistics(project: Optional[str] = None) -> Dict[str, Any]:
    """Return dashboard statistics: by country, firmware, honeypots. project filters by Camera.project."""
    init_db()
    session = get_session()
    q = session.query(Camera)
    if project is not None:
        q = q.filter(Camera.project == project)
    cameras = q.all()
    by_country: Dict[str, int] = {}
    by_product: Dict[str, int] = {}
    vuln_versions: Dict[str, int] = {}
    for c in cameras:
        by_country[c.country or "Unknown"] = by_country.get(c.country or "Unknown", 0) + 1
        by_product[c.product or "Unknown"] = by_product.get(c.product or "Unknown", 0) + 1
        if c.vulns and c.version:
            vuln_versions[c.version] = vuln_versions.get(c.version, 0) + 1
    session.close()
    return {
        "total": len(cameras),
        "by_country": by_country,
        "by_product": by_product,
        "vulnerable_firmware_versions": vuln_versions,
        "honeypot_count": sum(1 for c in cameras if c.is_honeypot),
    }
