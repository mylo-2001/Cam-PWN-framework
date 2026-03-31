"""
Shodan API client with geolocation filtering and SQLite storage.
Uses proxy from config (proxy.url or proxy.http/https) when set.
"""

import os
import logging
from typing import Any, Dict, Generator, List, Optional

from cam_pwn.config import get, get_current_project
from cam_pwn.http_client import get_proxies
from cam_pwn.db.models import Camera, get_session, init_db, ScanResult
from cam_pwn.risk import compute_honeypot_score_from_shodan_data, compute_risk_score

logger = logging.getLogger(__name__)

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False


# Common Shodan queries for IP cameras
DEFAULT_QUERIES = [
    "port:554 rtsp",
    "port:80 title:IPCAM",
    "port:80 title:Hikvision",
    "port:80 title:Dahua",
    "port:80 title:Foscam",
    "port:8080 title:webcam",
    "port:80 http.component:onvif",
    "port:554 product:VLC",
    'port:80 "Server: GoAhead"',
    "port:80 http.html:axis",
]


def _extract_geo(data: dict) -> tuple:
    loc = (data.get("location") or {})
    return (
        loc.get("country_code"),
        loc.get("city"),
        loc.get("latitude"),
        loc.get("longitude"),
    )


def _to_camera(shodan_result: dict, query: str = "") -> Optional[Camera]:
    try:
        ip = shodan_result.get("ip_str")
        if not ip:
            return None
        port = shodan_result.get("port")
        country, city, lat, lon = _extract_geo(shodan_result)
        product = (shodan_result.get("product") or shodan_result.get("http", {}).get("title") or "")[:255]
        version = (shodan_result.get("version") or "")[:100]
        vulns = shodan_result.get("vulns")
        vuln_list = list(vulns) if isinstance(vulns, list) else ([vulns] if vulns else [])
        if isinstance(vulns, dict):
            vuln_list = list(vulns.keys()) if vulns else []

        shodan_json = __import__("json").dumps(shodan_result) if shodan_result else None

        c = Camera(
            ip=ip,
            port=port or 80,
            rtsp_port=554,
            protocol="rtsp" if port == 554 else "http",
            country=country,
            city=city,
            lat=float(lat) if lat is not None else None,
            lon=float(lon) if lon is not None else None,
            product=product or None,
            version=version or None,
            vulns=__import__("json").dumps(vuln_list) if vuln_list else None,
            shodan_data=shodan_json,
        )

        # Honeypot & risk heuristics
        hp_score = compute_honeypot_score_from_shodan_data(shodan_json)
        c.honeypot_score = hp_score
        c.is_honeypot = hp_score >= 0.7
        c.risk_score = compute_risk_score(c)
        return c
    except Exception as e:
        logger.debug("Skip result %s: %s", shodan_result.get("ip_str"), e)
        return None


class ShodanClient:
    """Shodan API client with storage."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or get("shodan.api_key")
        self.client = None
        if SHODAN_AVAILABLE and self.api_key:
            self.client = shodan.Shodan(self.api_key)
        self.max_results = get("shodan.max_results_per_query", 1000)

    def search(
        self,
        query: str,
        limit: Optional[int] = None,
        country: Optional[str] = None,
        min_lat: Optional[float] = None,
        max_lat: Optional[float] = None,
        min_lon: Optional[float] = None,
        max_lon: Optional[float] = None,
    ) -> Generator[dict, None, None]:
        """Search Shodan with optional geo filter. Yields raw results."""
        if not self.client:
            raise RuntimeError("Shodan API key not set")
        q = query
        if country:
            q = f"{q} country:{country}"
        if min_lat is not None:
            q = f"{q} geo:{min_lat},{min_lon}"
        limit = limit or self.max_results
        try:
            cursor = self.client.search_cursor(q)
            n = 0
            for item in cursor:
                if n >= limit:
                    break
                if min_lat is not None and item.get("location"):
                    loc = item["location"]
                    la, lo = loc.get("latitude"), loc.get("longitude")
                    if la is not None and (la < min_lat or (max_lat is not None and la > max_lat)):
                        continue
                    if lo is not None and (min_lon is not None and lo < min_lon or (max_lon is not None and lo > max_lon)):
                        continue
                n += 1
                yield item
        except Exception as e:
            logger.error("Shodan search error: %s", e)
            raise

    def search_and_store(
        self,
        queries: Optional[List[str]] = None,
        country: Optional[str] = None,
        limit_per_query: Optional[int] = None,
    ) -> int:
        """Run queries and store cameras in SQLite. Uses proxy from config if set."""
        proxies = get_proxies()
        if proxies:
            if "http" in proxies:
                os.environ["HTTP_PROXY"] = proxies["http"]
            if "https" in proxies:
                os.environ["HTTPS_PROXY"] = proxies["https"]
        init_db()
        session = get_session()
        queries = queries or DEFAULT_QUERIES
        limit = limit_per_query or self.max_results
        added = 0
        try:
            for q in queries:
                for raw in self.search(q, limit=limit, country=country):
                    cam = _to_camera(raw, q)
                    if not cam:
                        continue
                    existing = session.query(Camera).filter(Camera.ip == cam.ip, Camera.port == cam.port).first()
                    if existing:
                        continue
                    cam.project = get_current_project()
                    session.add(cam)
                    session.flush()
                    session.add(ScanResult(camera_id=cam.id, scan_type="shodan", result=f'{{"query":"{q}"}}', success=True))
                    added += 1
                session.commit()
        except Exception as e:
            session.rollback()
            logger.exception("search_and_store failed: %s", e)
            raise
        finally:
            session.close()
        return added
