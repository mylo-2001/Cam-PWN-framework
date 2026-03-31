"""
Screenshot helpers for camera web UIs or snapshot endpoints.

To keep dependencies light, this uses HTTP snapshot URLs where possible.
Future work: integrate headless browser (Selenium/Playwright) when available.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import requests

from cam_pwn.kali_paths import get_screenshots_dir
from cam_pwn.db.models import Camera


def _get_screenshots_dir() -> Path:
    p = Path(get_screenshots_dir())
    p.mkdir(parents=True, exist_ok=True)
    return p


def capture_snapshot(camera: Camera) -> Optional[Path]:
    """
    Try to capture a snapshot image from a camera that has credentials.
    Returns path to saved file or None.
    """
    if not camera.ip or not camera.port:
        return None
    if not camera.credentials:
        return None

    import json

    try:
        creds = json.loads(camera.credentials)
    except Exception:
        creds = {}
    user = creds.get("user")
    password = creds.get("pass")
    if not user or not password:
        return None

    base_http = f"http://{camera.ip}:{camera.port}"
    candidates = [
        "/snapshot.jpg",
        "/cgi-bin/snapshot.cgi",
        "/ISAPI/Streaming/channels/101/picture",
        "/ISAPI/System/Video/inputs/channels/1/picture",
    ]
    session = requests.Session()
    session.auth = (user, password)
    for path in candidates:
        url = base_http + path
        try:
            r = session.get(url, timeout=5, stream=True)
            if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("image/"):
                out_dir = _get_screenshots_dir()
                ext = ".jpg"
                out = out_dir / f"cam_{camera.id or 'x'}_{camera.ip.replace('.', '_')}{ext}"
                with open(out, "wb") as f:
                    for chunk in r.iter_content(8192):
                        if chunk:
                            f.write(chunk)
                return out
        except Exception:
            continue
    return None


def capture_screenshot_headless(camera: "Camera") -> Optional[Path]:
    """
    Optional: full web UI screenshot via headless browser (Playwright or Selenium).
    Install: pip install playwright && playwright install chromium
    or: pip install selenium (with chromedriver/geckodriver on PATH).
    Returns path to saved file or None.
    """
    if not camera.ip or not camera.port:
        return None
    url = f"http://{camera.ip}:{camera.port}/"
    out_dir = _get_screenshots_dir()
    out_path = out_dir / f"cam_{camera.id or 'x'}_{camera.ip.replace('.', '_')}_ui.png"

    # Try Playwright first (lighter, no driver)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            if camera.credentials:
                import json as _json
                try:
                    cred = _json.loads(camera.credentials)
                    user, password = cred.get("user"), cred.get("pass")
                    if user and password:
                        page.goto(url, wait_until="networkidle", timeout=10000)
                        # Simple basic auth via URL
                        page.goto(url.replace("http://", f"http://{user}:{password}@"), wait_until="networkidle", timeout=10000)
                except Exception:
                    pass
            else:
                page.goto(url, wait_until="networkidle", timeout=10000)
            page.screenshot(path=str(out_path))
            browser.close()
        return out_path
    except Exception:
        pass

    # Fallback: Selenium (requires chromedriver/geckodriver)
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        driver = webdriver.Chrome(options=opts)
        try:
            if camera.credentials:
                import json as _json
                cred = _json.loads(camera.credentials)
                user, password = cred.get("user"), cred.get("pass")
                if user and password:
                    driver.get(url.replace("http://", f"http://{user}:{password}@"))
                else:
                    driver.get(url)
            else:
                driver.get(url)
            driver.save_screenshot(str(out_path))
        finally:
            driver.quit()
        return out_path
    except Exception:
        pass
    return None

