"""
Risk and honeypot scoring helpers for cameras.

These are intentionally simple heuristics that can be extended later.
"""

from __future__ import annotations

import json
from typing import Optional

from cam_pwn.db.models import Camera


def compute_honeypot_score_from_shodan_data(shodan_data: Optional[str]) -> float:
    """
    Return a honeypot likelihood score based on Shodan metadata.
    0.0 = likely real, 1.0 = likely honeypot.
    """
    if not shodan_data:
        return 0.0
    try:
        data = json.loads(shodan_data)
    except Exception:
        return 0.0

    score = 0.0

    tags = data.get("tags") or []
    if isinstance(tags, list):
        tags_lower = [str(t).lower() for t in tags]
        if "honeypot" in tags_lower:
            score += 0.8
        if any(t in ("dionaea", "conpot", "glastopf") for t in tags_lower):
            score += 0.5

    org = str(data.get("org") or "").lower()
    if "research" in org or "university" in org:
        score += 0.1

    # Clamp to [0, 1]
    return max(0.0, min(1.0, score))


def compute_risk_score(cam: Camera) -> float:
    """
    Compute a simple risk score for prioritization:
    - Base 1
    - +2 if has CVEs
    - +2 if has credentials
    - +1 if RTSP URL present
    - -2 if flagged honeypot (score >= 0.7)
    """
    score = 1.0
    try:
        vulns = json.loads(cam.vulns) if cam.vulns else []
    except Exception:
        vulns = []
    try:
        creds = json.loads(cam.credentials) if cam.credentials else {}
    except Exception:
        creds = {}

    if vulns:
        score += 2.0
        # Extra bump if specific high‑value CVEs
        if any("CVE-2017-7921" in v for v in vulns):
            score += 1.0
    if creds:
        score += 2.0
    if cam.rtsp_url:
        score += 1.0
    if cam.is_honeypot or (cam.honeypot_score or 0) >= 0.7:
        score -= 2.0

    return max(0.0, score)

