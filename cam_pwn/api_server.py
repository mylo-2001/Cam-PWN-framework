"""
REST API for Cam-PWN: run discover, Shodan, CVE scan, report from scripts or other UIs.
Run with: uvicorn cam_pwn.api_server:app --host 0.0.0.0 --port 8000
"""

import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Cam-PWN API", version="1.0")


def _set_project(project: Optional[str] = None) -> None:
    if project is not None:
        os.environ["CAM_PWN_PROJECT"] = project
    else:
        os.environ.pop("CAM_PWN_PROJECT", None)


class ShodanRequest(BaseModel):
    api_key: str
    limit: int = 500
    country: Optional[str] = None
    project: Optional[str] = None


class ReportRequest(BaseModel):
    project: Optional[str] = None
    title: str = "IP Camera Assessment"


class CVEScanRequest(BaseModel):
    project: Optional[str] = None
    max_workers: int = 20


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/cameras")
def list_cameras(project: Optional[str] = None, limit: int = 500) -> Dict[str, Any]:
    """List cameras; optional project filter."""
    from cam_pwn.db.models import Camera, get_session, init_db

    _set_project(project)
    init_db()
    session = get_session()
    try:
        q = session.query(Camera).order_by(Camera.id.desc()).limit(limit)
        if project is not None:
            q = q.filter(Camera.project == project)
        cams = [c.to_dict() for c in q.all()]
        return {"count": len(cams), "cameras": cams}
    finally:
        session.close()


@app.get("/stats")
def stats(project: Optional[str] = None) -> Dict[str, Any]:
    """Statistics by project."""
    from cam_pwn.reporting import get_statistics

    _set_project(project)
    return get_statistics(project=project)


@app.post("/discover")
def discover(project: Optional[str] = None) -> Dict[str, Any]:
    """Run local network discovery and store cameras."""
    from cam_pwn.discovery import discover_and_store

    _set_project(project)
    try:
        count = discover_and_store()
        return {"added": count, "project": project}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/shodan")
def shodan_search(body: ShodanRequest) -> Dict[str, Any]:
    """Run Shodan search and store results."""
    from cam_pwn.shodan_client import ShodanClient

    _set_project(body.project)
    if not body.api_key:
        raise HTTPException(status_code=400, detail="api_key required")
    try:
        client = ShodanClient(body.api_key)
        count = client.search_and_store(
            queries=None,
            country=body.country,
            limit_per_query=body.limit,
        )
        return {"added": count, "project": body.project}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cve-scan")
def cve_scan(body: Optional[CVEScanRequest] = None) -> Dict[str, Any]:
    """Run CVE checks on cameras in DB."""
    from cam_pwn.mass_exploit import mass_cve_scan

    body = body or CVEScanRequest()
    _set_project(body.project)
    try:
        results = mass_cve_scan(
            camera_ids=None,
            max_workers=body.max_workers,
            project=body.project,
        )
        vuln = [r for r in results if r.get("vulns")]
        return {"scanned": len(results), "with_vulns": len(vuln), "results": results[:100]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/report")
def report(body: Optional[ReportRequest] = None) -> Dict[str, str]:
    """Generate HTML report."""
    from cam_pwn.reporting import generate_html_report

    body = body or ReportRequest()
    _set_project(body.project)
    try:
        path = generate_html_report(
            output_path=None,
            camera_ids=None,
            title=body.title,
            project=body.project,
        )
        return {"path": path, "format": "html"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/report/pdf")
def report_pdf(body: Optional[ReportRequest] = None) -> Dict[str, Any]:
    """Generate HTML report and export to PDF (requires weasyprint)."""
    from cam_pwn.reporting import export_report_to_pdf

    body = body or ReportRequest()
    _set_project(body.project)
    try:
        path = export_report_to_pdf(
            html_path=None,
            project=body.project,
            title=body.title,
        )
        if not path:
            raise HTTPException(
                status_code=503,
                detail="PDF export failed; install weasyprint",
            )
        return {"path": path, "format": "pdf"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
