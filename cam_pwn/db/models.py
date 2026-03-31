"""
SQLite models for cameras, scan results, and exploit results.
Supports optional encryption via SQLCipher-style or application-layer encryption.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    Boolean,
    create_engine,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

Base = declarative_base()
_engine = None
_Session = None


def _get_db_path() -> str:
    from cam_pwn.kali_paths import get_db_path
    path = get_db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path


def get_engine(encrypt: bool = False):
    """Create or return SQLite engine. Encryption is app-layer if enabled."""
    global _engine
    if _engine is not None:
        return _engine
    path = _get_db_path()
    url = f"sqlite:///{path}"
    _engine = create_engine(
        url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    return _engine


def init_db(encrypt: bool = False) -> None:
    """Create all tables."""
    engine = get_engine(encrypt)
    Base.metadata.create_all(engine)
    global _Session
    _Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_session():
    if _Session is None:
        init_db()
    return _Session()


class Camera(Base):
    __tablename__ = "cameras"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project = Column(String(100))  # logical project name / tag
    ip = Column(String(45), nullable=False, index=True)
    port = Column(Integer, default=80)
    rtsp_port = Column(Integer, default=554)
    protocol = Column(String(10), default="http")  # http, rtsp, https
    country = Column(String(2), index=True)
    city = Column(String(255))
    lat = Column(Float)
    lon = Column(Float)
    product = Column(String(255))
    version = Column(String(100))
    vulns = Column(Text)  # JSON list of CVE IDs
    credentials = Column(Text)  # JSON {"user":"x","pass":"y"}
    rtsp_url = Column(String(1024))
    shodan_data = Column(Text)  # JSON raw Shodan result
    is_honeypot = Column(Boolean, default=False)
    honeypot_score = Column(Float)  # 0.0 (likely real) .. 1.0 (likely honeypot)
    risk_score = Column(Float)      # higher = more interesting target
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan_results = relationship("ScanResult", back_populates="camera")
    exploit_results = relationship("ExploitResult", back_populates="camera")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "project": self.project,
            "ip": self.ip,
            "port": self.port,
            "rtsp_port": self.rtsp_port,
            "protocol": self.protocol,
            "country": self.country,
            "city": self.city,
            "lat": self.lat,
            "lon": self.lon,
            "product": self.product,
            "version": self.version,
            "vulns": json.loads(self.vulns) if self.vulns else [],
            "credentials": json.loads(self.credentials) if self.credentials else {},
            "rtsp_url": self.rtsp_url,
            "is_honeypot": self.is_honeypot,
            "honeypot_score": self.honeypot_score,
            "risk_score": self.risk_score,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    camera_id = Column(Integer, ForeignKey("cameras.id"), nullable=False, index=True)
    scan_type = Column(String(50))  # shodan, rtsp_brute, cve_check, local_scan
    result = Column(Text)  # JSON
    success = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    camera = relationship("Camera", back_populates="scan_results")


class ExploitResult(Base):
    __tablename__ = "exploit_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    camera_id = Column(Integer, ForeignKey("cameras.id"), nullable=False, index=True)
    exploit_name = Column(String(100))
    payload = Column(String(255))
    success = Column(Boolean, default=False)
    output = Column(Text)
    session_id = Column(String(100))  # Metasploit session if any
    created_at = Column(DateTime, default=datetime.utcnow)

    camera = relationship("Camera", back_populates="exploit_results")
