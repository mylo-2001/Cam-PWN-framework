"""
Configuration loader with environment variable overrides.
"""

import os
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:
    yaml = None

_CONFIG: Optional[dict] = None
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


def load_config(path: Optional[Path] = None) -> dict:
    """Load YAML config with env overrides."""
    global _CONFIG
    if _CONFIG is not None:
        return _CONFIG
    p = path or _CONFIG_PATH
    cfg: dict = {}
    if yaml and p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            pass
    # Env overrides
    if not cfg.get("shodan", {}).get("api_key") and os.environ.get("CAM_PWN_SHODAN_KEY"):
        cfg.setdefault("shodan", {})["api_key"] = os.environ["CAM_PWN_SHODAN_KEY"]
    if os.environ.get("CAM_PWN_DB_KEY"):
        cfg.setdefault("database", {})["encryption_key"] = os.environ["CAM_PWN_DB_KEY"]
    if os.environ.get("CAM_PWN_MSF_PASS"):
        cfg.setdefault("exploitation", {})["metasploit_rpc_pass"] = os.environ["CAM_PWN_MSF_PASS"]
    _CONFIG = cfg
    return _CONFIG


def get(key_path: str, default: Any = None) -> Any:
    """Get config value by dot path (e.g. 'shodan.api_key')."""
    # Special-case project: allow runtime override via env without reload
    if key_path == "project" and os.environ.get("CAM_PWN_PROJECT"):
        return os.environ["CAM_PWN_PROJECT"]
    cfg = load_config()
    keys = key_path.split(".")
    for k in keys:
        cfg = (cfg or {}).get(k)
        if cfg is None:
            return default
    return cfg if cfg is not None else default


def get_current_project() -> Optional[str]:
    """Current project name for filtering (env CAM_PWN_PROJECT or config project). None = no filter."""
    v = os.environ.get("CAM_PWN_PROJECT") or get("project")
    if v is None or (isinstance(v, str) and not v.strip()):
        return None
    return str(v).strip()
