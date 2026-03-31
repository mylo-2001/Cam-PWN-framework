"""
Plugin loader: discover and load camera-specific and vulnerability plugins.
"""

import importlib.util
import logging
from pathlib import Path
from typing import Any, Callable, List, Optional, Type

logger = logging.getLogger(__name__)

# Built-in plugin packages
BUILTIN_PLUGINS = [
    "cam_pwn.plugins.cameras.hikvision",
    "cam_pwn.plugins.cameras.dahua",
    "cam_pwn.plugins.cameras.foscam",
]


def _load_module_from_path(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    return None


def load_scan_plugins(extra_dirs: Optional[List[str]] = None) -> List[Any]:
    """Load all scan/fingerprint plugins. Returns list of plugin classes or callables."""
    plugins = []
    # Built-in
    for name in BUILTIN_PLUGINS:
        try:
            mod = importlib.import_module(name)
            if hasattr(mod, "scan"):
                plugins.append(getattr(mod, "scan"))
            if hasattr(mod, "ScanPlugin"):
                plugins.append(getattr(mod, "ScanPlugin"))
        except ImportError as e:
            logger.debug("Plugin %s not loaded: %s", name, e)
    # Extra dirs
    for d in extra_dirs or []:
        p = Path(d)
        if not p.is_dir():
            continue
        for f in p.glob("**/scan_*.py"):
            m = _load_module_from_path(f)
            if m and hasattr(m, "run"):
                plugins.append(getattr(m, "run"))
    return plugins


def load_exploit_plugins(extra_dirs: Optional[List[str]] = None) -> List[Type]:
    """Load exploit plugins (subclasses of BaseExploit)."""
    from cam_pwn.exploits.base import BaseExploit
    plugins = []
    # Built-in exploit modules
    for name in ["cam_pwn.exploits.rfi", "cam_pwn.exploits.buffer_overflow", "cam_pwn.exploits.firmware", "cam_pwn.exploits.path_traversal"]:
        try:
            mod = importlib.import_module(name)
            for attr in dir(mod):
                cls = getattr(mod, attr)
                if isinstance(cls, type) and issubclass(cls, BaseExploit) and cls is not BaseExploit:
                    plugins.append(cls)
        except ImportError:
            pass
    for name in BUILTIN_PLUGINS:
        try:
            mod = importlib.import_module(name)
            for attr in dir(mod):
                cls = getattr(mod, attr)
                if isinstance(cls, type) and issubclass(cls, BaseExploit) and cls is not BaseExploit:
                    plugins.append(cls)
        except ImportError:
            pass
    for d in extra_dirs or []:
        p = Path(d)
        if not p.is_dir():
            continue
        for f in p.glob("**/*.py"):
            m = _load_module_from_path(f)
            if m:
                for attr in dir(m):
                    cls = getattr(m, attr)
                    if isinstance(cls, type) and issubclass(cls, BaseExploit) and cls is not BaseExploit:
                        plugins.append(cls)
    return plugins


def get_plugin(name: str, plugin_type: str = "exploit") -> Optional[Any]:
    """Get a single plugin by name."""
    if plugin_type == "exploit":
        for cls in load_exploit_plugins():
            if getattr(cls, "name", "") == name:
                return cls
    else:
        for p in load_scan_plugins():
            if getattr(p, "name", p.__name__) == name:
                return p
    return None
