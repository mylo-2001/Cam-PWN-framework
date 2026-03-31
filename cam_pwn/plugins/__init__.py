"""Plugin system for camera types and vulnerability modules."""

from .loader import load_scan_plugins, load_exploit_plugins, get_plugin

__all__ = ["load_scan_plugins", "load_exploit_plugins", "get_plugin"]
