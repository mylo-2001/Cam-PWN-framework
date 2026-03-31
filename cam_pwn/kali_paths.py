"""
Kali / Linux default paths. Use these when config does not specify a path.
Framework is Linux/Kali-first.
"""

import os
from pathlib import Path
from typing import Optional

from cam_pwn.config import get

# Kali standard paths
KALI_ROCKYOU = "/usr/share/wordlists/rockyou.txt"
KALI_ROCKYOU_GZ = "/usr/share/wordlists/rockyou.txt.gz"
KALI_WORDLISTS_DIR = "/usr/share/wordlists"
KALI_MSFRPCD = "/usr/bin/msfrpcd"
KALI_NMAP = "/usr/bin/nmap"


def get_wordlist_path() -> Optional[str]:
    """
    Best wordlist path: config bruteforce.wordlist_path or wordlist_path_kali,
    or Kali rockyou if it exists, else data/wordlists/rockyou_top1000.txt.
    """
    cfg = get("bruteforce.wordlist_path") or get("wordlist_path_kali")
    if cfg and Path(cfg).exists():
        return cfg
    if Path(KALI_ROCKYOU).exists():
        return KALI_ROCKYOU
    wl_dir = get("storage.wordlists_dir", "data/wordlists")
    default = get("bruteforce.default_wordlist", "rockyou_top1000.txt")
    fallback = str(Path(wl_dir) / default)
    return fallback if Path(fallback).exists() else None


def get_reports_dir() -> str:
    """Reports directory. Default: data/reports."""
    return get("storage.reports_dir", "data/reports")


def get_screenshots_dir() -> str:
    """Screenshots directory. Default: data/screenshots."""
    return get("storage.screenshots_dir", "data/screenshots")


def get_wordlists_dir() -> str:
    """Wordlists directory. On Kali also /usr/share/wordlists exists."""
    return get("storage.wordlists_dir", "data/wordlists")


def get_db_path() -> str:
    """Database path. Default: data/cam_pwn.db."""
    return get("database.path", "data/cam_pwn.db")
