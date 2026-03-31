#!/usr/bin/env python3
"""Ensure data directories exist. Run: python scripts/ensure_dirs.py"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRS = [
    "data",
    "data/wordlists",
    "data/reports",
    "data/screenshots",
    "data/exports",
]
for d in DIRS:
    p = ROOT / d
    p.mkdir(parents=True, exist_ok=True)
    print(f"  {d}/")
print("  OK")
