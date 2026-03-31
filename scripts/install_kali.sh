#!/bin/bash
# Cam-PWN Framework — install ONLY Python dependencies on Kali Linux
# Does NOT install: Metasploit, Empire, C2, Shodan CLI, Burp, ZAP (use those separately if you need them)
# Run from project root: bash scripts/install_kali.sh

set -e
echo "[*] Cam-PWN Kali installer (Python deps + venv + RockYou extract only)"

# System packages needed for Python/pip
echo "[*] Installing system packages (python3, pip, venv only)..."
sudo apt-get update -qq
sudo apt-get install -y \
  python3 \
  python3-pip \
  python3-venv \
  libpq-dev \
  || true

# Optional: extract rockyou if present as .gz (Kali default)
ROCKYOU_GZ="/usr/share/wordlists/rockyou.txt.gz"
ROCKYOU_TXT="/usr/share/wordlists/rockyou.txt"
if [ -f "$ROCKYOU_GZ" ] && [ ! -f "$ROCKYOU_TXT" ]; then
  echo "[*] Extracting RockYou wordlist..."
  sudo gunzip -k -f "$ROCKYOU_GZ" 2>/dev/null || true
fi
if [ -f "$ROCKYOU_TXT" ]; then
  echo "[*] RockYou wordlist: $ROCKYOU_TXT"
else
  echo "[!] RockYou not found. Later: sudo apt-get install wordlists; sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz"
fi

# Project dir (parent of scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Venv
if [ ! -d "venv" ]; then
  echo "[*] Creating venv..."
  python3 -m venv venv
fi
echo "[*] Activating venv..."
# shellcheck source=/dev/null
source venv/bin/activate

echo "[*] Installing Python dependencies (no Metasploit/Empire/C2 - only pip packages)..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "[*] Creating data dirs (data/wordlists, data/reports, data/screenshots, data/exports)..."
python3 -c "
from pathlib import Path
r = Path('data')
for d in ['wordlists','reports','screenshots','exports']:
    (r/d).mkdir(parents=True, exist_ok=True)
"

echo ""
echo "[*] Done. This script does NOT install:"
echo "    - Metasploit / msfrpcd (install & run yourself if you want reverse shell)"
echo "    - Empire / Covenant / C2 (optional; configure in config.yaml if you have one)"
echo "    - Shodan CLI (you only need a Shodan API key from shodan.io)"
echo "    - Burp Suite / OWASP ZAP (install separately; we only send URLs to them if they run)"
echo ""
echo "[*] To run:"
echo "    source venv/bin/activate"
echo "    python main.py --help"
echo "    python main_tui.py   # workflow menu (local / global / full pipeline)"
echo ""
echo "Wordlist (Kali): /usr/share/wordlists/rockyou.txt"
