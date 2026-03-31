"""
TUI colors and separators for professional output.
Uses colorama for Windows compatibility.
"""

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    Fore = type("Fore", (), {"GREEN": "", "YELLOW": "", "RED": "", "CYAN": "", "RESET": ""})()
    Style = type("Style", (), {"RESET_ALL": "", "BRIGHT": ""})()


def g(msg: str) -> str:
    """Green: ok, timeout, professional/info."""
    return f"{Fore.GREEN}{msg}{Style.RESET_ALL}" if COLORS_AVAILABLE else msg


def y(msg: str) -> str:
    """Yellow: vulnerability found."""
    return f"{Fore.YELLOW}{msg}{Style.RESET_ALL}" if COLORS_AVAILABLE else msg


def r(msg: str) -> str:
    """Red: critical / major vulnerability."""
    return f"{Fore.RED}{msg}{Style.RESET_ALL}" if COLORS_AVAILABLE else msg


def c(msg: str) -> str:
    """Cyan: high risk, many vulns."""
    return f"{Fore.CYAN}{msg}{Style.RESET_ALL}" if COLORS_AVAILABLE else msg


def sep() -> str:
    """Separator line (------)."""
    return "  " + ("-" * 54)


def format_vuln_count(n: int) -> str:
    """Color by severity: 0=green, 1-2=yellow, 3+=red, many=cyan."""
    if n == 0:
        return g(str(n))
    if n <= 2:
        return y(str(n))
    if n >= 5:
        return c(str(n))
    return r(str(n))
