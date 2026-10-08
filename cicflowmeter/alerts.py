"""Alert Generation and Severity System for CICFlowMeter

Categorises flow predictions into Normal Traffic or Attack,
and assigns severity levels according to:
    DDoS        -> Critical
    DoS         -> Critical
    Brute Force -> High
    Port Scan   -> Medium
    Normal      -> Normal (Benign)
"""

from typing import Dict, Any, Optional
from datetime import datetime

# Severity definitions
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_NORMAL = "Normal"

ATTACK_SEVERITY_MAP: Dict[str, str] = {
    "DDoS": SEVERITY_CRITICAL,
    "DoS": SEVERITY_CRITICAL,
    "Brute Force": SEVERITY_HIGH,
    "Port Scan": SEVERITY_MEDIUM,
    "Normal Traffic": SEVERITY_NORMAL,
}

# Hex color definitions for UI
SEVERITY_COLOR_MAP: Dict[str, Dict[str, str]] = {
    SEVERITY_CRITICAL: {
        "color": "#EF4444",        # Tailwind red-500
        "bg": "#450A0A",           # Tailwind red-950
        "border": "#DC2626",       # Tailwind red-600
        "badge": "#991B1B",        # Tailwind red-800
        "glow": "rgba(239, 68, 68, 0.4)",
    },
    SEVERITY_HIGH: {
        "color": "#F97316",        # Tailwind orange-500
        "bg": "#431407",           # Tailwind orange-950
        "border": "#EA580C",       # Tailwind orange-600
        "badge": "#9A3412",        # Tailwind orange-800
        "glow": "rgba(249, 115, 22, 0.4)",
    },
    SEVERITY_MEDIUM: {
        "color": "#EAB308",        # Tailwind yellow-500
        "bg": "#422006",           # Tailwind yellow-950
        "border": "#CA8A04",       # Tailwind yellow-600
        "badge": "#854D0E",        # Tailwind yellow-800
        "glow": "rgba(234, 179, 8, 0.4)",
    },
    SEVERITY_NORMAL: {
        "color": "#10B981",        # Tailwind emerald-500
        "bg": "#064E3B",           # Tailwind emerald-950
        "border": "#059669",       # Tailwind emerald-600
        "badge": "#065F46",        # Tailwind emerald-800
        "glow": "rgba(16, 185, 129, 0.2)",
    },
}

# ANSI codes for terminal output
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[91;1m"
ANSI_ORANGE = "\033[38;5;208;1m"
ANSI_YELLOW = "\033[93;1m"
ANSI_GREEN = "\033[92m"


def get_severity(label: str) -> str:
    """Return severity string for a given prediction label."""
    return ATTACK_SEVERITY_MAP.get(label, SEVERITY_HIGH if label != "Normal Traffic" else SEVERITY_NORMAL)


def is_attack_label(label: str) -> bool:
    """Check if prediction is classified as an Attack."""
    return label != "Normal Traffic"


def get_terminal_severity_badge(severity: str) -> str:
    """Format severity for terminal printing with ANSI colors."""
    if severity == SEVERITY_CRITICAL:
        return f"{ANSI_RED}[SEVERITY: CRITICAL]{ANSI_RESET}"
    elif severity == SEVERITY_HIGH:
        return f"{ANSI_ORANGE}[SEVERITY: HIGH]{ANSI_RESET}"
    elif severity == SEVERITY_MEDIUM:
        return f"{ANSI_YELLOW}[SEVERITY: MEDIUM]{ANSI_RESET}"
    else:
        return f"{ANSI_GREEN}[NORMAL]{ANSI_RESET}"


def build_alert_payload(
    flow_num: int,
    start_dt: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    label: str,
    confidence: Optional[float],
    probabilities: Optional[Dict[str, float]],
    duration_us: float,
    packet_count: int,
    byte_count: int,
    extra: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Build a serialisable dictionary for WebSockets and REST API."""
    severity = get_severity(label)
    is_attack = is_attack_label(label)
    colors = SEVERITY_COLOR_MAP.get(severity, SEVERITY_COLOR_MAP[SEVERITY_NORMAL])

    return {
        "id": flow_num,
        "timestamp": start_dt,
        "epoch": datetime.now().timestamp(),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "label": label,
        "is_attack": is_attack,
        "severity": severity,
        "colors": colors,
        "confidence": confidence,
        "probabilities": probabilities,
        "duration_us": duration_us,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "extra": extra or {}
    }
