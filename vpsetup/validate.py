import curses
import os
import random
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple



def validate_iface(v: str) -> Optional[str]:
    if not v or not re.match(r"^[a-zA-Z0-9_.-]{1,15}$", v):
        return "Interface name looks invalid (try wg0)."
    return None


def validate_port(v: str) -> Optional[str]:
    if not PORT_RE.match(v):
        return "Port must be numeric."
    n = int(v)
    if not (1 <= n <= 65535):
        return "Port must be between 1 and 65535."
    return None


def validate_cidr(v: str) -> Optional[str]:
    if not CIDR_RE.match(v):
        return "CIDR must look like 10.10.10.0/24"
    ip, mask = v.split("/", 1)
    parts = [int(p) for p in ip.split(".")]
    if any(p < 0 or p > 255 for p in parts):
        return "CIDR IP octets must be 0-255."
    m = int(mask)
    if m < 8 or m > 30:
        return "CIDR mask should be between /8 and /30 for this use."
    return None


def validate_ip(v: str) -> Optional[str]:
    if not IP_RE.match(v):
        return "IP must look like 10.10.10.2"
    parts = [int(p) for p in v.split(".")]
    if any(p < 0 or p > 255 for p in parts):
        return "IP octets must be 0-255."
    return None


def validate_dns(v: str) -> Optional[str]:
    parts = [p.strip() for p in v.split(",") if p.strip()]
    if not parts:
        return "DNS cannot be empty."
    for p in parts:
        if not IP_RE.match(p):
            return "DNS must be IPv4 (e.g. 1.1.1.1) or comma-separated IPv4 list."
    return None
