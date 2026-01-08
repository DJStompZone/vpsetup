from dataclasses import dataclass
from typing import List


@dataclass
class PortForward:
    """A DNAT forward definition."""
    proto: str  # tcp/udp
    public_port: int
    dest_ip: str
    dest_port: int


@dataclass
class SetupConfig:
    """Configuration from the TUI."""
    wg_iface: str
    wg_port: int
    wg_cidr: str
    server_ip: str
    client_ip: str
    dns: str
    route_all: bool
    randomize_port: bool
    add_forwards: List[PortForward]
