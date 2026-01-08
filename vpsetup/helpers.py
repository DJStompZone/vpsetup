from __future__ import annotations

import random
import re
from typing import List, Tuple

CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PORT_RE = re.compile(r"^\d{1,5}$")


def derive_server_client_ips(cidr: str) -> Tuple[str, str]:
    base_ip = cidr.split("/", 1)[0]
    octets = base_ip.split(".")
    if len(octets) != 4:
        raise ValueError("Bad CIDR base IP.")
    prefix = ".".join(octets[:3])
    return f"{prefix}.1", f"{prefix}.2"


def pick_random_port() -> int:
    return random.randint(20000, 60000)


def build_server_conf(server_addr: str, listen_port: int, privkey: str, peers: List[Tuple[str, str]]) -> str:
    lines = [
        "[Interface]",
        f"Address = {server_addr}",
        f"ListenPort = {listen_port}",
        f"PrivateKey = {privkey}",
    ]
    for pubkey, allowed_ips in peers:
        lines += ["", "[Peer]", f"PublicKey = {pubkey}", f"AllowedIPs = {allowed_ips}"]
    return "\n".join(lines) + "\n"


def build_client_conf(client_addr: str, privkey: str, dns: str, server_pub: str, endpoint: str, allowed_ips: str) -> str:
    return "\n".join(
        [
            "[Interface]",
            f"PrivateKey = {privkey}",
            f"Address = {client_addr}",
            f"DNS = {dns}",
            "",
            "[Peer]",
            f"PublicKey = {server_pub}",
            f"Endpoint = {endpoint}",
            f"AllowedIPs = {allowed_ips}",
            "PersistentKeepalive = 25",
            "",
        ]
    )
