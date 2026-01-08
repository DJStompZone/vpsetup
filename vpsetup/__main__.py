#!/usr/bin/env python3
"""
WireGuard VPS setup with a curses TUI.

This script configures a Debian/Ubuntu VPS as a WireGuard server suitable for
"reverse port forwarding" use-cases

Notes:
- Run as root.
- Intended for Debian/Ubuntu VPS images.
- Uses iptables. If your distro defaults to nft wrappers, it will still generally work via iptables compatibility layer.

Usage:
  sudo python3 wg_vps_setup.py
"""

from __future__ import annotations

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
from vpsetup.structures import PortForward, SetupConfig
from vpsetup.tui import CursesUI
from vpsetup.validate import validate_iface, validate_port, validate_ip, validate_dns, validate_cidr, IP_RE




class CmdError(RuntimeError):
    """Raised when a subprocess command fails."""


def run_cmd(
    args: Sequence[str],
    *,
    check: bool = True,
    capture: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """Runs a subprocess command with sane defaults."""
    try:
        return subprocess.run(
            list(args),
            check=check,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=text,
        )
    except subprocess.CalledProcessError as e:
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        raise CmdError(
            f"Command failed: {shlex.join(args)}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        ) from e


def require_root() -> None:
    """Exits if not running as root."""
    if os.geteuid() != 0:
        raise SystemExit("Run as root (sudo).")


def apt_install(packages: Sequence[str]) -> None:
    """Installs apt packages (best effort, noninteractive)."""
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"

    def _run(args: Sequence[str]) -> None:
        subprocess.run(list(args), check=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    _run(["apt-get", "update", "-y"])
    _run(["apt-get", "install", "-y", *packages])


def detect_default_iface() -> str:
    """Detects the default route interface."""
    cp = run_cmd(["ip", "route", "show", "default"])
    for line in cp.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("Could not detect default network interface.")


def detect_public_ipv4(iface: str) -> str:
    """Detects the IPv4 address on the given interface."""
    cp = run_cmd(["ip", "-4", "addr", "show", "dev", iface])
    for line in cp.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            ip_cidr = line.split()[1]
            ip = ip_cidr.split("/", 1)[0]
            if IP_RE.match(ip):
                return ip
    raise RuntimeError(f"Could not detect IPv4 on interface {iface}.")


def ensure_sysctl_forwarding() -> None:
    """Enables IPv4 forwarding persistently."""
    p = Path("/etc/sysctl.d/99-wireguard-forward.conf")
    p.write_text("net.ipv4.ip_forward=1\nnet.ipv4.conf.all.src_valid_mark=1\n", encoding="utf-8")
    run_cmd(["sysctl", "--system"], check=True, capture=True)


def file_write_secure(path: Path, content: str) -> None:
    """Writes a file with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    try:
        path.write_text(content, encoding="utf-8")
        os.chmod(path, 0o600)
    finally:
        os.umask(old_umask)


def wg_genkeypair() -> tuple[str, str]:
    """Generates (private_key, public_key) using wg."""
    priv = run_cmd(["wg", "genkey"]).stdout.strip()
    pub = subprocess.run(
        ["wg", "pubkey"],
        input=priv + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    return priv, pub



def systemctl_enable_restart(unit: str) -> None:
    """Enables and restarts a systemd unit."""
    run_cmd(["systemctl", "enable", unit], check=True, capture=True)
    run_cmd(["systemctl", "restart", unit], check=True, capture=True)


def iptables_has_rule(table: Optional[str], rule: List[str]) -> bool:
    """Checks whether an iptables rule exists via -C."""
    cmd = ["iptables"]
    if table:
        cmd += ["-t", table]
    cmd += ["-C", *rule]
    try:
        run_cmd(cmd, check=True, capture=True)
        return True
    except CmdError:
        return False


def iptables_add_rule(table: Optional[str], rule: List[str]) -> None:
    """Adds an iptables rule if missing."""
    if iptables_has_rule(table, rule):
        return
    cmd = ["iptables"]
    if table:
        cmd += ["-t", table]
    cmd += ["-A", *rule]
    run_cmd(cmd, check=True, capture=True)


def netfilter_persistent_save() -> None:
    """Saves iptables rules."""
    run_cmd(["netfilter-persistent", "save"], check=True, capture=True)


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


def ensure_packages(ui: Optional[CursesUI]) -> None:
    pkgs = ["wireguard", "iptables", "iptables-persistent", "qrencode", "ca-certificates"]
    if ui:
        ui.msgbox("Packages", "Installing dependencies via apt...\n\nwireguard, iptables, iptables-persistent, qrencode")
    apt_install(pkgs)


def apply_nat_and_forwarding(pub_iface: str, wg_iface: str, wg_cidr: str) -> None:
    iptables_add_rule(None, ["FORWARD", "-i", wg_iface, "-o", pub_iface, "-j", "ACCEPT"])
    iptables_add_rule(None, ["FORWARD", "-i", pub_iface, "-o", wg_iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    iptables_add_rule("nat", ["POSTROUTING", "-s", wg_cidr, "-o", pub_iface, "-j", "MASQUERADE"])


def apply_dnat_forward(pub_iface: str, wg_iface: str, fwd: PortForward) -> None:
    iptables_add_rule("nat", ["PREROUTING", "-i", pub_iface, "-p", fwd.proto, "--dport", str(fwd.public_port), "-j", "DNAT", "--to-destination", f"{fwd.dest_ip}:{fwd.dest_port}"])
    iptables_add_rule(None, ["FORWARD", "-i", pub_iface, "-o", wg_iface, "-p", fwd.proto, "-d", fwd.dest_ip, "--dport", str(fwd.dest_port), "-j", "ACCEPT"])


def setup_flow(stdscr: "curses._CursesWindow") -> None:
    ui = CursesUI(stdscr)

    try:
        require_root()
    except SystemExit as e:
        ui.msgbox("Nope", str(e))
        return

    try:
        ensure_packages(ui)
    except Exception as e:
        ui.msgbox("Install failed", f"apt install failed:\n{e}")
        return

    try:
        pub_iface = detect_default_iface()
        pub_ip = detect_public_ipv4(pub_iface)
    except Exception as e:
        ui.msgbox("Network detect failed", str(e))
        return

    wg_iface = ui.inputbox("WireGuard Setup", "WireGuard interface name:", "wg0", validator=validate_iface)
    wg_port_s = ui.inputbox("WireGuard Setup", "WireGuard UDP listen port:", "51820", validator=validate_port)
    wg_cidr = ui.inputbox("WireGuard Setup", "WireGuard subnet CIDR (server .1, client .2):", "10.10.10.0/24", validator=validate_cidr)

    server_ip, client_ip = derive_server_client_ips(wg_cidr)

    dns = ui.inputbox("WireGuard Setup", "Client DNS (comma-separated IPv4 ok):", "1.1.1.1", validator=validate_dns)

    route_choice = ui.menu(
        "Routing",
        "What should the client route through the VPN?",
        [
            ("all", "Everything (0.0.0.0/0) — VPS becomes default gateway"),
            ("wg", "Only WireGuard subnet — management access only"),
        ],
    )
    route_all = route_choice == "all"

    port_choice = ui.menu(
        "WireGuard Port",
        "Use chosen WireGuard port or randomize to a high port?",
        [
            ("keep", "Use the port I entered"),
            ("rand", "Random high port (helps reduce random scanning noise)"),
        ],
    )
    randomize_port = port_choice == "rand"
    wg_port = int(wg_port_s)
    if randomize_port:
        wg_port = pick_random_port()

    forwards: List[PortForward] = []
    if ui.yesno(
        "Port Forwarding",
        f"Add inbound port forward rules on the VPS to the WireGuard client ({client_ip})?\n\n"
        "Use this if you want VPS public ports forwarded over the tunnel to your Starlink-side box.",
    ):
        while True:
            proto = ui.menu("Add Forward", "Protocol:", [("tcp", "TCP"), ("udp", "UDP")])
            pub_port_s = ui.inputbox("Add Forward", "Public port on VPS:", "25565", validator=validate_port)
            dst_port_s = ui.inputbox("Add Forward", f"Destination port on client ({client_ip}):", pub_port_s, validator=validate_port)
            forwards.append(
                PortForward(proto=proto, public_port=int(pub_port_s), dest_ip=client_ip, dest_port=int(dst_port_s))
            )
            if not ui.yesno("Add Forward", "Add another port forward rule?"):
                break

    cfg = SetupConfig(
        wg_iface=wg_iface,
        wg_port=wg_port,
        wg_cidr=wg_cidr,
        server_ip=server_ip,
        client_ip=client_ip,
        dns=dns,
        route_all=route_all,
        randomize_port=randomize_port,
        add_forwards=forwards,
    )

    try:
        ensure_sysctl_forwarding()

        server_priv, server_pub = wg_genkeypair()
        client_priv, client_pub = wg_genkeypair()

        server_addr = f"{cfg.server_ip}/32"
        client_addr = f"{cfg.client_ip}/32"
        allowed_ips = "0.0.0.0/0" if cfg.route_all else cfg.wg_cidr
        endpoint = f"{pub_ip}:{cfg.wg_port}"

        server_conf_text = build_server_conf(
            server_addr=server_addr,
            listen_port=cfg.wg_port,
            privkey=server_priv,
            peers=[(client_pub, f"{cfg.client_ip}/32")],
        )
        server_conf_path = Path("/etc/wireguard") / f"{cfg.wg_iface}.conf"
        file_write_secure(server_conf_path, server_conf_text)

        apply_nat_and_forwarding(pub_iface=pub_iface, wg_iface=cfg.wg_iface, wg_cidr=cfg.wg_cidr)

        for fwd in cfg.add_forwards:
            apply_dnat_forward(pub_iface=pub_iface, wg_iface=cfg.wg_iface, fwd=fwd)

        netfilter_persistent_save()

        systemctl_enable_restart(f"wg-quick@{cfg.wg_iface}")

        outdir = Path("/root/wireguard-clients")
        outdir.mkdir(parents=True, exist_ok=True)
        client_conf_path = outdir / f"client-{cfg.wg_iface}.conf"
        client_conf_text = build_client_conf(
            client_addr=client_addr,
            privkey=client_priv,
            dns=cfg.dns,
            server_pub=server_pub,
            endpoint=endpoint,
            allowed_ips=allowed_ips,
        )
        file_write_secure(client_conf_path, client_conf_text)

    except Exception as e:
        ui.msgbox("Setup failed", f"{e}")
        return

    forward_lines = []
    if cfg.add_forwards:
        forward_lines.append("Forwards:")
        for f in cfg.add_forwards:
            forward_lines.append(f"  - {f.proto.upper()} {pub_ip}:{f.public_port} -> {f.dest_ip}:{f.dest_port}")
    else:
        forward_lines.append("Forwards: (none)")

    ui.msgbox(
        "Done",
        "\n".join(
            [
                "✅ WireGuard configured on VPS",
                "",
                f"Public iface: {pub_iface}",
                f"Endpoint:     {pub_ip}:{cfg.wg_port} (UDP)",
                f"WG iface:     {cfg.wg_iface}",
                f"WG subnet:    {cfg.wg_cidr}",
                f"Server IP:    {cfg.server_ip}",
                f"Client IP:    {cfg.client_ip}",
                "",
                f"Server conf:  /etc/wireguard/{cfg.wg_iface}.conf",
                f"Client conf:  /root/wireguard-clients/client-{cfg.wg_iface}.conf",
                "",
                *forward_lines,
                "",
                "Next: copy the client config to your Starlink-side machine/router and bring it up.",
            ]
        ),
    )

    curses.endwin()
    print(f"\nClient config: /root/wireguard-clients/client-{cfg.wg_iface}.conf\n")
    try:
        qr = subprocess.run(
            ["qrencode", "-t", "ansiutf8"],
            input=client_conf_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=5,
        ).stdout
        print(qr)
    except Exception:
        print("(qrencode not available or failed; you can scp the conf file instead.)")



def main() -> int:
    try:
        curses.wrapper(setup_flow)
        return 0
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())