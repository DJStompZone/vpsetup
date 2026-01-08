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


CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PORT_RE = re.compile(r"^\d{1,5}$")


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


def wg_genkeypair() -> Tuple[str, str]:
    """Generates (private_key, public_key) using wg."""
    priv = run_cmd(["wg", "genkey"]).stdout.strip()
    pub = run_cmd(["wg", "pubkey"], capture=True, text=True, check=True,).stdout  # placeholder
    # Pipe priv into wg pubkey safely without shells.
    pub = subprocess.run(["wg", "pubkey"], input=priv + "\n", text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout.strip()
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


# ----------------------------- Curses TUI ----------------------------- #

class CursesUI:
    """Tiny curses UI toolkit with menus, inputs, and dialogs."""

    def __init__(self, stdscr: "curses._CursesWindow") -> None:
        self.stdscr = stdscr
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)
        self.color_title = curses.color_pair(1) | curses.A_BOLD
        self.color_hint = curses.color_pair(2)
        self.color_ok = curses.color_pair(3)
        self.color_err = curses.color_pair(4) | curses.A_BOLD

    def _clear(self) -> None:
        self.stdscr.erase()
        self.stdscr.refresh()

    def msgbox(self, title: str, msg: str) -> None:
        """Shows a blocking message box."""
        self._draw_box(title, msg.splitlines(), footer="Press any key")
        self.stdscr.getch()

    def yesno(self, title: str, msg: str) -> bool:
        """Yes/No dialog."""
        lines = msg.splitlines()
        idx = 0  # 0 yes, 1 no
        while True:
            footer = "[ Yes ]   No" if idx == 0 else "  Yes   [ No ]"
            self._draw_box(title, lines, footer=footer)
            ch = self.stdscr.getch()
            if ch in (curses.KEY_LEFT, ord('h')):
                idx = 0
            elif ch in (curses.KEY_RIGHT, ord('l')):
                idx = 1
            elif ch in (10, 13, curses.KEY_ENTER):
                return idx == 0
            elif ch in (27,):  # ESC
                return False

    def inputbox(self, title: str, prompt: str, default: str, validator: Optional[Callable[[str], Optional[str]]] = None) -> str:
        """Text input box with optional validation."""
        buf = list(default)
        pos = len(buf)
        curses.curs_set(1)
        try:
            while True:
                self._draw_box(title, [prompt, "", "".join(buf)], footer="Enter=OK  ESC=Cancel")
                y, x = self._input_coords(prompt_lines=3)
                self.stdscr.move(y, x + pos)
                ch = self.stdscr.getch()
                if ch in (27,):  # ESC
                    return default
                if ch in (10, 13, curses.KEY_ENTER):
                    val = "".join(buf).strip()
                    if validator:
                        err = validator(val)
                        if err:
                            self.msgbox("Validation", err)
                            continue
                    return val
                if ch in (curses.KEY_BACKSPACE, 127, 8):
                    if pos > 0:
                        buf.pop(pos - 1)
                        pos -= 1
                elif ch == curses.KEY_LEFT:
                    pos = max(0, pos - 1)
                elif ch == curses.KEY_RIGHT:
                    pos = min(len(buf), pos + 1)
                elif 32 <= ch <= 126:
                    buf.insert(pos, chr(ch))
                    pos += 1
        finally:
            curses.curs_set(0)

    def menu(self, title: str, prompt: str, items: List[Tuple[str, str]]) -> str:
        """Simple vertical menu; returns chosen key."""
        idx = 0
        while True:
            self._clear()
            h, w = self.stdscr.getmaxyx()
            self.stdscr.addstr(1, 2, title, self.color_title)
            self.stdscr.addstr(3, 2, prompt, self.color_hint)
            start_y = 5
            for i, (k, label) in enumerate(items):
                marker = "➤ " if i == idx else "  "
                style = curses.A_REVERSE if i == idx else curses.A_NORMAL
                self.stdscr.addstr(start_y + i, 4, f"{marker}{label}", style)
            self.stdscr.addstr(h - 2, 2, "↑/↓ move   Enter select   ESC cancel", self.color_hint)
            self.stdscr.refresh()

            ch = self.stdscr.getch()
            if ch in (curses.KEY_UP, ord('k')):
                idx = (idx - 1) % len(items)
            elif ch in (curses.KEY_DOWN, ord('j')):
                idx = (idx + 1) % len(items)
            elif ch in (10, 13, curses.KEY_ENTER):
                return items[idx][0]
            elif ch in (27,):
                return items[0][0]

    def _draw_box(self, title: str, lines: List[str], footer: str) -> None:
        self._clear()
        h, w = self.stdscr.getmaxyx()
        box_w = min(90, w - 4)
        box_h = min(max(10, len(lines) + 7), h - 4)
        top = (h - box_h) // 2
        left = (w - box_w) // 2

        win = curses.newwin(box_h, box_w, top, left)
        win.box()
        win.addstr(0, 2, f" {title} ", self.color_title)

        y = 2
        for line in lines[: box_h - 5]:
            win.addstr(y, 2, line[: box_w - 4])
            y += 1

        win.addstr(box_h - 2, 2, footer[: box_w - 4], self.color_hint)
        win.refresh()

    def _input_coords(self, prompt_lines: int) -> Tuple[int, int]:
        h, w = self.stdscr.getmaxyx()
        box_w = min(90, w - 4)
        box_h = min(max(10, prompt_lines + 7), h - 4)
        top = (h - box_h) // 2
        left = (w - box_w) // 2
        # Input line is third content line inside the box (after prompt + blank).
        y = top + 2 + 2
        x = left + 2
        return y, x


# ----------------------------- Flow ----------------------------- #

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
    # Allow comma-separated.
    parts = [p.strip() for p in v.split(",") if p.strip()]
    if not parts:
        return "DNS cannot be empty."
    for p in parts:
        if not IP_RE.match(p):
            return "DNS must be IPv4 (e.g. 1.1.1.1) or comma-separated IPv4 list."
    return None


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

    # Collect config
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

    # Apply config
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

    # Summary
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

    # Drop out of curses and print QR + path for copy/paste usability.
    curses.endwin()
    print(f"\nClient config: /root/wireguard-clients/client-{cfg.wg_iface}.conf\n")
    try:
        cp = run_cmd(["qrencode", "-t", "ansiutf8"], capture=True, text=True, check=True)
        # qrencode reads stdin; use subprocess.run directly
        qr = subprocess.run(
            ["qrencode", "-t", "ansiutf8"],
            input=client_conf_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
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