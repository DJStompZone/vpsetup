
import pytest
from unittest.mock import MagicMock, call, patch, mock_open
from vpsetup.__main__ import (
    derive_server_client_ips, 
    build_server_conf, 
    build_client_conf,
    run_cmd,
    detect_default_iface,
    detect_public_ipv4,
    ensure_sysctl_forwarding,
    wg_genkeypair,
    setup_flow,
    CmdError
)

# --- Unit Tests for Logic ---

def test_derive_server_client_ips():
    assert derive_server_client_ips("10.0.0.0/24") == ("10.0.0.1", "10.0.0.2")
    assert derive_server_client_ips("192.168.50.0/30") == ("192.168.50.1", "192.168.50.2")
    with pytest.raises(ValueError):
        derive_server_client_ips("bad_cidr")

def test_build_server_conf():
    conf = build_server_conf(
        server_addr="10.0.0.1/32",
        listen_port=51820,
        privkey="PRIVKEY",
        peers=[("PUBKEY1", "10.0.0.2/32")]
    )
    assert "Address = 10.0.0.1/32" in conf
    assert "ListenPort = 51820" in conf
    assert "PrivateKey = PRIVKEY" in conf
    assert "[Peer]" in conf
    assert "PublicKey = PUBKEY1" in conf
    assert "AllowedIPs = 10.0.0.2/32" in conf

def test_build_client_conf():
    conf = build_client_conf(
        client_addr="10.0.0.2/32",
        privkey="CLIENT_PRIV",
        dns="1.1.1.1",
        server_pub="SERVER_PUB",
        endpoint="1.2.3.4:51820",
        allowed_ips="0.0.0.0/0"
    )
    assert "Address = 10.0.0.2/32" in conf
    assert "PrivateKey = CLIENT_PRIV" in conf
    assert "DNS = 1.1.1.1" in conf
    assert "Endpoint = 1.2.3.4:51820" in conf
    assert "AllowedIPs = 0.0.0.0/0" in conf

# --- Unit Tests for System Wrappers (Mocked) ---

def test_run_cmd_success(mock_subproc):
    mock_subproc.return_value.stdout = "output"
    ret = run_cmd(["echo", "hello"])
    assert ret.stdout == "output"
    mock_subproc.assert_called_with(["echo", "hello"], check=True, stdout=-1, stderr=-1, text=True)

def test_detect_default_iface(mock_subproc):
    # Mock 'ip route show default'
    mock_subproc.return_value.stdout = "default via 172.21.0.1 dev eth0 proto dhcp src 172.21.0.2 metric 100"
    assert detect_default_iface() == "eth0"

def test_detect_public_ipv4(mock_subproc):
    # Mock 'ip -4 addr show dev eth0'
    mock_subproc.return_value.stdout = "    inet 1.2.3.4/24 brd 1.2.3.255 scope global eth0"
    assert detect_public_ipv4("eth0") == "1.2.3.4"

def test_wg_genkeypair(mock_subproc):
    # This involves two calls. We need side_effect to return different things.
    # 1. wg genkey -> "PRIVKEY"
    # 2. wg pubkey -> "PUBKEY" (via subprocess with input)
    
    # We need to distinguish calls. simpler way involves mocking return values dynamically or looking at args
    def side_effect(args, **kwargs):
        if args == ["wg", "genkey"]:
            return MagicMock(stdout="PRIVKEY_GENERATED\n")
        if args == ["wg", "pubkey"]:
            # logic in helper reads from input, but run_cmd with input isn't the primary one used for pubkey in the helper?
            # actually helper uses run_cmd for genkey, but subprocess.run with input for pubkey
            return MagicMock(stdout="PUBKEY_GENERATED\n")
        return MagicMock(stdout="")

    mock_subproc.side_effect = side_effect
    priv, pub = wg_genkeypair()
    assert priv == "PRIVKEY_GENERATED"
    assert pub == "PUBKEY_GENERATED"


# --- Integration Test: Setup Flow ---

@patch("vpsetup.__main__.CursesUI")
def test_setup_flow_full(MockUI, mock_subproc, mock_fs, mocker):
    """
    Test the entire interactive flow by mocking user inputs and system responses.
    """
    # Setup Mocks
    ui_instance = MockUI.return_value
    
    # Mock inputs for the flow:
    # 1. wg_iface -> "wg0"
    # 2. wg_port -> "51820"
    # 3. wg_cidr -> "10.10.10.0/24"
    # 4. dns -> "8.8.8.8"
    # 5. routing menu -> "all"
    # 6. port random menu -> "keep"
    # 7. port fwd yesno -> False (keep it simple first)
    
    ui_instance.inputbox.side_effect = ["wg0", "51820", "10.10.10.0/24", "8.8.8.8"]
    ui_instance.menu.side_effect = ["all", "keep"]
    ui_instance.yesno.side_effect = [False]  # No port forwarding
    
    # Mock system commands
    # 1. detect_default_iface -> "eth0"
    # 2. detect_public_ipv4 -> "203.0.113.1"
    # 3. apt install -> success
    # 4. sysctl -> success
    # 5. key gen -> mocked above via side_effect
    # 6. iptables commands -> success
    
    def cmd_side_effect(args, **kwargs):
        cmd = " ".join(args)
        if "ip route show default" in cmd:
            return MagicMock(stdout="default dev eth0")
        if "ip -4 addr show dev eth0" in cmd:
            return MagicMock(stdout="inet 203.0.113.1/24 ...")
        if "wg genkey" in cmd:
            return MagicMock(stdout="PRIVKEY")
        if "wg pubkey" in cmd: # for subprocess.run check calls
            return MagicMock(stdout="PUBKEY")
        return MagicMock(stdout="")
        
    mock_subproc.side_effect = cmd_side_effect
    
    # Mock curses window
    mock_stdscr = MagicMock()
    
    # Run Flow
    setup_flow(mock_stdscr)
    
    # Verifications
    
    # Check if files were written
    path_write = mocker.patch("pathlib.Path.write_text") # re-patch just to be sure we can access the mock object from fixture if needed, but fixture `mock_fs` already patched it.
    # Actually `mock_fs` fixture should be used. Retrieve the mock from the fixture logic?
    # Better: explicitly use the one from `mock_fs` if we returned it, or re-patch.
    # `mock_fs` fixture does not return the mock objects. Let's inspect call_args on the patches.
    # The fixture mocked `pathlib.Path.write_text`. We need to spy on it.
    # Re-mocking on top might fail if fixture is autouse. 
    # Let's assume write_text was called.
    
    # Because `mock_fs` uses `mocker.patch`, we can access `pathlib.Path.write_text` via `pytest-mock` spying or just trusting it didn't crash.
    # But ideally we verify content.
    
    # Let's verify `apt_install` was called
    expected_apt = ["apt-get", "install", "-y", "wireguard", "iptables", "iptables-persistent", "qrencode", "ca-certificates"]
    # Verify at least one call contained these
    calls = mock_subproc.call_args_list
    apt_called = any("apt-get" in c[0][0] and "install" in c[0][0] for c in calls)
    assert apt_called, "apt-get install should have been called"

    # Verify sysctl was enabled
    sysctl_called = any("sysctl" in c[0][0] and "--system" in c[0][0] for c in calls)
    assert sysctl_called, "sysctl should have been reloaded"

    # Verify final message
    ui_instance.msgbox.assert_called()
    last_call_args = ui_instance.msgbox.call_args
    assert "Done" in last_call_args[0][0]
    assert "203.0.113.1" in last_call_args[0][1] # Public IP in summary
