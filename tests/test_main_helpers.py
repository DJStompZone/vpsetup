from vpsetup.helpers import build_client_conf, build_server_conf, derive_server_client_ips


def test_derive_server_client_ips() -> None:
    server_ip, client_ip = derive_server_client_ips("10.10.10.0/24")
    assert server_ip == "10.10.10.1"
    assert client_ip == "10.10.10.2"


def test_build_server_conf_includes_peer() -> None:
    conf = build_server_conf(
        server_addr="10.10.10.1/32",
        listen_port=51820,
        privkey="priv",
        peers=[("pub", "10.10.10.2/32")],
    )
    assert "[Interface]" in conf
    assert "ListenPort = 51820" in conf
    assert "PublicKey = pub" in conf
    assert "AllowedIPs = 10.10.10.2/32" in conf


def test_build_client_conf_contents() -> None:
    conf = build_client_conf(
        client_addr="10.10.10.2/32",
        privkey="priv",
        dns="1.1.1.1",
        server_pub="pub",
        endpoint="203.0.113.1:51820",
        allowed_ips="0.0.0.0/0",
    )
    assert "Address = 10.10.10.2/32" in conf
    assert "DNS = 1.1.1.1" in conf
    assert "Endpoint = 203.0.113.1:51820" in conf
    assert "AllowedIPs = 0.0.0.0/0" in conf
