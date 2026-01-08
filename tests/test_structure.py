
import pytest
from vpsetup.structures import PortForward, SetupConfig
from vpsetup.validate import validate_iface, validate_port, validate_cidr, validate_ip, validate_dns

def test_port_structure():
    pf = PortForward(proto="tcp", public_port=80, dest_ip="10.0.0.2", dest_port=8080)
    assert pf.proto == "tcp"
    assert pf.public_port == 80

def test_validate_iface():
    assert validate_iface("wg0") is None
    assert validate_iface("eth0") is None
    assert validate_iface("veth-1.2") is None
    assert validate_iface("") is not None
    assert validate_iface("verylonginterfacename") is not None
    assert validate_iface("invalid/char") is not None

def test_validate_port():
    assert validate_port("80") is None
    assert validate_port("65535") is None
    assert validate_port("0") is not None  # Too small? Implementation said 1-65535
    assert validate_port("65536") is not None
    assert validate_port("abc") is not None

def test_validate_cidr():
    assert validate_cidr("10.0.0.0/24") is None
    assert validate_cidr("192.168.1.1/30") is None
    assert validate_cidr("10.0.0.1") is not None  # Missing mask
    assert validate_cidr("10.0.0.0/33") is not None
    assert validate_cidr("300.0.0.0/24") is not None
    assert validate_cidr("text/24") is not None

def test_validate_ip():
    assert validate_ip("1.1.1.1") is None
    assert validate_ip("255.255.255.255") is None
    assert validate_ip("256.0.0.1") is not None
    assert validate_ip("1.2.3") is not None
    assert validate_ip("abc") is not None

def test_validate_dns():
    assert validate_dns("1.1.1.1") is None
    assert validate_dns("1.1.1.1, 8.8.8.8") is None
    assert validate_dns("1.1.1.1,8.8.8.8") is None
    assert validate_dns("") is not None
    assert validate_dns("google.com") is not None  # Only accepting IPv4 by logic
