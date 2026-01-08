import pytest

from vpsetup import validate


@pytest.mark.parametrize(
    "value",
    ["wg0", "eth0", "wg-test", "wg0.1"],
)
def test_validate_iface_accepts_valid_names(value: str) -> None:
    assert validate.validate_iface(value) is None


@pytest.mark.parametrize(
    "value",
    ["", "wg0!", "interface-name-too-long"],
)
def test_validate_iface_rejects_invalid_names(value: str) -> None:
    assert validate.validate_iface(value) is not None


@pytest.mark.parametrize(
    "value",
    ["1", "51820", "65535"],
)
def test_validate_port_accepts_range(value: str) -> None:
    assert validate.validate_port(value) is None


@pytest.mark.parametrize(
    "value",
    ["0", "65536", "-1", "abc"],
)
def test_validate_port_rejects_invalid(value: str) -> None:
    assert validate.validate_port(value) is not None


@pytest.mark.parametrize(
    "value",
    ["10.10.10.0/24", "192.168.50.0/16"],
)
def test_validate_cidr_accepts_valid(value: str) -> None:
    assert validate.validate_cidr(value) is None


@pytest.mark.parametrize(
    "value",
    ["10.10.10.0", "10.10.10/24", "10.10.300.0/24", "10.10.10.0/31"],
)
def test_validate_cidr_rejects_invalid(value: str) -> None:
    assert validate.validate_cidr(value) is not None


@pytest.mark.parametrize(
    "value",
    ["10.10.10.2", "8.8.8.8"],
)
def test_validate_ip_accepts_valid(value: str) -> None:
    assert validate.validate_ip(value) is None


@pytest.mark.parametrize(
    "value",
    ["10.10.10", "10.10.10.256", "abc"],
)
def test_validate_ip_rejects_invalid(value: str) -> None:
    assert validate.validate_ip(value) is not None


@pytest.mark.parametrize(
    "value",
    ["1.1.1.1", "1.1.1.1,8.8.8.8"],
)
def test_validate_dns_accepts_valid(value: str) -> None:
    assert validate.validate_dns(value) is None


@pytest.mark.parametrize(
    "value",
    ["", "1.1.1", "1.1.1.1,not-ip"],
)
def test_validate_dns_rejects_invalid(value: str) -> None:
    assert validate.validate_dns(value) is not None
