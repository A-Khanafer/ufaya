"""Live command timeout and SSH session recovery regressions."""

from contextlib import nullcontext
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest
from netmiko.exceptions import ReadTimeout

from ufaya import get_firewall_driver
from ufaya.drivers.juniper import JuniperSRXDriver

CONFIG_COMMAND = "show configuration | display xml | no-more"
HIT_COUNT_COMMAND = "show security policies hit-count | display xml | no-more"
CONFIG_XML = (Path(__file__).parent / "fixtures" / "juniper_actions.xml").read_text()


def _connection():
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    return conn


def _driver(**kwargs):
    return get_firewall_driver(
        "juniper_srx",
        host="192.0.2.1",
        username="test-user",
        password="test-password",
        **kwargs,
    )


@pytest.mark.parametrize("timeout", [None, 120.5])
@pytest.mark.parametrize(
    "operation", ["get_rules", "get_nat_rules", "export_rules_json", "export_nat_json"]
)
def test_slow_commands_use_configured_timeout(
    monkeypatch, tmp_path, timeout, operation
):
    """Simulate commands exceeding Netmiko's default without wall-clock sleeps."""
    conn = _connection()

    def send_command(command, *, read_timeout=10):
        if read_timeout < 15:
            raise ReadTimeout("Simulated command needs 15 seconds")
        return CONFIG_XML if command == CONFIG_COMMAND else ""

    conn.send_command.side_effect = send_command
    handler = MagicMock(return_value=conn)
    monkeypatch.setattr("netmiko.ConnectHandler", handler)
    driver = _driver(**({} if timeout is None else {"read_timeout": timeout}))
    method = getattr(driver, operation)
    result = method(tmp_path) if operation.startswith("export_") else method()

    assert result is not None
    expected_timeout = 60 if timeout is None else timeout
    commands = [CONFIG_COMMAND]
    if "rules" in operation and "nat" not in operation:
        commands.insert(0, HIT_COUNT_COMMAND)
    assert conn.send_command.call_args_list == [
        call(command, read_timeout=expected_timeout) for command in commands
    ]
    handler.assert_called_once()
    conn.__exit__.assert_called_once()


@pytest.mark.parametrize("managed", [False, True])
def test_hit_count_timeout_discards_session_before_config(monkeypatch, managed):
    failed = _connection()
    failed.send_command.side_effect = ReadTimeout("Hit-count output is incomplete")
    recovered = _connection()
    recovered.send_command.return_value = CONFIG_XML

    def connect(**kwargs):
        if handler.call_count == 1:
            return failed
        failed.__exit__.assert_called_once()
        return recovered

    handler = MagicMock(side_effect=connect)
    monkeypatch.setattr("netmiko.ConnectHandler", handler)
    driver = _driver(read_timeout=90)

    with driver if managed else nullcontext():
        records = driver.get_rules()
        assert len(records) == 3
        assert all(record.rule.hit_count is None for record in records)
        assert driver._last_hit_counts_collected_at is None
        if managed:
            recovered.__exit__.assert_not_called()
            assert driver._conn is recovered
            driver.get_nat_rules()
        else:
            assert driver._conn is None

    assert handler.call_count == 2
    failed.send_command.assert_called_once_with(HIT_COUNT_COMMAND, read_timeout=90)
    assert recovered.send_command.call_args_list == [
        call(CONFIG_COMMAND, read_timeout=90)
    ] * (2 if managed else 1)
    failed.__exit__.assert_called_once()
    recovered.__exit__.assert_called_once()
    assert driver._conn is None


@pytest.mark.parametrize("managed", [False, True])
def test_reconnection_failure_propagates(monkeypatch, managed):
    failed = _connection()
    failed.send_command.side_effect = ReadTimeout("Hit-count output is incomplete")
    error = RuntimeError("Replacement connection failed")
    handler = MagicMock(side_effect=[failed, error])
    monkeypatch.setattr("netmiko.ConnectHandler", handler)
    driver = _driver()

    with driver if managed else nullcontext():
        with pytest.raises(
            ConnectionError, match="Replacement connection failed"
        ) as exc:
            driver.get_rules()
        assert exc.value.__cause__ is error
        assert driver._conn is None

    assert handler.call_count == 2
    assert failed.send_command.call_count == 1
    failed.__exit__.assert_called_once()


@pytest.mark.parametrize("managed", [False, True])
@pytest.mark.parametrize(
    ("operation", "hit_count_fails"),
    [("get_rules", False), ("get_rules", True), ("get_nat_rules", False)],
)
def test_config_timeout_propagates_and_closes_session(
    monkeypatch, managed, hit_count_fails, operation
):
    conn = _connection()
    error = ReadTimeout("Configuration output is incomplete")
    conn.send_command.side_effect = ["", error] if operation == "get_rules" else error
    failed = _connection()
    failed.send_command.side_effect = ReadTimeout("Hit-count output is incomplete")
    recovery_needed = hit_count_fails and operation == "get_rules"
    if recovery_needed:
        conn.send_command.side_effect = error
    handler = MagicMock(side_effect=[failed, conn] if recovery_needed else [conn])
    monkeypatch.setattr("netmiko.ConnectHandler", handler)
    driver = _driver()

    with driver if managed else nullcontext():
        with pytest.raises(ConnectionError, match="Configuration output") as exc:
            getattr(driver, operation)()
        assert exc.value.__cause__ is error
        assert driver._conn is None

    assert handler.call_count == (2 if recovery_needed else 1)
    conn.__exit__.assert_called_once()
    if recovery_needed:
        failed.__exit__.assert_called_once()


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), -float("inf")])
def test_invalid_read_timeout_rejected_before_connecting(monkeypatch, timeout):
    handler = MagicMock()
    monkeypatch.setattr("netmiko.ConnectHandler", handler)
    with pytest.raises(
        ValueError, match="read_timeout must be a finite positive number"
    ):
        JuniperSRXDriver(
            host="192.0.2.1",
            username="test-user",
            password="test-password",
            read_timeout=timeout,
        )
    handler.assert_not_called()
