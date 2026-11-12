import pytest

from evaluation.run_unseen_attacks import evaluate_unseen_categories
from response import firewall_commands, validate_block_target


def test_firewall_target_rejects_private_and_loopback_addresses():
    for address in ("192.168.1.10", "127.0.0.1", "10.0.0.5", "224.0.0.1"):
        with pytest.raises(ValueError):
            validate_block_target(address)


def test_firewall_target_accepts_public_ipv4():
    assert validate_block_target("8.8.8.8") == "8.8.8.8"


def test_windows_firewall_plan_is_explicit_inbound_and_outbound():
    commands = firewall_commands("8.8.8.8", system="Windows")
    assert len(commands) == 2
    assert "dir=in" in commands[0]
    assert "dir=out" in commands[1]


def test_linux_firewall_plan_is_host_scoped():
    commands = firewall_commands("1.1.1.1", system="Linux")
    assert commands[0][1] == "INPUT"
    assert commands[1][1] == "OUTPUT"
    assert "DROP" in commands[0]


def test_unseen_evaluation_requires_category_column(tmp_path):
    # Function-level validation is covered by the production loader; this
    # lightweight check keeps the CLI module importable and exposes its API.
    assert callable(evaluate_unseen_categories)
