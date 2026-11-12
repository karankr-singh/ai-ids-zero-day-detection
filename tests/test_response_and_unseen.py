import pandas as pd
import pytest

from evaluation.run_unseen_attacks import evaluate_unseen_categories
from response import firewall_commands, validate_block_target


def test_zenodo_split_roles_are_resolved_by_content_not_filename(tmp_path, monkeypatch):
    from evaluation import run_unsw_nb15

    # The Zenodo "training-set" filename contains the standard test partition,
    # and vice versa. The resolver must return the 175,341-row partition first.
    signatures = {
        tmp_path / "UNSW_NB15_training-set.csv": (82332, 37000),
        tmp_path / "UNSW_NB15_testing-set.csv": (175341, 56000),
    }
    monkeypatch.setattr(
        run_unsw_nb15, "_unsw_split_signature",
        lambda path: signatures[path],
    )
    paths = {
        "UNSW_NB15_training-set.csv": tmp_path / "UNSW_NB15_training-set.csv",
        "UNSW_NB15_testing-set.csv": tmp_path / "UNSW_NB15_testing-set.csv",
    }
    training, testing = run_unsw_nb15._resolve_unsw_split_paths(paths)
    assert training == paths["UNSW_NB15_testing-set.csv"]
    assert testing == paths["UNSW_NB15_training-set.csv"]


def test_firewall_target_rejects_private_and_loopback_addresses():
    for address in ("192.168.1.10", "127.0.0.1", "10.0.0.5", "224.0.0.1"):
        with pytest.raises(ValueError):
            validate_block_target(address)


def test_firewall_target_accepts_public_ipv4():
    assert validate_block_target("8.8.8.8") == "8.8.8.8"


def test_firewall_target_rejects_ipv6_and_cidr():
    for address in ("2001:4860:4860::8888", "8.8.8.8/32"):
        with pytest.raises(ValueError):
            validate_block_target(address)


def test_windows_firewall_plan_is_explicit_inbound_and_outbound():
    commands = firewall_commands("8.8.8.8", system="Windows")
    assert len(commands) == 2
    assert "dir=in" in commands[0]
    assert "dir=out" in commands[1]


def test_linux_firewall_plan_is_host_scoped():
    commands = firewall_commands("1.1.1.1", system="Linux")
    assert len(commands) == 2
    assert commands[0][1:3] == ["-I", "INPUT"]
    assert commands[1][1:3] == ["-I", "OUTPUT"]
    assert "DROP" in commands[0]


def test_unseen_evaluation_uses_only_normal_training_rows(tmp_path):
    train_rows = []
    for i in range(100):
        train_rows.append({
            "id": i, "dur": 0.1 + (i % 7) * 0.01,
            "proto": "tcp" if i % 2 else "udp", "service": "http",
            "attack_cat": "Normal", "label": 0,
        })
    for i in range(20):
        train_rows.append({
            "id": 100 + i, "dur": 2.0 + i,
            "proto": "icmp", "service": "-", "attack_cat": "Fuzzers",
            "label": 1,
        })

    test_rows = []
    for i in range(30):
        test_rows.append({
            "id": 200 + i, "dur": 0.1 + (i % 5) * 0.01,
            "proto": "tcp" if i % 2 else "udp", "service": "http",
            "attack_cat": "Normal", "label": 0,
        })
    for category, base in (("Worms", 3.0), ("Shellcode", 5.0)):
        for i in range(12):
            test_rows.append({
                "id": 300 + len(test_rows), "dur": base + i * 0.1,
                "proto": "icmp", "service": "-", "attack_cat": category,
                "label": 1,
            })

    train_path = tmp_path / "train.csv"
    test_path = tmp_path / "test.csv"
    pd.DataFrame(train_rows).to_csv(train_path, index=False)
    pd.DataFrame(test_rows).to_csv(test_path, index=False)

    report = evaluate_unseen_categories(
        train_path, test_path, tmp_path / "results",
        categories=["Worms", "Shellcode"], estimators=10,
        validation_fraction=0.2, target_fpr=0.05,
    )
    assert report["training"]["attack_training_rows_excluded"] == 20
    assert report["training"]["fit_normal_rows"] + report["training"]["calibration_normal_rows"] == 100
    assert report["holdout"]["test_selected_attack_records"] == 24
    assert report["holdout"]["test_excluded_attack_records"] == 0
    assert set(report["per_unseen_attack_category"]) == {"Worms", "Shellcode"}
    assert (tmp_path / "results" / "unsw_nb15_unseen_categories.json").is_file()
