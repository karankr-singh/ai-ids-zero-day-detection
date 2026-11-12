"""Guarded, operator-approved host firewall blocking.

This is deliberately not an automatic response to anomaly scores. The caller
must name one public IPv4 address, opt in, and explicitly confirm the action.
Network-segment isolation and subnet blocking are not supported.
"""
from __future__ import annotations

import argparse
import ipaddress
import platform
import subprocess
import sys


def validate_block_target(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("Only a single IPv4 address can be blocked; IPv6 and subnets are unsupported.")
    if (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_unspecified or address.is_reserved
    ):
        raise ValueError("Refusing to block a private, local, multicast, reserved, or unspecified address.")
    return str(address)


def firewall_commands(ip: str, system: str | None = None) -> list[list[str]]:
    target = validate_block_target(ip)
    os_name = system or platform.system()
    if os_name == "Windows":
        safe_name = target.replace(".", "-")
        return [
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=AI-IDS-Block-{safe_name}-Inbound", "dir=in", "action=block",
             f"remoteip={target}", "profile=any", "enable=yes"],
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=AI-IDS-Block-{safe_name}-Outbound", "dir=out", "action=block",
             f"remoteip={target}", "profile=any", "enable=yes"],
        ]
    if os_name == "Linux":
        return [
            ["iptables", "-I", "INPUT", "1", "-s", target, "-j", "DROP"],
            ["iptables", "-I", "OUTPUT", "1", "-d", target, "-j", "DROP"],
        ]
    raise RuntimeError("Firewall response is supported only on Windows and Linux.")


def apply_block(
    ip: str,
    *,
    confirm: bool = False,
    system: str | None = None,
    runner=subprocess.run,
) -> list[list[str]]:
    commands = firewall_commands(ip, system)
    if not confirm:
        raise PermissionError("Explicit operator confirmation is required before applying firewall rules.")
    os_name = system or platform.system()
    if os_name == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("Run the terminal as Administrator to apply Windows Firewall rules.")
    elif os_name == "Linux":
        import os
        if os.geteuid() != 0:
            raise PermissionError("Run with sudo to apply Linux iptables rules.")

    completed = []
    try:
        for command in commands:
            runner(command, check=True, capture_output=True, text=True)
            completed.append(command)
    except Exception:
        # Best-effort rollback of rules already inserted by this invocation.
        rollback = []
        for command in reversed(completed):
            if os_name == "Windows":
                rollback.append(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={command[6]}"])
            else:
                rollback.append(["iptables", "-D", command[1], *command[2:]])
        for command in rollback:
            try:
                runner(command, check=True, capture_output=True, text=True)
            except Exception:
                pass
        raise
    return commands


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--block-ip", required=True, help="One public IPv4 address to block")
    parser.add_argument("--apply", action="store_true", help="Apply host firewall rules (otherwise dry-run)")
    args = parser.parse_args()
    try:
        commands = firewall_commands(args.block_ip)
        print("Planned host firewall rules:")
        for command in commands:
            print("  " + subprocess.list2cmdline(command))
        if not args.apply:
            print("DRY RUN ONLY — no firewall changes were made. Add --apply to request an interactive confirmation.")
            return 0
        expected = validate_block_target(args.block_ip)
        typed = input(f"Type BLOCK {expected} to apply inbound and outbound host firewall rules: ").strip()
        if typed != f"BLOCK {expected}":
            print("Confirmation did not match; no firewall changes were made.")
            return 2
        applied = apply_block(expected, confirm=True)
        print(f"Applied {len(applied)} host firewall rules for {expected}.")
        return 0
    except (ValueError, RuntimeError, PermissionError, subprocess.CalledProcessError) as exc:
        print(f"Firewall action not applied: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
