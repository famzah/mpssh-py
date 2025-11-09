#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Iterator, List, Sequence


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    default_output_dir = Path("~/.ssh/known_hosts_single").expanduser()
    default_known_hosts = Path("~/.ssh/known_hosts").expanduser()

    parser = argparse.ArgumentParser(
        description="Resolve hostnames/IPs and dump ssh-keygen outputs per entry."
    )
    parser.add_argument(
        "--dot-ssh-output-dir",
        default=str(default_output_dir),
        help="Directory to store ssh-keygen outputs (default: %(default)s)",
    )
    parser.add_argument(
        "--known-hosts-file",
        default=str(default_known_hosts),
        help="Path to the known_hosts file to search (default: %(default)s)",
    )
    parser.add_argument(
        "--input-file",
        default=None,
        help="Optional file to read entries from instead of STDIN",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Print each processed entry",
    )
    args = parser.parse_args(argv)

    args.dot_ssh_output_dir = Path(args.dot_ssh_output_dir)
    args.known_hosts_file = Path(args.known_hosts_file)
    if args.input_file is not None:
        args.input_file = Path(args.input_file)

    return args


def gather_input_lines(input_path: Path | None) -> Iterator[str]:
    if input_path is None:
        yield from sys.stdin
        return

    with input_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            yield line


def is_ip_address(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def resolve_hostname(hostname: str) -> List[str]:
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        print(f"Failed to resolve hostname '{hostname}': {exc}", file=sys.stderr)
        addrinfo = []

    resolved: List[str] = []
    for info in addrinfo:
        ip_literal = info[4][0]
        if ip_literal not in resolved:
            resolved.append(ip_literal)
    return resolved


def unique_entries(original: str, resolved_ips: Iterable[str]) -> List[str]:
    ordered: List[str] = []
    seen: set[str] = set()
    for item in [original, *resolved_ips]:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def sanitize_entry_name(entry: str) -> str:
    if entry in {"", ".", ".."}:
        raise ValueError(f"Unsafe entry name '{entry}'")
    if not re.fullmatch(r"[0-9A-Za-z._:%-]+", entry):
        raise ValueError(f"Unsafe entry name '{entry}'")
    return entry


def run_ssh_keygen(entry: str, known_hosts_file: Path) -> str:
    result = subprocess.run(
        ["ssh-keygen", "-F", entry, "-f", str(known_hosts_file)],
        capture_output=True,
        text=True,
    )
    if result.stderr:
        raise RuntimeError(
            f"ssh-keygen produced stderr output for entry '{entry}': {result.stderr}"
        )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"ssh-keygen failed for entry '{entry}' with exit code {result.returncode}"
        )
    return result.stdout


def process_line(
    raw_line: str,
    known_hosts_file: Path,
    output_dir: Path,
    show_progress: bool,
) -> None:
    stripped = raw_line.strip()
    if not stripped or stripped.startswith("#"):
        return

    if show_progress:
        print(stripped, flush=True)

    resolved_ips: List[str] = []
    if not is_ip_address(stripped):
        resolved_ips = resolve_hostname(stripped)

    for entry in unique_entries(stripped, resolved_ips):
        stdout = run_ssh_keygen(entry, known_hosts_file)
        output_path = output_dir / sanitize_entry_name(entry)
        output_path.write_text(stdout, encoding="utf-8")


def main() -> int:
    args = parse_args()

    output_dir = args.dot_ssh_output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    known_hosts_file = args.known_hosts_file
    input_path = args.input_file if args.input_file else None

    for line in gather_input_lines(input_path):
        process_line(
            line,
            known_hosts_file=known_hosts_file,
            output_dir=output_dir,
            show_progress=args.progress,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
