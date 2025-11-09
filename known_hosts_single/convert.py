#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Iterator, List, Sequence


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    default_output_dir = Path("~/.ssh/known_hosts_single").expanduser()
    default_known_hosts = Path("~/.ssh/known_hosts").expanduser()

    parser = argparse.ArgumentParser(
        description="Resolve hostnames/IPs and dump ssh-keygen outputs per entry.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.epilog = (
        "Example:\n"
        f"  {parser.prog} --known-hosts-file ~/.ssh/known_hosts.monolith --input-file ~/servers.list"
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


def sanitize_entry_name(entry: str) -> str:
    if entry in {"", ".", ".."}:
        raise ValueError(f"Unsafe entry name '{entry}'")
    if not re.fullmatch(r"[0-9A-Za-z._:%-\[\]]+", entry):
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

    lookup_hostname = stripped
    storage_name = stripped
    port: str | None = None

    # Known_hosts entries with custom ports look like [host]:port; resolve/store by host.
    bracket_match = re.fullmatch(r"\[(?P<host>[^]]+)\]:(?P<port>\d+)", stripped)
    if bracket_match:
        lookup_hostname = bracket_match.group("host")
        storage_name = lookup_hostname
        port = bracket_match.group("port")

    resolved_ips: List[str] = []
    if not is_ip_address(lookup_hostname):
        resolved_ips = resolve_hostname(lookup_hostname)

    entries_to_process: List[tuple[str, str]] = [(stripped, storage_name)]
    seen_ips: set[str] = set()
    for resolved_ip in resolved_ips:
        if resolved_ip in seen_ips:
            continue
        seen_ips.add(resolved_ip)
        lookup_entry = resolved_ip
        storage_entry = resolved_ip
        if port is not None:
            lookup_entry = f"[{resolved_ip}]:{port}"
            storage_entry = resolved_ip
        entries_to_process.append((lookup_entry, storage_entry))

    for lookup_entry, storage_entry in entries_to_process:
        stdout = run_ssh_keygen(lookup_entry, known_hosts_file)
        output_path = output_dir / sanitize_entry_name(storage_entry)
        if len(stdout):
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
