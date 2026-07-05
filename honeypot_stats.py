#!/usr/bin/env python3
"""Analyse honeypot JSON log and print statistics."""

from __future__ import annotations

import gzip
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


def iter_logs(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    records: list[dict[str, Any]] = []
    sources: list[Path] = []

    if p.exists():
        sources.append(p)
    for gz in sorted(p.parent.glob(f"{p.name}.*.gz")):
        sources.append(gz)

    for src in sources:
        opener = gzip.open if src.suffix == ".gz" else open
        with opener(str(src), "rt", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def top(seq, n: int = 20) -> list[tuple[str, int]]:
    return Counter(seq).most_common(n)


def _default_log() -> str:
    candidates = [
        "honeypot.log",
        "/var/log/ssh-honeypot/honeypot.log",
    ]
    for p in candidates:
        if Path(p).exists():
            return p
    return candidates[0]


def main() -> None:
    log_path = sys.argv[1] if len(sys.argv) > 1 else _default_log()

    if not Path(log_path).exists():
        print(f"Log not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    records = iter_logs(log_path)
    total = len(records)
    auths = [r for r in records if r.get("event") == "auth_attempt"]

    if total == 0:
        print("No log records found.")
        return

    print(f"Total records: {total}")
    print(f"Auth attempts: {len(auths)}")

    events = Counter(r.get("event", "unknown") for r in records)
    print(f"\n── Event summary ──")
    for ev, cnt in events.most_common():
        print(f"  {ev}: {cnt}")

    ips = [r["src_ip"] for r in auths if "src_ip" in r]
    print(f"\n── Top source IPs (auth attempts) ──")
    for ip, cnt in top(ips):
        print(f"  {ip:20s}  {cnt}")

    passwords = [r.get("password", "") for r in auths]
    creds = [
        f"{r.get('username', '')}:{r.get('password', '')}"
        for r in auths
    ]
    print(f"\n── Top passwords ──")
    for pw, cnt in top(passwords):
        if pw:
            print(f"  {pw!r:30s}  {cnt}")

    print(f"\n── Top username:password pairs ──")
    for c, cnt in top(creds):
        print(f"  {c:40s}  {cnt}")

    print(f"\n── Stats by day ──")
    days: Counter[str] = Counter()
    for r in auths:
        ts = r.get("timestamp", "")
        day = ts[:10] if ts else "unknown"
        days[day] += 1
    for day, cnt in days.most_common():
        print(f"  {day}: {cnt}")


if __name__ == "__main__":
    main()
