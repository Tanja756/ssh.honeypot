#!/usr/bin/env python3
"""
Optional IP blacklisting for SSH Honeypot.

After N failed auth attempts from an IP, executes a configurable
command (e.g. iptables/nftables) to block the attacker.

Configuration via honeypot.yaml:
  blacklist_enabled: true
  blacklist_ban_after: 100        # auth attempts before ban
  blacklist_ban_command: iptables -A INPUT -s {ip} -j DROP
  blacklist_ban_file: blacklist.json   # persists bans across restarts
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


class BlacklistManager:
    """Tracks auth attempts per IP and bans repeat offenders."""

    def __init__(
        self,
        enabled: bool = False,
        ban_after: int = 100,
        ban_command: str = "",
        ban_file: str = "",
    ) -> None:
        self._enabled = enabled
        self._ban_after = ban_after
        self._ban_command = ban_command
        self._ban_file = ban_file
        self._lock = threading.Lock()
        self._attempts: dict[str, int] = {}
        self._banned: set[str] = set()

        if enabled and ban_file:
            self._load_bans()

    def _load_bans(self) -> None:
        path = Path(self._ban_file)
        if path.exists():
            try:
                data: dict[str, int] = json.loads(path.read_text())
                self._banned = set(data.keys())
            except (json.JSONDecodeError, OSError):
                pass

    def _save_bans(self) -> None:
        if not self._ban_file:
            return
        try:
            data = {ip: 1 for ip in self._banned}
            Path(self._ban_file).write_text(json.dumps(data, indent=2))
        except OSError:
            pass

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
        except ValueError:
            return True

    @staticmethod
    def _is_safe_ip(ip: str) -> bool:
        """Check IP is a valid non-private address (prevents command injection)."""
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
                return False
            return True
        except ValueError:
            return False

    def record_attempt(self, ip: str) -> None:
        """Increment attempt counter for IP; ban if threshold exceeded."""
        if not self._enabled:
            return
        if ip in self._banned:
            return
        if not self._is_safe_ip(ip):
            return

        with self._lock:
            self._attempts[ip] = self._attempts.get(ip, 0) + 1
            count = self._attempts[ip]

        if count >= self._ban_after:
            self._ban(ip)

    def _ban(self, ip: str) -> None:
        self._banned.add(ip)
        self._save_bans()

        if not self._ban_command:
            return

        try:
            cmd = self._ban_command.replace("{ip}", ip)
            subprocess.run(
                cmd, shell=True, timeout=10,
                capture_output=True, text=True,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            pass

    def is_banned(self, ip: str) -> bool:
        return ip in self._banned

    @property
    def banned_count(self) -> int:
        return len(self._banned)
