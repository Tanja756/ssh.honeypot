#!/usr/bin/env python3
"""
SSH client fingerprinting — identifies the connecting SSH client
by its banner string and auth behaviour.

Heavily based on known SSH implementation banners.
"""

from __future__ import annotations

import re
from typing import Optional

# Priority-ordered patterns: first match wins
CLIENT_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^SSH-2\.0-libssh_([\d.]+)"), "libssh", "libssh {version}"),
    (re.compile(r"^SSH-2\.0-libssh-([\d.]+)"), "libssh", "libssh {version}"),
    (re.compile(r"^SSH-2\.0-PuTTY"), "PuTTY", "PuTTY"),
    (re.compile(r"^SSH-2\.0-PuTTY_Release_([\d.]+)"), "PuTTY", "PuTTY {version}"),
    (re.compile(r"^SSH-2\.0-AsyncSSH"), "AsyncSSH", "AsyncSSH"),
    (re.compile(r"^SSH-2\.0-Paramiko"), "Paramiko", "Paramiko"),
    (re.compile(r"^SSH-2\.0-Paramiko_([\d.]+)"), "Paramiko", "Paramiko {version}"),
    (re.compile(r"^SSH-2\.0-Go"), "Go ssh", "Go ssh"),
    (re.compile(r"^SSH-2\.0-masscan"), "Masscan", "Masscan"),
    (re.compile(r"^SSH-2\.0-Mirai"), "Mirai", "Mirai"),
    (re.compile(r"^SSH-2\.0-cowrie"), "Cowrie", "Cowrie scanner"),
    (re.compile(r"^SSH-2\.0-Hydra"), "Hydra", "Hydra"),
    (re.compile(r"^SSH-2\.0-Medusa"), "Medusa", "Medusa"),
    (re.compile(r"^SSH-2\.0-nscript"), "Nmap", "Nmap NSE"),
    (re.compile(r"^SSH-2\.0-Twisted"), "Twisted", "Twisted SSH"),
    (re.compile(r"^SSH-2\.0-JSCH"), "JSch", "JSch"),
    (re.compile(r"^SSH-2\.0-OpenSSH"), "OpenSSH", None),  # version extracted from raw
    (re.compile(r"^SSH-2\.0-dropbear"), "Dropbear", "Dropbear"),
    (re.compile(r"^SSH-2\.0-Rabbit"), "Rabbit", "Rabbit SSH"),
    (re.compile(r"^SSH-2\.0-rankey"), "RanKey", "RanKey"),
    (re.compile(r"^SSH-2\.0-SSHTerm"), "SSHTerm", "SSHTerm"),
    (re.compile(r"^SSH-2\.0-mobileSSH"), "mobileSSH", "mobileSSH"),
    (re.compile(r"^SSH-2\.0-sshmaster"), "SSH Master", "SSH Master"),
]

# Auth sequence fingerprints (methods tried in order, comma-separated)
SEQUENCE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^none$"), "Masscan (no auth follow-up)"),
    (re.compile(r"^none,password"), "Brute-forcer (basic)"),
    (re.compile(r"^publickey,password"), "OpenSSH client"),
    (re.compile(r"^publickey,none,password"), "Putty (key + password)"),
]


def fingerprint_client(banner: str, auth_sequence: Optional[list[str]] = None) -> dict[str, str]:
    """Identify the SSH client from its banner.

    Returns:
        {"client": "OpenSSH", "version": "9.7", "client_name": "OpenSSH 9.7"}

    When detection fails, client is "unknown".
    """
    result: dict[str, str] = {"client": "unknown", "client_name": "unknown"}

    for pattern, client, name_template in CLIENT_PATTERNS:
        m = pattern.search(banner)
        if m:
            result["client"] = client
            version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            if version:
                result["version"] = version

            if name_template:
                label = name_template.format(version=version) if version else name_template.format(version="")
            elif version:
                label = f"{client} {version}"
            else:
                label = client

            result["client_name"] = label
            break

    # If client matches known but version not extracted, try generic version extraction
    if result["client"] != "unknown" and "version" not in result:
        version_match = re.search(r"_([\d]+\.[\d]+)", banner)
        if version_match:
            result["version"] = version_match.group(1)
            result["client_name"] = f"{result['client']} {result['version']}"

    # Auth sequence refinement
    if auth_sequence:
        seq_str = ",".join(auth_sequence)
        for seq_pat, seq_label in SEQUENCE_PATTERNS:
            if seq_pat.fullmatch(seq_str):
                result["client_behavior"] = seq_label
                break

    return result
