"""
SSH banner profiles for OS emulation.
Each profile defines the SSH banner string, key type, and key size
to make the honeypot appear as a specific OS.
"""

from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    "ubuntu-20.04": {
        "ssh_banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "ubuntu-22.04": {
        "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "ubuntu-24.04": {
        "ssh_banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "debian-11": {
        "ssh_banner": "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "debian-12": {
        "ssh_banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "centos-7": {
        "ssh_banner": "SSH-2.0-OpenSSH_7.4p1 CentOS",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "centos-8": {
        "ssh_banner": "SSH-2.0-OpenSSH_8.0p1 CentOS",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "centos-9": {
        "ssh_banner": "SSH-2.0-OpenSSH_8.7p1 CentOS",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "freebsd-13": {
        "ssh_banner": "SSH-2.0-OpenSSH_9.3 FreeBSD-20230320",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "freebsd-14": {
        "ssh_banner": "SSH-2.0-OpenSSH_9.6 FreeBSD-20240315",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "alpine-3.20": {
        "ssh_banner": "SSH-2.0-OpenSSH_9.7",
        "host_key_type": "ed25519",
        "host_key_bits": 256,
    },
    "opensuse-15": {
        "ssh_banner": "SSH-2.0-OpenSSH_8.4p1 openSUSE-150400.3.1",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
    "arch-2024": {
        "ssh_banner": "SSH-2.0-OpenSSH_9.7",
        "host_key_type": "ed25519",
        "host_key_bits": 256,
    },
    "custom": {
        "ssh_banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "host_key_type": "rsa",
        "host_key_bits": 4096,
    },
}

DEFAULT_PROFILE = "ubuntu-22.04"


def resolve(profile_name: str, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    if profile_name not in PROFILES:
        available = ", ".join(sorted(PROFILES))
        raise KeyError(f"Unknown profile '{profile_name}'. Available: {available}")

    cfg = dict(PROFILES[profile_name])
    if overrides:
        cfg.update({k: v for k, v in overrides.items() if v is not None})
    return cfg


def list_profiles() -> str:
    rows = []
    for name, p in sorted(PROFILES.items()):
        rows.append(f"  {name:<18s}  {p['ssh_banner']}")
    return "\n".join(rows)
