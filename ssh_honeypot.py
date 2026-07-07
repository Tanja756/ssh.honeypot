#!/usr/bin/env python3
"""
Secure SSH Honeypot — captures attacker credentials in isolation.
No shell access, privilege separation, rate limiting, structured logging.

Security model:
  - Always rejects authentication (no valid credentials exist)
  - Drops root privileges after binding socket
  - Chroot jails the process when run as root
  - Rate-limits connections and auth attempts per source IP
  - TCP keepalive detects dead peers
  - Resource limits prevent abuse
  - No system commands are ever executed
"""

from __future__ import annotations

import grp
import gzip
import json
import logging
import os
import pwd
import resource
import shutil
import concurrent.futures
import random
import signal
import socket
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, TextIO

import paramiko
import yaml

import banners
import blacklist
import fingerprints
import geoip

# ── Configuration ──────────────────────────────────────────────
# Defaults — overridden by honeypot.yaml + profile + CLI args

CONFIG: Dict[str, Any] = {
    "profile": "ubuntu-22.04",
    "config_path": "honeypot.yaml",
    "bind_host": "0.0.0.0",
    "bind_port": 2222,
    "backlog": 100,
    "connection_timeout": 60.0,
    "auth_timeout": 30.0,
    "ssh_banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
    "host_key_path": "ssh_host_key",
    "host_key_type": "rsa",
    "host_key_bits": 4096,
    "host_key_extra_path": "",
    "host_key_extra_type": "",
    "host_key_extra_bits": 0,
    "auth_delay_min": 1.0,
    "auth_delay_max": 3.0,
    "auth_methods": "publickey,password,keyboard-interactive",
    "rate_window": 60,
    "rate_max_conn": 5,
    "auth_rate_window": 60,
    "auth_rate_max_attempts": 10,

    "log_file": "honeypot.log",
    "log_max_size": 104857600,
    "log_max_backups": 2,
    "log_max_field_len": 256,
    "log_json": True,
    "geoip_city_db": "",
    "geoip_asn_db": "",
    "geoip_cache_size": 10000,
    "drop_privileges": False,
    "run_as_user": "nobody",
    "run_as_group": "nogroup",
    "chroot_dir": "/var/empty",
    "blacklist_enabled": False,
    "blacklist_ban_after": 100,
    "blacklist_ban_command": "",
    "blacklist_ban_file": "",
}

# ── Logging ────────────────────────────────────────────────────

_logger = logging.getLogger("ssh_honeypot")
_logger.setLevel(logging.INFO)

logging.getLogger("paramiko").setLevel(logging.WARNING)


class CompressedRotatingFileHandler(logging.Handler):
    def __init__(
        self, filename: str,
        max_bytes: int = 104857600,
        backup_count: int = 2,
    ) -> None:
        super().__init__()
        self._filename = filename
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._stream: Optional[TextIO] = None
        self._open_stream()

    @property
    def baseFilename(self) -> str:
        return self._filename

    def _open_stream(self) -> None:
        self._stream = open(self._filename, "a", encoding="utf-8")

    def _rotate(self) -> None:
        self._stream.close()
        self._stream = None

        log_path = Path(self._filename)

        for i in range(self._backup_count - 1, 0, -1):
            src = log_path.with_name(f"{log_path.name}.{i}.gz")
            dst = log_path.with_name(f"{log_path.name}.{i + 1}.gz")
            if src.exists():
                shutil.move(str(src), str(dst))

        archive = log_path.with_name(f"{log_path.name}.1.gz")
        with open(self._filename, "rb") as f_in, gzip.open(str(archive), "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        os.unlink(self._filename)

        self._open_stream()

    def emit(self, record: logging.LogRecord) -> None:
        if self._stream is None:
            return
        try:
            if self._stream.tell() >= self._max_bytes:
                self._rotate()
            msg = self.format(record)
            self._stream.write(msg + "\n")
            self._stream.flush()
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        super().close()


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(record.msg, ensure_ascii=False, default=str)


_fh: Optional[CompressedRotatingFileHandler] = None
_geo_resolver: geoip.GeoResolver = geoip.GeoResolver()
_blacklist_manager: blacklist.BlacklistManager = blacklist.BlacklistManager()

_sh = logging.StreamHandler()
_sh.setLevel(logging.INFO)
_sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
_logger.addHandler(_sh)


def log_event(event: str, **fields: Any) -> None:
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event}
    record.update(fields)
    _logger.info(record)


def log_error(event: str, **fields: Any) -> None:
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event}
    record.update(fields)
    _logger.error(record)


# ── Rate Limiter ───────────────────────────────────────────────

class RateLimiter:
    """Sliding-window rate limiter keyed by source IP."""

    def __init__(self, window: float, max_events: int) -> None:
        self._window = window
        self._max = max_events
        self._lock = threading.Lock()
        self._buckets: Dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            times = self._buckets[key]
            times[:] = [t for t in times if t > cutoff]
            if len(times) >= self._max:
                return False
            times.append(now)
            return True

    def prune(self) -> None:
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            stale = [
                k for k, v in self._buckets.items()
                if all(t <= cutoff for t in v)
            ]
            for k in stale:
                del self._buckets[k]


# ── Privilege dropping ─────────────────────────────────────────

def drop_privileges(user: str, group: str, chroot_dir: str) -> None:
    """Drop root privileges: chroot, then setgid/setuid."""
    if os.geteuid() != 0:
        log_event("privilege_skip", reason="not_root")
        return

    try:
        if os.path.isdir(chroot_dir):
            os.chroot(chroot_dir)
            os.chdir("/")
            log_event("chroot", directory=chroot_dir)
            try:
                os.urandom(1)
            except OSError:
                log_error("urandom_unavailable", hint="mount --bind /dev/urandom /var/empty/dev/urandom")

        gid = grp.getgrnam(group).gr_gid
        uid = pwd.getpwnam(user).pw_uid

        os.setgid(gid)
        os.setuid(uid)

        log_event("privilege_drop", user=user, group=group)
    except Exception as exc:
        log_error("privilege_drop_failed", error=str(exc))
        raise


# ── Resource limits ────────────────────────────────────────────

def set_resource_limits() -> None:
    """Apply safe resource limits to prevent resource exhaustion."""
    limits = {
        resource.RLIMIT_NOFILE: (1024, 1024),
        resource.RLIMIT_NPROC: (5000, 5000),
        resource.RLIMIT_FSIZE: (1024 * 1024, 1024 * 1024),
        resource.RLIMIT_AS: (256 * 1024 * 1024, 256 * 1024 * 1024),
    }
    for rlim, (soft, hard) in limits.items():
        try:
            resource.setrlimit(rlim, (soft, hard))
        except (ValueError, resource.error) as exc:
            log_event("resource_limit_skip", limit=rlim.__name__ if hasattr(rlim, '__name__') else str(rlim), error=str(exc))


# ── SSH Server Interface ───────────────────────────────────────

class HoneypotServer(paramiko.ServerInterface):
    """Paramiko ServerInterface that logs credentials, always rejects auth."""

    def __init__(
        self, peer: tuple, client_version: str,
        auth_limiter: RateLimiter, transport: paramiko.Transport,
        session_id: str, attack_id: str,
    ) -> None:
        super().__init__()
        self.event = threading.Event()
        self._peer = peer
        self._client_version = client_version
        self._auth_limiter = auth_limiter
        self._transport = transport
        self._auth_attempts = 0
        self._session_id = session_id
        self._attack_id = attack_id
        self._auth_sequence: list[str] = []

    def _log(self, event_name: str, **fields: Any) -> None:
        log_event(event_name, session_id=self._session_id, attack_id=self._attack_id, **fields)

    def get_allowed_auths(self, username: str = "") -> str:
        return CONFIG.get("auth_methods", "publickey,password,keyboard-interactive")

    def _truncated(self, val: str, label: str = "") -> str:
        max_len = CONFIG.get("log_max_field_len", 256)
        if len(val) > max_len:
            return val[:max_len] + "..."
        return val

    def _auth_delay(self) -> None:
        delay = random.uniform(CONFIG.get("auth_delay_min", 1.0), CONFIG.get("auth_delay_max", 3.0))
        time.sleep(delay)

    def _log_auth(self, username: str, password: str, auth_method: str, **extras: Any) -> None:
        ip = self._peer[0]

        _blacklist_manager.record_attempt(ip)
        if _blacklist_manager.is_banned(ip):
            self._transport.close()
            return

        if not self._auth_limiter.allow(ip):
            self._log(
                "auth_rate_limited",
                src_ip=ip, auth_method=auth_method,
                client_version=self._client_version,
            )
            self._transport.close()
            return

        self._auth_sequence.append(auth_method)
        fp = fingerprints.fingerprint_client(self._client_version, self._auth_sequence)

        geo = _geo_resolver.lookup(ip)

        self._log(
            "auth_attempt",
            src_ip=ip,
            src_port=self._peer[1],
            username=self._truncated(username),
            password=self._truncated(password),
            auth_method=auth_method,
            client_version=self._client_version,
            client_name=fp.get("client_name", ""),
            **geo,
            **extras,
        )

    def check_auth_none(self, username: str) -> int:
        self._log_auth(username=username, password="", auth_method="none")
        self._auth_delay()
        self.event.set()
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        self._auth_attempts += 1
        self._log_auth(
            username=username, password=password,
            auth_method="password",
            attempt=self._auth_attempts,
        )
        self._auth_delay()
        self.event.set()
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        self._log_auth(
            username=username, password="<public_key>",
            auth_method="publickey",
            fingerprint=key.get_fingerprint().hex() if hasattr(key, 'get_fingerprint') else "",
        )
        self._auth_delay()
        self.event.set()
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username: str, subtypes: list[str]) -> tuple[int, list[tuple[str, bool, bool]]]:
        self._log_auth(
            username=username, password="<keyboard-interactive>",
            auth_method="keyboard-interactive",
            subtypes=",".join(subtypes) if subtypes else "",
        )
        self._auth_delay()
        self.event.set()
        return paramiko.AUTH_FAILED, []

    def check_auth_interactive_response(self, responses: list[str]) -> int:
        password = responses[0] if responses else ""
        self._auth_attempts += 1
        self._log_auth(
            username="", password=password,
            auth_method="keyboard-interactive",
            attempt=self._auth_attempts,
        )
        self._auth_delay()
        self.event.set()
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        self._log(
            "channel_request",
            src_ip=self._peer[0],
            kind=kind,
            client_version=self._client_version,
        )
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return False

    def check_channel_pty_request(
        self, channel: paramiko.Channel, term: str,
        width: int, height: int,
        pixelwidth: int, pixelheight: int, modes: bytes,
    ) -> bool:
        return False

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self._log(
            "exec_request",
            src_ip=self._peer[0],
            command=command.decode(errors="replace")[:CONFIG.get("log_max_field_len", 256)],
            client_version=self._client_version,
        )
        return False


# ── Host key management ────────────────────────────────────────

def _load_key_by_type(path: str, key_type: str) -> paramiko.PKey:
    cls = {
        "rsa": paramiko.RSAKey,
        "ecdsa": paramiko.ECDSAKey,
        "ed25519": paramiko.Ed25519Key,
    }.get(key_type)
    if cls is None:
        raise ValueError(f"Unsupported key type: {key_type}")
    return cls(filename=path)


def _gen_ed25519_key() -> tuple[paramiko.Ed25519Key, bytes]:
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _e
    from cryptography.hazmat.primitives import serialization as _s
    import io as _io
    _pk = _e.Ed25519PrivateKey.generate()
    _pem = _pk.private_bytes(
        encoding=_s.Encoding.PEM,
        format=_s.PrivateFormat.OpenSSH,
        encryption_algorithm=_s.NoEncryption(),
    )
    return paramiko.Ed25519Key.from_private_key(_io.StringIO(_pem.decode())), _pem


def _generate_key(key_type: str, bits: int) -> paramiko.PKey:
    if key_type == "rsa":
        return paramiko.RSAKey.generate(bits)
    elif key_type == "ecdsa":
        return paramiko.ECDSAKey.generate(bits=bits)
    elif key_type == "ed25519":
        return _gen_ed25519_key()[0]
    raise ValueError(f"Unsupported key type: {key_type}")


def _write_key_file(key: paramiko.PKey, key_type: str, path: str, write: bytes | None = None) -> None:
    if key_type == "ed25519" and write:
        Path(path).write_bytes(write)
    else:
        key.write_private_key_file(path)


def load_or_generate_host_key(path: str, key_type: str = "rsa", bits: int = 4096) -> paramiko.PKey:
    key_path = Path(path)
    if key_path.exists():
        log_event("host_key_loaded", path=str(key_path), type=key_type)
        try:
            return _load_key_by_type(str(key_path), key_type)
        except (paramiko.SSHException, ValueError) as exc:
            log_error("host_key_load_failed", error=str(exc))
            log_event("host_key_replacing")
            key_path.unlink()

    log_event("host_key_generate", type=key_type, bits=bits)
    key, pem = (None, None)
    if key_type == "rsa":
        key = paramiko.RSAKey.generate(bits)
    elif key_type == "ecdsa":
        key = paramiko.ECDSAKey.generate(bits=bits)
    elif key_type == "ed25519":
        key, pem = _gen_ed25519_key()
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    _write_key_file(key, key_type, str(key_path), write=pem)
    key_path.chmod(0o600)
    return key


def load_or_generate_extra_host_key(
    path: str, key_type: str, bits: int,
) -> paramiko.PKey | None:
    if not path or not key_type:
        return None
    return load_or_generate_host_key(path, key_type, max(bits, 256))


# ── TCP keepalive ──────────────────────────────────────────────

def enable_tcp_keepalive(
    sock: socket.socket,
    after_idle: int = 10,
    interval: int = 3,
    count: int = 5,
) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
    except OSError:
        pass


# ── Per-connection handler ─────────────────────────────────────

def handle_connection(
    client_sock: socket.socket,
    addr: tuple,
    host_keys: list[paramiko.PKey],
    auth_limiter: RateLimiter,
) -> None:
    peer_ip, peer_port = addr
    session_id = str(uuid.uuid4())
    attack_id = session_id

    enable_tcp_keepalive(client_sock)
    client_sock.settimeout(CONFIG["connection_timeout"])

    transport: Optional[paramiko.Transport] = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.banner_timeout = CONFIG["auth_timeout"]
        transport.local_version = CONFIG["ssh_banner"]
        for key in host_keys:
            transport.add_server_key(key)

        server = HoneypotServer(addr, transport.remote_version or "unknown", auth_limiter, transport, session_id, attack_id)
        event = threading.Event()
        transport.start_server(event=event, server=server)
        # Wait for SSH key exchange to complete
        event.wait()
        # Wait for auth to finish (client gets rejected, then disconnects).
        transport.server_object.event.wait(CONFIG["auth_timeout"])
        # Drain any stray channel that snuck through, then close.
        channel = transport.accept(0.5)
        if channel is not None:
            channel.close()

    except paramiko.SSHException:
        pass
    except socket.timeout:
        log_event("connection_timeout", src_ip=peer_ip, session_id=session_id)
    except EOFError:
        pass
    except (RuntimeError, Exception) as exc:
        log_event("connection_error", src_ip=peer_ip, error=str(exc), session_id=session_id)
    finally:
        if transport is not None:
            transport.close()
        try:
            client_sock.close()
        except OSError:
            pass


# ── Background rate-limiter pruner ─────────────────────────────

def _pruner_loop(conn_limiter: RateLimiter, interval: float = 300.0) -> None:
    while _running:
        time.sleep(interval)
        conn_limiter.prune()


# ── Main server ────────────────────────────────────────────────

_server_sock: Optional[socket.socket] = None
_running = True


def _signal_handler(signum: int, frame: object = None) -> None:
    global _running
    signame = signal.Signals(signum).name
    log_event("shutdown", signal=signame)
    _running = False
    if _server_sock is not None:
        try:
            _server_sock.close()
        except OSError:
            pass


def print_banner() -> None:
    print("  ┌─────────────────────────────────────────────┐")
    print("  │        Secure SSH Honeypot v1.0             │")
    print("  │   Captures credentials — never grants       │")
    print("  │   access. Security-isolated design.         │")
    print("  └─────────────────────────────────────────────┘")


def parse_args() -> None:
    for i, arg in enumerate(sys.argv):
        if arg in ("--help", "-h"):
            print("Usage: python ssh_honeypot.py [options]")
            print()
            print("Options:")
            print("  --config PATH       Config file path (default: honeypot.yaml)")
            print("  --profile NAME      OS profile (see --list-profiles)")
            print("  --list-profiles     List available OS profiles and exit")
            print("  --port PORT         Listening port (default: 2222)")
            print("  --bind HOST         Bind address (default: 0.0.0.0)")
            print("  --log FILE          Log file path (default: honeypot.log)")
            print("  --drop-privs        Drop root privileges after bind")
            print("  --user USER         Unprivileged user (default: nobody)")
            print("  --group GROUP       Unprivileged group (default: nogroup)")
            print("  --banner BANNER     SSH banner string")
            print("  --key PATH          Host key file path")
            sys.exit(0)

        if arg == "--list-profiles":
            print("Available OS profiles:\n")
            print(banners.list_profiles())
            sys.exit(0)

        if arg == "--config" and i + 1 < len(sys.argv):
            CONFIG["config_path"] = sys.argv[i + 1]
        elif arg == "--profile" and i + 1 < len(sys.argv):
            CONFIG["profile"] = sys.argv[i + 1]
            try:
                _merge_config(banners.resolve(CONFIG["profile"]))
            except KeyError as exc:
                log_error("cli_profile_error", error=str(exc))
        elif arg == "--port" and i + 1 < len(sys.argv):
            CONFIG["bind_port"] = int(sys.argv[i + 1])
        elif arg == "--bind" and i + 1 < len(sys.argv):
            CONFIG["bind_host"] = sys.argv[i + 1]
        elif arg == "--log" and i + 1 < len(sys.argv):
            CONFIG["log_file"] = sys.argv[i + 1]
        elif arg == "--drop-privs":
            CONFIG["drop_privileges"] = True
        elif arg == "--user" and i + 1 < len(sys.argv):
            CONFIG["run_as_user"] = sys.argv[i + 1]
        elif arg == "--group" and i + 1 < len(sys.argv):
            CONFIG["run_as_group"] = sys.argv[i + 1]
        elif arg == "--banner" and i + 1 < len(sys.argv):
            CONFIG["ssh_banner"] = sys.argv[i + 1]
        elif arg == "--key" and i + 1 < len(sys.argv):
            CONFIG["host_key_path"] = sys.argv[i + 1]


# ── Config loading (YAML + profile) ─────────────────────────────

def _merge_config(src: Dict[str, Any]) -> None:
    CONFIG.update({k: v for k, v in src.items() if v is not None})


def load_config() -> None:
    """Load honeypot.yaml, resolve profile, merge into CONFIG."""
    cfg_path = Path(CONFIG["config_path"])
    yaml_cfg: Dict[str, Any] = {}

    if cfg_path.exists():
        log_event("config_loaded", path=str(cfg_path))
        with open(cfg_path) as f:
            yaml_cfg = yaml.safe_load(f) or {}
    else:
        log_event("config_not_found", path=str(cfg_path))

    profile_name = yaml_cfg.get("profile") or CONFIG["profile"]
    profile_overrides = {k: yaml_cfg[k] for k in ("ssh_banner", "host_key_type", "host_key_bits") if k in yaml_cfg}

    try:
        profile_cfg = banners.resolve(profile_name, profile_overrides)
    except KeyError as exc:
        log_error("config_profile_error", error=str(exc))
        profile_cfg = banners.resolve(banners.DEFAULT_PROFILE)

    _merge_config(profile_cfg)
    _merge_config(yaml_cfg)


def _reconfigure_logging() -> None:
    global _fh
    if _fh is not None and CONFIG["log_file"] == _fh.baseFilename:
        return
    if _fh is not None:
        _logger.removeHandler(_fh)
        _fh.close()
    _fh = CompressedRotatingFileHandler(
        CONFIG["log_file"],
        max_bytes=CONFIG["log_max_size"],
        backup_count=CONFIG["log_max_backups"],
    )
    _fh.setLevel(logging.INFO)
    _fmt: logging.Formatter
    if CONFIG["log_json"]:
        _fmt = JSONFormatter()
    else:
        _fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    _fh.setFormatter(_fmt)
    _logger.addHandler(_fh)


def main() -> None:
    global _server_sock, _running

    load_config()
    parse_args()
    print_banner()
    _reconfigure_logging()

    global _geo_resolver, _blacklist_manager
    _geo_resolver = geoip.GeoResolver(
        city_db_path=CONFIG["geoip_city_db"] or None,
        asn_db_path=CONFIG["geoip_asn_db"] or None,
        cache_size=CONFIG["geoip_cache_size"],
    )
    _blacklist_manager = blacklist.BlacklistManager(
        enabled=CONFIG["blacklist_enabled"],
        ban_after=CONFIG["blacklist_ban_after"],
        ban_command=CONFIG["blacklist_ban_command"],
        ban_file=CONFIG["blacklist_ban_file"],
    )

    # Signal handling for graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Apply resource limits
    set_resource_limits()

    # Load or generate host key(s)
    host_keys: list[paramiko.PKey] = [
        load_or_generate_host_key(CONFIG["host_key_path"], CONFIG["host_key_type"], CONFIG["host_key_bits"]),
    ]
    extra_key = load_or_generate_extra_host_key(
        CONFIG["host_key_extra_path"], CONFIG["host_key_extra_type"], CONFIG["host_key_extra_bits"],
    )
    if extra_key is not None:
        host_keys.append(extra_key)

    # Rate limiters
    conn_limiter = RateLimiter(CONFIG["rate_window"], CONFIG["rate_max_conn"])
    auth_limiter = RateLimiter(CONFIG["auth_rate_window"], CONFIG["auth_rate_max_attempts"])

    # Start background pruner (prunes both limiters)
    conn_pruner = threading.Thread(
        target=_pruner_loop, args=(conn_limiter,), daemon=True
    )
    conn_pruner.start()
    auth_pruner = threading.Thread(
        target=_pruner_loop, args=(auth_limiter,), daemon=True
    )
    auth_pruner.start()

    # Create listening socket
    _server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _server_sock.settimeout(1.0)
    _server_sock.bind((CONFIG["bind_host"], CONFIG["bind_port"]))
    _server_sock.listen(CONFIG["backlog"])

    bind_addr = f"{CONFIG['bind_host']}:{CONFIG['bind_port']}"
    log_event("server_start", bind=bind_addr)

    # Drop privileges AFTER binding the socket
    if CONFIG["drop_privileges"]:
        drop_privileges(CONFIG["run_as_user"], CONFIG["run_as_group"], CONFIG["chroot_dir"])

    print(f"  [+] Listening on {bind_addr}")
    print(f"  [+] Profile: {CONFIG['profile']}")
    print(f"  [+] SSH banner: {CONFIG['ssh_banner']}")
    print(f"  [+] Host key: {CONFIG['host_key_type']} ({CONFIG['host_key_bits']} bit)")
    print(f"  [+] Logging to {CONFIG['log_file']}")
    if CONFIG["drop_privileges"]:
        print(f"  [+] Running as {CONFIG['run_as_user']}:{CONFIG['run_as_group']}")
    print()

    # Main accept loop — sequential (no threads) to avoid paramiko thread leak
    while _running:
        try:
            client, addr = _server_sock.accept()
        except socket.timeout:
            continue
        except OSError as exc:
            if not _running:
                break
            log_error("accept_error", error=str(exc))
            continue

        peer_ip = addr[0]
        if not conn_limiter.allow(peer_ip):
            log_event("connection_dropped", src_ip=peer_ip, reason="rate_limit")
            try:
                client.close()
            except OSError:
                pass
            continue

        handle_connection(client, addr, host_keys, auth_limiter)

    # Cleanup
    _running = False
    if _server_sock is not None:
        try:
            _server_sock.close()
        except OSError:
            pass

    log_event("server_stop")
    print("  [+] Honeypot stopped.")


if __name__ == "__main__":
    main()
