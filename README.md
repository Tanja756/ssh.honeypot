# SSH Honeypot

A production-ready SSH honeypot that captures attacker credentials in isolation. Always rejects authentication — no valid credentials exist on the system.

## Features

- **Credential capture** — logs every login/password pair with source IP, port, auth method, and client version
- **OS emulation** — 14 built-in profiles (Ubuntu, Debian, CentOS, FreeBSD, Alpine, Arch, openSUSE) with realistic SSH banners and host key types
- **Security-first** — privilege dropping, chroot jail, resource limits, TCP keepalive, rate limiting per source IP
- **No shell access** — all channel, shell, PTY, and exec requests are rejected
- **Connection rate limiting** — max connections per IP per time window
- **Auth rate limiting** — max authentication attempts per IP per time window (separate from connection limit)
- **Log rotation** — automatic gzip compression (configurable size, keeps N archives)
- **Field truncation** — long usernames/passwords are truncated to prevent log inflation
- **Graceful shutdown** — drains active connections on SIGINT / SIGTERM
- **Structured logging** — JSON format for easy ingestion into SIEM / ELK / Splunk
- **Log analyser** — bundled `honeypot_stats.py` for quick statistics
- **Docker support** — Dockerfile included

## Quick start

```bash
pip install -r requirements.txt
python3 ssh_honeypot.py
```

## Usage

```
python3 ssh_honeypot.py [options]

  --profile NAME       OS profile (default: ubuntu-22.04)
  --list-profiles      List available OS profiles
  --port PORT          Listening port (default: 2222)
  --bind HOST          Bind address (default: 0.0.0.0)
  --banner BANNER      Custom SSH banner string
  --key PATH           Host key file path
  --drop-privs         Drop root privileges after bind (requires root)
  --user USER          Unprivileged user (default: nobody)
  --group GROUP        Unprivileged group (default: nogroup)
  --log FILE           Log file path (default: honeypot.log)
  --config PATH        Config file path (default: honeypot.yaml)
```

### Examples

```bash
# Emulate an Ubuntu 24.04 server
python3 ssh_honeypot.py --profile ubuntu-24.04

# Emulate Debian 12 on a non-standard port
python3 ssh_honeypot.py --profile debian-12 --port 2222

# Run as root with privilege dropping
sudo python3 ssh_honeypot.py --port 22 --drop-privs

# Custom banner and key type
python3 ssh_honeypot.py --banner "SSH-2.0-OpenSSH_8.0" --key-type ed25519
```

## Configuration

All settings in `honeypot.yaml`. CLI flags override the config file.

### Network

| Key | Default | Description |
|-----|---------|-------------|
| `bind_host` | `0.0.0.0` | Listening address |
| `bind_port` | `2222` | Listening port |
| `backlog` | `100` | TCP listen backlog |

### Timeouts

| Key | Default | Description |
|-----|---------|-------------|
| `connection_timeout` | `60.0` | Socket timeout (seconds) |
| `auth_timeout` | `30.0` | Max time to wait for auth (seconds) |

### Rate limiting (per source IP)

| Key | Default | Description |
|-----|---------|-------------|
| `rate_window` | `60` | Time window (seconds) for connection limit |
| `rate_max_conn` | `5` | Max TCP connections per window |
| `auth_rate_window` | `60` | Time window (seconds) for auth attempt limit |
| `auth_rate_max_attempts` | `10` | Max auth attempts per window per IP |

### Logging

| Key | Default | Description |
|-----|---------|-------------|
| `log_file` | `honeypot.log` | Log file path |
| `log_json` | `true` | Output JSON format |
| `log_max_size` | `104857600` | Max bytes before rotation (100 MB) |
| `log_max_backups` | `2` | Number of compressed archives to keep |
| `log_max_field_len` | `256` | Truncate username/password to this length |

### Security (requires root)

| Key | Default | Description |
|-----|---------|-------------|
| `drop_privileges` | `false` | Drop root after bind |
| `run_as_user` | `nobody` | Unprivileged user |
| `run_as_group` | `nogroup` | Unprivileged group |
| `chroot_dir` | `/var/empty` | Chroot jail directory |

### Host key

| Key | Default | Description |
|-----|---------|-------------|
| `host_key_path` | `ssh_host_key` | Path to host key (auto-generated if missing) |

## Log format

```json
{"timestamp": "2026-07-05T00:00:00", "event": "auth_attempt", "src_ip": "10.0.0.1", "username": "root", "password": "admin123", "auth_method": "password"}
```

### Events

| Event | Description |
|-------|-------------|
| `auth_attempt` | Authentication attempt logged |
| `auth_rate_limited` | Auth attempt dropped due to rate limit |
| `connection_dropped` | Connection rejected (rate limit) |
| `connection_timeout` | Socket timeout |
| `channel_request` | Channel open request |
| `exec_request` | Command execution request (rejected) |
| `server_start` / `server_stop` | Server lifecycle |
| `shutdown` | Signal received |
| `host_key_*` | Host key events |
| `config_*` | Configuration events |
| `privilege_*` | Privilege operations |

## Log analyser

```bash
python3 honeypot_stats.py honeypot.log
```

Outputs top IPs, top passwords, top credential pairs, and daily statistics.

## Profiles

Available via `--list-profiles` or in `banners.py`:
`ubuntu-20.04`, `ubuntu-22.04`, `ubuntu-24.04`, `debian-11`, `debian-12`, `centos-7`, `centos-8`, `centos-9`, `freebsd-13`, `freebsd-14`, `alpine-3.20`, `opensuse-15`, `arch-2024`, `custom`

## Systemd

```bash
cp ssh-honeypot.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ssh-honeypot
```

## Docker

```bash
docker build -t ssh-honeypot .
docker run -d -p 2222:2222 --name honeypot ssh-honeypot
```

To persist logs:

```bash
docker run -d -p 2222:2222 -v $(pwd)/logs:/opt/ssh-honeypot --name honeypot ssh-honeypot
```

## Security

- The honeypot **never** grants shell access
- All authentication is rejected (`AUTH_FAILED`)
- Connection and auth rate limiting prevent resource exhaustion
- Privilege dropping, chroot, and capability bounding isolate the process
- Resource limits cap file descriptors, processes, and memory
- No system commands are ever executed
