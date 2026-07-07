#!/usr/bin/env python3
"""Test all honeypot functionality end-to-end."""

import sys
import json
import socket
import time
import paramiko

HOST = "127.0.0.1"
PORT = 2223
LOG = "honeypot.log"

tests_passed = 0
tests_failed = 0

def log_size():
    with open(LOG) as f:
        return len([l for l in f if l.strip()])

def get_entries():
    with open(LOG) as f:
        return [json.loads(l) for l in f if l.strip()]

def check(label, condition, detail=""):
    global tests_passed, tests_failed
    if condition:
        tests_passed += 1
        print(f"  [PASS] {label}")
    else:
        tests_failed += 1
        print(f"  [FAIL] {label}  {detail}")

# ── 1. Basic connection ─────────────────────────────────────
print("\n=== 1. Basic connection (auth_method=none) ===")
time.sleep(1)
before = log_size()
try:
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    t = paramiko.Transport(sock)
    t.connect()
    time.sleep(0.5)
    try:
        t.auth_none("testuser")
    except paramiko.AuthenticationException:
        pass
    t.close()
except Exception as e:
    print(f"  Connection error: {e}")

entries = get_entries()
auth_none = [e for e in entries if e.get("auth_method") == "none"]
check("auth_method=none logged", len(auth_none) >= 1)
if auth_none:
    e = auth_none[0]
    check("session_id present in event", "session_id" in e and e["session_id"])
    check("attack_id = session_id", e.get("attack_id") == e.get("session_id"))
    check("src_ip present", "src_ip" in e and e["src_ip"] == "127.0.0.1")
    check("username present", "username" in e)
    check("client_version present", "client_version" in e)

# ── 2. Password auth attempt ────────────────────────────────
print("\n=== 2. Password auth attempt ===")

def try_auth(password, username="test"):
    try:
        sock = socket.socket()
        sock.settimeout(10)
        sock.connect((HOST, PORT))
        t = paramiko.Transport(sock)
        t.connect()
        try:
            t.auth_password(username, password)
        except paramiko.AuthenticationException:
            pass
        t.close()
    except Exception as e:
        print(f"  Error: {e}")

try_auth("testpass123")
time.sleep(1)

entries = get_entries()
auth_pw = [e for e in entries if e.get("auth_method") == "password"]
check("auth_method=password logged", len(auth_pw) >= 1)
if auth_pw:
    e = auth_pw[0]
    check("password field present", "password" in e and e["password"] == "testpass123")
    check("session_id in password auth", "session_id" in e)
    check("attack_id in password auth", "attack_id" in e)

# ── 3. Publickey auth attempt ───────────────────────────────
print("\n=== 3. Publickey auth attempt ===")
time.sleep(1)
key = paramiko.RSAKey.generate(2048)
try:
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    t = paramiko.Transport(sock)
    t.connect()
    try:
        t.auth_publickey("root", key)
    except paramiko.AuthenticationException:
        pass
    t.close()
except Exception as e:
    print(f"  Error: {e}")

entries = get_entries()
auth_pk = [e for e in entries if e.get("auth_method") == "publickey"]
check("auth_method=publickey logged", len(auth_pk) >= 1)
if auth_pk:
    e = auth_pk[0]
    check("fingerprint in publickey auth", "fingerprint" in e and e["fingerprint"])
    check("password=<public_key> in log", "password" in e and e["password"] == "<public_key>")

# ── 4. Keyboard-interactive auth attempt ────────────────────
print("\n=== 4. Keyboard-interactive auth attempt ===")
time.sleep(1)
try:
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    t = paramiko.Transport(sock)
    t.connect()
    try:
        t.auth_interactive("admin", lambda t, p, p2: ["adminpass"])
    except paramiko.AuthenticationException:
        pass
    t.close()
except Exception as e:
    print(f"  Error: {e}")

entries = get_entries()
auth_ki = [e for e in entries if e.get("auth_method") == "keyboard-interactive"]
check("auth_method=keyboard-interactive logged", len(auth_ki) >= 1)
if auth_ki:
    e = auth_ki[0]
    check("password in keyboard-interactive", "password" in e and e["password"] == "adminpass")
    check("username=admin in log", e.get("username") == "admin")

# ── 5. Rate limiting (rapid connections) ────────────────────
print("\n=== 5. Rate limiting ===")
dropped_before = len([e for e in get_entries() if e.get("event") == "connection_dropped" and e.get("reason") == "rate_limit"])

# Connect faster than rate limit allows
for i in range(8):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((HOST, PORT))
        t = paramiko.Transport(sock)
        t.connect()
        t.close()
    except:
        pass
    time.sleep(0.5)

entries = get_entries()
dropped_after = len([e for e in entries if e.get("event") == "connection_dropped" and e.get("reason") == "rate_limit"])
check("rate limiting drops connections", dropped_after > dropped_before,
      f"dropped events: {dropped_before} -> {dropped_after}")

# ── 6. Session ID unique per connection ─────────────────────
print("\n=== 6. Session ID uniqueness ===")
entries = get_entries()
auth_events = [e for e in entries if e.get("event") == "auth_attempt" and "session_id" in e]
if auth_events:
    sids = set(e["session_id"] for e in auth_events)
    check(f"multiple unique session_ids ({len(sids)} unique)",
          len(sids) >= 2)
    # Check that auth events within the same session share attack_id
    from collections import Counter
    sid_counts = Counter(e["session_id"] for e in auth_events)
    multi = [sid for sid, cnt in sid_counts.items() if cnt >= 2]
    if multi:
        s = multi[0]
        same_sid = [e for e in auth_events if e["session_id"] == s]
        aids = set(e["attack_id"] for e in same_sid)
        check(f"shared attack_id in same session (sid={s[:8]}...)",
              len(aids) == 1 and list(aids)[0] == s)

# ── 7. Connection timeout ───────────────────────────────────
print("\n=== 7. Connection timeout ===")
# This is harder to test without a real timeout; just check if any exist
entries = get_entries()
timeouts = [e for e in entries if e.get("event") == "connection_timeout"]
check("connection_timeout has session_id",
      all("session_id" in e for e in timeouts) if timeouts else True)

# ── 8. Dashboard accessible ─────────────────────────────────
print("\n=== 8. Dashboard ===")
try:
    import urllib.request
    resp = urllib.request.urlopen("http://127.0.0.1:1235/", timeout=5)
    html = resp.read().decode()
    check("dashboard responds 200", resp.status == 200)
    check("dashboard has stats section", "stats" in html.lower() or "Events" in html or "Honeypot" in html)
    # Check API endpoints
    stats = urllib.request.urlopen("http://127.0.0.1:1235/api/stats", timeout=3)
    stat_data = json.loads(stats.read().decode())
    check("/api/stats returns JSON", isinstance(stat_data, dict))
    check("/api/stats has total_attempts", "total_attempts" in stat_data)
    timeline = urllib.request.urlopen("http://127.0.0.1:1235/api/timeline", timeout=3)
    t_data = json.loads(timeline.read().decode())
    check("/api/timeline returns list", isinstance(t_data, list))
except Exception as e:
    check(f"dashboard test failed: {e}", False)

# ── Summary ─────────────────────────────────────────────────
print("\n" + "=" * 50)
print(f"TESTS: {tests_passed} passed, {tests_failed} failed")
if tests_failed == 0:
    print("ALL TESTS PASSED")
else:
    print(f"SOME TESTS FAILED ({tests_failed})")
    sys.exit(1)
