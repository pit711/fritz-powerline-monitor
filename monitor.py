#!/usr/bin/env python3
"""FRITZ!Powerline spectrum monitor — live mode + tiered archive.

Tiers:
  samples_live  — full resolution (default 3 s), kept ~25 h
  samples_arch  — 5-min buckets (min/avg/max), kept 30 d
Daily rollup (default 03:00) compresses live → arch and prunes both.

Usage:
  python3 monitor.py                  # collector + HTTP + SSE (auto-runs the
                                      # setup wizard if config.json is missing)
  python3 monitor.py --setup          # (re-)run the interactive setup wizard
  python3 monitor.py --once           # single fetch, print, exit
  python3 monitor.py --rollup         # run rollup once, exit

No external dependencies — Python 3.7+ stdlib + the system `ping` binary only.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import queue
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zlib
from array import array
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
SECRET_PATH = os.path.join(HERE, ".secret")
DB_PATH = os.path.join(HERE, "data.db")
DASHBOARD_HTML = os.path.join(HERE, "dashboard.html")

PASSWORD_SCHEME = "scrypt-hmac-sha256-v1"

DEFAULT_CONFIG = {
    "host": "fritz.powerline",          # IP or hostname of the FRITZ!Powerline adapter
    "password_enc": None,                # encrypted via setup wizard (see PASSWORD_SCHEME)
    "password_scheme": None,
    "local_mac": None,                   # auto-discovered if null
    "remote_mac": None,                  # auto-discovered if null
    "poll_seconds": 3,                   # FRITZ refreshes spectrum data every ~3 s
    "http_port": 8089,
    "bind_addr": "0.0.0.0",
    "live_retention_hours": 25,
    "arch_retention_days": 30,
    "arch_bucket_seconds": 300,          # 5-minute buckets in the archive tier
    "rollup_hour": 3,                    # daily rollup at 03:00 local time
    "granularity": 4,                    # carrier downsampling factor (matches AVM webui)
    "ping_target": None,                 # IP for periodic ICMP ping; null disables
    "ping_timeout_seconds": 2,
}


# ============================================================================
# Password encryption — stdlib-only (scrypt KDF + HMAC-SHA256 stream & tag)
# ============================================================================
# Key is bound to this machine via /etc/machine-id plus a per-install random
# salt (.secret, chmod 600). Leaking config.json without either machine-id or
# .secret does not reveal the password.

def _machine_id():
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p) as f:
                v = f.read().strip()
                if v:
                    return v
        except OSError:
            pass
    return socket.gethostname() or "fritz-powerline-monitor"


def _install_salt():
    if os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "rb") as f:
            data = f.read()
        if len(data) >= 16:
            return data
    salt = os.urandom(32)
    tmp = SECRET_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(salt)
    os.chmod(tmp, 0o600)
    os.rename(tmp, SECRET_PATH)
    return salt


def _derive_key():
    return hashlib.scrypt(
        _machine_id().encode("utf-8"),
        salt=_install_salt(),
        n=2 ** 14, r=8, p=1, dklen=32,
    )


def _keystream(key, nonce, length):
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out += hmac.new(key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return bytes(out[:length])


def encrypt_password(plaintext):
    pt = plaintext.encode("utf-8")
    key = _derive_key()
    nonce = os.urandom(16)
    ct = bytes(a ^ b for a, b in zip(pt, _keystream(key, nonce, len(pt))))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(nonce + ct + tag).decode("ascii")


def decrypt_password(token):
    raw = base64.b64decode(token)
    if len(raw) < 16 + 32:
        raise ValueError("ciphertext too short")
    nonce, ct, tag = raw[:16], raw[16:-32], raw[-32:]
    key = _derive_key()
    if not hmac.compare_digest(tag, hmac.new(key, nonce + ct, hashlib.sha256).digest()):
        raise ValueError("authentication failed — machine-id or .secret changed?")
    pt = bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct))))
    return pt.decode("utf-8")


_PING_RE = re.compile(r"time[=<]([\d.]+)\s*ms")

def ping_once(target, timeout=2):
    if not target:
        return None
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(timeout)), "-n", target],
            capture_output=True, timeout=timeout + 1, text=True,
        )
        if r.returncode != 0:
            return None
        m = _PING_RE.search(r.stdout)
        return float(m.group(1)) if m else None
    except Exception:
        return None


def log(tag, msg):
    print(f"{time.strftime('%H:%M:%S')} [{tag}] {msg}", flush=True)


SERVICE_START_TS = int(time.time())
APP_VERSION = "2.1"

# Amateur bands inside HomePlug 1.8–68 MHz (informational, mirrored in JS).
HAM_BANDS = [
    ("160m", 1.810, 2.000),
    ("80m",  3.500, 3.800),
    ("60m",  5.351, 5.366),
    ("40m",  7.000, 7.200),
    ("30m", 10.100, 10.150),
    ("20m", 14.000, 14.350),
    ("17m", 18.068, 18.168),
    ("15m", 21.000, 21.450),
    ("12m", 24.890, 24.990),
    ("10m", 28.000, 29.700),
    ("6m",  50.000, 52.000),
]


# ============================================================================
# FRITZ!Powerline API client
# ============================================================================

class FritzPlc:
    def __init__(self, host, password):
        self.host, self.password = host, password
        self.sid = None
        self._lock = threading.Lock()  # serialize calls (device dislikes concurrency)

    def _get(self, path):
        with urllib.request.urlopen(f"http://{self.host}{path}", timeout=15) as r:
            return r.read().decode()

    def _post(self, path, params):
        body = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(f"http://{self.host}{path}", data=body)
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode()

    def login(self):
        xml = self._get("/login_sid.lua?version=2")
        ch = re.search(r"<Challenge>([^<]+)", xml).group(1)
        block = int(re.search(r"<BlockTime>(\d+)", xml).group(1))
        if block:
            log("auth", f"BlockTime={block}s, waiting…")
            time.sleep(block + 1)
            xml = self._get("/login_sid.lua?version=2")
            ch = re.search(r"<Challenge>([^<]+)", xml).group(1)
        h = hashlib.md5((ch + "-" + self.password).encode("utf-16le")).hexdigest()
        xml = self._get(f"/login_sid.lua?version=2&response={ch}-{h}")
        sid = re.search(r"<SID>([^<]+)", xml).group(1)
        if sid == "0000000000000000":
            raise RuntimeError("login failed — wrong password?")
        self.sid = sid
        log("auth", f"logged in, sid={sid}")

    def cmd(self, params, retry=True):
        with self._lock:
            if not self.sid:
                self.login()
            params = dict(params, sid=self.sid)
            body = self._post("/net/plc_json.lua", params)
            if not body.strip():
                if retry:
                    self.sid = None
                    self.login()
                    params["sid"] = self.sid
                    body = self._post("/net/plc_json.lua", params)
                if not body.strip():
                    return None
            return json.loads(body)

    def list_adapters(self):
        return self.cmd({"Cmd": "ListAdapters"})

    def get_handle(self, local, remote):
        return self.cmd({
            "Cmd": "RequestDataHandle",
            "AdapterFrom": local, "AdapterTo": remote, "Coupling": "0",
        })

    def get_data(self, handle, granularity=4):
        return self.cmd({
            "Cmd": "RequestData",
            "HandleId": str(handle["HandleId"]),
            "ProcFunction": "7",
            "RxSlotMask": str(handle["RxSlotMask"]),
            "TxSlotMask": str(handle["TxSlotMask"]),
            "CarrierStart": "0",
            "CarrierCount": str(handle["CarrierCount"]),
            "Granularity": str(granularity),
            "UID": "1234",
            "Coupling": "0",
        })


# ============================================================================
# Schema + spectrum codec
# ============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples_live (
    ts INTEGER PRIMARY KEY,
    rx_phy INTEGER, tx_phy INTEGER,
    granularity INTEGER, carrier_count INTEGER,
    rx_slot_mask INTEGER, tx_slot_mask INTEGER,
    spectrum BLOB,
    ping_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_live_ts ON samples_live(ts);

CREATE TABLE IF NOT EXISTS samples_arch (
    ts INTEGER PRIMARY KEY,
    bucket_seconds INTEGER,
    n_samples INTEGER,
    rx_phy_avg REAL, rx_phy_min INTEGER, rx_phy_max INTEGER,
    tx_phy_avg REAL, tx_phy_min INTEGER, tx_phy_max INTEGER,
    granularity INTEGER, carrier_count INTEGER,
    rx_slot_mask INTEGER, tx_slot_mask INTEGER,
    spectrum BLOB,
    ping_ms_avg REAL, ping_ms_min REAL, ping_ms_max REAL
);
CREATE INDEX IF NOT EXISTS idx_arch_ts ON samples_arch(ts);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

# Columns added in later versions — applied by _migrate() if missing.
_MIGRATIONS = [
    ("samples_live", "ping_ms",     "REAL"),
    ("samples_arch", "ping_ms_avg", "REAL"),
    ("samples_arch", "ping_ms_min", "REAL"),
    ("samples_arch", "ping_ms_max", "REAL"),
]


def _migrate(conn):
    for table, col, typ in _MIGRATIONS:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if col not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
            log("db", f"migrated: added {table}.{col}")

# Spectrum BLOB = zlib( 6 layers × N carriers × uint16 LE )
# Layer order: rx_min, rx_max, rx_mean, tx_min, tx_max, tx_mean
LAYERS = ("rx_min", "rx_max", "rx_mean", "tx_min", "tx_max", "tx_mean")


def pack_spectrum(layers_dict, n):
    parts = []
    for name in LAYERS:
        arr = layers_dict.get(name)
        if arr is None:
            parts.append(b"\x00" * (n * 2))
        else:
            a = array("H", (max(0, min(65535, int(v))) for v in arr))
            if len(a) < n:
                a.extend([0] * (n - len(a)))
            parts.append(a[:n].tobytes())
    return zlib.compress(b"".join(parts), 6)


def unpack_spectrum(blob, n):
    raw = zlib.decompress(blob)
    out = {}
    for i, name in enumerate(LAYERS):
        a = array("H")
        a.frombytes(raw[i * n * 2:(i + 1) * n * 2])
        out[name] = list(a)
    return out


def db_connect():
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def slot_by_proc(carrier_data, proc):
    for s in carrier_data or []:
        if s.get("ProcFunction") == proc:
            return s["Carriers"]
    return None


def store_live(conn, ts, data, ping_ms=None):
    rx = data.get("RxCarrierData") or []
    tx = data.get("TxCarrierData") or []
    layers = {
        "rx_min": slot_by_proc(rx, 1),
        "rx_max": slot_by_proc(rx, 2),
        "rx_mean": slot_by_proc(rx, 4),
        "tx_min": slot_by_proc(tx, 1),
        "tx_max": slot_by_proc(tx, 2),
        "tx_mean": slot_by_proc(tx, 4),
    }
    # Array length is the meaningful "carrier bins shown"; CarrierCount is the device's
    # raw count which gets divided by Granularity when the device returns the arrays.
    n = max((len(v) for v in layers.values() if v), default=0)
    spec_blob = pack_spectrum(layers, n)
    conn.execute(
        "INSERT OR REPLACE INTO samples_live "
        "(ts, rx_phy, tx_phy, granularity, carrier_count, "
        "rx_slot_mask, tx_slot_mask, spectrum, ping_ms) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (
            ts,
            data.get("RxPhyRate"), data.get("TxPhyRate"),
            data.get("Granularity"), n,
            data.get("RxSlotMask"), data.get("TxSlotMask"),
            spec_blob, ping_ms,
        ),
    )
    return n, layers, spec_blob


# ============================================================================
# Live broadcaster (SSE)
# ============================================================================

class Broadcaster:
    def __init__(self):
        self._lock = threading.Lock()
        self._subs = []

    def subscribe(self):
        q = queue.Queue(maxsize=4)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            try:
                self._subs.remove(q)
            except ValueError:
                pass

    def publish(self, msg):
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    def count(self):
        with self._lock:
            return len(self._subs)


# ============================================================================
# Collector
# ============================================================================

def discover_adapters(fritz, cfg):
    adapters = fritz.list_adapters()
    if not adapters or "Adapters" not in adapters:
        raise RuntimeError("ListAdapters: no data")
    local = next((a for a in adapters["Adapters"] if a.get("isLocal") and a.get("active")), None)
    remote = next((a for a in adapters["Adapters"] if not a.get("isLocal") and a.get("active")), None)
    if not local or not remote:
        raise RuntimeError(f"need 1 local + 1 remote active; got: {adapters['Adapters']}")
    if not cfg.get("local_mac"):
        cfg["local_mac"] = local["mac"]
    if not cfg.get("remote_mac"):
        cfg["remote_mac"] = remote["mac"]
    log("disco", f"local={cfg['local_mac']} remote={cfg['remote_mac']} ({remote.get('usr','?')})")


def collector_loop(cfg, fritz, broadcaster):
    conn = db_connect()
    try:
        discover_adapters(fritz, cfg)
    except Exception as e:
        log("disco", f"error: {e} — will retry")

    interval = float(cfg.get("poll_seconds", 3))
    granularity = int(cfg.get("granularity", 4))
    ping_target = cfg.get("ping_target")
    ping_timeout = int(cfg.get("ping_timeout_seconds", 2))

    while True:
        t0 = time.time()
        ping_ms = None
        try:
            if not cfg.get("local_mac") or not cfg.get("remote_mac"):
                discover_adapters(fritz, cfg)
            handle = fritz.get_handle(cfg["local_mac"], cfg["remote_mac"])
            if not handle or handle.get("Status") != 0:
                raise RuntimeError(f"handle: {handle}")
            data = fritz.get_data(handle, granularity=granularity)
            if not data or data.get("Status") != 0:
                raise RuntimeError(f"data: {data}")

            if ping_target:
                ping_ms = ping_once(ping_target, timeout=ping_timeout)

            ts = int(time.time())
            n, layers, _ = store_live(conn, ts, data, ping_ms=ping_ms)

            # Push to SSE subscribers (small message — JSON arrays).
            if broadcaster.count() > 0:
                broadcaster.publish({
                    "type": "sample",
                    "ts": ts,
                    "rx_phy": data.get("RxPhyRate"),
                    "tx_phy": data.get("TxPhyRate"),
                    "ping_ms": ping_ms,
                    "granularity": data.get("Granularity"),
                    "carrier_count": n,
                    "rx_slot_mask": data.get("RxSlotMask"),
                    "tx_slot_mask": data.get("TxSlotMask"),
                    **layers,
                })
        except Exception as e:
            log("poll", f"error: {e}")
            fritz.sid = None
        elapsed = time.time() - t0
        time.sleep(max(0.5, interval - elapsed))


# ============================================================================
# Daily rollup: compress samples_live > 24h into 5-min buckets in samples_arch
# ============================================================================

def rollup(conn, cfg):
    bucket = int(cfg.get("arch_bucket_seconds", 300))
    live_retention_s = int(cfg.get("live_retention_hours", 25)) * 3600
    arch_retention_s = int(cfg.get("arch_retention_days", 30)) * 86400
    now = int(time.time())
    cutoff_live = now - live_retention_s

    # Group live samples older than retention into buckets
    rows = conn.execute(
        "SELECT ts, rx_phy, tx_phy, granularity, carrier_count, rx_slot_mask, tx_slot_mask, "
        "spectrum, ping_ms "
        "FROM samples_live WHERE ts < ? ORDER BY ts",
        (cutoff_live,),
    ).fetchall()

    if not rows:
        log("rollup", "no live samples to compress")
    else:
        buckets = {}
        for row in rows:
            bts = (row[0] // bucket) * bucket
            buckets.setdefault(bts, []).append(row)

        log("rollup", f"compressing {len(rows)} live samples into {len(buckets)} buckets")

        for bts, items in sorted(buckets.items()):
            # phy stats
            rx_vals = [r[1] for r in items if r[1] is not None]
            tx_vals = [r[2] for r in items if r[2] is not None]
            ping_vals = [r[8] for r in items if r[8] is not None]
            if not rx_vals and not tx_vals:
                continue
            rx_avg = sum(rx_vals) / len(rx_vals) if rx_vals else None
            tx_avg = sum(tx_vals) / len(tx_vals) if tx_vals else None
            ping_avg = sum(ping_vals) / len(ping_vals) if ping_vals else None
            ping_min = min(ping_vals) if ping_vals else None
            ping_max = max(ping_vals) if ping_vals else None

            # carrier aggregation
            n = items[-1][4] or 0
            granularity = items[-1][3]
            rx_mask = items[-1][5]
            tx_mask = items[-1][6]
            agg = {k: None for k in LAYERS}
            if n:
                rx_min_acc = [65535] * n
                rx_max_acc = [0] * n
                rx_sum = [0] * n; rx_cnt = 0
                tx_min_acc = [65535] * n
                tx_max_acc = [0] * n
                tx_sum = [0] * n; tx_cnt = 0
                for row in items:
                    if not row[7]:
                        continue
                    L = unpack_spectrum(row[7], n)
                    for i, v in enumerate(L["rx_min"]):
                        if v < rx_min_acc[i]: rx_min_acc[i] = v
                    for i, v in enumerate(L["rx_max"]):
                        if v > rx_max_acc[i]: rx_max_acc[i] = v
                    for i, v in enumerate(L["rx_mean"]):
                        rx_sum[i] += v
                    rx_cnt += 1
                    for i, v in enumerate(L["tx_min"]):
                        if v < tx_min_acc[i]: tx_min_acc[i] = v
                    for i, v in enumerate(L["tx_max"]):
                        if v > tx_max_acc[i]: tx_max_acc[i] = v
                    for i, v in enumerate(L["tx_mean"]):
                        tx_sum[i] += v
                    tx_cnt += 1
                agg["rx_min"] = rx_min_acc
                agg["rx_max"] = rx_max_acc
                agg["rx_mean"] = [s // max(1, rx_cnt) for s in rx_sum]
                agg["tx_min"] = tx_min_acc
                agg["tx_max"] = tx_max_acc
                agg["tx_mean"] = [s // max(1, tx_cnt) for s in tx_sum]

            spec_blob = pack_spectrum(agg, n)
            conn.execute(
                "INSERT OR REPLACE INTO samples_arch "
                "(ts, bucket_seconds, n_samples, "
                "rx_phy_avg, rx_phy_min, rx_phy_max, "
                "tx_phy_avg, tx_phy_min, tx_phy_max, "
                "granularity, carrier_count, rx_slot_mask, tx_slot_mask, spectrum, "
                "ping_ms_avg, ping_ms_min, ping_ms_max) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    bts, bucket, len(items),
                    rx_avg, min(rx_vals) if rx_vals else None, max(rx_vals) if rx_vals else None,
                    tx_avg, min(tx_vals) if tx_vals else None, max(tx_vals) if tx_vals else None,
                    granularity, n, rx_mask, tx_mask, spec_blob,
                    ping_avg, ping_min, ping_max,
                ),
            )

        conn.execute("DELETE FROM samples_live WHERE ts < ?", (cutoff_live,))
        conn.execute("VACUUM")

    # Prune archive
    cutoff_arch = now - arch_retention_s
    deleted = conn.execute("DELETE FROM samples_arch WHERE ts < ?", (cutoff_arch,)).rowcount
    if deleted:
        log("rollup", f"pruned {deleted} arch buckets older than {cfg.get('arch_retention_days')} d")

    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('last_rollup', ?)", (str(now),))


def rollup_scheduler(cfg):
    conn = db_connect()
    target_hour = int(cfg.get("rollup_hour", 3))
    while True:
        now = datetime.now()
        next_run = now.replace(hour=target_hour, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        sleep_s = (next_run - now).total_seconds()
        log("rollup", f"next run at {next_run.isoformat(timespec='seconds')} (in {int(sleep_s)}s)")
        time.sleep(sleep_s)
        try:
            rollup(conn, cfg)
        except Exception as e:
            log("rollup", f"error: {e}")


# ============================================================================
# HTTP / SSE server
# ============================================================================

# Display scaling matches AVM webui:  display_value = raw / Granularity / divider / 4  (dB)
#   divider = popcount(slot_mask) for mean; 1 for min/max
def popcount(n): return bin(n & 0xFFFFFFFF).count("1") or 1

def to_dB(raw, granularity, divider):
    return raw / float(granularity * divider * 4)


def fetch_range(conn, t_from, t_to, max_buckets=600):
    """Combine arch + live for [t_from, t_to], bucketed to ≤max_buckets cols.
    Returns dict suitable for JSON: phy series + spectrum heatmap (rx_mean, tx_mean)."""
    span = max(1, t_to - t_from)
    target_bucket = max(int(span // max_buckets), 3)

    # 1) Pull arch in range
    arch_rows = conn.execute(
        "SELECT ts, bucket_seconds, n_samples, rx_phy_avg, rx_phy_min, rx_phy_max, "
        "tx_phy_avg, tx_phy_min, tx_phy_max, granularity, carrier_count, "
        "rx_slot_mask, tx_slot_mask, spectrum, "
        "ping_ms_avg, ping_ms_min, ping_ms_max "
        "FROM samples_arch WHERE ts >= ? AND ts < ? ORDER BY ts",
        (t_from, t_to),
    ).fetchall()

    # 2) Pull live in range
    live_rows = conn.execute(
        "SELECT ts, rx_phy, tx_phy, granularity, carrier_count, rx_slot_mask, tx_slot_mask, "
        "spectrum, ping_ms "
        "FROM samples_live WHERE ts >= ? AND ts < ? ORDER BY ts",
        (t_from, t_to),
    ).fetchall()

    # Determine N (carrier count) and granularity from any row
    n, granularity = 0, 4
    rx_mask, tx_mask = 1, 1
    for r in arch_rows:
        n = r[10] or 0; granularity = r[9] or 4
        rx_mask = r[11] or rx_mask; tx_mask = r[12] or tx_mask
        break
    for r in live_rows:
        if not n:
            n = r[4] or 0; granularity = r[3] or 4
            rx_mask = r[5] or rx_mask; tx_mask = r[6] or tx_mask
        break
    if not n:
        return None

    rx_div = popcount(rx_mask); tx_div = popcount(tx_mask)
    sf_minmax = 1.0 / (granularity * 4)
    sf_rx_mean = 1.0 / (granularity * rx_div * 4)
    sf_tx_mean = 1.0 / (granularity * tx_div * 4)

    # Build per-bucket aggregator
    class Acc:
        __slots__ = ("rx_avg_n", "rx_avg_s", "rx_min", "rx_max",
                     "tx_avg_n", "tx_avg_s", "tx_min", "tx_max",
                     "ping_avg_n", "ping_avg_s", "ping_min", "ping_max",
                     "rx_mean_n", "rx_mean_s", "tx_mean_n", "tx_mean_s")
        def __init__(self):
            self.rx_avg_n = 0; self.rx_avg_s = 0.0
            self.rx_min = None; self.rx_max = None
            self.tx_avg_n = 0; self.tx_avg_s = 0.0
            self.tx_min = None; self.tx_max = None
            self.ping_avg_n = 0; self.ping_avg_s = 0.0
            self.ping_min = None; self.ping_max = None
            self.rx_mean_n = 0; self.rx_mean_s = None
            self.tx_mean_n = 0; self.tx_mean_s = None

    bk = {}

    def add_phy(b, rx, tx, w=1, rx_min=None, rx_max=None, tx_min=None, tx_max=None):
        a = bk.setdefault(b, Acc())
        if rx is not None:
            a.rx_avg_s += rx * w; a.rx_avg_n += w
            rmn = rx if rx_min is None else rx_min
            rmx = rx if rx_max is None else rx_max
            if a.rx_min is None or rmn < a.rx_min: a.rx_min = rmn
            if a.rx_max is None or rmx > a.rx_max: a.rx_max = rmx
        if tx is not None:
            a.tx_avg_s += tx * w; a.tx_avg_n += w
            tmn = tx if tx_min is None else tx_min
            tmx = tx if tx_max is None else tx_max
            if a.tx_min is None or tmn < a.tx_min: a.tx_min = tmn
            if a.tx_max is None or tmx > a.tx_max: a.tx_max = tmx

    def add_ping(b, p, w=1, pmin=None, pmax=None):
        if p is None:
            return
        a = bk.setdefault(b, Acc())
        a.ping_avg_s += p * w; a.ping_avg_n += w
        lo = p if pmin is None else pmin
        hi = p if pmax is None else pmax
        if a.ping_min is None or lo < a.ping_min: a.ping_min = lo
        if a.ping_max is None or hi > a.ping_max: a.ping_max = hi

    def add_spec(b, blob, n):
        if not blob:
            return
        L = unpack_spectrum(blob, n)
        a = bk.setdefault(b, Acc())
        if a.rx_mean_s is None:
            a.rx_mean_s = list(L["rx_mean"])
            a.rx_mean_n = 1
        else:
            for i, v in enumerate(L["rx_mean"]):
                a.rx_mean_s[i] += v
            a.rx_mean_n += 1
        if a.tx_mean_s is None:
            a.tx_mean_s = list(L["tx_mean"])
            a.tx_mean_n = 1
        else:
            for i, v in enumerate(L["tx_mean"]):
                a.tx_mean_s[i] += v
            a.tx_mean_n += 1

    # ingest arch
    for r in arch_rows:
        (ts, bs, ns, rxa, rxn, rxm, txa, txn, txm, _g, _n, _rm, _tm, blob,
         pa, pn, pm) = r
        b = (ts // target_bucket) * target_bucket
        # weight by n_samples so re-aggregation across larger buckets stays accurate
        w = max(1, ns or 1)
        add_phy(b, rxa, txa, w=w, rx_min=rxn, rx_max=rxm, tx_min=txn, tx_max=txm)
        add_spec(b, blob, _n)
        add_ping(b, pa, w=w, pmin=pn, pmax=pm)

    # ingest live (give precedence to live where overlap exists by adding regardless)
    for r in live_rows:
        ts, rx, tx, _g, _n, _rm, _tm, blob, ping = r
        b = (ts // target_bucket) * target_bucket
        add_phy(b, rx, tx, w=1)
        add_spec(b, blob, _n)
        add_ping(b, ping, w=1)

    if not bk:
        return None

    timestamps = sorted(bk.keys())
    phy = []
    rx_heat = []
    tx_heat = []
    for t in timestamps:
        a = bk[t]
        phy.append({
            "ts": t,
            "rx_avg": (a.rx_avg_s / a.rx_avg_n) if a.rx_avg_n else None,
            "rx_min": a.rx_min, "rx_max": a.rx_max,
            "tx_avg": (a.tx_avg_s / a.tx_avg_n) if a.tx_avg_n else None,
            "tx_min": a.tx_min, "tx_max": a.tx_max,
            "ping_avg": (a.ping_avg_s / a.ping_avg_n) if a.ping_avg_n else None,
            "ping_min": a.ping_min, "ping_max": a.ping_max,
        })
        if a.rx_mean_s:
            rx_heat.append([round(v / a.rx_mean_n * sf_rx_mean, 2) for v in a.rx_mean_s])
        else:
            rx_heat.append(None)
        if a.tx_mean_s:
            tx_heat.append([round(v / a.tx_mean_n * sf_tx_mean, 2) for v in a.tx_mean_s])
        else:
            tx_heat.append(None)

    return {
        "from": t_from, "to": t_to,
        "bucket_seconds": target_bucket,
        "carrier_count": n,
        "granularity": granularity,
        "freq_min_mhz": (0 * granularity + 74) / 40.96,
        "freq_max_mhz": ((n - 1) * granularity + 74) / 40.96,
        "phy": phy,
        "rx_heat": rx_heat,
        "tx_heat": tx_heat,
    }


class DeviceInfoCache:
    """Caches the (slow) FRITZ ListAdapters call."""
    def __init__(self, fritz):
        self.fritz = fritz
        self._data = None
        self._at = 0
        self._lock = threading.Lock()

    def get(self, ttl=300):
        with self._lock:
            if self._data and time.time() - self._at < ttl:
                return self._data
            try:
                d = self.fritz.list_adapters()
                if d and "Adapters" in d:
                    self._data = d["Adapters"]
                    self._at = time.time()
            except Exception as e:
                log("devinfo", f"refresh error: {e}")
            return self._data or []


def _stats(vals):
    if not vals:
        return {"avg": None, "min": None, "max": None, "n": 0}
    return {
        "avg": round(sum(vals) / len(vals), 2),
        "min": round(min(vals), 2),
        "max": round(max(vals), 2),
        "n": len(vals),
    }


def _window_stats(conn, since_ts):
    """Combined live + arch stats since a timestamp; returns rx, tx, ping dicts."""
    rx_vals, tx_vals, ping_vals = [], [], []
    for r in conn.execute(
        "SELECT rx_phy, tx_phy, ping_ms FROM samples_live WHERE ts >= ?", (since_ts,)
    ):
        if r[0] is not None: rx_vals.append(r[0])
        if r[1] is not None: tx_vals.append(r[1])
        if r[2] is not None: ping_vals.append(r[2])
    for r in conn.execute(
        "SELECT rx_phy_avg, tx_phy_avg, ping_ms_avg FROM samples_arch WHERE ts >= ?", (since_ts,)
    ):
        if r[0] is not None: rx_vals.append(r[0])
        if r[1] is not None: tx_vals.append(r[1])
        if r[2] is not None: ping_vals.append(r[2])
    return {"rx": _stats(rx_vals), "tx": _stats(tx_vals), "ping": _stats(ping_vals)}


def compute_insights(conn, cfg, devcache):
    now = int(time.time())

    # ---- Service ----
    last_rollup = conn.execute(
        "SELECT value FROM meta WHERE key='last_rollup'").fetchone()
    service = {
        "start_ts": SERVICE_START_TS,
        "uptime_seconds": now - SERVICE_START_TS,
        "version": APP_VERSION,
        "last_rollup_ts": int(last_rollup[0]) if last_rollup else None,
        "rollup_hour": cfg.get("rollup_hour"),
        "poll_seconds": cfg.get("poll_seconds"),
    }

    # ---- DB / storage ----
    live_n = conn.execute("SELECT COUNT(*), MIN(ts), MAX(ts) FROM samples_live").fetchone()
    arch_n = conn.execute("SELECT COUNT(*), MIN(ts), MAX(ts) FROM samples_arch").fetchone()
    db = {
        "size_bytes": os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0,
        "live_count": live_n[0], "live_from": live_n[1], "live_to": live_n[2],
        "arch_count": arch_n[0], "arch_from": arch_n[1], "arch_to": arch_n[2],
        "live_retention_hours": cfg.get("live_retention_hours"),
        "arch_retention_days": cfg.get("arch_retention_days"),
        "arch_bucket_seconds": cfg.get("arch_bucket_seconds"),
    }

    # ---- Device ----
    adapters = devcache.get() if devcache else []
    device = {
        "host": cfg.get("host"),
        "local_mac": cfg.get("local_mac"),
        "remote_mac": cfg.get("remote_mac"),
        "ping_target": cfg.get("ping_target"),
        "adapters": [
            {
                "mac": a.get("mac"),
                "model": a.get("usr"),
                "is_local": a.get("isLocal"),
                "status": a.get("status"),
                "coupling": a.get("couplingClass"),
                "remote_adapters": a.get("remoteAdapters"),
                "active": a.get("active"),
            } for a in adapters
        ],
    }

    # ---- Latest spectrum + computed signal stats ----
    spectrum = None
    notches = []
    row = conn.execute(
        "SELECT ts, rx_phy, tx_phy, granularity, carrier_count, "
        "rx_slot_mask, tx_slot_mask, spectrum, ping_ms "
        "FROM samples_live ORDER BY ts DESC LIMIT 1").fetchone()
    if row:
        ts, rx_phy, tx_phy, g, n, rxm, txm, blob, ping_ms = row
        L = unpack_spectrum(blob, n) if blob else None
        if L and n:
            rx_div = popcount(rxm or 1)
            tx_div = popcount(txm or 1)
            sf_minmax = 1.0 / (g * 4)
            sf_rx_mean = 1.0 / (g * rx_div * 4)
            sf_tx_mean = 1.0 / (g * tx_div * 4)

            rx_max = L["rx_max"]; rx_mean = L["rx_mean"]
            tx_max = L["tx_max"]; tx_mean = L["tx_mean"]

            def freq(i): return (i * g + 74) / 40.96

            active_rx_idx = [i for i in range(n) if rx_max[i] > 0]
            active_tx_idx = [i for i in range(n) if tx_max[i] > 0]
            notched_rx_idx = [i for i in range(n) if rx_max[i] == 0]

            rx_mean_db = [rx_mean[i] * sf_rx_mean for i in active_rx_idx]
            tx_mean_db = [tx_mean[i] * sf_tx_mean for i in active_tx_idx]

            best_rx = max(active_rx_idx, key=lambda i: rx_mean[i]) if active_rx_idx else None
            worst_rx = min(active_rx_idx, key=lambda i: rx_mean[i]) if active_rx_idx else None

            def pct(arr, p):
                if not arr: return None
                arr = sorted(arr)
                return arr[min(len(arr) - 1, int(p / 100 * len(arr)))]

            spectrum = {
                "ts": ts,
                "rx_phy": rx_phy, "tx_phy": tx_phy, "ping_ms": ping_ms,
                "carrier_count": n,
                "freq_min_mhz": round(freq(0), 2),
                "freq_max_mhz": round(freq(n - 1), 2),
                "carrier_step_khz": round(g * 1000 / 40.96, 2),
                "rx_slot_mask": rxm, "tx_slot_mask": txm,
                "rx_slots_active": popcount(rxm or 0),
                "tx_slots_active": popcount(txm or 0),
                "active_carriers_rx": len(active_rx_idx),
                "active_carriers_tx": len(active_tx_idx),
                "notched_carriers_rx": len(notched_rx_idx),
                "rx_mean_snr_db": round(sum(rx_mean_db) / len(rx_mean_db), 2) if rx_mean_db else None,
                "rx_p50_snr_db": round(pct(rx_mean_db, 50), 2) if rx_mean_db else None,
                "rx_p95_snr_db": round(pct(rx_mean_db, 95), 2) if rx_mean_db else None,
                "tx_mean_snr_db": round(sum(tx_mean_db) / len(tx_mean_db), 2) if tx_mean_db else None,
                "best_rx_carrier": {
                    "freq_mhz": round(freq(best_rx), 2),
                    "snr_db": round(rx_mean[best_rx] * sf_rx_mean, 2),
                } if best_rx is not None else None,
                "worst_rx_carrier": {
                    "freq_mhz": round(freq(worst_rx), 2),
                    "snr_db": round(rx_mean[worst_rx] * sf_rx_mean, 2),
                } if worst_rx is not None else None,
                "spectral_efficiency_mbps_per_mhz":
                    round(rx_phy / max(0.1, freq(n - 1) - freq(0)), 2)
                    if rx_phy is not None else None,
            }

            # Notch detection per amateur band
            for name, lo, hi in HAM_BANDS:
                idxs = [i for i in range(n) if lo <= freq(i) <= hi]
                if not idxs:
                    continue
                rx_zero = sum(1 for i in idxs if rx_max[i] == 0)
                tx_zero = sum(1 for i in idxs if tx_max[i] == 0)
                notches.append({
                    "band": name, "lo_mhz": lo, "hi_mhz": hi,
                    "carriers_in_band": len(idxs),
                    "rx_notched_pct": round(100 * rx_zero / len(idxs), 1),
                    "tx_notched_pct": round(100 * tx_zero / len(idxs), 1),
                })

    # ---- Time-window stats ----
    windows = {
        "5m": now - 5 * 60,
        "1h": now - 3600,
        "24h": now - 86400,
        "7d": now - 7 * 86400,
        "30d": now - 30 * 86400,
    }
    window_stats = {label: _window_stats(conn, since) for label, since in windows.items()}

    return {
        "service": service,
        "device": device,
        "spectrum": spectrum,
        "notches": notches,
        "rates": {k: v["rx"] for k, v in window_stats.items()},
        "tx_rates": {k: v["tx"] for k, v in window_stats.items()},
        "ping": {k: v["ping"] for k, v in window_stats.items()},
        "db": db,
    }


def fetch_snapshot(conn, ts):
    """Get nearest live (or arch) sample to ts; return min/avg/max layers."""
    row = conn.execute(
        "SELECT ts, rx_phy, tx_phy, granularity, carrier_count, "
        "rx_slot_mask, tx_slot_mask, spectrum, ping_ms FROM samples_live "
        "ORDER BY ABS(ts - ?) LIMIT 1", (ts,),
    ).fetchone()
    src = "live"
    if not row:
        row = conn.execute(
            "SELECT ts, rx_phy_avg, tx_phy_avg, granularity, carrier_count, "
            "rx_slot_mask, tx_slot_mask, spectrum, ping_ms_avg FROM samples_arch "
            "ORDER BY ABS(ts - ?) LIMIT 1", (ts,),
        ).fetchone()
        src = "arch"
    if not row:
        return None
    ts_, rx_phy, tx_phy, g, n, rxm, txm, blob, ping_ms = row
    L = unpack_spectrum(blob, n) if blob else {k: None for k in LAYERS}
    return {
        "source": src, "ts": ts_,
        "rx_phy": rx_phy, "tx_phy": tx_phy, "ping_ms": ping_ms,
        "granularity": g, "carrier_count": n,
        "rx_slot_mask": rxm, "tx_slot_mask": txm,
        **L,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "FritzPlcMonitor/2.0"

    def log_message(self, *a, **k): pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra.items(): self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)

        try:
            if u.path in ("/", "/index.html"):
                with open(DASHBOARD_HTML, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")

            if u.path == "/api/info":
                cfg = self.server.cfg
                return self._send(200, {
                    "host": cfg.get("host"),
                    "local_mac": cfg.get("local_mac"),
                    "remote_mac": cfg.get("remote_mac"),
                    "poll_seconds": cfg.get("poll_seconds"),
                    "live_retention_hours": cfg.get("live_retention_hours"),
                    "arch_retention_days": cfg.get("arch_retention_days"),
                    "arch_bucket_seconds": cfg.get("arch_bucket_seconds"),
                    "rollup_hour": cfg.get("rollup_hour"),
                    "ping_target": cfg.get("ping_target"),
                })

            if u.path == "/api/latest":
                conn = db_connect()
                cur = conn.execute(
                    "SELECT ts, rx_phy, tx_phy, granularity, carrier_count, "
                    "rx_slot_mask, tx_slot_mask, spectrum, ping_ms "
                    "FROM samples_live ORDER BY ts DESC LIMIT 1")
                row = cur.fetchone()
                if not row:
                    return self._send(200, {"error": "Noch keine Messung."})
                ts, rx_phy, tx_phy, g, n, rxm, txm, blob, ping_ms = row
                L = unpack_spectrum(blob, n) if blob else {k: None for k in LAYERS}
                return self._send(200, {
                    "ts": ts, "rx_phy": rx_phy, "tx_phy": tx_phy, "ping_ms": ping_ms,
                    "granularity": g, "carrier_count": n,
                    "rx_slot_mask": rxm, "tx_slot_mask": txm,
                    **L,
                })

            if u.path == "/api/range":
                t_to = int(q.get("to", [int(time.time())])[0])
                t_from = int(q.get("from", [t_to - 3600])[0])
                max_b = int(q.get("max_buckets", [600])[0])
                max_b = max(20, min(max_b, 2000))
                include_spectrum = q.get("include_spectrum", ["1"])[0] != "0"
                conn = db_connect()
                res = fetch_range(conn, t_from, t_to, max_buckets=max_b)
                if not res:
                    return self._send(200, {"empty": True, "from": t_from, "to": t_to})
                if not include_spectrum:
                    res.pop("rx_heat", None)
                    res.pop("tx_heat", None)
                return self._send(200, res)

            if u.path == "/api/snapshot":
                ts = int(q.get("ts", [int(time.time())])[0])
                conn = db_connect()
                res = fetch_snapshot(conn, ts)
                if not res:
                    return self._send(404, {"error": "no data"})
                return self._send(200, res)

            if u.path == "/api/insights":
                conn = db_connect()
                return self._send(200, compute_insights(
                    conn, self.server.cfg, self.server.devcache))

            if u.path == "/api/stats":
                conn = db_connect()
                live_n = conn.execute("SELECT COUNT(*), MIN(ts), MAX(ts) FROM samples_live").fetchone()
                arch_n = conn.execute("SELECT COUNT(*), MIN(ts), MAX(ts) FROM samples_arch").fetchone()
                size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
                last_rollup = conn.execute(
                    "SELECT value FROM meta WHERE key='last_rollup'").fetchone()
                return self._send(200, {
                    "live": {"count": live_n[0], "from": live_n[1], "to": live_n[2]},
                    "arch": {"count": arch_n[0], "from": arch_n[1], "to": arch_n[2]},
                    "db_size_bytes": size,
                    "last_rollup_ts": int(last_rollup[0]) if last_rollup else None,
                    "sse_subs": self.server.broadcaster.count(),
                })

            if u.path == "/api/live":
                # SSE stream
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache, no-store")
                self.send_header("X-Accel-Buffering", "no")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                bc = self.server.broadcaster
                qsub = bc.subscribe()
                # send a hello + the most recent sample so the client paints immediately
                try:
                    self.wfile.write(b": connected\n\n")
                    self.wfile.flush()
                    # initial latest
                    conn = db_connect()
                    cur = conn.execute(
                        "SELECT ts, rx_phy, tx_phy, granularity, carrier_count, "
                        "rx_slot_mask, tx_slot_mask, spectrum, ping_ms "
                        "FROM samples_live ORDER BY ts DESC LIMIT 1")
                    row = cur.fetchone()
                    if row:
                        ts, rx_phy, tx_phy, g, n, rxm, txm, blob, ping_ms = row
                        L = unpack_spectrum(blob, n) if blob else {k: None for k in LAYERS}
                        init = {"type": "sample", "ts": ts, "rx_phy": rx_phy, "tx_phy": tx_phy,
                                "ping_ms": ping_ms,
                                "granularity": g, "carrier_count": n,
                                "rx_slot_mask": rxm, "tx_slot_mask": txm, **L}
                        self.wfile.write(b"data: " + json.dumps(init).encode() + b"\n\n")
                        self.wfile.flush()
                    while True:
                        try:
                            msg = qsub.get(timeout=20)
                            self.wfile.write(b"data: " + json.dumps(msg).encode() + b"\n\n")
                            self.wfile.flush()
                        except queue.Empty:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    bc.unsubscribe(qsub)
                return

            return self._send(404, {"error": "not found"})

        except Exception as e:
            log("http", f"500 on {u.path}: {e}")
            return self._send(500, {"error": str(e)})


class ThreadingServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(cfg, broadcaster, devcache):
    addr = (cfg.get("bind_addr", "0.0.0.0"), int(cfg.get("http_port", 8089)))
    srv = ThreadingServer(addr, Handler)
    srv.cfg = cfg
    srv.broadcaster = broadcaster
    srv.devcache = devcache
    log("http", f"listening on http://{addr[0]}:{addr[1]}/")
    srv.serve_forever()


# ============================================================================
# Setup wizard + config loading
# ============================================================================

def _prompt(label, default=None, allow_empty=False):
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        val = input(f"  {label}{suffix}: ").strip()
        if not val and default is not None:
            return default
        if val or allow_empty:
            return val
        print("    (Pflichtfeld)")


def _yes(val):
    return val.strip().lower() in ("y", "yes", "j", "ja", "")


def _is_fritz_host(host, timeout=2):
    """Return True if `host` answers with an AVM login_sid.lua challenge."""
    try:
        req = urllib.request.Request(f"http://{host}/login_sid.lua?version=2")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2048).decode("utf-8", "ignore")
            return "<Challenge>" in body and "<BlockTime>" in body
    except Exception:
        return False


def _discover_fritz_hosts():
    """Probe common AVM hostnames — fritz.powerline first, then fritz.box."""
    hits = []
    for name in ("fritz.powerline", "fritz.box"):
        print(f"    … probiere {name}")
        if _is_fritz_host(name):
            hits.append(name)
            print(f"      ✓ antwortet als FRITZ-Gerät")
        else:
            print(f"      – keine Antwort")
    return hits


def _arp_neighbors():
    """Return IPv4 neighbors from `ip neigh` (REACHABLE/STALE/DELAY)."""
    try:
        r = subprocess.run(["ip", "-4", "neigh"],
                           capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return []
        out = []
        for line in r.stdout.splitlines():
            parts = line.split()
            if not parts or parts[0].count(".") != 3:
                continue
            if "FAILED" in line or "INCOMPLETE" in line:
                continue
            out.append(parts[0])
        return out
    except Exception:
        return []


def _pick(label, items, fmt, default_idx=0):
    """Numbered picker; single-item lists return immediately."""
    if len(items) == 1:
        print(f"    → {fmt(items[0])}")
        return items[0]
    print(f"  {label}:")
    for i, it in enumerate(items, 1):
        marker = "→" if i - 1 == default_idx else " "
        print(f"    {marker} [{i}] {fmt(it)}")
    while True:
        val = input(f"  Auswahl [1-{len(items)}, Enter={default_idx + 1}]: ").strip()
        if not val:
            return items[default_idx]
        try:
            idx = int(val) - 1
            if 0 <= idx < len(items):
                return items[idx]
        except ValueError:
            pass
        print("    (ungültig)")


def setup_wizard():
    """Interactive first-run setup. Validates against the device, then writes config.json."""
    if not sys.stdin.isatty():
        sys.exit(f"{CONFIG_PATH} nicht gefunden und kein TTY — "
                 f"bitte python3 monitor.py --setup auf einer interaktiven Shell aufrufen.")

    print()
    print("==============================================================")
    print(" FRITZ!Powerline Monitor — Setup")
    print("==============================================================")
    print()
    if os.path.exists(CONFIG_PATH):
        print(f"  Bestehende Konfiguration in {CONFIG_PATH} wird überschrieben.")
        if not _yes(_prompt("Fortfahren? (yes/no)", default="no")):
            sys.exit("abgebrochen.")
        print()

    # ---- 1) Host discovery ----
    print(" 1) FRITZ!Powerline-Gerät suchen")
    hits = _discover_fritz_hosts()
    print()
    if hits:
        host = _pick("Gefundene Geräte", hits, lambda h: h)
        override = _prompt("Anderen Host verwenden? (leer = übernehmen)",
                           default="", allow_empty=True)
        if override:
            host = override
    else:
        print("  ⚠ nichts automatisch gefunden — bitte manuell eingeben.")
        host = _prompt("Host/IP", default="fritz.powerline")
    print()

    # ---- 2) Password (visible) ----
    print(" 2) Passwort")
    print("    Hinweis: wird während der Eingabe im Klartext angezeigt, damit du")
    print("    Tippfehler sofort siehst. Gespeichert wird nur verschlüsselt.")
    password = _prompt("FRITZ!Powerline Passwort")
    print()

    # ---- 3) Login ----
    print(f" 3) Verbinde mit {host} …")
    fritz = FritzPlc(host, password)
    try:
        fritz.login()
    except Exception as e:
        sys.exit(f"    ✗ Login fehlgeschlagen: {e}")
    print("    ✓ Login OK")
    print()

    # ---- 4) Adapter picker ----
    print(" 4) Adapter erkennen")
    try:
        adapters = (fritz.list_adapters() or {}).get("Adapters", [])
    except Exception as e:
        sys.exit(f"    ✗ ListAdapters fehlgeschlagen: {e}")

    locals_ = [a for a in adapters if a.get("isLocal") and a.get("active")]
    remotes = [a for a in adapters if not a.get("isLocal") and a.get("active")]
    inactive = [a for a in adapters if not a.get("active")]
    if not locals_:
        sys.exit("    ✗ kein aktiver lokaler Adapter gefunden.")

    def fmt_adapter(a):
        return (f"{a.get('mac')}  {(a.get('usr') or '?'):<14}  "
                f"status={a.get('status','?')}  coupling={a.get('couplingClass','?')}")

    print()
    print("  Lokal:")
    local = _pick("Lokale Adapter", locals_, fmt_adapter)
    print()
    if remotes:
        print("  Remote:")
        remote = _pick("Remote-Adapter", remotes, fmt_adapter)
    else:
        remote = None
        print("  ⚠ kein aktiver Remote-Adapter — Spektrum bleibt leer, bis du")
        print("    einen zweiten FRITZ!Powerline per Pairing-Taste koppelst.")
    if inactive:
        print(f"  (ignoriert: {len(inactive)} inaktive Adapter)")
    print()

    # ---- 5) Optional settings ----
    print(" 5) Optionale Einstellungen (Enter = Standard)")
    port = _prompt("HTTP-Port für das Dashboard", default="8089")
    print()

    print("  Ping-Ziel (IP hinter dem Remote-Adapter, misst die Powerline-Latenz).")
    neighbors = _arp_neighbors()
    if neighbors:
        print("  ARP-Nachbarn auf diesem Host:")
        for n in neighbors[:12]:
            print(f"    • {n}")
    ping_target = _prompt("Ping-Ziel (leer = deaktiviert)",
                          default="", allow_empty=True) or None
    print()

    # ---- 6) Summary + confirm ----
    print(" 6) Zusammenfassung")
    print(f"    Host:          {host}")
    print(f"    Passwort:      {password}   ← wird gleich verschlüsselt")
    print(f"    Lokal-MAC:     {local.get('mac')}")
    print(f"    Remote-MAC:    {remote.get('mac') if remote else '—'}")
    print(f"    HTTP-Port:     {port}")
    print(f"    Ping-Ziel:     {ping_target or '—'}")
    print()
    if not _yes(_prompt("Speichern? (yes/no)", default="yes")):
        sys.exit("abgebrochen.")

    cfg = dict(DEFAULT_CONFIG)
    cfg.update({
        "host": host,
        "password_enc": encrypt_password(password),
        "password_scheme": PASSWORD_SCHEME,
        "http_port": int(port),
        "ping_target": ping_target,
        "local_mac": local.get("mac"),
        "remote_mac": remote.get("mac") if remote else None,
    })

    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.rename(tmp, CONFIG_PATH)

    print()
    print(f"  ✓ {CONFIG_PATH} gespeichert (chmod 600, Passwort verschlüsselt)")
    print(f"  ✓ {SECRET_PATH} enthält den Maschinen-Salt (chmod 600, niemals in Git committen)")
    print()
    print(" Nächste Schritte:")
    print("    • Test im Vordergrund:          python3 monitor.py")
    print("    • Als Dienst installieren:      siehe README.md  →  systemd")
    print(f"    • Dashboard öffnen:             http://<dieser-host>:{port}/")
    print()


def load_config():
    with open(CONFIG_PATH) as f:
        raw = json.load(f)
    cfg = {**DEFAULT_CONFIG, **raw}
    if "password" in raw:
        sys.exit(
            "config: Klartext-Feld 'password' wird nicht mehr unterstützt — "
            "bitte python3 monitor.py --setup neu ausführen (hard cutover zu 'password_enc')."
        )
    enc = cfg.get("password_enc")
    if not enc:
        sys.exit("config: 'password_enc' fehlt — bitte python3 monitor.py --setup ausführen.")
    try:
        cfg["password"] = decrypt_password(enc)
    except Exception as e:
        sys.exit(f"config: Passwort konnte nicht entschlüsselt werden ({e}) — "
                 f"ggf. .secret verloren? Dann python3 monitor.py --setup erneut ausführen.")
    return cfg


# ============================================================================
# main
# ============================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--setup",  action="store_true", help="(re-)run interactive setup wizard")
    ap.add_argument("--once",   action="store_true", help="single fetch, print, exit")
    ap.add_argument("--rollup", action="store_true", help="run rollup once, exit")
    args = ap.parse_args()

    if args.setup or not os.path.exists(CONFIG_PATH):
        setup_wizard()
        if args.setup:
            return

    cfg = load_config()

    if args.rollup:
        conn = db_connect()
        rollup(conn, cfg)
        return

    fritz = FritzPlc(cfg["host"], cfg["password"])
    if args.once:
        fritz.login()
        adapters = fritz.list_adapters()
        print(json.dumps(adapters, indent=2))
        local = cfg.get("local_mac") or next(a["mac"] for a in adapters["Adapters"] if a.get("isLocal"))
        remote = cfg.get("remote_mac") or next(a["mac"] for a in adapters["Adapters"] if not a.get("isLocal"))
        h = fritz.get_handle(local, remote)
        d = fritz.get_data(h, granularity=int(cfg.get("granularity", 4)))
        print(f"PhyRate Rx={d.get('RxPhyRate')} Tx={d.get('TxPhyRate')} "
              f"carriers={d.get('CarrierCount')} g={d.get('Granularity')}")
        return

    db_connect()  # ensure schema
    broadcaster = Broadcaster()
    devcache = DeviceInfoCache(fritz)
    threading.Thread(target=collector_loop, args=(cfg, fritz, broadcaster), daemon=True).start()
    threading.Thread(target=rollup_scheduler, args=(cfg,), daemon=True).start()
    try:
        serve(cfg, broadcaster, devcache)
    except KeyboardInterrupt:
        log("main", "shutting down")


if __name__ == "__main__":
    main()
