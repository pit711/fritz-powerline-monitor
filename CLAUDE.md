# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A self-contained service that polls a FRITZ!Powerline adapter, records its OFDM spectrum + PHY rates + ICMP ping over time, and serves a real-time dashboard. Two source files (`monitor.py`, `dashboard.html`), Python 3.7+ stdlib only — **no dependencies, no build step**.

## First-time setup

`python3 monitor.py` auto-runs an interactive setup wizard if `config.json` is missing. The wizard prompts for IP/password, validates against the device, auto-discovers the local + remote MAC, and writes `config.json` with chmod 600.

To re-run the wizard explicitly: `python3 monitor.py --setup`.

## Service management

A systemd unit template ships in `fritz-powerline.service` (install to `/etc/systemd/system/`). After editing `monitor.py` or `config.json`, restart via systemd:

```
systemctl restart fritz-powerline           # apply changes
systemctl status fritz-powerline            # health
journalctl -u fritz-powerline -f            # tail logs
```

Editing `dashboard.html` does **not** need a restart — the file is served fresh on every request. Browser reload picks it up.

## Direct invocations (debugging)

```
python3 monitor.py            # foreground: collector + HTTP + SSE
python3 monitor.py --setup    # (re-)run interactive setup
python3 monitor.py --once     # single fetch via FRITZ API, print, exit
python3 monitor.py --rollup   # force one rollup pass and exit
```

`--once` is the right tool for diagnosing FRITZ-side problems (auth, adapter discovery, response shape) without touching the DB. To exercise the rollup against fresh data, temporarily set `live_retention_hours: 0` in `config.json` and run `--rollup`.

## Quick API checks

```
curl -s http://127.0.0.1:8089/api/stats     | jq
curl -s http://127.0.0.1:8089/api/latest    | jq
curl -s http://127.0.0.1:8089/api/insights  | jq
curl -sN http://127.0.0.1:8089/api/live     | head -c 800   # SSE stream
```

## Architecture

### One file, layered top-to-bottom

`monitor.py` is structured as discrete sections in this order:

1. **`FritzPlc`** — auth + JSON-RPC-style client. MD5 challenge-response on `/login_sid.lua?version=2` (UTF-16LE encoded; older AVM firmwares such as 07.15 do not support PBKDF2). Three-step spectrum read: `ListAdapters` → `RequestDataHandle` → `RequestData`. A `_lock` serializes calls because the device times out under concurrent requests.
2. **Schema + spectrum codec** — `samples_live` and `samples_arch` tables, `pack_spectrum`/`unpack_spectrum` (uint16 LE × 6 layers, zlib-compressed → ~960 B/sample vs. ~10 KB JSON).
3. **`Broadcaster`** — thread-safe SSE fan-out, one `queue.Queue` per subscriber, drops on full.
4. **Collector loop** — runs every `poll_seconds` (3 s default), pings `ping_target`, writes one row, publishes to broadcaster.
5. **`rollup()` + `rollup_scheduler()`** — daily at `rollup_hour` (03:00). Aggregates `samples_live` rows older than `live_retention_hours` into 5-min buckets in `samples_arch`, prunes arch beyond `arch_retention_days`, then `VACUUM`s.
6. **`compute_insights()` / `fetch_range()` / `fetch_snapshot()`** — read paths. `fetch_range` merges live + arch into one bucketed view.
7. **HTTP `Handler`** — routes; `/api/live` is the long-lived SSE stream that loops on the subscriber's queue with 20 s keepalive pings.
8. **`setup_wizard()`** — interactive first-run config, requires a TTY.

### Data semantics — read these before changing anything spectrum-related

- **Carrier array length is `ceil(CarrierCount / Granularity)`**, NOT `CarrierCount`. The device reports `CarrierCount=2690` but the arrays are downsampled to ~672 elements when `Granularity=4`. We store the array length in `carrier_count`. Confusing this leads to 4× larger BLOBs full of trailing zeros.
- **`ProcFunction` codes**: `1=min`, `2=max`, `4=mean`. (Easy to misread `2` as "average".)
- **SNR scaling matches the AVM web UI**: `dB = raw / Granularity / divider / 4`, where `divider = popcount(slot_mask)` for `mean`, and `divider = 1` for `min`/`max`. Implemented in JS as `scaleArr()` and on the server in `compute_insights`.
- **Frequency mapping**: `MHz = (carrier_idx * Granularity + 74) / 40.96`. So with `g=4` the spectrum runs ~1.81–67.79 MHz.
- **Slot masks** are 6-bit fields representing 6 time slots per AC half-cycle. The chip enables/disables them adaptively and the divider math above depends on the popcount.

### Storage tiers

| Table | Cadence | Retention | Spectrum stored as |
|---|---|---|---|
| `samples_live` | `poll_seconds` (3 s) | `live_retention_hours` (25) | per-sample BLOB |
| `samples_arch` | `arch_bucket_seconds` (300) | `arch_retention_days` (30) | per-bucket BLOB (min-of-min, max-of-max, avg-of-mean) |

DB grows to ~36 MB total (28 MB live + 8 MB arch) at defaults.

### Schema migrations

Add new columns by appending to the `_MIGRATIONS` list — `_migrate()` runs `ALTER TABLE ADD COLUMN` if missing on every `db_connect()`. Don't drop the DB to add columns.

### Dashboard

`dashboard.html` is one self-contained file: vanilla JS, `<canvas>` rendering throughout, no libs, no CDN. Five tabs (`live`, `day`, `week`, `month`, `info`); the three archive tabs share one `<section data-tab="archive">` and call `loadArchive(name)` with different time spans.

Key client-side details:
- **Live waterfall** uses two offscreen canvases (one per direction). New rows are pushed via `drawImage(self, …)` to shift the existing image down 1 px, then `putImageData` for the new top row — the standard SDR waterfall trick.
- **Archive heatmap** (Tag/Woche/Monat) is also a waterfall (X=freq, Y=time, newest on top), built into a `tmp` canvas at native resolution then `drawImage`-scaled.
- **Pre-fill on load**: `prefillLiveBuffers()` fetches `/api/range?include_spectrum=0` for the last 24 h to populate the rate/ping buffers immediately. `prefillWaterfall()` fetches the last 20 min with spectrum data to seed the waterfall canvas.
- **Live stream**: `EventSource('/api/live')`. SSE samples are deduped against the prefill (same `ts` not pushed twice).

## Configuration

`config.json` (chmod 600 — contains the FRITZ password). All keys have defaults in `DEFAULT_CONFIG`. Notable knobs:

- `host`, `password` — FRITZ powerline adapter (NOT the FRITZ!Box).
- `local_mac` / `remote_mac` — auto-discovered from `ListAdapters` if `null`.
- `ping_target` — IP to ICMP ping each cycle. Set to a host *behind the remote adapter* so the round-trip traverses the powerline link. `null` disables ping.
- `granularity` — passed to `RequestData`. `4` matches the AVM UI default.

## Gotchas worth remembering

- **Don't ever poll the FRITZ from a second client while the daemon is running** — the device only handles one request at a time and will time out. Stop the service first if you need to test against the device manually.
- **Login lockout**: wrong password triggers exponential `BlockTime` (2 → 4 → 7 → … seconds). The client honours it, but if you've been spamming bad attempts, give the device a minute before retrying.
- **`RxSlotMask` / `TxSlotMask` change over time** as the chip adapts. The `divider` for SNR scaling must be derived per sample, not cached.
- **Amateur-band "notches"** (160 m, 80 m, 40 m, …) appear as carriers with `rx_max == 0`. This is regulatory (BNetzA / EN 50561-1), not a measurement error. The dashboard overlays these bands as yellow stripes via `HAM_BANDS` (defined identically in both `monitor.py` and `dashboard.html`).
