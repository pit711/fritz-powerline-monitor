# FRITZ!Powerline Monitor

Real-time spectrum + link quality monitor for AVM **FRITZ!Powerline** HomePlug AV2 adapters, with a self-contained web dashboard.

Polls the adapter's hidden `/net/plc_json.lua` endpoint to read the per-carrier SNR (the same data shown in the official AVM webui's "Powerline-Spektrum" view), aggregates it into a tiered SQLite store, and renders an SDR-style waterfall + line charts in the browser.

## Features

- **Live mode** — spectrum + SDR-style waterfall + PHY rate + ICMP ping, pushed to the browser via Server-Sent Events.
- **Tag / Woche / Monat archive views** with phy/ping time series and a frequency × time waterfall heatmap. Click anywhere in the waterfall to load the spectrum snapshot at that moment.
- **Tiered storage** — full-resolution samples for the last ~25 h, then 5-minute buckets for 30 days. Daily rollup keeps total DB size under ~40 MB.
- **Compact spectrum codec** — uint16 + zlib, ~960 B per sample (vs. ~10 KB JSON).
- **Amateur-radio band overlay** — 160 m … 6 m bands labelled in every spectrum view, makes the regulatory notches visible at a glance.
- **Info tab** with adapter details, SNR statistics, time-window aggregates, notch detection, and a primer on how HomePlug AV2 works.
- **Setup wizard** prompts for IP/password and validates against the device on first run.

No build step, no JS framework, no external Python dependencies — just `python3` and the system `ping` binary.

## Tested with

- FRITZ!Powerline **540E** (local, with WiFi/repeater) ↔ **510E** (remote)
- FRITZ!OS 07.15 on the powerline adapter
- Python 3.10 / Linux

The protocol should also work on the 1240E / 1260E / 546E and similar HomePlug AV2 models from AVM, but is untested.

## Quick start

```bash
git clone https://github.com/<you>/fritz-powerline-monitor.git
cd fritz-powerline-monitor
python3 monitor.py            # launches the setup wizard on first run
```

The wizard asks for the powerline adapter's IP/hostname and password, validates the login, auto-discovers the local + remote MAC addresses, and writes `config.json` (chmod 600).

After setup, the same command starts the collector and the dashboard:

    Open http://<this-host>:8089/

## Install as a systemd service

```bash
sudo cp fritz-powerline.service /etc/systemd/system/
# adjust WorkingDirectory / ExecStart paths in the unit file if you cloned elsewhere
sudo systemctl daemon-reload
sudo systemctl enable --now fritz-powerline
journalctl -u fritz-powerline -f
```

## Usage

```
python3 monitor.py            # collector + HTTP server (uses config.json)
python3 monitor.py --setup    # re-run the interactive setup wizard
python3 monitor.py --once     # single API fetch, print summary, exit
python3 monitor.py --rollup   # force one rollup pass and exit
```

## Configuration

Edit `config.json` and `systemctl restart fritz-powerline` to apply.

| Key | Default | Notes |
|---|---|---|
| `host` | `fritz.powerline` | IP or hostname of the **powerline adapter** (not the FRITZ!Box) |
| `password` | — | Powerline adapter password (or the FRITZ!Box password, if paired) |
| `poll_seconds` | `3` | The chip refreshes spectrum data ~every 3 s; faster polling gets duplicates |
| `http_port` | `8089` | LAN-exposed dashboard port |
| `live_retention_hours` | `25` | How long to keep full-resolution samples before rollup |
| `arch_retention_days` | `30` | Archive retention; older buckets are pruned by the daily rollup |
| `arch_bucket_seconds` | `300` | Archive bucket size (5 min) |
| `rollup_hour` | `3` | Local hour at which the daily rollup runs |
| `granularity` | `4` | Carrier downsampling factor passed to the chip; 4 matches the AVM webui |
| `ping_target` | `null` | IP for ICMP RTT measurement. Set to a host **behind the remote adapter** to measure the powerline link itself; `null` disables ping entirely |
| `ping_timeout_seconds` | `2` | Per-ping wait timeout |

## API

| Endpoint | Purpose |
|---|---|
| `GET /` | Dashboard HTML |
| `GET /api/info` | Static config (host, MACs, retention, ping target) |
| `GET /api/stats` | DB size, sample counts, last rollup, SSE subscribers |
| `GET /api/latest` | Most recent live sample (full spectrum, scaled in dB by the client) |
| `GET /api/range?from=&to=&max_buckets=&include_spectrum=0` | Bucketed phy + ping series; spectrum heatmap arrays optional |
| `GET /api/snapshot?ts=` | Nearest spectrum sample to the given timestamp |
| `GET /api/insights` | Adapter list, signal stats, time-window aggregates, notch detection |
| `GET /api/live` | **SSE** stream — one event per new sample (~3 s cadence), keep-alive every 20 s |

## Security notes

- `config.json` contains the powerline password in plaintext. The setup wizard sets `chmod 600`; if you create it manually, do the same.
- The HTTP server binds `0.0.0.0` by default — anyone on your LAN can read the dashboard. Set `bind_addr` to `127.0.0.1` if you want to restrict it and reverse-proxy with auth.
- ICMP ping requires either root or `CAP_NET_RAW` on the `ping` binary.

## How it works

See [CLAUDE.md](./CLAUDE.md) for a pointed architecture brief: the spectrum codec, SNR scaling formula, frequency mapping, and the live-vs-arch read merge. It's written for AI coding assistants but humans benefit too.

In short: HomePlug AV2 is OFDM over the AC mains in 1.8–67 MHz with adaptive bit-loading per carrier. The chip exposes per-carrier SNR (Min/Max/Mean across 6 AC-synchronous time slots) and a target carrier count. Each FRITZ poll yields ~672 carrier values per direction × 3 statistics; we re-scale them to dB the same way the AVM webui does and visualise the result.
