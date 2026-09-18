# Yuki Core

The server ("brain") of the Yuki ecosystem. A Python `asyncio` WebSocket server that authenticates
devices, routes commands, relays device-to-device messages, collects metrics, and serves the
real-time channel `yuki-webui`'s dashboard connects to.

## Requirements

Python 3.10+, dependencies pinned in `requirements.txt` (`websockets==16.0`, `psutil==7.2.2`).

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python core.py
```

By default it listens on `ws://0.0.0.0:8000`, with two paths: `/device` (for `yuki-humidifier`,
`yuki-device-pc`, `yuki-device-pc-linux`, `yuki-device-android`) and `/webui` (for `yuki-webui`'s
browser-side dashboard).

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `YUKI_AUTH_TOKEN` | (auto-generated) | Shared device auth token. If unset, a random 32-char token is generated on first run, saved to `.token` (mode 600), and rotated on the schedule below. |
| `YUKI_TOKEN_ROTATION_HOURS` | `24` | How often the auto-generated token rotates. Ignored if `YUKI_AUTH_TOKEN` is set. |
| `YUKI_DEBUG` | unset | When set, prints full tracebacks for unexpected connection errors instead of just logging a one-line message. |
| `YUKI_TLS_ENABLED` | unset | When truthy (`1`/`true`/`yes`), serves `wss://` instead of `ws://` - requires `YUKI_TLS_CERT`/`YUKI_TLS_KEY` too. |
| `YUKI_TLS_CERT` / `YUKI_TLS_KEY` | unset | PEM certificate/key paths used when `YUKI_TLS_ENABLED` is set. |

Encryption is **off by default** across the whole ecosystem; set the three `YUKI_TLS_*` variables
together to turn it on for the core↔device/webui link.

## Data files

All stored next to `core.py`: `yuki_core.db` (SQLite - known devices, authorization, blacklist,
metrics history, audit log), `.token`/`.token_meta` (current auth token + its creation time, mode
600), `logs/` (one log file per run).

## Device authorization

A device that presents a valid `auth_token` isn't automatically trusted - if it's not already in
the authorized-devices list, `yuki-core` asks connected `yuki-webui` clients to approve it
(`device_auth_request`/`device_auth_response`) before completing its handshake. Devices can also be
blacklisted, which rejects the connection outright regardless of token.

## Protocol

Speaks Yuki Protocol `yuki/1.0` via the vendored copy in `libs/yuki-protocol/python/` - see
[`yuki-protocol`](../yuki-protocol) for the message format itself.
