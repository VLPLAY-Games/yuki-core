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
| `YUKI_AUTH_TOKEN` | (auto-generated) | Shared device auth token, admin-managed - core never rotates it. Takes priority over everything below. |
| `CREDENTIALS_DIRECTORY` | unset | Set by systemd's `LoadCredential=yuki_auth_token:/path/to/file` - if present, the token is read from `$CREDENTIALS_DIRECTORY/yuki_auth_token` instead of the `.token` file. Also admin-managed/never rotated. Preferred over the plaintext file for systemd deployments. |
| `YUKI_TOKEN_ROTATION_HOURS` | `24` | How often the auto-generated token rotates (a background task checks every 5 minutes and rotates once this elapses). Has no effect when the token comes from `YUKI_AUTH_TOKEN`/`CREDENTIALS_DIRECTORY`. |
| `YUKI_TOKEN_GRACE_MINUTES` | `30` | After a rotation (automatic or admin-triggered), the previous token stays valid for this long, so a device that was offline at the moment of rotation isn't locked out before it notices the `token_update` push. |
| `YUKI_DEBUG` | unset | When set, prints full tracebacks for unexpected connection errors instead of just logging a one-line message. |
| `YUKI_TLS_ENABLED` | unset | When truthy (`1`/`true`/`yes`), serves `wss://` instead of `ws://` - requires `YUKI_TLS_CERT`/`YUKI_TLS_KEY` too. If set without both of those, the server refuses to start (`RuntimeError`) rather than silently falling back to plaintext. |
| `YUKI_TLS_CERT` / `YUKI_TLS_KEY` | unset | PEM certificate/key paths used when `YUKI_TLS_ENABLED` is set. |
| `YUKI_WEBUI_ALLOWED_ORIGINS` | `http(s)://localhost:5000`, `http(s)://127.0.0.1:5000` | Comma-separated list of `Origin` headers accepted on the `/webui` socket. A browser page from any other origin is rejected before it can authenticate; non-browser clients that send no `Origin` header at all (scripts, CLI tools) are unaffected. Override this if `yuki-webui` is bound to a different host/port. |

Encryption is **off by default** across the whole ecosystem; set the three `YUKI_TLS_*` variables
together to turn it on for the core↔device/webui link.

## Authentication

Two device handshakes are supported on `/device`, both driven by the `hello` message:

- **Legacy** (still the default for every existing client): the device sends its `auth_token`
  directly inside `hello`. Simple, but the token is on the wire - only safe with TLS on, or on a
  network you fully trust.
- **Challenge-response** (opt-in per device, no server config needed): the device sends `hello`
  with a `nonce_c` field and no token at all; core replies with `challenge{nonce_s}`; the device
  answers with `auth{hmac}` where `hmac = HMAC-SHA256(token, "{nonce_c}:{nonce_s}")`. The token
  itself never crosses the network, even over plain `ws://`. A device is free to use this instead
  of the legacy flow at any time - core picks the method based on whether `hello` has `nonce_c`.

Either way, a valid token isn't enough on its own: a device new to `yuki-core` is held pending until
an admin approves it from `yuki-webui` (`device_auth_request`/`device_auth_response`), and devices
can be blacklisted outright regardless of token.

`/webui` uses its own single-token handshake (`{"type":"auth","token":...}` as the first message,
answered with `{"type":"auth_ok"}`) plus the `Origin` check above - `yuki-webui`'s Flask backend
fetches the current token for the logged-in admin via its own `GET /api/core-token` and forwards it.

Rate limiting applies both per source IP (on the handshake itself, before any device_id is trusted -
stops one IP from brute-forcing many different device_ids, each of which would otherwise get its
own fresh quota) and per device_id (on commands, after the handshake).

## Data files

All stored next to `core.py`: `yuki_core.db` (SQLite, WAL mode - known devices, authorization,
blacklist, metrics history, audit log; never holds the shared auth token), `.token`/`.token_meta`
(current auth token + its creation time, mode 600, used only when no env var/systemd credential is
set), `logs/` (one log file per run).

## Protocol

Speaks Yuki Protocol `yuki/1.0` via the `libs/yuki-protocol` git submodule
([VLPLAY-Games/yuki-protocol](https://github.com/VLPLAY-Games/yuki-protocol)) - see
[`yuki-protocol`](../yuki-protocol) for the message format itself, including `challenge`/`auth`.

## License

GNU General Public License v3.0 (GPLv3), same as the rest of the Yuki ecosystem - see
[yuki-system](https://github.com/VLPLAY-Games/yuki-system) for details.
