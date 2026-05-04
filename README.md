# tunneld

Self-hosted HTTP reverse-tunnel server. Public requests to a random
four-word subdomain are routed over a websocket to a client process running
next to your local service. Single binary, single bearer token, no
license fees.

```
public user → https://flower-geek-episode-thirst.tunnel.le.ht
                                  │
                                  ▼
                        traefik (TLS terminate)
                                  │
                                  ▼
                          tunneld server  ◄── ws ─── tunneld client ── http://127.0.0.1:3000
```

## Get started

On the machine that hosts the service you want to expose:

```sh
# install the client (Linux/macOS, x86_64 or aarch64)
curl -fsSL https://tunnel.le.ht/install | sh

# expose a local service
TUNNELD_SECRET=<token> tunneld client --local 127.0.0.1:3000
# →  https://flower-geek-episode-thirst.tunnel.le.ht
```

The subdomain is generated server-side from a 13 679-word list (≥ 10 240
per position, ≥ 10¹⁶ unique combinations). It can't be chosen.

Windows: download `tunneld-windows-x86_64.exe` from
`https://tunnel.le.ht/dl/`.

## Client flags

| flag / env var | default | description |
|---|---|---|
| `--url` / `TUNNELD_URL` | `https://tunnel.le.ht` | server base URL |
| `--secret` / `TUNNELD_SECRET` | *required* | bearer token |
| `--local` | *required* | local upstream, e.g. `127.0.0.1:3000` |

## REST API

```sh
# create — returns subdomain, tunnel_id, ws_url
curl -X POST https://tunnel.le.ht/api/tunnels \
  -H "Authorization: Bearer $TUNNELD_SECRET"

# list active tunnels
curl https://tunnel.le.ht/api/tunnels \
  -H "Authorization: Bearer $TUNNELD_SECRET"

# revoke
curl -X DELETE https://tunnel.le.ht/api/tunnels/<id> \
  -H "Authorization: Bearer $TUNNELD_SECRET"
```

The websocket data plane lives at `/ws/<id>`; the client establishes it
automatically after `POST /api/tunnels`.

## Server

| flag / env var | default | description |
|---|---|---|
| `--bind` / `TUNNELD_BIND` | `0.0.0.0:8080` | listen address |
| `--secret` / `TUNNELD_SECRET` | *required, ≥16 chars* | bearer token |
| `--domain` / `TUNNELD_DOMAIN` | `tunnel.le.ht` | apex; `*.<domain>` is proxied |
| `--public-base` / `TUNNELD_PUBLIC_BASE` | `https://tunnel.le.ht` | URL clients see in API responses |
| `--dist-dir` / `TUNNELD_DIST_DIR` | `/dist` | binaries served at `/dl/` |

Routes:

| path | host | purpose |
|---|---|---|
| `/api/tunnels` | apex | REST control plane |
| `/ws/:id` | apex | websocket data plane |
| `/health` | any | liveness |
| `/install` | apex | shell installer |
| `/dl/*` | apex | static binaries |
| `/*` | `<sub>.<domain>` | proxied to that tunnel's client |

## Build from source

```sh
cargo build --release
./target/release/tunneld --help
```

## Architecture

Each public HTTP request is given a `request_id` and serialised onto the
single websocket as a sequence of binary frames:

```
[type:u8][request_id:u32 BE][payload...]
```

Frame types: `ReqHead` (JSON), `ReqBody`, `ReqEnd`, `RespHead`, `RespBody`,
`RespEnd`, `Cancel`. Multiplexing N concurrent requests over one ws is the
whole trick — no per-request connections, no separate ports.

Limits, deliberately:

- One client per tunnel (second ws upgrade returns 409).
- A tunnel only exists while its client's ws is live; on disconnect the
  record is dropped and the subdomain freed.
- No reconnect grace, no client retry, no metrics endpoint yet.
