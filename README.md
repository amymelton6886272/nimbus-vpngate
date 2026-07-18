# Nimbus VPNGate Hub

Nimbus VPNGate Hub is a multi-region VPNGate gateway stack. It runs one VPN manager per region, exposes an HTTP/SOCKS5 proxy for each region, and provides a central Hub page for unified monitoring and operations.

Current regions:

- `JP` Japan
- `US` United States
- `KR` Korea
- `RU` Russia
- `VN` Vietnam
- `OTHER` all available nodes except JP/US/KR/RU/VN

## Features

- Docker Compose based multi-container deployment.
- Central Hub dashboard on port `8788`.
- Per-region proxy ports and per-region management ports.
- Region filtering so each container only shows its own country/region nodes.
- `OTHER` region excludes the dedicated fixed regions.
- Best-node connection prefers residential/mobile nodes first, then falls back to hosting nodes.
- Built-in health checks, log rotation, and runtime resource display.
- Public `/healthz` only returns minimal health state; detailed health is available through authenticated Hub API proxy.
- Hub Basic Auth with `.htpasswd`, kept out of Git.

## Quick Start

Requirements:

- Linux host with Docker and Docker Compose
- `/dev/net/tun` enabled
- root or equivalent permission for Docker and TUN

Clone and enter the project:

```bash
git clone git@github.com:nimbus-vpngate.git
cd nimbus-vpngate
```

Create Hub Basic Auth credentials:

```bash
mkdir -p hub
htpasswd -nbB admin '<strong-password>' > hub/.htpasswd
```

If `htpasswd` is not installed:

```bash
apt-get update
apt-get install -y apache2-utils
```

Start the stack:

```bash
docker compose up -d --build
```

Open the Hub:

```text
http://<server-ip>:8788/
```

## Ports

| Region | Container | Proxy | Region UI |
| --- | --- | ---: | ---: |
| JP | `nimbus-jp` | `20001` | `21001` |
| US | `nimbus-us` | `20002` | `21002` |
| KR | `nimbus-kr` | `20003` | `21003` |
| RU | `nimbus-ru` | `20004` | `21004` |
| VN | `nimbus-vn` | `20005` | `21005` |
| OTHER | `nimbus-other` | `20006` | `21006` |
| Hub | `nimbus-hub` | - | `8788` |

Proxy URLs:

```text
socks5://<server-ip>:20001  # JP
socks5://<server-ip>:20002  # US
socks5://<server-ip>:20003  # KR
socks5://<server-ip>:20004  # RU
socks5://<server-ip>:20005  # VN
socks5://<server-ip>:20006  # OTHER
```

The proxy listener accepts both HTTP and SOCKS5 style clients through the same exposed proxy port.

## Hub Operations

The Hub can:

- refresh all region states
- connect the best node in each region
- disconnect all regions
- test proxy exits
- open each region's native management UI
- show current active node, IP type, exit IP, memory usage, uptime, and node counts

Best-node policy:

1. Prefer `residential` and `mobile`.
2. If no residential/mobile node is available, use `hosting`.
3. Within the same type group, prefer lower latency and then higher score.

## Configuration

Main configuration lives in `docker-compose.yml`.

Important environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TARGET_VALID_NODES` | `1` | Minimum target valid nodes per scan |
| `MAX_SCAN_ROWS` | `40` | Max VPNGate rows to scan |
| `OPENVPN_TEST_TIMEOUT_SECONDS` | `12` | OpenVPN test timeout |
| `MIN_NODE_SPEED` | `0` | Disable minimum speed filter by default |
| `MAX_NODE_LATENCY_MS` | `0` | Disable hard latency filter by default |
| `MAX_NODE_SESSIONS` | `0` | Disable session-count filter by default |
| `ROUTING_MODE` | per service | `fixed_region` or `auto` |
| `FORCE_COUNTRY` | per service | Fixed country code for region containers |
| `EXCLUDE_COUNTRIES` | OTHER only | Countries excluded from OTHER |
| `HUB_API_TOKEN` | compose value | Internal Hub-to-node API token |

Region metadata for the Hub lives in:

```text
hub/regions.json
```

When adding or changing regions, update both `docker-compose.yml` and `hub/regions.json`, then run:

```bash
python3 scripts/validate_regions.py
```

## Security Notes

- Do not commit `hub/.htpasswd`; it is ignored by `.gitignore`.
- `hub/.htpasswd.example` is only a placeholder.
- The Hub is protected by Basic Auth.
- Node APIs are accessed through the Hub using `X-Nimbus-Hub-Token`.
- Public `/healthz` is intentionally minimal and does not expose detailed runtime data.
- If exposing proxy ports to the internet, restrict access with a firewall or cloud security group.

Recommended firewall example:

```bash
ufw allow 8788/tcp
ufw allow 20001:20006/tcp
ufw deny 21001:21006/tcp
```

The `21001-21006` region UI ports are useful for direct troubleshooting, but they should not be public unless you understand the risk.

## Maintenance

Show status:

```bash
docker compose ps
```

Follow logs:

```bash
docker compose logs -f nimbus-hub
docker compose logs -f nimbus-jp
```

Rebuild after code changes:

```bash
docker compose up -d --build
```

Restart only the Hub:

```bash
docker compose up -d --no-deps --force-recreate nimbus-hub
```

Validate region wiring:

```bash
python3 scripts/validate_regions.py
```

Check a node container health endpoint:

```bash
curl -fsS http://127.0.0.1:21001/healthz
```

Check detailed health through Hub:

```bash
curl -fsS -u admin:'<password>' http://127.0.0.1:8788/api/jp/health
```

## Troubleshooting

### `/dev/net/tun` is missing

Enable TUN/TAP in the VPS provider panel or host kernel. Containers require:

```yaml
devices:
  - /dev/net/tun:/dev/net/tun
cap_add:
  - NET_ADMIN
```

### Hub opens but node cards show errors

Check:

```bash
docker compose ps
docker compose logs --tail 100 nimbus-hub
docker compose logs --tail 100 nimbus-jp
```

Also verify `hub/.htpasswd` exists on the host.

### A region has zero available nodes

VPNGate availability changes constantly. Click "拉取并检测" in the Hub or wait for the next scan. Some countries may temporarily have no usable nodes.

### "Connect best" does not choose hosting

This is expected when residential/mobile nodes are available. Hosting is only used as fallback when no residential/mobile node is available.

## Repository

```text
git@github.com:nimbus-vpngate.git
```
