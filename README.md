# ulaknode-exporter

A Prometheus exporter for the [ulaknode](https://github.com/itefix/ulaknode)
mail stack. It runs as a sidecar next to the `ulaknode` container, tails its
log files, and serves counters and gauges for the stack, plus basic host
resource usage, on a single endpoint.

No third-party dependencies — built with the Python standard library only.

This version matches ulaknode 2.8.0 and later.

## Quick start

The exporter reads the `ulak_logs` and `ulak_mail` volumes that the main
`ulaknode` container creates on first run, so start `ulaknode` first. Both
volumes are mounted read-only.

```bash
docker run -d \
  --name ulaknode-exporter \
  --restart unless-stopped \
  -p 9101:9101 \
  -v ulak_logs:/var/log:ro \
  -v ulak_mail:/var/mail:ro \
  ghcr.io/itefix/ulaknode-exporter:latest

curl http://localhost:9101/metrics
```

Or with Compose:

```yaml
services:
  exporter:
    image: ghcr.io/itefix/ulaknode-exporter:latest
    container_name: ulaknode-exporter
    restart: unless-stopped
    volumes:
      - ulak_logs:/var/log:ro
      - ulak_mail:/var/mail:ro
    ports:
      - "9101:9101"

volumes:
  # Must already exist — created by the main ulaknode container on first run
  ulak_logs:
    external: true
  ulak_mail:
    external: true
```

If you deployed `ulaknode` with Compose rather than `docker run`, Compose
prefixes the volume names with its project name (e.g. `ulaknode_ulak_logs`) —
adjust the volume references to match.

Then point Prometheus at it:

```yaml
scrape_configs:
  - job_name: ulaknode
    static_configs:
      - targets: ["mail.yourdomain.com:9101"]
```

The endpoint has no authentication or TLS, so restrict access to port `9101`
to your Prometheus server.

## Metrics

Metrics are served on `/metrics` (default port `9101`).

| Metric | Type | Description |
|---|---|---|
| `postfix_postscreen_connections_total{result}` | counter | Postscreen events by result: `connected`, `passed`, `blocked`, `whitelisted`, `rejected`, `pregreet` |
| `postfix_postscreen_dnsbl_hits_total` | counter | Postscreen DNSBL hits |
| `postfix_postscreen_active_connections` | gauge | Active Postscreen connections |
| `postfix_sasl_auth_failures_total` | counter | SASL authentication failures |
| `postfix_deliveries_total{status}` | counter | Delivery attempts by status: `sent`, `deferred`, `bounced` |
| `ulaknode_dovecot_logins_total` | counter | Successful Dovecot logins |
| `ulaknode_dovecot_login_failures_total` | counter | Failed Dovecot login attempts |
| `ulaknode_dovecot_active_sessions` | gauge | Active IMAP sessions |
| `ulaknode_dovecot_lmtp_deliveries_total` | counter | Local deliveries via Dovecot LMTP |
| `ulaknode_fail2ban_bans_total` | counter | New Fail2ban bans (bans restored after a restart are not counted) |
| `ulaknode_fail2ban_rejections_total` | counter | SMTP rejections caused by Fail2ban bans |
| `ulaknode_fail2ban_active_bans` | gauge | Active bans |
| `ulaknode_node_load1` | gauge | 1-minute load average |
| `ulaknode_node_load5` | gauge | 5-minute load average |
| `ulaknode_node_load15` | gauge | 15-minute load average |
| `ulaknode_node_memory_total_bytes` | gauge | Total memory |
| `ulaknode_node_memory_available_bytes` | gauge | Available memory |
| `ulaknode_node_filesystem_size_bytes{mountpoint}` | gauge | Filesystem size |
| `ulaknode_node_filesystem_avail_bytes{mountpoint}` | gauge | Filesystem space available |
| `ulaknode_node_network_receive_bytes_total{device}` | counter | Bytes received per network device |
| `ulaknode_node_network_transmit_bytes_total{device}` | counter | Bytes transmitted per network device |
| `ulaknode_exporter_info{version}` | gauge | Running build version (always `1`) |

Mail metrics are accumulated from the logs: on startup the exporter reads the
existing log files, then follows new lines. Host metrics are read fresh on
every scrape.

The exporter follows log files across rotation and truncation. On a restart,
the counters are rebuilt from the current log files only.

### Host network metrics

By default the container runs in its own network namespace, so the network
byte counters describe its own virtual interface, not the host's NIC. To see
real host traffic, run it with `network_mode: host` (`--network host` with
`docker run`) and drop the port mapping. This is the same tradeoff the
Prometheus `node_exporter` makes: it lowers network isolation, so it is
opt-in. The exporter then listens directly on the host's port `9101`.

## Configuration

All configuration is via environment variables; none are required.

| Variable | Default | Description |
|---|---|---|
| `EXPORTER_HOST` | `0.0.0.0` | Address the HTTP server binds to |
| `EXPORTER_PORT` | `9101` | Port the HTTP server binds to |
| `POSTSCREEN_LOG` | `/var/log/mail.log` | Postfix/Postscreen log path |
| `FAIL2BAN_LOG` | `/var/log/fail2ban.log` | Fail2ban log path |
| `DOVECOT_LOG` | `/var/log/dovecot.log` | Dovecot log path |
| `NODE_FS_MOUNTPOINTS` | `/var/mail,/var/log` | Comma-separated paths to report filesystem usage for |
| `POLL_INTERVAL` | `1.0` | Seconds between checks for new log lines |

## Grafana dashboard

Import [`grafana-dashboard.json`](grafana-dashboard.json) into Grafana. It has
an always-visible "Overview" row (active connections, sessions and bans, load,
memory, mail storage free space, delivery outcomes, auth failures) and rows for
Postfix/Postscreen, Dovecot, Fail2ban and Host, collapsed by default.

Counters are not shown as running totals. Tiles count mail events in the
selected time range (24 hours by default), graphs show events per hour over a
sliding one-hour window, and network traffic is in bytes per second.

## Development

Build and run from source:

```bash
docker compose up -d --build
```

The image is tagged `ghcr.io/itefix/ulaknode-exporter:dev` by default. Set
`EXPORTER_VERSION` to build a release, e.g.
`EXPORTER_VERSION=1.0.4 docker compose build`.

Run the tests:

```bash
python3 -m unittest -v test_exporter
```

| File | Purpose |
|---|---|
| `exporter.py` | The exporter |
| `test_exporter.py` | Regression tests |
| `Dockerfile` | Builds the image; the `VERSION` build arg becomes `EXPORTER_VERSION` |
| `docker-compose.yml` | Sidecar service definition |
| `grafana-dashboard.json` | Grafana dashboard |
| `CHANGELOG.md` | Release history |
| `.github/workflows/docker.yml` | Tests, image build and publishing |

### Releases

[GitHub Actions](.github/workflows/docker.yml) runs the tests and builds the
image (`linux/amd64` and `linux/arm64`) for pull requests and pushes to
`main`. Pushing a version tag such as `v1.0.4` publishes the image to
`ghcr.io/itefix/ulaknode-exporter` with the tags `1.0.4`, `1.0` and `latest`.
The latest release is also rebuilt monthly to pick up base image updates.

## Links

- [ulaknode source](https://github.com/itefix/ulaknode)
- [Monitoring overview and screenshots](https://itefix.net/ulaknode)
- [Release history](CHANGELOG.md)

## License

BSD 2-Clause — see [LICENSE](LICENSE).
