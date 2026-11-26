# Changelog

All notable changes to this project will be documented in this file.

## [1.0.4] - 2026-11-26

- Fixed Dovecot login failures including connections that never tried to
  authenticate: only `auth failed` lines are counted now.
- Fixed Fail2ban restored bans being counted as new bans and inflating the
  active bans gauge. Error messages that mention a ban are no longer counted.
- Postscreen `PREGREET` events are now counted, as
  `postfix_postscreen_connections_total{result="pregreet"}`.
- Fixed text sent by remote clients being able to pass for a Postscreen event.
- Fixed log files not being reopened after rotation or truncation, and lines
  written during startup being skipped.
- Fixed `/metrics` output lacking a final newline and interleaving the samples
  of different metrics.
- Fixed the exporter not exiting on SIGTERM, so stopping the container no
  longer waits for it to be killed.
- Images are now built by GitHub Actions and published to
  `ghcr.io/itefix/ulaknode-exporter`.
- Added the BSD 2-Clause license.
- Replaced the sample data in the tests with reserved example addresses.

## [1.0.3] - 2026-11-26

- Removed Postgrey and SpamAssassin support, as ulaknode no longer ships them
  (Postgrey since 2.7.0, SpamAssassin since 2.8.0): dropped the
  `ulaknode_postgrey_greylisted_total` and `ulaknode_spamassassin_*` metrics,
  the `POSTGREY_LOG`/`SPAMASSASSIN_LOG` settings, and the SpamAssassin and
  Postgrey rows in the Grafana dashboard.
- Grafana dashboard no longer shows ever-growing totals: the "Total ..." tiles
  now count events in the selected time range (network tiles show bytes per
  second), event graphs changed from per second to per hour over a one-hour
  window, and the default time range is now 24 hours.
- Fixed the Postscreen connections tile counting each connection more than
  once by summing all results; it now counts `connected` only.

## [1.0.2] - 2026-10-18

- Removed ClamAV support, as ulaknode no longer ships ClamAV: dropped the
  `ulaknode_clamav_*` metrics, the `CLAMAV_LOG`/`FRESHCLAM_LOG` settings,
  the `ulak_clamav` volume mount and `/var/lib/clamav` filesystem metric,
  and the ClamAV row in the Grafana dashboard.

## [1.0.1] - 2026-07-18

- Fixed the Host row's "Total Network Received/Transmitted" stat panels
  summing across all interfaces reported by the host (the exporter runs
  with `NetworkMode: host`), which double-counted traffic: WireGuard's
  `wg0` tunnel rides over the physical NIC, and `lo` never leaves the
  host, so summing them alongside `eth0`/`docker0` inflated the total
  well past the real figure. Now excludes loopback and known virtual/
  tunnel devices (`docker*`, `wg*`, `veth*`, `br-*`, `tun*`) from the sum.

## [1.0.0] - 2026-07-18

- Added a "Total" stat tile row to the top of each collapsed component
  section in the Grafana dashboard (Postfix/Postscreen, Dovecot, ClamAV,
  SpamAssassin, Postgrey, Fail2ban, Host), showing the cumulative counter
  value alongside the existing rate/current-value timeseries panels.
- Fixed `postfix_postscreen_active_connections` leaking upward forever:
  postscreen's "NOQUEUE: reject: CONNECT from ... too many connections"
  status line was mistaken for a second incoming connection because it
  contains the substring "connect from". Also makes the previously-dead
  `connections_total{result="rejected"}` series live.
- Fixed SpamAssassin scan/hit metrics always reporting zero: spamd's syslog
  init fails inside the container, so it logs to stderr (`spamd.err`)
  instead of the previously-watched `spamd.log`, which is always empty.
  Scan/hit detection now also keys off spamd's own `result: Y|.` summary
  line instead of ad-hoc keyword matching that didn't match real log lines.
- Initial exporter implementation for ulaknode mail stack monitoring.
- Added Prometheus metrics for Postfix, Dovecot, ClamAV, SpamAssassin, Postgrey, Fail2ban, and host resource usage.
- Added `ulaknode_exporter_info{version="..."}` build info metric.
- Added Dockerfile and `docker-compose.yml` sidecar setup.
- Added Grafana dashboard JSON for monitoring visualization.
- No third-party dependencies; exporter is built with Python standard library only.
