#!/usr/bin/env python3
"""Unified Prometheus exporter for ulaknode monitoring.

This exporter watches Postfix (including Postscreen), Dovecot, and
Fail2ban log lines, plus basic host resource usage, and exposes a compact
set of counters and gauges through one endpoint.
"""

import os
import re
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = os.environ.get("EXPORTER_HOST", "0.0.0.0")
PORT = int(os.environ.get("EXPORTER_PORT", "9101"))
EXPORTER_VERSION = os.environ.get("EXPORTER_VERSION", "dev")
POSTSCREEN_LOG = os.environ.get("POSTSCREEN_LOG", "/var/log/mail.log")
FAIL2BAN_LOG = os.environ.get("FAIL2BAN_LOG", "/var/log/fail2ban.log")
DOVECOT_LOG = os.environ.get("DOVECOT_LOG", "/var/log/dovecot.log")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "1.0"))

# mail.log carries Postscreen, Fail2ban rejections, and generic Postfix
# (smtpd/qmgr/smtp/lmtp) lines interleaved, so it is the one source that still
# needs content-based sub-dispatch. Every other log file below is written by
# exactly one service, so it is routed unconditionally.
LOG_SOURCES = [
    ("mail_log", POSTSCREEN_LOG),
    ("fail2ban", FAIL2BAN_LOG),
    ("dovecot", DOVECOT_LOG),
]

NODE_FS_MOUNTPOINTS = [
    path.strip()
    for path in os.environ.get("NODE_FS_MOUNTPOINTS", "/var/mail,/var/log").split(",")
    if path.strip()
]

# Both patterns are anchored on the program tag, because the rest of a log line
# can contain text chosen by the remote client (e.g. a PREGREET's EHLO).
POSTSCREEN_LINE = re.compile(r"^[^\]]*postscreen\[\d+\]: (.*)")
FAIL2BAN_ACTION = re.compile(
    r"fail2ban\.actions\s*\[\d+\]:\s+notice\s+\[([^\]]+)\]\s+(restore ban|unban|ban)\s+(\S+)"
)
FAIL2BAN_START = re.compile(r"fail2ban\.server\s*\[\d+\]:\s+info\s+starting fail2ban")


class MetricsStore:
    def __init__(self):
        self.connections_total = {"connected": 0, "passed": 0, "blocked": 0, "whitelisted": 0, "rejected": 0, "pregreet": 0}
        self.dnsbl_hits_total = 0
        self.active_connections = 0
        self.fail2ban_bans_total = 0
        self.fail2ban_rejections_total = 0
        self.postfix_sasl_auth_failures_total = 0
        self.postfix_deliveries_total = {"sent": 0, "deferred": 0, "bounced": 0}
        self.dovecot_logins_total = 0
        self.dovecot_login_failures_total = 0
        self.dovecot_active_sessions = 0
        self.dovecot_lmtp_deliveries_total = 0
        self._active_hosts = set()
        self._active_dovecot_sessions = set()
        self._active_bans = set()  # (jail, ip)

    def apply_line(self, line, source):
        line = line.strip()
        if not line:
            return
        lowered = line.lower()

        if source == "mail_log":
            self._apply_mail_log(line, lowered)
        elif source == "fail2ban":
            self._apply_fail2ban(line, lowered)
        elif source == "dovecot":
            self._apply_dovecot(line, lowered)

    def _apply_mail_log(self, line, lowered):
        postscreen = POSTSCREEN_LINE.match(lowered)
        if postscreen:
            self._apply_postscreen(line, postscreen.group(1))
            return

        if "banned by fail2ban" in lowered:
            self._apply_fail2ban(line, lowered)
            return

        self._apply_postfix(line, lowered)

    def _release_connection(self, line):
        key = self._connection_key(line)
        if key is not None and key not in self._active_hosts:
            # Already released by an earlier outcome line for this connection
            # (e.g. postscreen logs both a rejection reason and DISCONNECT).
            return False
        self._active_hosts.discard(key)
        self.active_connections = max(0, self.active_connections - 1)
        return True

    @staticmethod
    def _connection_key(line):
        match = re.search(r"\[[0-9a-fA-F:.]+\]:\d+", line)
        return match.group(0) if match else None

    def _apply_postscreen(self, line, message):
        """Count one postscreen line; `message` is its lowercased text after the tag."""
        if message.startswith("noqueue: reject:"):
            self.connections_total["rejected"] += 1
        elif message.startswith("connect from "):
            key = self._connection_key(line)
            self.active_connections += 1
            self.connections_total["connected"] += 1
            if key is not None:
                self._active_hosts.add(key)
        elif message.startswith("pass "):
            self._release_connection(line)
            self.connections_total["passed"] += 1
        elif message.startswith(("allowlisted ", "whitelisted ")):
            self._release_connection(line)
            self.connections_total["whitelisted"] += 1
        elif message.startswith("dnsbl rank "):
            self.dnsbl_hits_total += 1
        elif message.startswith("pregreet "):
            # The client talked before the greeting. The connection stays open
            # until postscreen logs how it ended.
            self.connections_total["pregreet"] += 1
        elif message.startswith(("non-smtp command ", "bare newline ")):
            self._release_connection(line)
            self.connections_total["blocked"] += 1
        elif message.startswith("disconnect "):
            self._release_connection(line)

    def _apply_fail2ban(self, line, lowered):
        if "client host rejected: banned by fail2ban" in lowered:
            self.fail2ban_rejections_total += 1
            return

        # A restarting fail2ban re-announces the bans that still apply.
        if FAIL2BAN_START.search(lowered):
            self._active_bans.clear()
            return

        match = FAIL2BAN_ACTION.search(lowered)
        if not match:
            return
        jail, action, address = match.groups()
        if action == "unban":
            self._active_bans.discard((jail, address))
            return
        self._active_bans.add((jail, address))
        if action == "ban":
            self.fail2ban_bans_total += 1

    def _apply_postfix(self, line, lowered):
        if "sasl" in lowered and "authentication failed" in lowered:
            self.postfix_sasl_auth_failures_total += 1
            return

        status_match = re.search(r"status=(sent|deferred|bounced)\b", lowered)
        if status_match:
            status = status_match.group(1)
            self.postfix_deliveries_total[status] = self.postfix_deliveries_total.get(status, 0) + 1

    def _apply_dovecot(self, line, lowered):
        if "lmtp(" in lowered:
            if "saved mail to" in lowered:
                self.dovecot_lmtp_deliveries_total += 1
            return

        # "Login aborted" alone is not a failure: Dovecot also logs it for
        # clients that disconnect without trying to authenticate.
        if "auth failed" in lowered:
            self.dovecot_login_failures_total += 1
            return

        if "logged in:" in lowered:
            self.dovecot_logins_total += 1
            match = re.search(r"mpid=(\d+)", line)
            if match:
                pid = match.group(1)
                if pid not in self._active_dovecot_sessions:
                    self._active_dovecot_sessions.add(pid)
                    self.dovecot_active_sessions += 1
            return

        if "disconnected" in lowered:
            match = re.search(r"\)<(\d+)><", line)
            if match:
                pid = match.group(1)
                if pid in self._active_dovecot_sessions:
                    self._active_dovecot_sessions.discard(pid)
                    self.dovecot_active_sessions = max(0, self.dovecot_active_sessions - 1)
            return

    def snapshot(self):
        return {
            "connections_total": dict(self.connections_total),
            "dnsbl_hits_total": self.dnsbl_hits_total,
            "active_connections": self.active_connections,
            "fail2ban_bans_total": self.fail2ban_bans_total,
            "fail2ban_rejections_total": self.fail2ban_rejections_total,
            "fail2ban_active_bans": len(self._active_bans),
            "postfix_sasl_auth_failures_total": self.postfix_sasl_auth_failures_total,
            "postfix_deliveries_total": dict(self.postfix_deliveries_total),
            "dovecot_logins_total": self.dovecot_logins_total,
            "dovecot_login_failures_total": self.dovecot_login_failures_total,
            "dovecot_active_sessions": self.dovecot_active_sessions,
            "dovecot_lmtp_deliveries_total": self.dovecot_lmtp_deliveries_total,
        }


class NodeCollector:
    """Collects a small set of host resource metrics fresh on every scrape.

    Unlike MetricsStore, this has no persistent state: CPU/memory/disk/network
    usage are current-state facts, not events accumulated from a log stream.
    """

    def __init__(self, mountpoints):
        self.mountpoints = mountpoints

    def collect(self):
        data = {
            "load1": None,
            "load5": None,
            "load15": None,
            "memory_total_bytes": None,
            "memory_available_bytes": None,
            "filesystems": {},
            "network": {},
        }

        try:
            with open("/proc/loadavg", encoding="utf-8") as handle:
                fields = handle.read().split()
            data["load1"], data["load5"], data["load15"] = fields[0], fields[1], fields[2]
        except (OSError, IndexError):
            pass

        try:
            meminfo = {}
            with open("/proc/meminfo", encoding="utf-8") as handle:
                for line in handle:
                    key, _, rest = line.partition(":")
                    value_kb = rest.strip().split()[0]
                    meminfo[key] = int(value_kb) * 1024
            data["memory_total_bytes"] = meminfo.get("MemTotal")
            data["memory_available_bytes"] = meminfo.get("MemAvailable")
        except (OSError, IndexError, ValueError):
            pass

        for mountpoint in self.mountpoints:
            try:
                stat = os.statvfs(mountpoint)
                data["filesystems"][mountpoint] = (
                    stat.f_frsize * stat.f_blocks,
                    stat.f_frsize * stat.f_bavail,
                )
            except OSError:
                continue

        try:
            with open("/proc/net/dev", encoding="utf-8") as handle:
                lines = handle.readlines()[2:]
            for line in lines:
                name, _, rest = line.partition(":")
                fields = rest.split()
                if len(fields) < 9:
                    continue
                data["network"][name.strip()] = (int(fields[0]), int(fields[8]))
        except (OSError, IndexError, ValueError):
            pass

        return data


class MetricsHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, store=None, node_collector=None, **kwargs):
        self.store = store
        self.node_collector = node_collector
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        snapshot = self.store.snapshot()
        body = [
            "# HELP ulaknode_exporter_info Exporter build info.",
            "# TYPE ulaknode_exporter_info gauge",
            f'ulaknode_exporter_info{{version="{EXPORTER_VERSION}"}} 1',
            "# HELP postfix_postscreen_connections_total Total Postfix Postscreen connections by result.",
            "# TYPE postfix_postscreen_connections_total counter",
        ]
        for result, value in snapshot["connections_total"].items():
            body.append(f'postfix_postscreen_connections_total{{result="{result}"}} {value}')

        body.extend([
            "# HELP postfix_postscreen_dnsbl_hits_total Total Postfix Postscreen DNSBL hits.",
            "# TYPE postfix_postscreen_dnsbl_hits_total counter",
            f"postfix_postscreen_dnsbl_hits_total {snapshot['dnsbl_hits_total']}",
            "# HELP postfix_postscreen_active_connections Current number of active Postfix Postscreen connections.",
            "# TYPE postfix_postscreen_active_connections gauge",
            f"postfix_postscreen_active_connections {snapshot['active_connections']}",
            "# HELP postfix_sasl_auth_failures_total Total Postfix SASL authentication failures.",
            "# TYPE postfix_sasl_auth_failures_total counter",
            f"postfix_sasl_auth_failures_total {snapshot['postfix_sasl_auth_failures_total']}",
            "# HELP postfix_deliveries_total Total Postfix delivery attempts by final status.",
            "# TYPE postfix_deliveries_total counter",
        ])
        for status, value in snapshot["postfix_deliveries_total"].items():
            body.append(f'postfix_deliveries_total{{status="{status}"}} {value}')

        body.extend([
            "# HELP ulaknode_fail2ban_bans_total Total Fail2ban ban events.",
            "# TYPE ulaknode_fail2ban_bans_total counter",
            f"ulaknode_fail2ban_bans_total {snapshot['fail2ban_bans_total']}",
            "# HELP ulaknode_fail2ban_rejections_total Total SMTP rejections caused by Fail2ban bans.",
            "# TYPE ulaknode_fail2ban_rejections_total counter",
            f"ulaknode_fail2ban_rejections_total {snapshot['fail2ban_rejections_total']}",
            "# HELP ulaknode_fail2ban_active_bans Current number of active Fail2ban bans.",
            "# TYPE ulaknode_fail2ban_active_bans gauge",
            f"ulaknode_fail2ban_active_bans {snapshot['fail2ban_active_bans']}",
            "# HELP ulaknode_dovecot_logins_total Total successful Dovecot logins.",
            "# TYPE ulaknode_dovecot_logins_total counter",
            f"ulaknode_dovecot_logins_total {snapshot['dovecot_logins_total']}",
            "# HELP ulaknode_dovecot_login_failures_total Total failed Dovecot login attempts.",
            "# TYPE ulaknode_dovecot_login_failures_total counter",
            f"ulaknode_dovecot_login_failures_total {snapshot['dovecot_login_failures_total']}",
            "# HELP ulaknode_dovecot_active_sessions Current number of active Dovecot IMAP sessions.",
            "# TYPE ulaknode_dovecot_active_sessions gauge",
            f"ulaknode_dovecot_active_sessions {snapshot['dovecot_active_sessions']}",
            "# HELP ulaknode_dovecot_lmtp_deliveries_total Total local deliveries via Dovecot LMTP.",
            "# TYPE ulaknode_dovecot_lmtp_deliveries_total counter",
            f"ulaknode_dovecot_lmtp_deliveries_total {snapshot['dovecot_lmtp_deliveries_total']}",
        ])

        if self.node_collector is not None:
            node = self.node_collector.collect()
            body.extend([
                "# HELP ulaknode_node_load1 1-minute load average.",
                "# TYPE ulaknode_node_load1 gauge",
            ])
            if node["load1"] is not None:
                body.append(f"ulaknode_node_load1 {node['load1']}")
                body.append("# HELP ulaknode_node_load5 5-minute load average.")
                body.append("# TYPE ulaknode_node_load5 gauge")
                body.append(f"ulaknode_node_load5 {node['load5']}")
                body.append("# HELP ulaknode_node_load15 15-minute load average.")
                body.append("# TYPE ulaknode_node_load15 gauge")
                body.append(f"ulaknode_node_load15 {node['load15']}")

            if node["memory_total_bytes"] is not None:
                body.append("# HELP ulaknode_node_memory_total_bytes Total host memory in bytes.")
                body.append("# TYPE ulaknode_node_memory_total_bytes gauge")
                body.append(f"ulaknode_node_memory_total_bytes {node['memory_total_bytes']}")
            if node["memory_available_bytes"] is not None:
                body.append("# HELP ulaknode_node_memory_available_bytes Available host memory in bytes.")
                body.append("# TYPE ulaknode_node_memory_available_bytes gauge")
                body.append(f"ulaknode_node_memory_available_bytes {node['memory_available_bytes']}")

            if node["filesystems"]:
                body.append("# HELP ulaknode_node_filesystem_size_bytes Total filesystem size in bytes.")
                body.append("# TYPE ulaknode_node_filesystem_size_bytes gauge")
                for mountpoint, (size, _) in node["filesystems"].items():
                    body.append(f'ulaknode_node_filesystem_size_bytes{{mountpoint="{mountpoint}"}} {size}')
                body.append("# HELP ulaknode_node_filesystem_avail_bytes Available filesystem space in bytes.")
                body.append("# TYPE ulaknode_node_filesystem_avail_bytes gauge")
                for mountpoint, (_, avail) in node["filesystems"].items():
                    body.append(f'ulaknode_node_filesystem_avail_bytes{{mountpoint="{mountpoint}"}} {avail}')

            if node["network"]:
                body.append("# HELP ulaknode_node_network_receive_bytes_total Cumulative bytes received per network device.")
                body.append("# TYPE ulaknode_node_network_receive_bytes_total counter")
                for device, (rx_bytes, _) in node["network"].items():
                    body.append(f'ulaknode_node_network_receive_bytes_total{{device="{device}"}} {rx_bytes}')
                body.append("# HELP ulaknode_node_network_transmit_bytes_total Cumulative bytes transmitted per network device.")
                body.append("# TYPE ulaknode_node_network_transmit_bytes_total counter")
                for device, (_, tx_bytes) in node["network"].items():
                    body.append(f'ulaknode_node_network_transmit_bytes_total{{device="{device}"}} {tx_bytes}')

        payload = ("\n".join(body) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


def build_store():
    return MetricsStore()


class LogTailer:
    """Follows one log file across rotation and truncation."""

    def __init__(self, store, source, path):
        self.store = store
        self.source = source
        self.path = path
        self._handle = None
        self._partial = b""

    def poll(self):
        """Apply every complete line that has appeared since the last call."""
        if self._handle is None and not self._open():
            return

        if os.fstat(self._handle.fileno()).st_size < self._handle.tell():
            self._handle.seek(0)
            self._partial = b""

        # Checked before reading, so the old file is drained before switching.
        replaced = self._replaced()
        self._read()
        if replaced:
            self.close()
            if self._open():
                self._read()

    def close(self):
        if self._handle is not None:
            self._handle.close()
        self._handle = None
        self._partial = b""

    def _open(self):
        try:
            self._handle = open(self.path, "rb")
        except OSError:
            return False
        return True

    def _replaced(self):
        try:
            current = os.stat(self.path)
        except OSError:
            # Renamed away and not yet recreated: keep reading the old file.
            return False
        return not os.path.samestat(current, os.fstat(self._handle.fileno()))

    def _read(self):
        for chunk in iter(self._handle.readline, b""):
            if not chunk.endswith(b"\n"):
                self._partial += chunk
                return
            line, self._partial = self._partial + chunk, b""
            self.store.apply_line(line.decode("utf-8", errors="ignore"), self.source)


def follow(tailer):
    while True:
        time.sleep(POLL_INTERVAL)
        tailer.poll()


def main():
    store = build_store()
    node_collector = NodeCollector(NODE_FS_MOUNTPOINTS)

    # Read the existing logs before serving, so the first scrape is complete.
    tailers = [LogTailer(store, source, path) for source, path in LOG_SOURCES]
    for tailer in tailers:
        tailer.poll()

    server = HTTPServer(
        (HOST, PORT),
        lambda *args, **kwargs: MetricsHandler(*args, store=store, node_collector=node_collector, **kwargs),
    )

    for tailer in tailers:
        threading.Thread(target=follow, args=(tailer,), daemon=True).start()

    def handle_signal(signum, frame):
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    print(f"Serving metrics on http://{HOST}:{PORT}/metrics", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
