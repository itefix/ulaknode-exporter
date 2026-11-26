import os
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))

from exporter import HTTPServer, LogTailer, MetricsHandler, MetricsStore, NodeCollector


class MetricsStoreTest(unittest.TestCase):
    def test_parses_connect_pass_and_disconnect(self):
        store = MetricsStore()

        store.apply_line("Jul 15 18:09:43 mail postfix/postscreen[8767]: CONNECT from [198.51.100.1]:57976 to [192.0.2.10]:25", "mail_log")
        store.apply_line("Jul 15 18:09:43 mail postfix/postscreen[8767]: PASS OLD [198.51.100.1]:57976", "mail_log")
        store.apply_line("Jul 15 18:09:43 mail postfix/postscreen[8767]: DISCONNECT [198.51.100.1]:57976", "mail_log")

        self.assertEqual(store.connections_total.get("connected"), 1)
        self.assertEqual(store.connections_total.get("passed"), 1)
        self.assertEqual(store.active_connections, 0)

    def test_counts_dnsbl_hits_and_blocked_connections(self):
        store = MetricsStore()

        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: DNSBL rank 1 for [198.51.100.2]:2406", "mail_log")
        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: NON-SMTP COMMAND from [198.51.100.2]:2406 after CONNECT: ??????", "mail_log")
        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: DISCONNECT [198.51.100.2]:2406", "mail_log")

        self.assertEqual(store.dnsbl_hits_total, 1)
        self.assertEqual(store.connections_total.get("blocked"), 1)
        self.assertEqual(store.active_connections, 0)

    def test_counts_allowlisted_connections(self):
        store = MetricsStore()

        store.apply_line("Jul 15 10:54:52 mail postfix/postscreen[700]: CONNECT from [127.0.0.1]:42288 to [127.0.0.1]:25", "mail_log")
        store.apply_line("Jul 15 10:54:52 mail postfix/postscreen[700]: ALLOWLISTED [127.0.0.1]:42288", "mail_log")

        self.assertEqual(store.connections_total.get("whitelisted"), 1)
        self.assertEqual(store.active_connections, 0)

    def test_active_connections_not_double_released_for_rejected_connection(self):
        store = MetricsStore()

        # A second, still-open connection acts as a control: postscreen logs both
        # a rejection reason *and* DISCONNECT for the first connection, and that
        # must only release it once, not bleed into the control's active count.
        store.apply_line("Jul 15 18:09:00 mail postfix/postscreen[8768]: CONNECT from [198.51.100.3]:3000 to [192.0.2.10]:25", "mail_log")

        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: CONNECT from [198.51.100.2]:2406 to [192.0.2.10]:25", "mail_log")
        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: DNSBL rank 1 for [198.51.100.2]:2406", "mail_log")
        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: NON-SMTP COMMAND from [198.51.100.2]:2406 after CONNECT: ??????", "mail_log")
        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: DISCONNECT [198.51.100.2]:2406", "mail_log")

        self.assertEqual(store.active_connections, 1)

    def test_too_many_connections_reject_does_not_leak_active_connections(self):
        # postscreen's own throttling logs "NOQUEUE: reject: CONNECT from
        # [ip]:port: too many connections" for a connection already opened
        # by an earlier CONNECT line - it must not be treated as a second
        # connection, or active_connections leaks forever since only one
        # DISCONNECT follows for the one real connection.
        store = MetricsStore()

        store.apply_line("Jul 16 04:46:47 mail postfix/postscreen[20206]: CONNECT from [198.51.100.4]:11092 to [192.0.2.10]:25", "mail_log")
        store.apply_line("Jul 16 04:46:47 mail postfix/postscreen[20206]: NOQUEUE: reject: CONNECT from [198.51.100.4]:11092: too many connections", "mail_log")
        store.apply_line("Jul 16 04:46:47 mail postfix/postscreen[20206]: DISCONNECT [198.51.100.4]:11092", "mail_log")

        self.assertEqual(store.active_connections, 0)
        self.assertEqual(store.connections_total.get("connected"), 1)
        self.assertEqual(store.connections_total.get("rejected"), 1)

    def test_counts_pregreet_without_releasing_the_connection(self):
        store = MetricsStore()

        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: CONNECT from [192.0.2.3]:1000 to [192.0.2.10]:25", "mail_log")
        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: PREGREET 11 after 0.1 from [192.0.2.3]:1000: EHLO x", "mail_log")

        self.assertEqual(store.connections_total["pregreet"], 1)
        self.assertEqual(store.active_connections, 1)

        store.apply_line("Jul 15 18:08:08 mail postfix/postscreen[8767]: DISCONNECT [192.0.2.3]:1000", "mail_log")

        self.assertEqual(store.active_connections, 0)

    def test_client_supplied_text_is_not_read_as_a_postscreen_event(self):
        store = MetricsStore()

        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: PREGREET 30 after 0.1 from [192.0.2.3]:1000: CONNECT FROM PASS DNSBL rank ", "mail_log")
        store.apply_line("Jul 15 18:08:07 mail postfix/postscreen[8767]: NON-SMTP COMMAND from [192.0.2.3]:1000 after CONNECT: PASS WHITELISTED", "mail_log")

        self.assertEqual(
            store.connections_total,
            {"connected": 0, "passed": 0, "blocked": 1, "whitelisted": 0, "rejected": 0, "pregreet": 1},
        )
        self.assertEqual(store.dnsbl_hits_total, 0)

    def test_parses_fail2ban_bans_and_rejections(self):
        store = MetricsStore()

        store.apply_line("2026-07-15 10:50:41,771 fail2ban.actions[335]: NOTICE [ulaknode-smtp] Ban 203.0.113.5", "fail2ban")
        store.apply_line(
            "Jul 15 00:00:10 mail postfix/smtpd[101107]: NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 554 5.7.1 <unknown[203.0.113.5]>: Client host rejected: banned by fail2ban; from=<user@example.com> to=<user@example.net> proto=ESMTP helo=<client.example.net>",
            "mail_log",
        )

        self.assertEqual(store.fail2ban_bans_total, 1)
        self.assertEqual(store.fail2ban_rejections_total, 1)
        self.assertEqual(store.snapshot()["fail2ban_active_bans"], 1)

    def test_fail2ban_unban_decrements_without_being_counted_as_a_ban(self):
        store = MetricsStore()

        store.apply_line("2026-07-15 10:50:41,771 fail2ban.actions[335]: NOTICE [ulaknode-smtp] Ban 203.0.113.5", "fail2ban")
        store.apply_line("2026-07-15 11:50:41,771 fail2ban.actions[335]: NOTICE [ulaknode-smtp] Unban 203.0.113.5", "fail2ban")

        self.assertEqual(store.fail2ban_bans_total, 1)
        self.assertEqual(store.snapshot()["fail2ban_active_bans"], 0)

    def test_fail2ban_restored_ban_is_not_a_new_ban(self):
        store = MetricsStore()

        store.apply_line("2026-07-15 10:50:41,771 fail2ban.actions        [335]: NOTICE  [ulaknode-smtp] Ban 203.0.113.5", "fail2ban")
        store.apply_line("2026-07-15 11:00:00,000 fail2ban.actions        [400]: NOTICE  [ulaknode-smtp] Restore Ban 203.0.113.5", "fail2ban")

        self.assertEqual(store.fail2ban_bans_total, 1)
        self.assertEqual(store.snapshot()["fail2ban_active_bans"], 1)

    def test_fail2ban_restart_forgets_bans_that_are_not_restored(self):
        store = MetricsStore()

        store.apply_line("2026-07-15 10:50:41,771 fail2ban.actions        [335]: NOTICE  [ulaknode-smtp] Ban 203.0.113.5", "fail2ban")
        store.apply_line("2026-07-15 10:51:41,771 fail2ban.actions        [335]: NOTICE  [ulaknode-smtp] Ban 203.0.113.6", "fail2ban")
        store.apply_line("2026-07-15 13:00:00,000 fail2ban.server         [400]: INFO    Starting Fail2ban v1.1.0", "fail2ban")
        store.apply_line("2026-07-15 13:00:01,000 fail2ban.actions        [400]: NOTICE  [ulaknode-smtp] Restore Ban 203.0.113.6", "fail2ban")

        self.assertEqual(store.fail2ban_bans_total, 2)
        self.assertEqual(store.snapshot()["fail2ban_active_bans"], 1)

    def test_fail2ban_error_mentioning_a_ban_is_not_counted(self):
        store = MetricsStore()

        store.apply_line("2026-07-15 10:50:41,771 fail2ban.actions        [335]: ERROR   Failed to execute ban jail 'ulaknode-smtp' action 'ulaknode'", "fail2ban")

        self.assertEqual(store.fail2ban_bans_total, 0)

    def test_parses_postfix_sasl_auth_failures(self):
        store = MetricsStore()

        store.apply_line(
            "Jul 10 10:39:47 mail postfix/smtpd[1188]: warning: unknown[203.0.113.6]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=alice@example.com",
            "mail_log",
        )
        store.apply_line(
            "Jul 10 12:14:21 mail postfix/submission/smtpd[736]: warning: unknown[203.0.113.7]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=",
            "mail_log",
        )

        self.assertEqual(store.postfix_sasl_auth_failures_total, 2)

    def test_parses_postfix_delivery_statuses(self):
        store = MetricsStore()

        store.apply_line(
            "Jul 14 09:00:21 mail postfix/lmtp[85500]: 0000000001: to=<alice@example.com>, relay=mail.example.com[private/dovecot-lmtp], delay=1.3, delays=1.3/0.01/0.02/0.01, dsn=2.0.0, status=sent (250 2.0.0 <alice@example.com> exampleLmtpSession0001 Saved)",
            "mail_log",
        )
        store.apply_line(
            "Jul 14 18:05:49 mail postfix/smtp[95038]: 0000000002: to=<carol@example.net>, relay=mx.example.net[2001:db8::1]:25, delay=6, delays=0.2/0/4.3/1.5, dsn=4.7.25, status=deferred (host said: 450 4.7.25 Service unavailable)",
            "mail_log",
        )
        store.apply_line(
            "Jul 11 18:59:26 mail postfix/smtp[21205]: 0000000003: to=<dave@example.org>, relay=mx.example.org[2001:db8::2]:25, delay=0.63, delays=0.14/0.01/0.26/0.22, dsn=5.7.26, status=bounced (host said: 550-5.7.26 DMARC policy)",
            "mail_log",
        )

        self.assertEqual(store.postfix_deliveries_total, {"sent": 1, "deferred": 1, "bounced": 1})

    def test_parses_dovecot_login_and_disconnect(self):
        store = MetricsStore()

        store.apply_line(
            "Jul 15 17:45:02 imap-login: Info: Logged in: user=<bob@example.com>, method=PLAIN, rip=192.0.2.12, lip=192.0.2.11, mpid=8396, TLS, session=<exampleSession01>",
            "dovecot",
        )
        store.apply_line(
            "Jul 15 17:45:02 imap(bob@example.com)<8396><exampleSession01>: Info: Disconnected: Logged out in=49 out=953 deleted=0 expunged=0 trashed=0 hdr_count=0 hdr_bytes=0 body_count=0 body_bytes=0",
            "dovecot",
        )

        self.assertEqual(store.dovecot_logins_total, 1)
        self.assertEqual(store.dovecot_active_sessions, 0)

    def test_dovecot_active_sessions_tracked_independently_per_session(self):
        store = MetricsStore()

        store.apply_line(
            "Jul 15 18:10:42 imap-login: Info: Logged in: user=<alice@example.com>, method=PLAIN, rip=192.0.2.11, lip=192.0.2.11, mpid=8856, TLS, session=<exampleSession02>",
            "dovecot",
        )
        store.apply_line(
            "Jul 15 18:10:42 imap-login: Info: Logged in: user=<alice@example.com>, method=PLAIN, rip=192.0.2.11, lip=192.0.2.11, mpid=8857, TLS, session=<exampleSession03>",
            "dovecot",
        )
        store.apply_line(
            "Jul 15 18:10:42 imap(alice@example.com)<8856><exampleSession02>: Info: Disconnected: Logged out in=450 out=1391 deleted=0 expunged=0 trashed=0 hdr_count=0 hdr_bytes=0 body_count=0 body_bytes=0",
            "dovecot",
        )

        self.assertEqual(store.dovecot_active_sessions, 1)

    def test_parses_dovecot_login_failure(self):
        store = MetricsStore()

        store.apply_line(
            "Jul 10 21:48:44 imap-login: Info: Login aborted: Connection closed (auth failed, 1 attempts in 8 secs) (auth_failed): user=<alice@example.invalid>, method=PLAIN, rip=192.0.2.11, lip=192.0.2.11, TLS, session=<exampleSession04>",
            "dovecot",
        )

        self.assertEqual(store.dovecot_login_failures_total, 1)
        self.assertEqual(store.dovecot_active_sessions, 0)

    def test_dovecot_abort_without_auth_attempt_is_not_a_failure(self):
        store = MetricsStore()

        store.apply_line(
            "Jul 10 21:48:44 imap-login: Info: Login aborted: Connection closed (no auth attempts in 0 secs) (no_auth_attempts): user=<>, rip=203.0.113.5",
            "dovecot",
        )

        self.assertEqual(store.dovecot_login_failures_total, 0)

    def test_parses_dovecot_lmtp_delivery_without_affecting_sessions(self):
        store = MetricsStore()

        store.apply_line("Jul 15 18:15:01 lmtp(8950): Info: Connect from local", "dovecot")
        store.apply_line(
            "Jul 15 18:15:01 lmtp(alice@example.com)<8950><exampleLmtpSession0002>: Info: msgid=<message-1@mail.example.org>: saved mail to INBOX",
            "dovecot",
        )
        store.apply_line("Jul 15 18:15:01 lmtp(8950): Info: Disconnect from local: Logged out (state=READY)", "dovecot")

        self.assertEqual(store.dovecot_lmtp_deliveries_total, 1)
        self.assertEqual(store.dovecot_active_sessions, 0)


class LogTailerTest(unittest.TestCase):
    LINE = "Jul 10 21:48:44 imap-login: Info: Login aborted: (auth failed, 1 attempts)\n"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = os.path.join(directory.name, "dovecot.log")
        self.store = MetricsStore()
        self.tailer = LogTailer(self.store, "dovecot", self.path)
        self.addCleanup(self.tailer.close)

    def write(self, text, mode="a"):
        with open(self.path, mode, encoding="utf-8") as handle:
            handle.write(text)

    def failures_after_poll(self):
        self.tailer.poll()
        return self.store.dovecot_login_failures_total

    def test_reads_existing_lines_once_then_follows(self):
        self.assertEqual(self.failures_after_poll(), 0)  # no file yet
        self.write(self.LINE)
        self.assertEqual(self.failures_after_poll(), 1)
        self.assertEqual(self.failures_after_poll(), 1)
        self.write(self.LINE)
        self.assertEqual(self.failures_after_poll(), 2)

    def test_waits_for_a_complete_line(self):
        self.write(self.LINE[:60])
        self.assertEqual(self.failures_after_poll(), 0)
        self.write(self.LINE[60:])
        self.assertEqual(self.failures_after_poll(), 1)

    def test_follows_rotation_and_drains_the_old_file(self):
        self.write(self.LINE)
        self.assertEqual(self.failures_after_poll(), 1)
        self.write(self.LINE)  # written just before rotation
        os.rename(self.path, self.path + ".1")
        self.assertEqual(self.failures_after_poll(), 2)
        self.write(self.LINE)
        self.assertEqual(self.failures_after_poll(), 3)

    def test_follows_truncation(self):
        self.write(self.LINE * 2)
        self.assertEqual(self.failures_after_poll(), 2)
        self.write(self.LINE, mode="w")
        self.assertEqual(self.failures_after_poll(), 3)


class ServerTest(unittest.TestCase):
    def test_metrics_output_is_grouped_and_ends_with_a_newline(self):
        store = MetricsStore()
        collector = NodeCollector(mountpoints=["/", "/proc"])
        server = HTTPServer(
            ("127.0.0.1", 0),
            lambda *args: MetricsHandler(*args, store=store, node_collector=collector),
        )
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)

        url = f"http://127.0.0.1:{server.server_port}/metrics"
        with urllib.request.urlopen(url, timeout=5) as response:
            output = response.read().decode()

        self.assertTrue(output.endswith("\n"))
        names = [line.split("{")[0].split()[0] for line in output.splitlines() if not line.startswith("#")]
        blocks = [name for index, name in enumerate(names) if index == 0 or names[index - 1] != name]
        self.assertEqual(len(blocks), len(set(blocks)), "samples of a metric are not contiguous")

    def test_exits_on_sigterm(self):
        missing = "/definitely-not-a-real-log"
        env = dict(
            os.environ, EXPORTER_HOST="127.0.0.1", EXPORTER_PORT="0",
            POSTSCREEN_LOG=missing, FAIL2BAN_LOG=missing, DOVECOT_LOG=missing,
        )
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exporter.py")
        process = subprocess.Popen([sys.executable, script], env=env, stderr=subprocess.PIPE)
        self.addCleanup(process.stderr.close)
        self.addCleanup(process.kill)
        process.stderr.readline()  # "Serving metrics on ..."

        process.send_signal(signal.SIGTERM)

        self.assertEqual(process.wait(5), 0)


class NodeCollectorTest(unittest.TestCase):
    def test_collect_returns_basic_host_metrics(self):
        collector = NodeCollector(mountpoints=["/"])

        data = collector.collect()

        self.assertIsNotNone(data["load1"])
        self.assertIsNotNone(data["memory_total_bytes"])
        self.assertIn("/", data["filesystems"])
        size, avail = data["filesystems"]["/"]
        self.assertGreater(size, 0)
        self.assertGreaterEqual(avail, 0)
        self.assertIn("lo", data["network"])

    def test_collect_skips_missing_mountpoints(self):
        collector = NodeCollector(mountpoints=["/definitely-not-a-real-mount"])

        data = collector.collect()

        self.assertEqual(data["filesystems"], {})


if __name__ == "__main__":
    unittest.main()
