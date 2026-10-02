"""Private local-node contracts and an optional real-core loopback exercise."""

import json
import hashlib
import http.cookiejar
import os
from pathlib import Path
import plistlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error, parse, request
import re
import shutil

import local_node
import run_panel


CORE = os.environ.get("FARVATER_TEST_CORE")


def free_port():
    with socket.socket() as channel:
        channel.bind(("127.0.0.1", 0))
        return channel.getsockname()[1]


class DNSStub:
    def __init__(self):
        self.channel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.channel.bind(("127.0.0.1", 0))
        self.port = self.channel.getsockname()[1]
        self.channel.settimeout(0.1)
        self.active = True
        self.received = 0
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while self.active:
            try:
                query, peer = self.channel.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(query) < 17:
                continue
            self.received += 1
            # Mirror the question, then answer with the synthetic loopback HTTP host.
            answer = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00"
            answer += query[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x7f\x00\x00\x01"
            self.channel.sendto(answer, peer)

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self.active = False
        self.channel.close()
        self.thread.join(timeout=2)


class HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_):
        pass


class LocalNodeTests(unittest.TestCase):
    @staticmethod
    def core_settings(core):
        return {"version": 1, "core": str(core), "dns_port": 15301,
                "proxy_port": 12081, "api_port": 19091, "api_secret": "x" * 40,
                "lan": None, "probe_url": "https://example.com/", "probe_domain": "example.com"}

    def test_forged_download_manifest_cannot_authorize_executable_stub(self):
        from download_core import DIGESTS, VERSION
        with tempfile.TemporaryDirectory() as directory:
            core = Path(directory) / "sing-box"
            core.write_bytes(b"#!/bin/sh\nexit 0\n")
            core.chmod(0o700)
            run_panel.write_private_json(core.parent / "manifest.json", {
                "version": VERSION, "platform": "darwin-arm64",
                "archive_sha256": DIGESTS[("Darwin", "arm64")],
                "files": {"sing-box": hashlib.sha256(core.read_bytes()).hexdigest()}})
            with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"):
                with self.assertRaises(local_node.NodeError):
                    local_node.validate_settings(self.core_settings(core))

    @unittest.skipUnless(CORE and sys.platform == "darwin", "requires the verified Darwin core")
    def test_core_byte_drift_rejected_even_when_manifest_is_rewritten(self):
        source = Path(CORE).resolve()
        with tempfile.TemporaryDirectory() as directory:
            core = Path(directory) / "sing-box"
            shutil.copyfile(source, core)
            core.chmod(0o700)
            data = bytearray(core.read_bytes())
            data[-1] ^= 1
            core.write_bytes(data)
            manifest = run_panel.private_json(source.parent / "manifest.json", max_bytes=4096)
            manifest["files"]["sing-box"] = hashlib.sha256(data).hexdigest()
            run_panel.write_private_json(core.parent / "manifest.json", manifest)
            with self.assertRaises(local_node.NodeError):
                local_node.validate_settings(self.core_settings(core))

    def test_login_agent_contains_only_owned_paths_and_no_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            state = home / "state"
            run_panel.private_directory(state)
            with (patch("local_node.sys.platform", "darwin"), patch("local_node.Supervisor"),
                  patch("local_node.Path.home", return_value=home),
                  patch("local_node.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as command):
                target = local_node.install_login_agent(state)
            document = plistlib.loads(target.read_bytes())
            self.assertEqual(document["Label"], "com.farvater.local-node")
            self.assertIn(str(state.resolve()), document["ProgramArguments"])
            self.assertNotIn("password", target.read_text().lower())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(command.call_args.args[0][:2], ["launchctl", "bootstrap"])

    def test_input_restrictions_and_linux_only_policy(self):
        for address in ("0.0.0.0", "127.0.0.1", "8.8.8.8", "::1"):
            with self.assertRaises(local_node.NodeError):
                local_node.private_lan_address(address)
        self.assertEqual(local_node.private_lan_address("192.168.10.1"), "192.168.10.1")
        policy = run_panel.initial_policy("192.0.2.53")
        policy["incoming_connections"] = [{"type": "wireguard"}]
        with self.assertRaises(local_node.NodeError):
            local_node.validate_local_policy(policy)
        malformed = run_panel.initial_policy("192.0.2.53")
        malformed["exits"]["direct"]["native"] = []
        with self.assertRaises(local_node.NodeError):
            local_node.validate_local_policy(malformed)
        with self.assertRaises(local_node.NodeError):
            local_node.probe_target("http://user:secret@127.0.0.1/", "example.test")

    @unittest.skipUnless(CORE and sys.platform == "darwin", "requires the verified Darwin core")
    def test_real_darwin_core_dns_socks_http_and_revision_guard(self):
        core = Path(CORE).resolve()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "private"
            run_panel.private_directory(state)
            dns = DNSStub().start()
            server = ThreadingHTTPServer(("127.0.0.1", 0), HTTPHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            self.addCleanup(dns.close)
            policy = run_panel.initial_policy("192.0.2.53")
            policy["dns"]["resolver"]["native"].update(server="127.0.0.1", server_port=dns.port)
            run_panel.write_private_json(state / "policy.json", policy)
            from werkzeug.security import generate_password_hash
            run_panel.write_private_json(state / "auth.json", {
                "username": "operator", "password_hash": generate_password_hash("synthetic-admin-password"),
                "session_secret": "synthetic-private-session"})
            ports = [free_port() for _ in range(3)]
            while len(set(ports)) != 3:
                ports = [free_port() for _ in range(3)]
            local_node.create_node(state, core, dns_port=ports[0], proxy_port=ports[1], api_port=ports[2],
                                   lan_listen=None, lan_port=2082, lan_user=None,
                                   probe_url=f"http://127.0.0.1:{server.server_port}/",
                                   probe_domain="node.test")
            process = subprocess.Popen([sys.executable, "-B", str(Path(local_node.__file__)), "serve",
                                        "--state-dir", str(state)], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            try:
                for _ in range(120):
                    if process.poll() is not None:
                        self.fail("supervisor exited: " + process.stderr.read()[-1000:])
                    try:
                        view = local_node.send(state, "status")
                        break
                    except (OSError, ValueError):
                        time.sleep(0.1)
                else:
                    self.fail("supervisor did not open its private control socket")
                self.assertEqual(view["transaction"]["status"], "confirmed")
                self.assertTrue(local_node._dns_probe(local_node.load(state / "node/settings.json")))
                self.assertTrue(local_node._socks_probe(local_node.load(state / "node/settings.json")))
                self.assertGreater(dns.received, 0)
                next_policy = json.loads(json.dumps(policy))
                next_policy["exits"]["direct"]["name"] = "Synthetic next revision"
                with self.assertRaises(local_node.NodeError):
                    local_node.send(state, "apply", policy=next_policy, expected_config_sha256="0" * 64)
                pending = local_node.send(state, "apply", policy=next_policy,
                                          expected_config_sha256=view["config_sha256"])
                self.assertEqual(pending["transaction"]["status"], "pending")
                confirmed = local_node.send(state, "confirm", transaction=pending["transaction"]["id"],
                                            expected_config_sha256=pending["config_sha256"])
                self.assertEqual(confirmed["transaction"]["status"], "confirmed")
                self.assertTrue(confirmed["integrity"])
                self.check_panel(state)
                third_policy = json.loads(json.dumps(next_policy))
                third_policy["exits"]["direct"]["name"] = "Another synthetic revision"
                pending = local_node.send(state, "apply", policy=third_policy,
                                          expected_config_sha256=confirmed["config_sha256"])
                tx = local_node.load(state / "node/transaction.json")
                tx["deadline_monotonic"] = time.monotonic() - 1
                local_node.save(state / "node/transaction.json", tx)
                for _ in range(60):
                    view = local_node.send(state, "status")
                    if view["transaction"]["status"] == "rolled_back":
                        break
                    time.sleep(0.1)
                self.assertEqual(view["transaction"]["status"], "rolled_back")
                self.assertEqual(view["config_sha256"], confirmed["config_sha256"])
                pending = local_node.send(state, "apply", policy=third_policy,
                                          expected_config_sha256=view["config_sha256"])
                self.assertEqual(pending["transaction"]["status"], "pending")
                process.terminate()
                process.communicate(timeout=8)
                process = subprocess.Popen([sys.executable, "-B", str(Path(local_node.__file__)), "serve",
                                            "--state-dir", str(state)], stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                for _ in range(120):
                    if process.poll() is not None:
                        self.fail("restarted supervisor exited: " + process.stderr.read()[-1000:])
                    try:
                        view = local_node.send(state, "status")
                        break
                    except (OSError, ValueError):
                        time.sleep(0.1)
                else:
                    self.fail("restarted supervisor did not open its control socket")
                self.assertEqual(view["transaction"]["status"], "rolled_back")
                self.assertEqual(view["config_sha256"], confirmed["config_sha256"])
                self.assertTrue(view["transaction"]["runtime_ready"])
                upstream_port = free_port()
                upstream_config = state / "upstream-test.json"
                upstream_config.write_text(json.dumps({
                    "log": {"level": "warn"},
                    "inbounds": [{"type": "socks", "tag": "upstream", "listen": "127.0.0.1",
                                 "listen_port": upstream_port,
                                 "users": [{"username": "synthetic", "password": "synthetic-private-password"}]}],
                    "outbounds": [{"type": "direct", "tag": "direct"}],
                    "route": {"final": "direct"}}))
                upstream_config.chmod(0o600)
                upstream = subprocess.Popen([str(core), "run", "-c", str(upstream_config)],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    for _ in range(60):
                        try:
                            with socket.create_connection(("127.0.0.1", upstream_port), timeout=0.1):
                                break
                        except OSError:
                            time.sleep(0.1)
                    else:
                        self.fail("synthetic upstream core did not open SOCKS")
                    chained = json.loads(json.dumps(next_policy))
                    chained["exits"]["remote"] = {
                        "name": "Synthetic next hop", "scope": "public", "native": {
                            "type": "socks", "server": "127.0.0.1", "server_port": upstream_port,
                            "username": "synthetic", "password": "synthetic-private-password"}}
                    chained["default_exit"] = "remote"
                    chained["failover"]["priority"] = ["remote"]
                    chained["failover"]["dns_by_exit"] = {"remote": "resolver"}
                    pending = local_node.send(state, "apply", policy=chained,
                                              expected_config_sha256=view["config_sha256"])
                    self.assertEqual(pending["transaction"]["status"], "pending")
                    confirmed_chain = local_node.send(state, "confirm",
                                                      transaction=pending["transaction"]["id"],
                                                      expected_config_sha256=pending["config_sha256"])
                    self.assertEqual(confirmed_chain["transaction"]["status"], "confirmed")
                finally:
                    upstream.terminate()
                    upstream.wait(timeout=5)
                self.assertFalse(local_node._socks_probe(local_node.load(state / "node/settings.json")),
                                 "next-hop failure must break the probe")
            finally:
                process.terminate()
                try:
                    process.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)

    def check_panel(self, state):
        port = free_port()
        process = subprocess.Popen([sys.executable, "-B", str(Path(run_panel.__file__)),
                                    "--mode", "local-node", "--state-dir", str(state),
                                    "--port", str(port)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        base = f"http://127.0.0.1:{port}"
        opener = request.build_opener(request.ProxyHandler({}),
                                      request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        try:
            for _ in range(100):
                try:
                    with opener.open(base + "/login", timeout=1) as response:
                        login = response.read()
                        break
                except (error.URLError, TimeoutError):
                    if process.poll() is not None:
                        self.fail("local-node panel exited: " + process.stderr.read()[-1000:])
                    time.sleep(0.1)
            else:
                self.fail("local-node panel did not open loopback")
            csrf = re.search(rb'name="csrf" value="([^"]+)"', login)
            self.assertIsNotNone(csrf)
            form = parse.urlencode({"username": "operator", "password": "synthetic-admin-password",
                                    "csrf": csrf.group(1).decode()}).encode()
            with opener.open(request.Request(base + "/login", data=form,
                                           headers={"Origin": base}), timeout=5) as response:
                self.assertEqual(response.status, 200)
            for route in ("/overview", "/changes", "/rules", "/help", "/server/access"):
                try:
                    with opener.open(base + route, timeout=5) as response:
                        body = response.read()
                        self.assertEqual(response.status, 200, route)
                        self.assertIn("Локальный proxy/DNS-узел".encode(), body)
                except error.HTTPError as failure:
                    process.terminate()
                    _, diagnostics = process.communicate(timeout=5)
                    self.fail(f"{route}: HTTP {failure.code}; {diagnostics[-2500:]}")
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
