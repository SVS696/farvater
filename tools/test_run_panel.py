"""Portable launcher and local Mac/Linux remote-panel acceptance tests."""

import getpass
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib import error, parse, request
import http.cookiejar

import run_panel


RELEASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RELEASE / "src"))


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "private-state"

    def test_state_locations_and_environment_are_bounded(self):
        home = self.root / "home"
        self.assertEqual(run_panel.default_state_dir(platform="darwin", home=home),
                         home / "Library/Application Support/Farvater")
        self.assertEqual(run_panel.default_state_dir(platform="linux", home=home,
                                                      environ={"XDG_STATE_HOME": str(self.root / "xdg")}),
                         self.root / "xdg/farvater")
        with self.assertRaises(ValueError):
            run_panel.default_state_dir(platform="linux", home=home,
                                        environ={"XDG_STATE_HOME": "relative"})
        env = run_panel.panel_environment(self.state, 18081, environ={
            "OKOPY_CANDIDATE_CONTROL": "local", "OKOPY_HEALTH_SOURCE": "local",
            "OKOPY_HTTPS": "1", "OKOPY_UNIX_SOCKET": "/tmp/unsafe.sock",
            "OKOPY_TRUSTED_HOSTS": "*",
        })
        self.assertEqual(env["OKOPY_CANDIDATE_CONTROL"], "ssh")
        self.assertEqual(env["OKOPY_HEALTH_SOURCE"], "ssh")
        self.assertEqual(env["OKOPY_TRUSTED_HOSTS"], "127.0.0.1,localhost")
        self.assertEqual(env["OKOPY_HTTPS"], "0")
        self.assertNotIn("OKOPY_UNIX_SOCKET", env)
        for port in (0, 443, 65536):
            with self.assertRaises(ValueError):
                run_panel.panel_environment(self.state, port)

    def test_interactive_setup_writes_private_state_without_plaintext(self):
        answers = iter(["192.0.2.53", "operator"])
        passwords = iter(["synthetic-admin-password", "synthetic-admin-password"])
        run_panel.ensure_state(self.state, ask=lambda _: next(answers),
                               ask_password=lambda _: next(passwords), interactive=True)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        for name in ("auth.json", "policy.json"):
            self.assertEqual(stat.S_IMODE((self.state / name).stat().st_mode), 0o600)
        auth = json.loads((self.state / "auth.json").read_text())
        self.assertNotIn("synthetic-admin-password", (self.state / "auth.json").read_text())
        from werkzeug.security import check_password_hash
        self.assertTrue(check_password_hash(auth["password_hash"], "synthetic-admin-password"))
        self.assertEqual(auth["username"], "operator")
        self.assertEqual(json.loads((self.state / "policy.json").read_text())["default_exit"], "direct")
        run_panel.ensure_state(self.state, ask=lambda _: self.fail("unexpected prompt"),
                               ask_password=lambda _: self.fail("unexpected password prompt"),
                               interactive=False)

    def test_insecure_state_or_server_settings_are_rejected(self):
        self.state.mkdir(mode=0o700)
        run_panel.write_private_json(self.state / "policy.json", run_panel.initial_policy("192.0.2.53"))
        run_panel.write_private_json(self.state / "auth.json", {
            "username": "owner", "password_hash": "synthetic-hash", "session_secret": "synthetic-key"})
        (self.state / "auth.json").chmod(0o644)
        with self.assertRaises(ValueError):
            run_panel.ensure_state(self.state, interactive=False)
        (self.state / "auth.json").chmod(0o600)
        run_panel.write_private_json(self.state / "server.json", {"version": 1, "targets": [], "sudo_password": ""})
        with self.assertRaises(ValueError):
            run_panel.ensure_state(self.state, interactive=False)
        (self.state / "server.json").unlink()
        (self.state / "server.json").symlink_to(self.root / "other.json")
        with self.assertRaises(OSError):
            run_panel.ensure_state(self.state, interactive=False)

    def test_existing_transport_keeps_known_host_and_no_write_retry(self):
        from candidate_remote import CandidateRemote, RemoteError, FRAME
        from server_connection import ssh
        self.state.mkdir(mode=0o700)
        settings = {"version": 1, "targets": [
            {"host": "first.example.test", "port": 2222, "username": "operator", "identity_file": "/keys/test"},
            {"host": "backup.example.test", "port": 2222, "username": "operator", "identity_file": "/keys/test"},
        ], "sudo_password": "synthetic-sudo-password"}
        run_panel.write_private_json(self.state / "server.json", settings)
        command = ssh(settings["targets"][0])
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertNotIn(settings["sudo_password"], " ".join(command))
        with patch("candidate_remote.subprocess.run", return_value=subprocess.CompletedProcess(
                [], 0, b'{"ok":true,"result":{}}', b"")) as run:
            CandidateRemote(self.state / "server.json").call("status")
        self.assertEqual(run.call_count, 1)
        self.assertTrue(run.call_args.kwargs["input"].startswith(
            settings["sudo_password"].encode() + b"\n" + FRAME + b"\n"))
        with patch("candidate_remote.subprocess.run", side_effect=[
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.TimeoutExpired("ssh", 1),
        ]) as run, self.assertRaises(RemoteError):
            CandidateRemote(self.state / "server.json").call("apply", policy={})
        self.assertEqual(run.call_count, 2)  # one connectivity probe, one write, no retry

    @unittest.skipUnless(importlib.util.find_spec("waitress"), "waitress is not installed")
    def test_actual_loopback_login_and_routes_without_ssh_config(self):
        from werkzeug.security import generate_password_hash
        self.state.mkdir(mode=0o700)
        run_panel.write_private_json(self.state / "policy.json", run_panel.initial_policy("192.0.2.53"))
        run_panel.write_private_json(self.state / "auth.json", {
            "username": "owner", "password_hash": generate_password_hash("synthetic-admin-password"),
            "session_secret": "synthetic-session-secret"})
        with socket.socket() as channel:
            channel.bind(("127.0.0.1", 0))
            port = channel.getsockname()[1]
        ssh_marker = self.root / "ssh-called"
        fake_ssh = self.root / "ssh"
        fake_ssh.write_text("#!/bin/sh\nprintf called > " + str(ssh_marker) + "\nexit 99\n")
        fake_ssh.chmod(0o755)
        env = {**os.environ, "PATH": str(self.root) + os.pathsep + os.environ.get("PATH", "")}
        process = subprocess.Popen(
            [sys.executable, str(RELEASE / "tools/run_panel.py"), "--state-dir", str(self.state),
             "--port", str(port)], cwd=RELEASE, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
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
                        self.fail("local panel exited before opening its port")
                    time.sleep(0.1)
            else:
                self.fail("local panel did not bind loopback")
            csrf = re.search(rb'name="csrf" value="([^"]+)"', login)
            self.assertIsNotNone(csrf)
            form = parse.urlencode({"username": "owner", "password": "synthetic-admin-password",
                                    "csrf": csrf.group(1).decode()}).encode()
            with opener.open(request.Request(base + "/login", data=form,
                         headers={"Origin": base}), timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertTrue(response.url.endswith("/overview"))
            with opener.open(base + "/server/access", timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertIn("Подключение к сетевому ядру".encode(), response.read())
            with self.assertRaises(error.HTTPError) as caught:
                opener.open(request.Request(base + "/login", headers={"Host": "other.example.test"}), timeout=5)
            self.assertEqual(caught.exception.code, 400)
            self.assertFalse(ssh_marker.exists(), "launcher connected to a server before it was configured")
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
