"""Unprivileged Farvater proxy/DNS node using the existing sing-box policy compiler.

The supervisor is independent of the web panel. Its private Unix control
socket accepts only bounded JSON actions. An unconfirmed config is restored
before sing-box starts after any supervisor restart.
"""

from __future__ import annotations

import argparse
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import select
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
from urllib.request import Request, ProxyHandler, build_opener
import uuid

import run_panel


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
MAX_REQUEST = 256 * 1024
ALLOWED_OUTBOUNDS = {"direct", "socks", "http", "shadowsocks", "vless"}
ALLOWED_DNS = {"udp", "tcp", "https", "tls", "hosts"}
TRUSTED_CORE_SHA256 = {
    ("Darwin", "arm64"): "602bce530f540146e8e2feace24a81bdaf7873456203db0cda162811eb44f338",
    ("Darwin", "amd64"): "1f93d60c553fab810ab0a8411cbd8140f63b3bbbd0539d7c124ca95960886db6",
    ("Linux", "arm64"): "6bd105030ade4c8ab7abdeb419f64c63babdf77b08da56aa8aeedaf42101d6c7",
    ("Linux", "amd64"): "9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9",
}
LAN_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class NodeError(ValueError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def node_root(state: Path) -> Path:
    run_panel.private_directory(state)
    return run_panel.private_directory(state / "node")


def load(path: Path):
    return run_panel.private_json(path)


def atomic(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise NodeError("A private node file was replaced by a link")
    temporary = path.with_name("." + path.name + "-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def save(path: Path, value) -> None:
    atomic(path, (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode())


def valid_port(port: int) -> int:
    if type(port) is not int or not 1024 <= port <= 65535:
        raise NodeError("Node ports must be unprivileged integers from 1024 to 65535")
    return port


def private_lan_address(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise NodeError("LAN listener needs one IPv4 address") from None
    if not any(address in network for network in LAN_NETWORKS):
        raise NodeError("LAN listener must use an RFC1918 address")
    return str(address)


def probe_target(url: str, domain: str) -> tuple[str, int, str, bool]:
    try:
        if not isinstance(url, str) or not isinstance(domain, str):
            raise ValueError()
        parsed = urlsplit(url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or parsed.query or len(url) > 1000
                or any(ord(character) <= 32 or ord(character) == 127 for character in url)):
            raise ValueError()
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError()
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", domain):
            raise ValueError()
        if any(not 1 <= len(label) <= 63 for label in domain.split(".")):
            raise ValueError()
    except ValueError:
        raise NodeError("Probe needs an HTTP(S) URL without credentials or query and a DNS name") from None
    return parsed.hostname, port, parsed.path or "/", parsed.scheme == "https"


def validate_settings(value: dict) -> dict:
    expected = {"version", "core", "dns_port", "proxy_port", "api_port", "api_secret",
                "lan", "probe_url", "probe_domain"}
    if not isinstance(value, dict) or set(value) != expected or value["version"] != 1:
        raise NodeError("Invalid local node settings")
    ports = [valid_port(value[key]) for key in ("dns_port", "proxy_port", "api_port")]
    lan = value["lan"]
    if lan is not None:
        if not isinstance(lan, dict) or set(lan) != {"listen", "port", "username", "password"}:
            raise NodeError("Invalid authenticated LAN listener")
        private_lan_address(lan["listen"])
        ports.append(valid_port(lan["port"]))
        if (not isinstance(lan["username"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", lan["username"])
                or not isinstance(lan["password"], str) or len(lan["password"]) < 12
                or any(c in lan["password"] for c in "\r\n\0")):
            raise NodeError("LAN access requires a username and a private password of at least 12 characters")
    if len(set(ports)) != len(ports):
        raise NodeError("Node listen ports must be distinct")
    if not isinstance(value["core"], str):
        raise NodeError("Native core path must be a string")
    core = Path(value["core"])
    if not core.is_absolute() or core.is_symlink() or not core.is_file():
        raise NodeError("Native core must be an absolute regular file")
    info = core.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022 or not info.st_mode & 0o100:
        raise NodeError("Native core must be executable, owned by this user and not group-writable")
    from download_core import DIGESTS, VERSION
    import platform
    architecture = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(
        platform.machine().lower())
    expected_archive = DIGESTS.get((platform.system(), architecture))
    expected_core = TRUSTED_CORE_SHA256.get((platform.system(), architecture))
    manifest = run_panel.private_json(core.parent / "manifest.json", max_bytes=4096)
    expected_platform = platform.system().lower() + "-" + str(architecture)
    if (not expected_archive or not expected_core or not isinstance(manifest, dict) or manifest.get("version") != VERSION
            or manifest.get("platform") != expected_platform or manifest.get("archive_sha256") != expected_archive
            or not isinstance(manifest.get("files"), dict)):
        raise NodeError("Native core manifest does not match this pinned platform")
    with core.open("rb") as source:
        observed_core = hashlib.file_digest(source, "sha256").hexdigest()
    if observed_core != expected_core or observed_core != manifest["files"].get("sing-box"):
        raise NodeError("Native core is not the pinned release binary")
    if not isinstance(value["api_secret"], str) or len(value["api_secret"]) < 32:
        raise NodeError("Invalid local control secret")
    probe_target(value["probe_url"], value["probe_domain"])
    return value


def validate_local_policy(policy: dict) -> None:
    if (not isinstance(policy, dict) or not isinstance(policy.get("exits"), dict)
            or not isinstance(policy.get("dns"), dict)
            or not isinstance(policy.get("profiles"), list)
            or any(not isinstance(profile, dict) for profile in policy["profiles"])):
        raise NodeError("Expected a complete Farvater policy")
    if any(not isinstance(policy.get(key, {}), dict) for key in ("lan_ingress", "vpn_ingress", "filtering")):
        raise NodeError("Local ingress and filtering settings must be objects")
    if policy.get("incoming_connections"):
        raise NodeError("Native incoming VPN servers are available only on the Linux server")
    for key in ("lan_ingress", "vpn_ingress"):
        if policy.get(key, {}).get("enabled"):
            raise NodeError("Transparent LAN and VPN ingress require the Linux runtime")
    if policy.get("filtering", {}).get("default_enabled"):
        raise NodeError("AdGuard runtime filtering requires the Linux adapter")
    for name, item in policy["exits"].items():
        if (not isinstance(item, dict) or not isinstance(item.get("native"), dict)
                or item["native"].get("type") not in ALLOWED_OUTBOUNDS):
            raise NodeError("Local node exit " + str(name) + " uses a Linux-only or unsupported protocol")
    for name, item in policy["dns"].items():
        if (not isinstance(item, dict) or not isinstance(item.get("native"), dict)
                or item["native"].get("type") not in ALLOWED_DNS):
            raise NodeError("Local node DNS " + str(name) + " uses an unsupported resolver")
    if any(profile.get("source_networks") for profile in policy["profiles"]):
        raise NodeError("Source-network matching requires the Linux ingress adapter")
    from policy import validate_policy
    try:
        problems = [issue for issue in validate_policy(policy) if issue["severity"] == "error"]
    except (TypeError, ValueError, KeyError, AttributeError):
        raise NodeError("Malformed Farvater policy") from None
    if problems:
        raise NodeError("Policy has blocking validation errors; review the draft before applying")


def compile_config(policy: dict, settings: dict) -> tuple[bytes, dict]:
    validate_settings(settings)
    validate_local_policy(policy)
    sys.path.insert(0, str(SRC))
    from candidate_config import build_candidate_config
    built = build_candidate_config(policy, api_secret=settings["api_secret"], default_filtering=False,
                                   dns_port=settings["dns_port"], proxy_port=settings["proxy_port"],
                                   api_port=settings["api_port"])
    config = built["config"]
    lan = settings["lan"]
    if lan is not None:
        tag = "farvater-private-lan-socks"
        config["inbounds"].append({"type": "socks", "tag": tag, "listen": lan["listen"],
                                   "listen_port": lan["port"],
                                   "users": [{"username": lan["username"], "password": lan["password"]}]})
        config["route"]["rules"][:0] = [
            {"inbound": [tag], "port": 53, "action": "hijack-dns"},
            {"inbound": [tag], "action": "sniff", "timeout": "300ms"},
        ]
    return (json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(), built


def core_check(settings: dict, candidate: bytes, root: Path) -> None:
    path = root / (".check-" + uuid.uuid4().hex + ".json")
    try:
        atomic(path, candidate)
        result = subprocess.run([settings["core"], "check", "-c", str(path)],
                                capture_output=True, timeout=20, cwd=Path(settings["core"]).parent)
        if result.returncode:
            atomic(root / "last-check-error.log", result.stderr[:32 * 1024])
            raise NodeError("Native core rejected the policy; private diagnostic was saved")
    except (OSError, subprocess.SubprocessError):
        raise NodeError("Native core validation did not complete") from None
    finally:
        path.unlink(missing_ok=True)


def create_node(state: Path, core: Path, *, dns_port: int, proxy_port: int, api_port: int,
                lan_listen: str | None, lan_port: int, lan_user: str | None,
                probe_url: str, probe_domain: str, ask_password=getpass.getpass) -> Path:
    root = node_root(state)
    if (root / "settings.json").exists():
        raise NodeError("Local node is already initialized")
    policy = run_panel.private_json(state / "policy.json")
    lan = None
    if lan_listen is not None:
        password = ask_password("Private LAN SOCKS password (12+ characters): ")
        repeat = ask_password("Repeat LAN SOCKS password: ")
        if password != repeat:
            raise NodeError("LAN passwords differ")
        lan = {"listen": private_lan_address(lan_listen), "port": lan_port,
               "username": lan_user or "", "password": password}
    settings = {"version": 1, "core": str(core.expanduser()), "dns_port": dns_port,
                "proxy_port": proxy_port, "api_port": api_port,
                "api_secret": secrets.token_urlsafe(48), "lan": lan,
                "probe_url": probe_url, "probe_domain": probe_domain}
    validate_settings(settings)
    config, built = compile_config(policy, settings)
    core_check(settings, config, root)
    save(root / "settings.json", settings)
    atomic(root / "active-config.json", config)
    save(root / "applied-policy.json", policy)
    save(root / "transaction.json", {"id": "bootstrap", "status": "confirmed",
                                     "config_sha256": sha(config), "mode_count": len(built["modes"]),
                                     "runtime_ready": False})
    return root


def install_login_agent(state: Path) -> Path:
    """Install the current user's restartable supervisor without embedding secrets."""
    if sys.platform != "darwin":
        raise NodeError("The login agent is available only on macOS")
    if os.geteuid() == 0:
        raise NodeError("Install the local node as its regular owner, not root")
    state = state.expanduser().resolve(strict=True)
    Supervisor(state)
    agents = Path.home() / "Library/LaunchAgents"
    agents.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = agents.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o022):
        raise NodeError("LaunchAgents must be an owner-controlled directory")
    target = agents / "com.farvater.local-node.plist"
    if target.exists() or target.is_symlink():
        raise NodeError("Farvater login agent already exists; inspect it before replacing")
    root = node_root(state)
    document = {"Label": "com.farvater.local-node",
                "ProgramArguments": [sys.executable, "-B", str(Path(__file__).resolve()),
                                     "serve", "--state-dir", str(state)],
                "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 10,
                "Umask": 0o077,
                "StandardOutPath": str(root / "agent-out.log"),
                "StandardErrorPath": str(root / "agent-error.log")}
    atomic(target, plistlib.dumps(document))
    try:
        result = subprocess.run(["launchctl", "bootstrap", "gui/" + str(os.geteuid()), str(target)],
                                capture_output=True, timeout=15)
        if result.returncode:
            target.unlink(missing_ok=True)
            raise NodeError("launchd did not accept the private supervisor agent")
    except (OSError, subprocess.SubprocessError):
        target.unlink(missing_ok=True)
        raise NodeError("launchd could not install the private supervisor agent") from None
    return target


def _recv(sock: socket.socket, maximum: int = MAX_REQUEST) -> bytes:
    data = bytearray()
    while True:
        part = sock.recv(min(65536, maximum + 1 - len(data)))
        if not part:
            break
        data.extend(part)
        if len(data) > maximum:
            raise NodeError("Local request exceeds its size limit")
    return bytes(data)


def send(state: Path, action: str, **fields) -> dict:
    path = state / "node" / "control.sock"
    payload = json.dumps({"action": action, "fields": fields}, ensure_ascii=False).encode()
    if len(payload) > MAX_REQUEST:
        raise NodeError("Local request exceeds its size limit")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(65 if action in ("apply", "confirm", "rollback") else 5)
        channel.connect(str(path))
        channel.sendall(payload)
        channel.shutdown(socket.SHUT_WR)
        response = json.loads(_recv(channel, MAX_REQUEST))
    if not isinstance(response, dict) or type(response.get("ok")) is not bool:
        raise NodeError("Local node returned an invalid response")
    if not response["ok"]:
        raise NodeError(response.get("message") if isinstance(response.get("message"), str)
                        else "Local node rejected the action")
    if not isinstance(response.get("result"), dict):
        raise NodeError("Local node returned an invalid result")
    return response["result"]


class LocalNodeAdapter:
    """Four bounded actions for the existing panel; other Linux controls fail explicitly."""

    def __init__(self, state: Path):
        self.state = state

    def call(self, action: str, **fields):
        from candidate_remote import RemoteError
        if action not in ("status", "apply", "confirm", "rollback"):
            raise RemoteError("Этот раздел требует сервера Linux. Локальный узел поддерживает DNS, SOCKS/HTTP и правила выходов.")
        try:
            return send(self.state, action, **fields)
        except (OSError, ValueError, TimeoutError):
            raise RemoteError("Локальный узел не ответил или отклонил действие. Перечитайте состояние; применение не повторялось автоматически.") from None


def _api_ready(settings: dict, *, timeout: float = 12) -> bool:
    deadline = time.monotonic() + timeout
    address = f"http://127.0.0.1:{settings['api_port']}/version"
    opener = build_opener(ProxyHandler({}))
    while time.monotonic() < deadline:
        try:
            req = Request(address, headers={"Authorization": "Bearer " + settings["api_secret"]})
            with opener.open(req, timeout=0.5) as response:
                if isinstance(json.loads(response.read(4096)), dict):
                    return True
        except (OSError, ValueError):
            time.sleep(0.1)
    return False


def _dns_probe(settings: dict) -> bool:
    domain = settings["probe_domain"]
    labels = domain.split(".")
    query_id = secrets.token_bytes(2)
    query = (query_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             + b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels)
             + b"\x00\x00\x01\x00\x01")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.settimeout(3)
            channel.connect(("127.0.0.1", settings["dns_port"]))
            channel.send(query)
            answer = channel.recv(2048)
        return (len(answer) >= 12 and answer[:2] == query_id and answer[2] & 0x80 != 0
                and answer[3] & 0x0F == 0 and int.from_bytes(answer[6:8], "big") > 0)
    except OSError:
        return False


def _socks_probe(settings: dict) -> bool:
    host, port, path, secure = probe_target(settings["probe_url"], settings["probe_domain"])
    def exactly(channel, count):
        data = bytearray()
        while len(data) < count:
            part = channel.recv(count - len(data))
            if not part:
                raise OSError("SOCKS reply ended early")
            data.extend(part)
        return bytes(data)
    try:
        with socket.create_connection(("127.0.0.1", settings["proxy_port"]), timeout=4) as channel:
            channel.settimeout(6)
            channel.sendall(b"\x05\x01\x00")
            if exactly(channel, 2) != b"\x05\x00":
                return False
            try:
                address = ipaddress.ip_address(host)
                destination = (b"\x01" + address.packed if address.version == 4 else b"\x04" + address.packed)
            except ValueError:
                encoded = host.encode("idna")
                if len(encoded) > 255:
                    return False
                destination = b"\x03" + bytes((len(encoded),)) + encoded
            channel.sendall(b"\x05\x01\x00" + destination + port.to_bytes(2, "big"))
            response = exactly(channel, 4)
            if response[:2] != b"\x05\x00":
                return False
            address_type = response[3]
            address_size = 4 if address_type == 1 else 16 if address_type == 4 else None
            if address_type == 3:
                address_size = exactly(channel, 1)[0]
            if address_size is None:
                return False
            remaining = address_size + 2
            exactly(channel, remaining)
            stream = ssl.create_default_context().wrap_socket(channel, server_hostname=host) if secure else channel
            with stream:
                stream.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                status = stream.recv(128).split(b"\r\n", 1)[0].split()
                return len(status) >= 2 and status[1] in (b"200", b"204")
    except (OSError, ValueError, ssl.SSLError):
        return False


def _probe(settings: dict) -> bool:
    return _dns_probe(settings) and _socks_probe(settings)


class Supervisor:
    def __init__(self, state: Path):
        self.root = node_root(state)
        self.settings = validate_settings(load(self.root / "settings.json"))
        self.child: subprocess.Popen | None = None
        self.log = None
        self.stopping = False

    def transaction(self) -> dict:
        return load(self.root / "transaction.json")

    def _stop_child(self) -> None:
        child = self.child
        if child is None:
            return
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=2)
        self.child = None
        (self.root / "runtime.json").unlink(missing_ok=True)
        if self.log is not None:
            self.log.close()
            self.log = None

    def _start_child(self) -> None:
        self.log = (self.root / "core.log").open("wb")
        os.chmod(self.root / "core.log", 0o600)
        command = [self.settings["core"], "run", "-c", str(self.root / "active-config.json")]
        self.child = subprocess.Popen(command, cwd=Path(self.settings["core"]).parent,
                                      stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            identity = self._ps_identity(self.child.pid)
            save(self.root / "runtime.json", {"pid": self.child.pid, "core_sha256": self._core_sha(),
                                              "ps_identity": identity})
        except Exception:
            self._stop_child()
            raise
        if not _api_ready(self.settings) or self.child.poll() is not None:
            self._stop_child()
            raise NodeError("Native core did not open its authenticated loopback control port")

    def _core_sha(self) -> str:
        with Path(self.settings["core"]).open("rb") as core:
            return hashlib.file_digest(core, "sha256").hexdigest()

    def _ps_identity(self, pid: int) -> str:
        result = subprocess.run(["ps", "-p", str(pid), "-o", "uid=", "-o", "lstart=", "-o", "command="],
                                capture_output=True, text=True, timeout=3)
        value = result.stdout.strip()
        if result.returncode or not value.startswith(str(os.geteuid()) + " "):
            raise NodeError("Could not identify the owned native core process")
        return value

    def _remove_stale_child(self) -> None:
        path = self.root / "runtime.json"
        if not path.exists():
            return
        record = load(path)
        pid = record.get("pid")
        if type(pid) is not int or pid <= 1 or record.get("core_sha256") != self._core_sha():
            raise NodeError("Old core PID record is invalid; no process was stopped")
        try:
            group = os.getpgid(pid)
        except ProcessLookupError:
            path.unlink()
            return
        # Never signal a reused PID or another process group. A stale process
        # without this exact command must be resolved by the operator.
        try:
            observed = self._ps_identity(pid)
        except NodeError:
            raise NodeError("Old core PID no longer belongs to Farvater; no process was stopped") from None
        if observed != record.get("ps_identity") or group != pid:
            raise NodeError("Old core PID no longer belongs to Farvater; no process was stopped")
        os.killpg(pid, signal.SIGTERM)
        for _ in range(40):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                path.unlink(missing_ok=True)
                return
            time.sleep(0.1)
        raise NodeError("Old core did not stop; no second core was started")

    def _startup_recover(self) -> None:
        self._remove_stale_child()
        transaction = self.transaction()
        if transaction.get("status") in ("prepared", "pending"):
            previous = self.root / "previous-config.json"
            prior_policy = self.root / "previous-policy.json"
            if (not previous.is_file() or not prior_policy.is_file()
                    or sha(previous.read_bytes()) != transaction.get("previous_sha256")
                    or sha(prior_policy.read_bytes()) != transaction.get("previous_policy_sha256")):
                raise NodeError("Unconfirmed revision has no complete rollback material")
            atomic(self.root / "active-config.json", previous.read_bytes())
            atomic(self.root / "applied-policy.json", prior_policy.read_bytes())
            transaction.update(status="rolled_back", finished_at=time.time(), runtime_ready=False,
                               recovery_reason="supervisor restarted before confirmation",
                               config_sha256=transaction["previous_sha256"],
                               mode_count=transaction.get("previous_mode_count", 1))
            transaction.pop("next_sha256", None)
            save(self.root / "transaction.json", transaction)
        elif transaction.get("status") == "rollback_failed":
            raise NodeError("Previous rollback failed; inspect private state before restarting")

    def _status(self) -> dict:
        transaction = self.transaction()
        config = (self.root / "active-config.json").read_bytes()
        policy = load(self.root / "applied-policy.json")
        from policy_sections import section_hashes
        return {"config_sha256": sha(config), "integrity": sha(config) == transaction.get("next_sha256", transaction.get("config_sha256")),
                "journal_ok": True, "policy_sha256": sha(json.dumps(policy, sort_keys=True).encode()),
                "policy_section_sha256": section_hashes(policy), "transaction": {
                    key: transaction[key] for key in ("id", "status", "deadline", "created_at", "finished_at", "runtime_ready")
                    if key in transaction}, "observed_at": time.time(), "mode_count": transaction.get("mode_count", 1),
                "lan_ingress": {"enabled": self.settings["lan"] is not None},
                "adguard_adapter": False, "vpn_adapter": False,
                "vpn_ingress": {"enabled": False}, "default_filtering": False}

    def _rollback(self, identifier: str, *, reason: str = "operator") -> dict:
        transaction = self.transaction()
        if transaction.get("id") != identifier or transaction.get("status") not in ("prepared", "pending", "rollback_failed"):
            raise NodeError("No matching unconfirmed local revision")
        previous = self.root / "previous-config.json"
        prior_policy = self.root / "previous-policy.json"
        if (not previous.is_file() or not prior_policy.is_file()
                or sha(previous.read_bytes()) != transaction.get("previous_sha256")
                or sha(prior_policy.read_bytes()) != transaction.get("previous_policy_sha256")):
            raise NodeError("Previous local revision cannot be verified")
        self._stop_child()
        atomic(self.root / "active-config.json", previous.read_bytes())
        atomic(self.root / "applied-policy.json", prior_policy.read_bytes())
        try:
            self._start_child()
        except Exception:
            transaction["status"] = "rollback_failed"
            save(self.root / "transaction.json", transaction)
            raise
        transaction.update(status="rolled_back", finished_at=time.time(), runtime_ready=True,
                           recovery_reason=reason, config_sha256=transaction["previous_sha256"],
                           mode_count=transaction.get("previous_mode_count", 1))
        transaction.pop("next_sha256", None)
        save(self.root / "transaction.json", transaction)
        return self._status()

    def _apply(self, fields: dict) -> dict:
        transaction = self.transaction()
        if transaction.get("status") in ("prepared", "pending", "rollback_failed"):
            raise NodeError("Complete or roll back the current local revision first")
        old = (self.root / "active-config.json").read_bytes()
        if fields.get("expected_config_sha256") != sha(old):
            raise NodeError("Local core changed; refresh its status before applying")
        policy = fields.get("policy")
        config, built = compile_config(policy, self.settings)
        core_check(self.settings, config, self.root)
        identifier = uuid.uuid4().hex
        atomic(self.root / "previous-config.json", old)
        prior_policy = (self.root / "applied-policy.json").read_bytes()
        atomic(self.root / "previous-policy.json", prior_policy)
        transaction = {"id": identifier, "status": "prepared", "created_at": time.time(),
                       "deadline": time.time() + 120, "deadline_monotonic": time.monotonic() + 120,
                       "previous_sha256": sha(old), "next_sha256": sha(config),
                       "previous_policy_sha256": sha(prior_policy),
                       "previous_mode_count": transaction.get("mode_count", 1),
                       "mode_count": len(built["modes"]), "runtime_ready": False}
        save(self.root / "transaction.json", transaction)
        atomic(self.root / "active-config.json", config)
        save(self.root / "applied-policy.json", policy)
        transaction["status"] = "pending"
        save(self.root / "transaction.json", transaction)
        try:
            self._stop_child()
            self._start_child()
            if not _probe(self.settings):
                raise NodeError("Local DNS/HTTP path did not pass")
        except Exception:
            self._rollback(identifier, reason="failed apply")
            raise NodeError("Local apply failed and the previous core was restored") from None
        transaction["runtime_ready"] = True
        save(self.root / "transaction.json", transaction)
        return self._status()

    def _confirm(self, fields: dict) -> dict:
        transaction = self.transaction()
        current = (self.root / "active-config.json").read_bytes()
        if (transaction.get("status") != "pending" or transaction.get("id") != fields.get("transaction")
                or not transaction.get("runtime_ready") or fields.get("expected_config_sha256") != sha(current)
                or transaction.get("next_sha256") != sha(current)
                or time.monotonic() >= transaction["deadline_monotonic"]):
            raise NodeError("Local revision is stale or has expired")
        if self.child is None or self.child.poll() is not None or not _probe(self.settings):
            raise NodeError("Local DNS/HTTP path is not healthy; allow rollback")
        if time.monotonic() >= transaction["deadline_monotonic"]:
            raise NodeError("Local revision expired while checking connectivity")
        transaction.update(status="confirmed", finished_at=time.time(), config_sha256=sha(current))
        transaction.pop("next_sha256", None)
        save(self.root / "transaction.json", transaction)
        (self.root / "previous-config.json").unlink(missing_ok=True)
        (self.root / "previous-policy.json").unlink(missing_ok=True)
        return self._status()

    def dispatch(self, request: dict) -> dict:
        if not isinstance(request, dict) or set(request) != {"action", "fields"} or not isinstance(request["fields"], dict):
            raise NodeError("Invalid local control request")
        action, fields = request["action"], request["fields"]
        if action == "status" and not fields:
            return self._status()
        if action == "apply" and set(fields) == {"policy", "expected_config_sha256"}:
            return self._apply(fields)
        if action == "confirm" and set(fields) == {"transaction", "expected_config_sha256"}:
            return self._confirm(fields)
        if action == "rollback" and set(fields) == {"transaction", "expected_config_sha256"}:
            if fields["expected_config_sha256"] != sha((self.root / "active-config.json").read_bytes()):
                raise NodeError("Local revision changed; refresh status before rollback")
            return self._rollback(fields["transaction"])
        raise NodeError("Unsupported local control action")

    def serve(self) -> None:
        lock_path = self.root / "serve.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise NodeError("Local node supervisor is already running") from None
            self._startup_recover()
            self._start_child()
            if not _probe(self.settings):
                self._stop_child()
                raise NodeError("Local DNS/HTTP path did not pass during startup")
            transaction = self.transaction()
            transaction["runtime_ready"] = True
            save(self.root / "transaction.json", transaction)
            control = self.root / "control.sock"
            if control.exists() or control.is_symlink():
                if not stat.S_ISSOCK(control.lstat().st_mode) or control.lstat().st_uid != os.geteuid():
                    raise NodeError("Local control socket path is occupied")
                control.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(control))
                control.chmod(0o600)
                listener.listen(8)
                listener.setblocking(False)
                try:
                    while not self.stopping:
                        transaction = self.transaction()
                        if (transaction.get("status") == "pending"
                                and time.monotonic() >= transaction["deadline_monotonic"]):
                            self._rollback(transaction["id"], reason="confirmation deadline expired")
                        if self.child is None or self.child.poll() is not None:
                            raise NodeError("Local core stopped; supervisor must restart and recover")
                        readable, _, _ = select.select([listener], [], [], 0.5)
                        if not readable:
                            continue
                        channel, _ = listener.accept()
                        with channel:
                            channel.settimeout(35)
                            try:
                                result = self.dispatch(json.loads(_recv(channel)))
                                response = {"ok": True, "result": result}
                            except (OSError, ValueError, json.JSONDecodeError):
                                response = {"ok": False, "message": "Local action was not confirmed; read current status before retrying"}
                            try:
                                channel.sendall(json.dumps(response, ensure_ascii=False).encode())
                            except OSError:
                                pass  # The caller must read status after an ambiguous response.
                finally:
                    control.unlink(missing_ok=True)
                    self._stop_child()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "serve", "status", "install-agent"))
    parser.add_argument("--state-dir", type=Path, help="Same private state directory as run_panel.py")
    parser.add_argument("--core", type=Path, help="Verified sing-box binary for init")
    parser.add_argument("--dns-port", type=int, default=5301)
    parser.add_argument("--proxy-port", type=int, default=2081)
    parser.add_argument("--api-port", type=int, default=9091)
    parser.add_argument("--lan-listen", help="Optional RFC1918 address for authenticated SOCKS ingress")
    parser.add_argument("--lan-port", type=int, default=2082)
    parser.add_argument("--lan-user")
    parser.add_argument("--probe-domain", default="example.com")
    parser.add_argument("--probe-url", default="https://example.com/")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() == 0:
            raise NodeError("Run the portable local node as a regular user, not with sudo")
        state = (args.state_dir or run_panel.default_state_dir()).expanduser()
        if args.action == "init":
            if args.core is None:
                raise NodeError("init requires --core from the pinned downloader")
            run_panel.ensure_state(state)
            create_node(state, args.core, dns_port=args.dns_port, proxy_port=args.proxy_port,
                        api_port=args.api_port, lan_listen=args.lan_listen,
                        lan_port=args.lan_port, lan_user=args.lan_user,
                        probe_url=args.probe_url, probe_domain=args.probe_domain)
            print("Local node is initialized. Start its supervisor before using the panel.")
        elif args.action == "serve":
            supervisor = Supervisor(state)
            signal.signal(signal.SIGTERM, lambda *_: setattr(supervisor, "stopping", True))
            signal.signal(signal.SIGINT, lambda *_: setattr(supervisor, "stopping", True))
            supervisor.serve()
        elif args.action == "install-agent":
            path = install_login_agent(state)
            print("Local supervisor login agent installed: " + str(path))
        else:
            result = send(state, args.action)
            print(json.dumps(result, ensure_ascii=False))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, "Farvater local node: " + str(error) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
