"""Run the Farvater panel for a local node or a Linux server over SSH.

First run creates only private per-user panel state. Server access is configured
later in the panel and uses the existing strict-known-host SSH transport.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys


APP = Path(__file__).resolve().parents[1] / "src" / "web.py"
MAX_STATE_FILE = 256 * 1024
ADMIN_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")


def default_state_dir(*, platform: str | None = None, environ=None, home: Path | None = None) -> Path:
    platform = sys.platform if platform is None else platform
    environ = os.environ if environ is None else environ
    home = Path.home() if home is None else home
    if platform == "darwin":
        return home / "Library" / "Application Support" / "Farvater"
    if platform.startswith("linux"):
        configured = environ.get("XDG_STATE_HOME")
        if configured:
            root = Path(configured).expanduser()
            if not root.is_absolute():
                raise ValueError("XDG_STATE_HOME must be an absolute path")
            return root / "farvater"
        return home / ".local" / "state" / "farvater"
    raise ValueError("This launcher supports macOS and Linux")


def private_directory(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        raise ValueError("State directory must be an absolute path")
    os.umask(0o077)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("State directory must belong to this user and have mode 0700")
    return path


def private_json(path: Path, *, max_bytes: int = MAX_STATE_FILE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > max_bytes):
            raise ValueError(f"{path.name} must be a user-owned regular file with mode 0600")
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{path.name} is too large")
    return json.loads(data)


def write_private_json(path: Path, value) -> None:
    data = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    if len(data) > MAX_STATE_FILE:
        raise ValueError(f"{path.name} is too large")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def initial_policy(dns_address: str) -> dict:
    try:
        address = ipaddress.ip_address(dns_address)
    except ValueError:
        raise ValueError("Enter one IPv4 or IPv6 DNS address") from None
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("Choose a DNS address reachable from the Linux server")
    return {
        "default_exit": "direct",
        "default_dns": "resolver",
        "exits": {"direct": {"name": "Direct", "scope": "public", "native": {"type": "direct"}}},
        "dns": {"resolver": {"name": "Resolver", "scope": "public",
                             "native": {"type": "udp", "server": str(address)}}},
        "profiles": [],
        "failover": {"priority": ["direct"], "dns_by_exit": {"direct": "resolver"},
                     "failures": 3, "recovery_seconds": 30},
        "incoming_connections": [],
    }


def ensure_state(state: Path, *, ask=input, ask_password=getpass.getpass,
                 interactive: bool | None = None, mode: str = "remote") -> None:
    private_directory(state)
    interactive = sys.stdin.isatty() if interactive is None else interactive
    policy_path = state / "policy.json"
    auth_path = state / "auth.json"
    server_path = state / "server.json"
    if policy_path.exists() or policy_path.is_symlink():
        policy = private_json(policy_path)
        if not isinstance(policy, dict) or not {"default_exit", "default_dns", "exits", "dns", "profiles"} <= set(policy):
            raise ValueError("policy.json is not a Farvater policy document")
    else:
        if not interactive:
            raise ValueError("First-run policy setup requires an interactive terminal")
        dns = ask("DNS IP reachable from this node: " if mode == "local-node"
                  else "DNS IP reachable from the Linux server: ").strip()
        write_private_json(policy_path, initial_policy(dns))
    if auth_path.exists() or auth_path.is_symlink():
        auth = private_json(auth_path, max_bytes=32768)
        if (not isinstance(auth, dict) or set(auth) != {"username", "password_hash", "session_secret"}
                or any(not isinstance(value, str) or not value for value in auth.values())):
            raise ValueError("auth.json is not a valid administrator record")
    else:
        if not interactive:
            raise ValueError("First-run administrator setup requires an interactive terminal")
        username = ask("Administrator login [admin]: ").strip() or "admin"
        if not ADMIN_NAME.fullmatch(username):
            raise ValueError("Administrator login must contain only letters, digits, _, . or -")
        password = ask_password("Administrator password (12+ characters): ")
        repeat = ask_password("Repeat administrator password: ")
        if password != repeat or len(password) < 12 or "\x00" in password:
            raise ValueError("Administrator passwords differ or are too short")
        from werkzeug.security import generate_password_hash
        write_private_json(auth_path, {"username": username,
                                       "password_hash": generate_password_hash(password),
                                       "session_secret": secrets.token_urlsafe(48)})
    if server_path.exists() or server_path.is_symlink():
        sys.path.insert(0, str(APP.parent))
        from server_connection import read
        read(server_path)


def panel_environment(state: Path, port: int, *, environ=None) -> dict[str, str]:
    if isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError("Port must be between 1024 and 65535")
    env = dict(os.environ if environ is None else environ)
    env.update({"OKOPY_STATE_DIR": str(state), "OKOPY_SERVER_CONNECTION": str(state / "server.json"),
                "OKOPY_CANDIDATE_CONTROL": "ssh", "OKOPY_HEALTH_SOURCE": "ssh",
                "OKOPY_HTTPS": "0", "OKOPY_PORT": str(port),
                "OKOPY_TRUSTED_HOSTS": "127.0.0.1,localhost"})
    env.pop("OKOPY_UNIX_SOCKET", None)
    return env


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, help="Private state directory (absolute path)")
    parser.add_argument("--port", type=int, default=18081, help="Local loopback HTTP port (default: 18081)")
    parser.add_argument("--mode", choices=("remote", "local-node"), default="remote",
                        help="SSH panel or this computer's independent proxy/DNS node")
    parser.add_argument("--init-only", action="store_true", help="Set up or verify private state, then exit")
    args = parser.parse_args(argv)
    try:
        if os.geteuid() == 0:
            raise ValueError("Run the local panel as a regular user, not with sudo")
        if not APP.is_file():
            raise ValueError("Farvater source tree is incomplete")
        state = args.state_dir or default_state_dir()
        env = panel_environment(state.expanduser(), args.port)
        ensure_state(state, mode=args.mode)
        if args.mode == "local-node":
            import local_node
            local_node.Supervisor(state)  # Validate the pinned core and private node state before binding HTTP.
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(2, f"Farvater: {error}\n")
    if args.init_only:
        print("Private panel state is ready.")
        return 0
    print(f"Open http://127.0.0.1:{args.port}/login", flush=True)
    if args.mode == "local-node":
        import local_node
        from waitress import serve
        os.environ["OKOPY_HEALTH_SOURCE"] = "off"
        sys.path.insert(0, str(APP.parent))
        from web import create_app
        app = create_app(state, local_node.LocalNodeAdapter(state),
                         trusted_hosts=("127.0.0.1", "localhost"), secure_cookie=False)
        app.config["FARVATER_LOCAL_NODE"] = True
        serve(app, host="127.0.0.1", port=args.port, threads=4,
              clear_untrusted_proxy_headers=True)
        return 0
    os.execve(sys.executable, [sys.executable, "-E", "-s", "-B", str(APP)], env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
