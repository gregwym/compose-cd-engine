#!/usr/bin/env python3
"""Unprivileged multi-target GitHub webhook: can only wake fixed local targets."""
import hashlib
import hmac
import json
import os
import socket
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

MAX_BODY = 262144
POLICY_KEYS = {"repository", "repository_id", "workflow", "branch", "route", "signal_socket", "secret_file"}


def load_policy(path):
    """Only administrator-owned local configuration selects a wake target."""
    policy = json.loads(Path(path).read_text())
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        raise ValueError("invalid receiver policy keys")
    if (type(policy["repository_id"]) is not int or policy["repository_id"] <= 0
            or any(not isinstance(policy[k], str) or not policy[k]
                   for k in policy if k != "repository_id")
            or len(policy["repository"].split("/")) != 2
            or not policy["workflow"].startswith(".github/workflows/")
            or not policy["route"].startswith("/hooks/")
            or not policy["signal_socket"].startswith("/")
            or not policy["secret_file"].startswith("/")
            or ".." in Path(policy["signal_socket"]).parts):
        raise ValueError("invalid receiver policy")
    return policy


def validate(body, signature, event, secret, now=None, policy=None):
    if policy is None:
        raise ValueError("an administrator-owned target policy is required")
    if len(secret) < 32 or len(body) > MAX_BODY:
        raise ValueError("size/secret")
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("signature")
    payload = json.loads(body)
    if event == "ping":
        if payload.get("repository", {}).get("id") != policy["repository_id"]:
            raise ValueError("ping repository mismatch")
        return None
    if event != "workflow_run":
        raise ValueError("event")
    repo, run = payload["repository"], payload["workflow_run"]
    if repo["id"] != policy["repository_id"] or repo["full_name"] != policy["repository"]:
        raise ValueError("repository mismatch")
    if (payload["action"] != "completed" or run["status"] != "completed"
            or run["conclusion"] != "success" or run["head_branch"] != policy["branch"]
            or run["event"] not in ("push", "workflow_dispatch", "schedule")
            or run["path"] != policy["workflow"]
            or run["head_repository"]["id"] != policy["repository_id"]):
        return None  # Authenticated but irrelevant event: acknowledge without wake.
    stamp = datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00")).timestamp()
    age = (time.time() if now is None else now) - stamp
    if not -60 <= age <= 600:
        raise ValueError("expired event; worker polling recovers missed updates")
    return hashlib.sha256(body).digest()


class Receiver(BaseHTTPRequestHandler):
    policies = {}
    seen = {}

    def log_message(self, *_args):
        pass  # Never log request bodies, headers, or credentials.

    def do_POST(self):
        if self.path not in self.policies:
            self.send_error(404)
            return
        policy, secret = self.policies[self.path]
        try:
            if len(self.headers.get_all("Content-Length", [])) != 1:
                raise ValueError("ambiguous body size")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                raise ValueError("body size")
            self.connection.settimeout(5)
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("truncated body")
            key = validate(body, self.headers.get("X-Hub-Signature-256", ""),
                           self.headers.get("X-GitHub-Event", ""), secret,
                           policy=policy)
            if key is None:
                self.send_response(200)
                self.end_headers()
                return
            now = time.monotonic()
            self.__class__.seen = {k: t for k, t in self.seen.items() if now - t < 660}
            event_key = hashlib.sha256(self.path.encode() + b"\x00" + key).digest()
            if event_key not in self.seen:
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
                    client.sendto(b"check", policy["signal_socket"])
                if len(self.seen) < 4096:
                    self.seen[event_key] = now
            self.send_response(202)
            self.end_headers()
        except (ValueError, KeyError, TypeError, UnicodeError):
            self.send_error(403)
        except OSError:
            self.send_error(503)  # GitHub redelivery or periodic reconciliation.


class BoundedHTTPServer(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", default="/etc/compose-cd/routes",
                        help="directory of administrator-owned per-route JSON policies")
    parser.add_argument("--container", action="store_true",
                        help="listen on container interfaces; requires isolated Docker network, no published ports")
    args = parser.parse_args()
    configs = sorted(Path(args.config_dir).glob("*.json"))
    routes = {}
    for path in configs:
        st = path.stat()
        if path.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
            raise SystemExit(f"route policy must be root-owned and not group/world-writable: {path.name}")
        policy = load_policy(path)
        secret_file = policy.pop("secret_file")
        secret_path = Path(secret_file)
        if not secret_path.is_file() or secret_path.is_symlink():
            raise SystemExit(f"route secret missing or symlinked: {path.name}")
        st = secret_path.stat()
        if st.st_uid != 0 or st.st_gid != int(os.environ.get("CD_SECRET_GID", "30002")) or st.st_mode & 0o027:
            raise SystemExit(f"route secret must use root and the configured secret GID, mode 0440 or stricter: {path.name}")
        secret = secret_path.read_bytes().strip()
        if len(secret) < 32:
            raise SystemExit(f"route secret too short: {path.name}")
        if policy["route"] in routes:
            raise SystemExit("duplicate webhook route")
        routes[policy["route"]] = (policy, secret)
    Receiver.policies = routes
    os.umask(0o077)
    # Bind address is local administrator configuration, never webhook input.
    address = ("0.0.0.0" if args.container else
               os.environ.get("CD_BIND_ADDRESS", "127.0.0.1"))
    import ipaddress
    if not args.container and (not ipaddress.ip_address(address).is_private or address == "0.0.0.0"):
        raise SystemExit("receiver requires a private host/proxy bridge address")
    BoundedHTTPServer((address, 18791), Receiver).serve_forever()
