#!/usr/bin/env python3
"""Fixed-policy Docker Compose runner. Signals carry no commands or target data."""
import fcntl
import json
import os
import re
import shutil
import socket
import subprocess
import tarfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

TARGET_DIR = Path(os.environ.get("CD_TARGETS_DIR", "/etc/compose-cd/targets"))
STATE_DIR = Path(os.environ.get("CD_STATE_DIR", "/var/lib/compose-cd/state"))
DOCKER = "/usr/local/bin/docker"
SIGNAL_GID = int(os.environ.get("CD_SIGNAL_GID", "0"))


def load_target(path):
    st = path.stat(follow_symlinks=False)
    if not path.is_file() or path.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError("target policy must be a root-owned, non-writable regular file")
    cfg = json.loads(path.read_text())
    required = {"id", "socket", "strategy", "compose_dir", "project", "files", "services"}
    optional = {"health_timeout", "healthcheck", "rollback", "snapshot_paths", "snapshot_retention", "snapshot_exclude", "candidate_file", "allowed_images", "observe", "healthchecks", "tcp_checks", "same_digest", "privacy_scan", "management", "require_readiness"}
    if not isinstance(cfg, dict) or set(cfg) - required - optional or not required <= set(cfg):
        raise ValueError("invalid target keys")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", cfg["id"]):
        raise ValueError("invalid target id")
    if cfg["strategy"] != "compose":
        raise ValueError("unsupported strategy")
    if not Path(cfg["compose_dir"]).is_absolute() or not cfg["compose_dir"].startswith("/"):
        raise ValueError("compose_dir must be absolute")
    if not isinstance(cfg["project"], str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", cfg["project"]):
        raise ValueError("invalid Compose project")
    if (not isinstance(cfg["files"], list) or not cfg["files"]
            or any(not isinstance(x, str) or not x or x.startswith("/") or ".." in Path(x).parts for x in cfg["files"])):
        raise ValueError("invalid Compose files")
    if (not isinstance(cfg["services"], list) or not cfg["services"]
            or any(not isinstance(x, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", x) for x in cfg["services"])):
        raise ValueError("invalid Compose services")
    if not Path(cfg["socket"]).is_absolute() or not cfg["socket"].startswith("/"):
        raise ValueError("socket must be absolute")
    cfg.setdefault("health_timeout", 120)
    cfg.setdefault("rollback", True)
    if type(cfg["health_timeout"]) is not int or not 10 <= cfg["health_timeout"] <= 1800:
        raise ValueError("invalid health timeout")
    if type(cfg["rollback"]) is not bool:
        raise ValueError("rollback must be boolean")
    directory = Path(cfg["compose_dir"])
    paths = cfg.get("snapshot_paths", [])
    if (not isinstance(paths, list)
            or any(not isinstance(x, str) or not x.startswith("/") for x in paths)
            or len(paths) != len(set(paths))):
        raise ValueError("snapshot_paths must be unique absolute paths")
    directory_resolved = directory.resolve(strict=True)
    path_names = []
    for raw in paths:
        candidate = Path(raw)
        if candidate.is_symlink() or not candidate.is_dir():
            raise ValueError("snapshot paths must be existing directories, not symlinks")
        resolved = candidate.resolve(strict=True)
        if directory_resolved not in resolved.parents:
            raise ValueError("snapshot paths must be below compose_dir")
        st = resolved.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("snapshot paths must be root-owned and not group/world-writable")
        if resolved.name in path_names:
            raise ValueError("snapshot path basenames must be unique")
        path_names.append(resolved.name)
    excluded = cfg.get("snapshot_exclude", [])
    if (not isinstance(excluded, list) or any(not isinstance(x, str) or not x
            or x in (".", "..") or "/" in x for x in excluded)):
        raise ValueError("snapshot_exclude must contain top-level entry names")
    cfg["snapshot_exclude"] = excluded
    cfg["snapshot_paths"] = paths
    cfg.setdefault("snapshot_retention", 2)
    if type(cfg["snapshot_retention"]) is not int or not 1 <= cfg["snapshot_retention"] <= 10:
        raise ValueError("snapshot_retention must be between 1 and 10")
    hc = cfg.get("healthcheck")
    if hc is not None and (not isinstance(hc, list) or not hc or any(not isinstance(x, str) or not x for x in hc)):
        raise ValueError("healthcheck must be a fixed argv list")
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("Compose directory unavailable or unsafe")
    st = directory.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError("Compose directory must be root-owned and not group/world-writable")
    for name in cfg["files"]:
        candidate = directory / name
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError("Compose file unavailable or unsafe")
        st = candidate.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("Compose files must be root-owned and not group/world-writable")
    if not isinstance(cfg.get("candidate_file"), str) or not cfg["candidate_file"].startswith("/var/lib/compose-cd/inbox/"):
        raise ValueError("fixed candidate_file required")
    if set(cfg.get("allowed_images", {})) != set(cfg["services"]):
        raise ValueError("one approved image repository per service required")
    cfg.setdefault("observe", True)
    cfg.setdefault("require_readiness", False)
    if type(cfg["require_readiness"]) is not bool:
        raise ValueError("require_readiness must be boolean")
    if "management" in cfg:
        from management.broker import validate_policy
        validate_policy(cfg)
    return cfg


def log_process(cfg, service):
    # Fixed bounded Docker Compose logs, no caller-controlled options.
    argv = [DOCKER, "compose", "--project-directory", cfg["compose_dir"], "-p", cfg["project"]]
    for name in cfg["files"]:
        argv += ["-f", str(Path(cfg["compose_dir"]) / name)]
    argv += ["logs", "--no-color", "--no-log-prefix", "--tail", "100", "--since", "5m", service]
    return subprocess.Popen(argv, cwd=cfg["compose_dir"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def command(cfg, *args, timeout=1200, env=None, compose_files=None):
    argv = [DOCKER, "compose", "--project-directory", cfg["compose_dir"], "-p", cfg["project"]]
    files = list(cfg["files"]) if compose_files is None else list(compose_files)
    active = STATE_DIR / (cfg["id"] + ".active.json")
    if compose_files is None and active.exists():
        files.append(str(active))
    for name in files:
        path = Path(name)
        argv += ["-f", str(path if path.is_absolute() else Path(cfg["compose_dir"]) / path)]
    argv += list(args)
    return subprocess.run(argv, cwd=cfg["compose_dir"], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout, check=True, env=env)


def current_containers(cfg):
    found = {}
    for service in cfg["services"]:
        result = command(cfg, "ps", "-q", service, timeout=30)
        ids = result.stdout.decode("utf-8", "replace").split()
        if len(ids) > 1:
            raise RuntimeError("scaled services are not supported by this target adapter")
        found[service] = None
        if ids:
            out = subprocess.run([DOCKER, "inspect", "--format",
                                  "{{.Id}} {{.Image}} {{.Config.Image}}", ids[0]],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=30, check=True).stdout.decode().strip().split(" ", 2)
            if len(out) != 3:
                raise RuntimeError("could not record previous container image")
            found[service] = dict(container=out[0], image_id=out[1], image_ref=out[2])
    return found


def wait_healthy(cfg, services=None):
    services = cfg["services"] if services is None else services
    deadline = time.monotonic() + cfg["health_timeout"]
    last = {}
    while time.monotonic() < deadline:
        all_ok = True
        for service in services:
            ids = command(cfg, "ps", "-q", service, timeout=30).stdout.decode().split()
            if len(ids) != 1:
                all_ok = False
                last[service] = "missing or multiple containers"
                continue
            inspect = subprocess.run([DOCKER, "inspect", "--format",
                                      "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", ids[0]],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=30, check=True).stdout.decode().strip().split()
            status = inspect[0] if inspect else "unknown"
            health = inspect[1] if len(inspect) > 1 else "unknown"
            if status != "running" or health == "unhealthy" or health == "starting":
                all_ok = False
                last[service] = f"{status}/{health}"
                continue
            healthcheck = cfg.get("healthchecks", {}).get(service, cfg.get("healthcheck"))
            ports = cfg.get("tcp_checks", {}).get(service, [])
            if cfg.get("require_readiness") and health != "healthy" and not healthcheck:
                # TCP listeners alone do not establish application readiness.
                all_ok = False
                last[service] = "readiness probe required"
                continue
            if ports:
                probe = "import socket; [socket.create_connection(('127.0.0.1',p),3).close() for p in " + repr(ports) + "]"
                result = subprocess.run([DOCKER, "run", "--rm", "--pull", "never", "--read-only",
                    "--cap-drop", "ALL", "--pids-limit", "16", "--memory", "32m", "--network", "container:" + ids[0],
                    "python:3.12-slim-bookworm", "python3", "-c", probe], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                if result.returncode:
                    all_ok = False
                    last[service] = "TCP listener probe failed"
            if healthcheck:
                result = subprocess.run([DOCKER, "exec", ids[0], *healthcheck],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=15)
                if result.returncode:
                    all_ok = False
                    last[service] = "custom check failed"
        if all_ok:
            return
        time.sleep(3)
    raise RuntimeError("health check timeout: " + json.dumps(last, sort_keys=True))


def snapshot_data(cfg):
    paths = cfg["snapshot_paths"]
    if not paths:
        return None
    paths = [Path(p).resolve(strict=True) for p in paths]
    excluded = set(cfg.get("snapshot_exclude", []))
    data_size = 0
    for path in paths:
        if path.is_file():
            data_size += path.stat().st_size
        else:
            for root, _dirs, files in os.walk(path, followlinks=False):
                if Path(root) == path:
                    _dirs[:] = [x for x in _dirs if x not in excluded]
                    files = [x for x in files if x not in excluded]
                for name in files:
                    item = Path(root) / name
                    if not item.is_symlink():
                        data_size += item.stat().st_size
    # Keep room for the snapshot, staged extraction, and failed-data copy
    # when rollback restores into separately mounted application directories.
    needed = 3 * data_size + 128 * 1024 * 1024
    if shutil.disk_usage(STATE_DIR).free < needed:
        raise RuntimeError("insufficient disk space for target data snapshot")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = STATE_DIR / cfg["id"] / "snapshots"
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    archive = directory / f"{stamp}-{time.time_ns()}.tar.gz"
    temporary = archive.with_suffix(".next")
    with tarfile.open(temporary, "w:gz", compresslevel=1) as tar:
        for path in paths:
            tar.add(path, arcname=path.name, recursive=False)
            for child in path.iterdir():
                if child.name not in excluded:
                    tar.add(child, arcname=path.name + "/" + child.name, recursive=True)
    os.chmod(temporary, 0o600)
    temporary.replace(archive)
    return archive


def restore_data(cfg, archive):
    if archive is None:
        return
    stage = STATE_DIR / cfg["id"] / "restore" / str(time.time_ns())
    stage.mkdir(parents=True, mode=0o700)
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                target = Path(member.name)
                if target.is_absolute() or ".." in target.parts:
                    raise RuntimeError("unsafe path in deployment snapshot")
            tar.extractall(stage, filter="data")
        failed_root = STATE_DIR / cfg["id"] / "failed" / str(time.time_ns())
        failed_root.mkdir(parents=True, mode=0o700)
        for raw in cfg["snapshot_paths"]:
            path = Path(raw)
            saved = stage / path.name
            failed = failed_root / path.name
            if path.is_symlink() or not path.is_dir():
                raise RuntimeError("refusing to restore an unsafe snapshot path")
            excluded = set(cfg.get("snapshot_exclude", []))
            failed.mkdir(mode=0o700)
            for child in path.iterdir():
                if child.name in excluded:
                    continue
                if child.is_dir() and not child.is_symlink():
                    shutil.copytree(child, failed / child.name, symlinks=True)
                else:
                    shutil.copy2(child, failed / child.name, follow_symlinks=False)
            for child in path.iterdir():
                if child.name in excluded:
                    continue
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            for child in saved.iterdir():
                if child.name in excluded:
                    continue
                if child.is_dir() and not child.is_symlink():
                    shutil.copytree(child, path / child.name, symlinks=True, dirs_exist_ok=True)
                else:
                    shutil.copy2(child, path / child.name, follow_symlinks=False)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def prune_snapshots(cfg):
    if not cfg["snapshot_paths"]:
        return
    directory = STATE_DIR / cfg["id"] / "snapshots"
    archives = sorted(directory.glob("*.tar.gz"), reverse=True)
    for old in archives[cfg["snapshot_retention"]:]:
        old.unlink()


def restore(cfg, previous, snapshot=None):
    if not cfg["rollback"]:
        return
    command(cfg, "stop", *cfg["services"], timeout=300)
    restore_data(cfg, snapshot)
    restore_services = []
    rollback_images = {}
    for service, old in previous.items():
        if old is None:
            # The service did not exist before this deployment; remove only that
            # newly-created service, leaving named volumes and unrelated services.
            command(cfg, "rm", "-sf", service, timeout=300)
            continue
        restore_services.append(service)
        rollback_ref = f"compose-cd-rollback:{cfg['id']}-{service.lower()}"
        subprocess.run([DOCKER, "image", "tag", old["image_id"], rollback_ref],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=60, check=True)
        rollback_images[service] = rollback_ref
    if restore_services:
        override = STATE_DIR / (cfg["id"] + ".rollback.json")
        override.write_text(json.dumps({"services": {
            service: {"image": rollback_images[service]} for service in restore_services
        }}) + "\n")
        os.chmod(override, 0o600)
        command(cfg, "up", "-d", "--no-deps", "--pull", "never", *restore_services,
                timeout=1200, compose_files=[*cfg["files"], str(override)])
        wait_healthy(cfg, restore_services)
        write_json(STATE_DIR / (cfg["id"] + ".active.json"), {"services": {
            service: {"image": rollback_images[service]} for service in restore_services
        }})
        override.unlink(missing_ok=True)


def write_json(path, value):
    tmp = path.with_suffix(path.suffix + ".next")
    tmp.write_text(json.dumps(value, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def candidate(cfg):
    path = Path(cfg["candidate_file"])
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError("candidate unavailable or unsafe")
    value = json.loads(path.read_text())
    if (set(value) != {"schema_version", "project", "order", "source_sha", "mode", "images"}
            or value["schema_version"] != 1 or value["project"] != cfg["id"]
            or value["mode"] not in ("check", "deploy")
            or not isinstance(value["order"], list) or len(value["order"]) != 2
            or any(type(x) is not int or x < 1 for x in value["order"])
            or not re.fullmatch("[a-f0-9]{40}", value["source_sha"])
            or set(value["images"]) != set(cfg["services"])):
        raise ValueError("invalid fixed-target candidate")
    if cfg.get("same_digest") and len(set(value["images"].values())) != 1:
        raise ValueError("deployment group must use one digest")
    for service, image in value["images"].items():
        if not re.fullmatch(re.escape(cfg["allowed_images"][service]) + r"@sha256:[a-f0-9]{64}", image):
            raise ValueError("unapproved image source")
    return value


def receipt(cfg, value, status, **extra):
    data = {"project": cfg["id"], "status": status, "updated_at": int(time.time()),
            "order": value["order"], "source_sha": value["source_sha"],
            "requested_images": value["images"], **extra}
    deployed_path = STATE_DIR / (cfg["id"] + ".deployed.json")
    if status in ("success", "no_change"):
        write_json(deployed_path, dict(data))
    elif deployed_path.exists():
        data["last_deployment"] = json.loads(deployed_path.read_text())
    write_json(STATE_DIR / (cfg["id"] + ".receipt"), data)
    return data


def preflight_space(cfg):
    size = 0
    excluded = set(cfg.get("snapshot_exclude", []))
    for raw in cfg["snapshot_paths"]:
        base = Path(raw)
        for root, dirs, files in os.walk(base, followlinks=False):
            if Path(root) == base:
                dirs[:] = [x for x in dirs if x not in excluded]
                files = [x for x in files if x not in excluded]
            for name in files:
                p = Path(root) / name
                if not p.is_symlink():
                    size += p.stat().st_size
    if shutil.disk_usage(STATE_DIR).free < 3 * size + 256 * 1024 * 1024:
        raise RuntimeError("insufficient free space before service stop")


def scan_image(cfg, image):
    if not cfg.get("privacy_scan", False):
        return
    import hashlib
    path = Path("/etc/compose-cd/scan-fingerprints.json")
    st = path.stat()
    if path.is_symlink() or st.st_uid != 0 or st.st_mode & 0o077:
        raise ValueError("unsafe private scan configuration")
    raw = path.read_bytes()
    needles = [x.encode() for x in json.loads(raw)]
    if not needles or any(len(x) < 5 for x in needles):
        raise ValueError("invalid private scan fingerprints")
    key = hashlib.sha256(image.encode() + b"\0" + raw).hexdigest()
    cache = STATE_DIR / "scanned"
    cache.mkdir(mode=0o700, exist_ok=True)
    marker = cache / key
    if marker.exists():
        return
    keep = max(map(len, needles)) - 1
    process = subprocess.Popen([DOCKER, "image", "save", image], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    try:
        tail = b""
        while True:
            chunk = process.stdout.read(1024 * 1024)
            if not chunk:
                break
            data = tail + chunk
            if any(needle in data for needle in needles):
                raise RuntimeError("private deployment fingerprint found in image")
            tail = data[-keep:] if keep else b""
        if process.wait(timeout=30):
            raise RuntimeError("image privacy scan failed")
        marker.write_text("passed\n")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()


def deploy(cfg):
    STATE_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    # The host's small disk makes global serialization intentional.
    with (STATE_DIR / "global.lock").open("a") as global_lock:
        fcntl.flock(global_lock, fcntl.LOCK_EX)
        value = candidate(cfg)
        prior_path = STATE_DIR / (cfg["id"] + ".receipt")
        prior = json.loads(prior_path.read_text()) if prior_path.exists() else {}
        if value["order"] < prior.get("order", [0, 0]):
            raise ValueError("stale deployment candidate")
        if value["order"] == prior.get("order") and prior.get("status") in ("success", "no_change", "rolled_back", "rollback_failed", "recovery_required"):
            return
        if cfg["observe"] or value["mode"] == "check":
            receipt(cfg, value, "observed" if cfg["observe"] else "checked")
            return
        recovery_latch = STATE_DIR / (cfg["id"] + ".recovery-required.json")
        if "management" in cfg and recovery_latch.exists():
            raise RuntimeError("administrator recovery acknowledgement required")
        previous = current_containers(cfg)
        receipt(cfg, value, "validated")
        wanted_ids = {}
        try:
            preflight_space(cfg)
            for service, image in value["images"].items():
                subprocess.run([DOCKER, "pull", image], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1200, check=True)
                wanted_ids[service] = subprocess.run([DOCKER, "image", "inspect", "--format", "{{.Id}}", image],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30).stdout.decode().strip()
            for image in sorted(set(value["images"].values())):
                scan_image(cfg, image)
            preflight_space(cfg)
        except Exception as exc:
            receipt(cfg, value, "failed", error=type(exc).__name__)
            raise
        if all(previous[k] and previous[k]["image_id"] == wanted_ids[k] for k in cfg["services"]):
            try:
                wait_healthy(cfg)
            except Exception as exc:
                receipt(cfg, value, "failed", error=type(exc).__name__)
                raise
            receipt(cfg, value, "no_change", running_images=wanted_ids)
            return
        active = STATE_DIR / (cfg["id"] + ".active.json")
        next_override = STATE_DIR / (cfg["id"] + ".candidate.json")
        write_json(next_override, {"services": {k: {"image": v} for k, v in value["images"].items()}})
        snapshot = None
        receipt(cfg, value, "deploying")
        try:
            if cfg["snapshot_paths"]:
                command(cfg, "stop", *cfg["services"], timeout=300)
                snapshot = snapshot_data(cfg)
            command(cfg, "up", "-d", "--no-deps", "--no-build", "--pull", "never", *cfg["services"],
                    compose_files=[*cfg["files"], str(next_override)])
            wait_healthy(cfg)
            current = current_containers(cfg)
            if any(not current[k] or current[k]["image_id"] != wanted_ids[k] for k in cfg["services"]):
                raise RuntimeError("running digest does not match candidate")
            write_json(active, json.loads(next_override.read_text()))
        except Exception as exc:
            if not cfg.get("rollback", True):
                if "management" in cfg:
                    write_json(recovery_latch, {"status": "recovery_required", "order": value["order"]})
                receipt(cfg, value, "recovery_required", error=type(exc).__name__)
                raise
            try:
                restore(cfg, previous, snapshot if snapshot else None)
                receipt(cfg, value, "rolled_back", error=type(exc).__name__)
            except Exception as rollback_exc:
                receipt(cfg, value, "rollback_failed", error=type(rollback_exc).__name__)
                raise RuntimeError("deployment and automatic rollback both failed")
            raise
        finally:
            next_override.unlink(missing_ok=True)
        prune_snapshots(cfg)
        # Keep previous image IDs alive even if the upstream mutable tag moved.
        for service, old in previous.items():
            if old:
                subprocess.run([DOCKER, "image", "tag", old["image_id"],
                    f"compose-cd-rollback:{cfg['id']}-{service.lower()}"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=30)
        receipt(cfg, value, "success", running_images=wanted_ids)


def serve(cfg):
    path = Path(cfg["socket"])
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_socket():
            raise RuntimeError("refusing to replace non-socket signal path")
        path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        server.bind(str(path))
        os.chown(path, 0, SIGNAL_GID)
        os.chmod(path, 0o660)
        print(f"ready target={cfg['id']}", flush=True)
        while True:
            payload = server.recv(64)
            if payload != b"check":
                continue
            try:
                deploy(cfg)
                result = json.loads((STATE_DIR / (cfg["id"] + ".receipt")).read_text())
                print(f"check completed target={cfg['id']} status={result.get('status', 'unknown')}", flush=True)
            except BlockingIOError:
                print(f"deployment already running target={cfg['id']}", flush=True)
            except Exception as exc:
                print(f"deployment failed target={cfg['id']} error={type(exc).__name__}", flush=True)


def main():
    if os.geteuid() != 0:
        raise SystemExit("runner requires container-root access to the Docker socket")
    if not (Path("/var/run/docker.sock").exists() and Path(DOCKER).is_file()):
        raise SystemExit("Docker socket or CLI unavailable")
    os.umask(0o077)
    configs = [load_target(p) for p in sorted(TARGET_DIR.glob("*.json"))]
    if not configs:
        print("idle: no fixed deployment targets configured", flush=True)
        threading.Event().wait()
        return
    ids = [x["id"] for x in configs]
    sockets = [x["socket"] for x in configs]
    if len(ids) != len(set(ids)) or len(sockets) != len(set(sockets)):
        raise SystemExit("duplicate target id or socket")
    management_sockets = [x["management"]["socket"] for x in configs if "management" in x]
    if len(management_sockets) != len(set(management_sockets)):
        raise SystemExit("duplicate management socket")
    for cfg in configs:
        if "management" in cfg:
            import sys
            from management.broker import serve as management_serve
            threading.Thread(target=management_serve, args=(cfg, sys.modules[__name__]), daemon=True).start()
        threading.Thread(target=serve, args=(cfg,), daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
