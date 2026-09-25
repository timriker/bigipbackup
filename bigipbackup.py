#!/usr/bin/env python3
"""Weekly UCS backup of BIG-IP devices via iControl REST.

For each device in the config file:
  1. Authenticate and obtain an X-F5-Auth-Token
  2. Create a UCS archive using the async task endpoint
  3. Download it in chunks via the file-transfer endpoint
  4. Delete the UCS from the device
  5. Prune local backups older than the retention window

Config: --config, else the first bigipbackup.yaml found in the current directory,
the script's directory, or /etc/bigipbackup/.

Credentials come from the environment: BIGIP_USER, BIGIP_PASS. Any not already
set are read from bigipbackup.env, looked for in the config file's directory
and then the same search locations.

Exit code is 0 if every device succeeded, 1 otherwise.

Copyright (c) 2026 Tim Riker <timriker@gmail.com>
SPDX-License-Identifier: MIT
"""

import argparse
import logging
import logging.handlers
import os
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests
import urllib3
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

CHUNK_SIZE = 1024 * 1024  # 1 MiB; file-transfer endpoint limit
TOKEN_TIMEOUT = 3600  # seconds
TASK_POLL_INTERVAL = 10  # seconds
TASK_TIMEOUT = 1800  # seconds
TASK_MAX_POLL_ERRORS = 6  # consecutive failed polls before giving up
HTTP_TIMEOUT = 60  # seconds per request

DEFAULT_CONFIG = "bigipbackup.yaml"
DEFAULT_ENV = "bigipbackup.env"
SEARCH_DIRS = [Path.cwd(), Path(__file__).resolve().parent, Path("/etc/bigipbackup")]

log = logging.getLogger("bigipbackup")


class BackupError(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


class BigIP:
    def __init__(self, host, username, password, login_provider="tmos", verify=True):
        self.host = host
        self.base = f"https://{host}"
        self.username = username
        self.password = password
        self.login_provider = login_provider
        self.token = None

        self.session = requests.Session()
        self.session.verify = verify
        # Retries only apply to idempotent methods (GET/PUT/DELETE), never POST.
        retry = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=(502, 503, 504),
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def _url(self, path):
        return f"{self.base}{path}"

    def _request(self, method, path, **kwargs):
        kwargs.setdefault("timeout", HTTP_TIMEOUT)
        resp = self.session.request(method, self._url(path), **kwargs)
        if not resp.ok:
            raise BackupError(
                f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:500]}",
                status=resp.status_code,
            )
        return resp

    def login(self):
        resp = self._request(
            "POST",
            "/mgmt/shared/authn/login",
            json={
                "username": self.username,
                "password": self.password,
                "loginProviderName": self.login_provider,
            },
        )
        self.token = resp.json()["token"]["token"]
        self.session.headers["X-F5-Auth-Token"] = self.token
        # Extend token lifetime so long UCS saves/downloads don't expire it.
        self._request(
            "PATCH",
            f"/mgmt/shared/authz/tokens/{self.token}",
            json={"timeout": TOKEN_TIMEOUT},
        )

    def logout(self):
        if not self.token:
            return
        try:
            self._request("DELETE", f"/mgmt/shared/authz/tokens/{self.token}")
        except Exception as e:  # best effort
            log.debug("%s: token delete failed: %s", self.host, e)
        self.token = None
        self.session.headers.pop("X-F5-Auth-Token", None)

    def hostname(self):
        return self._request("GET", "/mgmt/tm/sys/global-settings").json()["hostname"]

    def list_ucs(self):
        return self._request("GET", "/mgmt/tm/sys/ucs").json().get("items", [])

    def ucs_size(self, name):
        """Size in bytes as reported by the device, or None if not found."""
        for item in self.list_ucs():
            raw = item.get("apiRawValues", {})
            if os.path.basename(raw.get("filename", item.get("name", ""))) == name:
                m = re.match(r"\s*(\d+)", raw.get("file_size", ""))
                return int(m.group(1)) if m else None
        return None

    def save_ucs(self, name):
        resp = self._request(
            "POST", "/mgmt/tm/task/sys/ucs", json={"command": "save", "name": name}
        )
        task_id = resp.json()["_taskId"]
        task_path = f"/mgmt/tm/task/sys/ucs/{task_id}"
        self._request("PUT", task_path, json={"_taskState": "VALIDATING"})

        deadline = time.monotonic() + TASK_TIMEOUT
        errors = 0
        relogged = False
        while time.monotonic() < deadline:
            time.sleep(TASK_POLL_INTERVAL)
            try:
                state = self._request("GET", task_path).json().get("_taskState")
            except (requests.RequestException, BackupError) as e:
                errors += 1
                if errors >= TASK_MAX_POLL_ERRORS:
                    raise BackupError(
                        f"UCS save task {task_id}: giving up after {errors} "
                        f"consecutive poll errors; last: {e}"
                    ) from e
                if getattr(e, "status", None) == 401:
                    # restjavad can restart during a UCS save, dropping all
                    # tokens. Log in again once; a second 401 is fatal.
                    if relogged:
                        raise BackupError(
                            f"UCS save task {task_id}: still unauthorized "
                            f"after re-login: {e}"
                        ) from e
                    log.warning("%s: token lost, logging in again", self.host)
                    relogged = True
                    try:
                        self.login()
                    except (requests.RequestException, BackupError) as le:
                        log.warning("%s: re-login failed: %s", self.host, le)
                    continue
                log.warning("%s: task poll error (will retry): %s", self.host, e)
                continue
            errors = 0
            log.debug("%s: UCS task %s state %s", self.host, task_id, state)
            if state == "COMPLETED":
                return
            if state == "FAILED":
                # The task reports no reason; the cause is only in the device logs.
                raise BackupError(
                    f"UCS save task {task_id} FAILED (see /var/log/ltm and "
                    f"/var/log/restjavad.0.log on the device)"
                )
        raise BackupError(f"UCS save task {task_id} timed out after {TASK_TIMEOUT}s")

    def download_ucs(self, name, dest):
        path = f"/mgmt/shared/file-transfer/ucs-downloads/{name}"
        tmp = dest.with_name(dest.name + ".part")
        start, total = 0, None

        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            while total is None or start < total:
                end = start + CHUNK_SIZE - 1
                if total is not None:
                    end = min(end, total - 1)
                resp = self._request(
                    "GET",
                    path,
                    headers={
                        "Content-Range": f"{start}-{end}/{total or 0}",
                        "Content-Type": "application/octet-stream",
                    },
                )
                crange = resp.headers.get("Content-Range")
                m = re.match(r"(\d+)-(\d+)/(\d+)", crange or "")
                if not m:
                    raise BackupError(f"unexpected Content-Range: {crange!r}")
                r_start, r_end, total = (int(x) for x in m.groups())
                if r_start != start or len(resp.content) != r_end - r_start + 1:
                    raise BackupError(
                        f"chunk mismatch: asked {start}, got {crange} "
                        f"({len(resp.content)} bytes)"
                    )
                f.write(resp.content)
                start = r_end + 1

        written = tmp.stat().st_size
        if written != total:
            raise BackupError(f"downloaded {written} bytes, expected {total}")
        tmp.rename(dest)
        return written

    def delete_ucs(self, name):
        self._request("DELETE", f"/mgmt/tm/sys/ucs/{name}")


def backup_device(host, cfg, username, password, dry_run=False):
    backup_root = Path(cfg["backup_dir"])
    dev = BigIP(
        host,
        username,
        password,
        login_provider=cfg.get("login_provider", "tmos"),
        verify=cfg.get("verify_tls", True),
    )
    try:
        dev.login()
        short = dev.hostname().split(".")[0]
        if dry_run:
            names = [i.get("name") for i in dev.list_ucs()]
            log.info("%s (%s): login OK; UCS on device: %s", host, short, names)
            return

        name = f"{short}_{datetime.now():%Y%m%d-%H%M}.ucs"
        dest_dir = backup_root / short
        dest_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(dest_dir, 0o700)

        log.info("%s: creating %s", host, name)
        created = False
        try:
            dev.save_ucs(name)
            created = True
            reported = dev.ucs_size(name)
            size = dev.download_ucs(name, dest_dir / name)
            if reported is not None and reported != size:
                raise BackupError(f"device reports {reported} bytes, got {size}")
            log.info("%s: saved %s (%d bytes)", host, dest_dir / name, size)
        finally:
            # A failed task may still have left a file behind; try to remove it.
            try:
                dev.delete_ucs(name)
            except Exception as e:
                (log.warning if created else log.debug)(
                    "%s: could not delete %s from device: %s", host, name, e
                )

        prune(dest_dir, cfg.get("retention_weeks", 8))
    finally:
        dev.logout()


def prune(dest_dir, retention_weeks):
    cutoff = time.time() - timedelta(weeks=retention_weeks).total_seconds()
    for p in dest_dir.glob("*.ucs"):
        if p.stat().st_mtime < cutoff:
            log.info("pruning %s", p)
            p.unlink()
    for p in dest_dir.glob("*.ucs.part"):
        p.unlink()


def find_file(name, dirs):
    for d in dirs:
        p = d / name
        if p.is_file():
            return p
    return None


def load_env_file(path):
    """Set KEY=VALUE pairs from path into os.environ without overriding."""
    if path.stat().st_mode & 0o077:
        log.warning("%s is readable by group/others; chmod 600 it", path)
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def setup_logging(log_file, verbose):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    root = logging.getLogger()
    root.setLevel(level)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=5
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--config",
        type=Path,
        help=f"path to config (default: first {DEFAULT_CONFIG} in "
        + ", ".join(str(d) for d in SEARCH_DIRS) + ")",
    )
    ap.add_argument("--device", help="back up only this device from the config")
    ap.add_argument("--dry-run", action="store_true", help="login and list UCS only")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    config_path = args.config or find_file(DEFAULT_CONFIG, SEARCH_DIRS)
    if not config_path:
        ap.error(f"no --config given and no {DEFAULT_CONFIG} found in: "
                 + ", ".join(str(d) for d in SEARCH_DIRS))
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    setup_logging(cfg.get("log_file"), args.verbose)
    log.debug("using config %s", config_path)

    env_path = find_file(DEFAULT_ENV, [config_path.resolve().parent, *SEARCH_DIRS])
    if env_path:
        log.debug("loading credentials from %s", env_path)
        load_env_file(env_path)

    username = os.environ.get("BIGIP_USER")
    password = os.environ.get("BIGIP_PASS")
    if not username or not password:
        log.error("BIGIP_USER and BIGIP_PASS must be set")
        return 2

    if cfg.get("verify_tls", True) is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    devices = cfg.get("devices") or []
    if args.device:
        if args.device not in devices:
            log.error("%s not in config", args.device)
            return 2
        devices = [args.device]

    failed = []
    for host in devices:
        try:
            backup_device(host, cfg, username, password, dry_run=args.dry_run)
        except Exception as e:
            log.error("%s: FAILED: %s", host, e)
            failed.append(host)

    ok = len(devices) - len(failed)
    log.info("summary: %d/%d succeeded%s", ok, len(devices),
             f"; failed: {', '.join(failed)}" if failed else "")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
