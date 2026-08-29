#!/usr/bin/env python3
"""Fail-closed KeyCourier host receiver.

The process either performs a read-only readiness check or accepts one
encrypted package on stdin. Both verbs emit content-free receipts. Paths,
reload actions and adapter parameters come only from owner-controlled host
configuration.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable


MAX_PACKAGE_BYTES = 128 * 1024
MAX_CONFIG_BYTES = 256 * 1024
MAX_SECRET_BYTES = 64 * 1024
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VARIABLE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")


class HostAgentError(Exception):
    pass


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise HostAgentError("invalid identifier")
    return value


def _absolute_path(value: object) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise HostAgentError("invalid path")
    path = Path(value)
    if ".." in path.parts or len(value) > 1024:
        raise HostAgentError("invalid path")
    return path


def _fixed_name(value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise HostAgentError("invalid fixed name")
    return value


def _parse_date(value: object) -> datetime:
    if not isinstance(value, str):
        raise HostAgentError("invalid date")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise HostAgentError("invalid date") from error
    if parsed.tzinfo is None:
        raise HostAgentError("invalid date")
    return parsed.astimezone(timezone.utc)


def _assert_regular_owner_file(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise HostAgentError("unsafe file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise HostAgentError("unsafe permissions")


def _assert_safe_parent(path: Path) -> None:
    parent = path.parent
    metadata = parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HostAgentError("unsafe parent")
    if metadata.st_uid != os.getuid():
        raise HostAgentError("unsafe owner")


def _atomic_write(path: Path, value: bytes, *, keep_previous: bool = True) -> None:
    if not value:
        raise HostAgentError("empty value")
    _assert_safe_parent(path)
    if path.exists() or path.is_symlink():
        _assert_regular_owner_file(path)
        if keep_previous:
            previous = Path(str(path) + ".keycourier.previous")
            _write_new_file(previous, path.read_bytes())
    _write_new_file(path, value)


def _write_new_file(path: Path, value: bytes) -> None:
    _assert_safe_parent(path)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".keycourier-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() or path.is_symlink():
            _assert_regular_owner_file(path)
        os.replace(temporary, path)
        os.chmod(path, 0o600, follow_symlinks=False)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _dotenv_value(secret: bytes) -> str:
    if not secret or len(secret) > MAX_SECRET_BYTES or b"\0" in secret or b"\n" in secret or b"\r" in secret:
        raise HostAgentError("invalid dotenv value")
    try:
        value = secret.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HostAgentError("invalid dotenv value") from error
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _install_dotenv(path: Path, variable: str, secret: bytes) -> None:
    encoded = _dotenv_value(secret)
    existing = b""
    if path.exists() or path.is_symlink():
        _assert_regular_owner_file(path)
        existing = path.read_bytes()
        if len(existing) > 1024 * 1024:
            raise HostAgentError("dotenv too large")
    try:
        text = existing.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HostAgentError("invalid dotenv") from error
    replacement = f'{variable}="{encoded}"'
    lines = text.splitlines()
    output = []
    replaced = False
    for line in lines:
        if line.startswith(f"{variable}="):
            if not replaced:
                output.append(replacement)
                replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(replacement)
    _atomic_write(path, ("\n".join(output) + "\n").encode("utf-8"))
    if replacement not in path.read_text(encoding="utf-8").splitlines():
        raise HostAgentError("verification failed")


def run_command(arguments: list[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            arguments,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HostAgentError("fixed command failed") from error
    if len(result.stdout) > 8192:
        raise HostAgentError("fixed command response too large")
    return result.stdout


class AdapterInstaller:
    ALLOWED_TYPES = {
        "dotenv",
        "dockerSecret",
        "systemdCredential",
        "macKeychain",
        "launchdEnvironment",
    }

    def __init__(
        self,
        runner: Callable[..., bytes] = run_command,
        *,
        uid: int | None = None,
    ) -> None:
        self.runner = runner
        self.uid = os.getuid() if uid is None else uid

    @classmethod
    def validate(cls, adapter: object) -> dict:
        if not isinstance(adapter, dict) or adapter.get("type") not in cls.ALLOWED_TYPES:
            raise HostAgentError("unsupported adapter")
        adapter_type = adapter["type"]
        if adapter_type in {"dotenv", "dockerSecret", "systemdCredential", "launchdEnvironment"}:
            _absolute_path(adapter.get("path"))
        if adapter_type in {"dotenv", "launchdEnvironment"}:
            _fixed_name(adapter.get("variable"), VARIABLE)
        if adapter_type == "dockerSecret":
            _absolute_path(adapter.get("composeFile"))
            _fixed_name(adapter.get("service"), SERVICE)
        if adapter_type == "systemdCredential":
            _fixed_name(adapter.get("credentialName"), SERVICE)
            _fixed_name(adapter.get("service"), SERVICE)
        if adapter_type == "macKeychain":
            _absolute_path(adapter.get("helperPath"))
            _fixed_name(adapter.get("service"), LABEL)
            _fixed_name(adapter.get("account"), LABEL)
        if adapter_type == "launchdEnvironment":
            _fixed_name(adapter.get("label"), LABEL)
        return adapter

    def install(self, adapter: dict, secret: bytes) -> None:
        adapter = self.validate(adapter)
        if not secret or len(secret) > MAX_SECRET_BYTES or b"\0" in secret:
            raise HostAgentError("invalid secret")
        adapter_type = adapter["type"]
        if adapter_type == "dotenv":
            _install_dotenv(_absolute_path(adapter["path"]), adapter["variable"], secret)
            return
        if adapter_type == "dockerSecret":
            destination = _absolute_path(adapter["path"])
            _atomic_write(destination, secret)
            if destination.read_bytes() != secret:
                raise HostAgentError("verification failed")
            self.runner(
                [
                    self._docker_path(),
                    "compose",
                    "-f",
                    str(_absolute_path(adapter["composeFile"])),
                    "up",
                    "-d",
                    "--no-deps",
                    adapter["service"],
                ],
                input_bytes=None,
            )
            return
        if adapter_type == "systemdCredential":
            destination = _absolute_path(adapter["path"])
            _assert_safe_parent(destination)
            descriptor, temporary_name = tempfile.mkstemp(prefix=".keycourier-credential-", dir=destination.parent)
            os.close(descriptor)
            temporary = Path(temporary_name)
            temporary.unlink()
            try:
                self.runner(
                    [
                        "/usr/bin/systemd-creds",
                        "encrypt",
                        f"--name={adapter['credentialName']}",
                        "-",
                        str(temporary),
                    ],
                    input_bytes=secret,
                )
                _atomic_write(destination, temporary.read_bytes())
            finally:
                temporary.unlink(missing_ok=True)
            self.runner(
                ["/usr/bin/systemctl", "try-restart", adapter["service"]],
                input_bytes=None,
            )
            return
        if adapter_type == "macKeychain":
            response = self.runner(
                [adapter["helperPath"], "upsert", adapter["service"], adapter["account"]],
                input_bytes=secret,
            )
            try:
                verified = json.loads(response).get("verified") is True
            except (json.JSONDecodeError, AttributeError) as error:
                raise HostAgentError("keychain verification failed") from error
            if not verified:
                raise HostAgentError("keychain verification failed")
            return
        if adapter_type == "launchdEnvironment":
            _install_dotenv(_absolute_path(adapter["path"]), adapter["variable"], secret)
            self.runner(
                [
                    "/bin/launchctl",
                    "kickstart",
                    "-k",
                    f"gui/{self.uid}/{adapter['label']}",
                ],
                input_bytes=None,
            )
            return
        raise HostAgentError("unsupported adapter")

    @staticmethod
    def _docker_path() -> str:
        for candidate in ("/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/usr/bin/docker"):
            if os.access(candidate, os.X_OK):
                return candidate
        return "/usr/bin/docker"


@dataclass(frozen=True)
class HostConfiguration:
    target_id: str
    identity_path: Path
    replay_path: Path
    profiles: dict[str, dict]

    @classmethod
    def from_dict(cls, value: object) -> "HostConfiguration":
        if not isinstance(value, dict) or value.get("schemaVersion") != 1:
            raise HostAgentError("invalid configuration")
        target_id = _identifier(value.get("targetID"))
        identity_path = _absolute_path(value.get("identityPath"))
        replay_value = value.get("replayPath", str(identity_path.parent / "replay"))
        replay_path = _absolute_path(replay_value)
        profiles_value = value.get("profiles")
        if not isinstance(profiles_value, dict) or len(profiles_value) > 128:
            raise HostAgentError("invalid profiles")
        profiles: dict[str, dict] = {}
        for profile_id, adapter in profiles_value.items():
            profiles[_identifier(profile_id)] = AdapterInstaller.validate(adapter)
        return cls(target_id, identity_path, replay_path, profiles)

    @classmethod
    def load(cls, path: Path) -> "HostConfiguration":
        _assert_regular_owner_file(path)
        data = path.read_bytes()
        if len(data) > MAX_CONFIG_BYTES:
            raise HostAgentError("configuration too large")
        try:
            return cls.from_dict(json.loads(data))
        except json.JSONDecodeError as error:
            raise HostAgentError("invalid configuration") from error


class ReplayStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def claim(self, request_id: uuid.UUID) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = self.root.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise HostAgentError("unsafe replay store")
        os.chmod(self.root, 0o700)
        marker = self.root / f"{str(request_id).lower()}.processed"
        try:
            descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError as error:
            raise HostAgentError("replayed request") from error
        os.close(descriptor)


def _age_path() -> str:
    for candidate in (
        str(Path.home() / ".local" / "bin" / "age"),
        "/usr/local/bin/age",
        "/opt/homebrew/bin/age",
        "/usr/bin/age",
    ):
        if os.access(candidate, os.X_OK):
            return candidate
    raise HostAgentError("age unavailable")


def _validate_window(created: datetime, expires: datetime, now: datetime) -> None:
    if expires <= created or expires - created > timedelta(hours=24):
        raise HostAgentError("invalid expiry")
    if created > now + timedelta(minutes=5) or now > expires:
        raise HostAgentError("expired request")


def _receipt(package: dict, status: str, code: str) -> dict:
    return {
        "requestID": package["requestID"],
        "targetID": package["targetID"],
        "consumerID": package["consumerID"],
        "status": status,
        "code": code,
    }


def safe_check(configuration: HostConfiguration) -> dict:
    """Validate host readiness without accepting or installing a secret."""
    _assert_regular_owner_file(configuration.identity_path)
    run_command([_age_path(), "--version"])
    return {
        "schemaVersion": 1,
        "targetID": configuration.target_id,
        "status": "ready",
        "code": "hostReady",
    }


def deliver(package_data: bytes, configuration: HostConfiguration) -> dict:
    if not package_data or len(package_data) > MAX_PACKAGE_BYTES:
        raise HostAgentError("invalid package")
    try:
        package = json.loads(package_data)
    except json.JSONDecodeError as error:
        raise HostAgentError("invalid package") from error
    if not isinstance(package, dict) or package.get("schemaVersion") != 1:
        raise HostAgentError("invalid package")
    request_id = uuid.UUID(package.get("requestID", ""))
    target_id = _identifier(package.get("targetID"))
    consumer_id = _identifier(package.get("consumerID"))
    if target_id != configuration.target_id or consumer_id not in configuration.profiles:
        raise HostAgentError("unapproved destination")
    created = _parse_date(package.get("createdAt"))
    expires = _parse_date(package.get("expiresAt"))
    _validate_window(created, expires, datetime.now(timezone.utc))
    ciphertext = base64.b64decode(package.get("ciphertext", ""), validate=True)
    if not ciphertext or len(ciphertext) > MAX_PACKAGE_BYTES:
        raise HostAgentError("invalid ciphertext")
    ReplayStore(configuration.replay_path).claim(request_id)
    plaintext = run_command(
        [_age_path(), "--decrypt", "--identity", str(configuration.identity_path)],
        input_bytes=ciphertext,
    )
    if not plaintext or len(plaintext) > MAX_PACKAGE_BYTES:
        raise HostAgentError("invalid payload")
    try:
        payload = json.loads(plaintext)
    except json.JSONDecodeError as error:
        raise HostAgentError("invalid payload") from error
    if not isinstance(payload, dict) or payload.get("schemaVersion") != 1:
        raise HostAgentError("invalid payload")
    if (
        payload.get("requestID") != package["requestID"]
        or payload.get("targetID") != target_id
        or payload.get("consumerID") != consumer_id
        or payload.get("createdAt") != package["createdAt"]
        or payload.get("expiresAt") != package["expiresAt"]
    ):
        raise HostAgentError("package binding mismatch")
    _identifier(payload.get("secretID"))
    secret = base64.b64decode(payload.get("secret", ""), validate=True)
    AdapterInstaller().install(configuration.profiles[consumer_id], secret)
    return _receipt(package, "verified", "consumerVerified")


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("verb")
    parsed = parser.parse_args(arguments)
    config_path = Path.home() / ".config" / "keycourier" / "host.json"
    if parsed.verb == "check":
        try:
            receipt = safe_check(HostConfiguration.load(config_path))
        except Exception:
            return 1
        sys.stdout.write(json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n")
        return 0
    if parsed.verb != "deliver":
        return 64
    package_data = sys.stdin.buffer.read(MAX_PACKAGE_BYTES + 1)
    package: dict | None = None
    try:
        decoded = json.loads(package_data)
        if isinstance(decoded, dict):
            package = decoded
    except json.JSONDecodeError:
        pass
    try:
        receipt = deliver(package_data, HostConfiguration.load(config_path))
    except Exception:
        if not package or not all(key in package for key in ("requestID", "targetID", "consumerID")):
            return 65
        receipt = _receipt(package, "failed", "deliveryFailed")
    sys.stdout.write(json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n")
    return 0 if receipt["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
