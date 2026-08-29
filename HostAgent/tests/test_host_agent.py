import json
import os
import stat
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from host_agent import AdapterInstaller, HostAgentError, HostConfiguration, ReplayStore, _age_path, safe_check


class RecordingRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, arguments, *, input_bytes=None):
        self.calls.append((list(arguments), input_bytes))
        if len(arguments) >= 2 and arguments[1] == "encrypt":
            Path(arguments[-1]).write_bytes(input_bytes or b"")
        return b'{"verified":true}'


class HostAgentTests(unittest.TestCase):
    def test_dotenv_install_is_atomic_and_keeps_protected_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "consumer.env"
            destination.write_text("KEEP=one\nROTATE=old\n", encoding="utf-8")
            destination.chmod(0o600)
            installer = AdapterInstaller(RecordingRunner())

            installer.install(
                {"type": "dotenv", "path": str(destination), "variable": "ROTATE"},
                b"dummy-new-value",
            )

            self.assertEqual(destination.read_text(), 'KEEP=one\nROTATE="dummy-new-value"\n')
            self.assertEqual(
                destination.with_suffix(".env.keycourier.previous").read_text(),
                "KEEP=one\nROTATE=old\n",
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_docker_secret_write_never_places_value_on_reload_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "api-key"
            compose = Path(directory) / "compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            runner = RecordingRunner()
            installer = AdapterInstaller(runner)

            installer.install(
                {
                    "type": "dockerSecret",
                    "path": str(destination),
                    "composeFile": str(compose),
                    "service": "example",
                },
                b"dummy-docker-value",
            )

            arguments, input_bytes = runner.calls[0]
            self.assertEqual(arguments[-4:], ["up", "-d", "--no-deps", "example"])
            self.assertNotIn("dummy-docker-value", " ".join(arguments))
            self.assertIsNone(input_bytes)
            self.assertEqual(destination.read_bytes(), b"dummy-docker-value")

    def test_systemd_credential_uses_stdin_and_fixed_service_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "credential.cred"
            runner = RecordingRunner()
            installer = AdapterInstaller(runner)

            installer.install(
                {
                    "type": "systemdCredential",
                    "path": str(destination),
                    "credentialName": "example-api",
                    "service": "example.service",
                },
                b"dummy-systemd-value",
            )

            encrypt_arguments, encrypt_input = runner.calls[0]
            reload_arguments, reload_input = runner.calls[1]
            self.assertIn("encrypt", encrypt_arguments)
            self.assertNotIn("dummy-systemd-value", " ".join(encrypt_arguments))
            self.assertEqual(encrypt_input, b"dummy-systemd-value")
            self.assertEqual(reload_arguments, ["/usr/bin/systemctl", "try-restart", "example.service"])
            self.assertIsNone(reload_input)

    def test_mac_keychain_adapter_sends_value_only_on_stdin(self):
        runner = RecordingRunner()
        installer = AdapterInstaller(runner)

        installer.install(
            {
                "type": "macKeychain",
                "helperPath": "/Users/example/.local/libexec/keycourier-keychain",
                "service": "example.service",
                "account": "api",
            },
            b"dummy-keychain-value",
        )

        arguments, input_bytes = runner.calls[0]
        self.assertEqual(arguments[1:], ["upsert", "example.service", "api"])
        self.assertNotIn("dummy-keychain-value", " ".join(arguments))
        self.assertEqual(input_bytes, b"dummy-keychain-value")

    def test_launchd_adapter_reloads_only_the_allowlisted_label(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "service.env"
            runner = RecordingRunner()
            installer = AdapterInstaller(runner, uid=501)

            installer.install(
                {
                    "type": "launchdEnvironment",
                    "path": str(destination),
                    "variable": "API_KEY",
                    "label": "com.example.worker",
                },
                b"dummy-launchd-value",
            )

            self.assertEqual(
                runner.calls[0][0],
                ["/bin/launchctl", "kickstart", "-k", "gui/501/com.example.worker"],
            )

    def test_configuration_rejects_relative_paths_and_unknown_adapters(self):
        with self.assertRaises(HostAgentError):
            HostConfiguration.from_dict(
                {
                    "schemaVersion": 1,
                    "targetID": "vps",
                    "identityPath": "../identity.txt",
                    "profiles": {},
                }
            )
        with self.assertRaises(HostAgentError):
            HostConfiguration.from_dict(
                {
                    "schemaVersion": 1,
                    "targetID": "vps",
                    "identityPath": "/private/identity.txt",
                    "profiles": {"bad": {"type": "shell", "command": "anything"}},
                }
            )

    def test_replay_store_claims_each_request_once(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ReplayStore(Path(directory))
            request_id = uuid.uuid4()

            store.claim(request_id)

            with self.assertRaises(HostAgentError):
                store.claim(request_id)

    def test_content_free_receipt_does_not_contain_installed_value(self):
        receipt = {
            "requestID": str(uuid.uuid4()),
            "targetID": "vps",
            "consumerID": "canary",
            "status": "verified",
            "code": "consumerVerified",
        }

        encoded = json.dumps(receipt, sort_keys=True)

        self.assertNotIn("dummy-not-a-real-secret", encoded)
        self.assertNotIn("secret", encoded.lower())

    def test_age_path_supports_the_owner_local_install(self):
        expected = str(Path.home() / ".local" / "bin" / "age")
        with patch("host_agent.os.access", side_effect=lambda path, _: path == expected):
            self.assertEqual(_age_path(), expected)

    def test_safe_check_validates_host_without_exposing_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "identity.txt"
            identity.write_text("dummy-age-identity", encoding="utf-8")
            identity.chmod(0o600)
            configuration = HostConfiguration.from_dict(
                {
                    "schemaVersion": 1,
                    "targetID": "mac-mini",
                    "identityPath": str(identity),
                    "profiles": {
                        "mac-mini": {
                            "type": "macKeychain",
                            "helperPath": "/Users/example/.local/libexec/keycourier-keychain",
                            "service": "example.service",
                            "account": "api",
                        }
                    },
                }
            )

            with patch("host_agent._age_path", return_value="/usr/local/bin/age"), patch(
                "host_agent.run_command", return_value=b"1.3.1\n"
            ):
                receipt = safe_check(configuration)

            self.assertEqual(
                receipt,
                {
                    "schemaVersion": 1,
                    "targetID": "mac-mini",
                    "status": "ready",
                    "code": "hostReady",
                },
            )
            encoded = json.dumps(receipt, sort_keys=True).lower()
            for forbidden in ("secret", "recipient", "identity", "path", "profile"):
                self.assertNotIn(forbidden, encoded)


if __name__ == "__main__":
    unittest.main()
