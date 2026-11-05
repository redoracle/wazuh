"""Exercise credential generation, one-time semantics and secret separation."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from scripts import bootstrap

BCRYPT = importlib.util.find_spec("bcrypt") is not None


class BootstrapTests(unittest.TestCase):
    def test_secrets_are_random_and_long(self):
        values = [bootstrap.random_secret() for _ in range(10)]
        self.assertEqual(len(set(values)), len(values))
        self.assertTrue(all(len(value) == 48 for value in values))
        self.assertTrue(all(any(ch.islower() for ch in v) and any(ch.isupper() for ch in v)
                            and any(ch.isdigit() for ch in v) and any(ch in "._-+@%=" for ch in v)
                            for v in values))

    def test_defaults_reject_unknown_keys(self):
        bootstrap.validate_defaults("DASHBOARD_BIND_ADDRESS=127.0.0.1\nAGENT_BIND_ADDRESS=127.0.0.1\nAPI_BIND_ADDRESS=127.0.0.1\n")
        with self.assertRaises(ValueError):
            bootstrap.validate_defaults("API_PASSWORD=danger\n")
        with self.assertRaises(ValueError):
            bootstrap.validate_defaults("DASHBOARD_BIND_ADDRESS=0.0.0.0\n")

    def test_dashboard_api_password_is_json_escaped(self):
        password = 'some"value\\more'
        content = bootstrap.make_dashboard_config(password)
        result = yaml.safe_load(content)
        self.assertEqual(result["hosts"][0][1513629884013]["password"], password)

    def test_manager_cluster_key_is_rendered(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = Path(tmp) / "manager.conf"
            manager.write_text("<cluster><key>{{CLUSTER_KEY}}</key></cluster>\n")
            with patch.object(bootstrap, "MANAGER_TEMPLATE", manager):
                self.assertEqual(bootstrap.make_manager_config("a" * 32), "<cluster><key>" + "a" * 32 + "</key></cluster>\n")
                manager.write_text("no key")
                with self.assertRaises(RuntimeError):
                    bootstrap.make_manager_config("abc")

    @unittest.skipUnless(BCRYPT, "bcrypt is installed in CI")
    def test_indexer_users_hashes_verify(self):
        import bcrypt
        data = yaml.safe_load(bootstrap.make_internal_users("admin unique", "service unique"))
        self.assertEqual(data["_meta"]["type"], "internalusers")
        self.assertTrue(bcrypt.checkpw(b"admin unique", data["admin"]["hash"].encode()))
        self.assertTrue(bcrypt.checkpw(b"service unique", data["kibanaserver"]["hash"].encode()))
        self.assertFalse(bcrypt.checkpw(b"wrong", data["admin"]["hash"].encode()))
        self.assertNotIn("kibanaro", data)

    @unittest.skipUnless(BCRYPT, "bcrypt is installed in CI")
    def test_bootstrap_is_one_time_and_does_not_print_secrets(self):
        from contextlib import redirect_stdout
        import io
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config" / "wazuh_cluster").mkdir(parents=True)
            (root / "config" / "wazuh_cluster" / "wazuh_manager.conf").write_text("<cluster><key>{{CLUSTER_KEY}}</key></cluster>\n")
            (root / ".env.example").write_text("DASHBOARD_BIND_ADDRESS=127.0.0.1\nAGENT_BIND_ADDRESS=127.0.0.1\nAPI_BIND_ADDRESS=127.0.0.1\n")
            with (patch.object(bootstrap, "ROOT", root),
                  patch.object(bootstrap, "ENV", root / ".env"),
                  patch.object(bootstrap, "EXAMPLE", root / ".env.example"),
                  patch.object(bootstrap, "GENERATED", root / "config" / "generated"),
                  patch.object(bootstrap, "MANAGER_TEMPLATE", root / "config" / "wazuh_cluster" / "wazuh_manager.conf")):
                output = io.StringIO()
                with redirect_stdout(output):
                    bootstrap.bootstrap()
                credential_text = (root / ".env").read_text()
                self.assertNotIn("INDEXER_PASSWORD=", output.getvalue())
                self.assertEqual((root / ".env").stat().st_mode & 0o777, 0o600)
                self.assertEqual((root / "config" / "generated").stat().st_mode & 0o777, 0o700)
                self.assertEqual(bootstrap.check_initialized(), [])
                with redirect_stdout(io.StringIO()):
                    bootstrap.bootstrap()
                self.assertEqual((root / ".env").read_text(), credential_text)
                self.assertIn("wazuh-wui", (root / "config" / "generated" / "wazuh.yml").read_text())
                self.assertNotIn("{{CLUSTER_KEY}}", (root / "config" / "generated" / "wazuh_manager.conf").read_text())
                (root / "config" / "generated" / "wazuh.yml").unlink()
                with self.assertRaises(RuntimeError):
                    bootstrap.bootstrap()

    def test_initialization_not_present_on_repository_checkout(self):
        self.assertFalse((bootstrap.ROOT / ".env").exists())


if __name__ == "__main__":
    unittest.main()
