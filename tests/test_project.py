"""Offline compatibility and security contracts for the Wazuh release bundle."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = "4.14.9"
SERVICES = {"wazuh.manager", "wazuh.indexer", "wazuh.dashboard"}


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError(f"Duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def read_yaml(path: Path) -> dict:
    doc = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)
    if not isinstance(doc, dict):
        raise ValueError(f"Expected a mapping in {path}")
    return doc


class ComposeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = read_yaml(ROOT / "docker-compose.yml")
        cls.services = cls.compose["services"]

    def test_modern_three_component_topology(self):
        self.assertEqual(set(self.services), SERVICES)
        self.assertEqual(self.compose["name"], "wazuh")
        self.assertNotIn("version", self.compose)
        for s in self.services.values():
            self.assertNotIn("links", s)
            self.assertNotIn("container_name", s)
            self.assertNotIn("privileged", s)
            self.assertNotIn("pid", s)
            self.assertNotIn("cap_add", s)

    def test_wazuh_release_is_coordinated_and_pinned(self):
        for name, service in self.services.items():
            self.assertEqual(service["image"], f"wazuh/wazuh-{name.split('.')[-1]}:{RELEASE}")
            self.assertEqual(service["hostname"], name)

    def test_indexer_is_internal_only(self):
        self.assertNotIn("ports", self.services["wazuh.indexer"])
        self.assertNotIn("expose", self.services["wazuh.indexer"])

    def test_published_ports_are_loopback_by_default(self):
        expected = {
            "wazuh.manager": {1514, 1515, 55000},
            "wazuh.dashboard": {443},
        }
        for name, allowed in expected.items():
            ports = self.services[name]["ports"]
            actual = set()
            for entry in ports:
                self.assertIsInstance(entry, str)
                host, port, container_protocol = entry.rsplit(":", 2)
                self.assertRegex(host, r"^\$\{(?:AGENT|API|DASHBOARD)_BIND_ADDRESS:-127\.0\.0\.1\}$")
                ext = int(port)
                self.assertTrue(container_protocol.endswith("/tcp"))
                actual.add(ext)
            self.assertEqual(actual, allowed)
        self.assertEqual(self.services["wazuh.dashboard"]["ports"][0].rsplit(":", 2)[2], "5601/tcp")

    def test_docker_host_is_not_mounted_into_containers(self):
        for name, service in self.services.items():
            for volume in service.get("volumes", []):
                self.assertNotIn("docker.sock", volume)
                self.assertFalse(volume.startswith("/:"))
                self.assertNotIn("/var/lib/docker/", volume)
                self.assertNotIn("/proc", volume)
                self.assertNotIn("/sys/fs/", volume)

    def test_certificates_and_configs_are_read_only(self):
        seen = 0
        for service in self.services.values():
            for volume in service.get("volumes", []):
                if volume.startswith("./config/"):
                    self.assertTrue(volume.endswith(":ro"), volume)
                    seen += 1
        self.assertGreaterEqual(seen, 12)

    def test_secret_environment_requires_explicit_initialization(self):
        required = {"INDEXER_PASSWORD", "DASHBOARD_PASSWORD", "API_PASSWORD"}
        actual = set()
        for service in self.services.values():
            for key, value in service.get("environment", {}).items():
                if key in required:
                    self.assertTrue(value.startswith("${" + key + ":?Run python3 scripts/bootstrap.py first}"))
                    actual.add(key)
                else:
                    self.assertNotIn("SecretPassword", str(value))
                    self.assertNotIn("MyS3cr37", str(value))
        self.assertEqual(actual, required)

    def test_expected_persistent_volumes_exist(self):
        named = self.compose["volumes"]
        for name in ["wazuh-indexer-data", "wazuh_etc", "wazuh_queue", "wazuh_logs", "filebeat_var"]:
            self.assertIn(name, named)
        for service in self.services.values():
            for volume in service.get("volumes", []):
                source = volume.split(":", 1)[0]
                if source.startswith("./"):
                    self.assertTrue(source.startswith("./config/"))
                else:
                    self.assertIn(source, named)

    def test_certificate_generator_is_release_aligned(self):
        gen = read_yaml(ROOT / "generate-indexer-certs.yml")["services"]["generator"]
        self.assertEqual(gen["image"], "wazuh/wazuh-certs-generator:0.0.4")
        self.assertEqual(gen["environment"]["CERT_TOOL_VERSION"], "4.14")
        self.assertIn("./config/certs.yml:/config/certs.yml:ro", gen["volumes"])

    def test_tls_hostname_contract(self):
        nodes = read_yaml(ROOT / "config/certs.yml")["nodes"]
        self.assertEqual(nodes["indexer"][0]["name"], "wazuh.indexer")
        self.assertEqual(nodes["server"][0]["name"], "wazuh.manager")
        self.assertEqual(nodes["dashboard"][0]["name"], "wazuh.dashboard")
        dashboard = read_yaml(ROOT / "config/wazuh_dashboard/opensearch_dashboards.yml")
        indexer = read_yaml(ROOT / "config/wazuh_indexer/wazuh.indexer.yml")
        self.assertTrue(dashboard["server.ssl.enabled"])
        self.assertEqual(dashboard["opensearch.ssl.verificationMode"], "certificate")
        self.assertTrue(indexer["plugins.security.ssl.http.enabled"])
        self.assertEqual(indexer["discovery.type"], "single-node")

    def test_manager_config_matches_indexer_and_has_unique_cluster_key_placeholder(self):
        config = (ROOT / "config/wazuh_cluster/wazuh_manager.conf").read_text(encoding="utf-8")
        self.assertEqual(config.count("{{CLUSTER_KEY}}"), 1)
        self.assertNotIn("aa093264ef885029653eea20dfcf51ae", config)
        self.assertIsNotNone(ET.fromstring("<root>" + config + "</root>"))

    def test_no_public_range_static_ips(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertNotIn("ipv4_address", compose)
        self.assertNotIn("172.13.0.", compose)
        self.assertNotIn("network_mode: host", compose)


class RepositoryContracts(unittest.TestCase):
    def test_configuration_example_has_no_secrets(self):
        example = (ROOT / ".env.example").read_text()
        self.assertIn("AGENT_BIND_ADDRESS=127.0.0.1", example)
        self.assertIn("DASHBOARD_BIND_ADDRESS=127.0.0.1", example)
        self.assertIn("API_BIND_ADDRESS=127.0.0.1", example)
        for word in ["PASSWORD", "SECRET", "KEY="]:
            self.assertNotIn(word, example)

    def test_gitignore_covers_local_credentials(self):
        ignored = (ROOT / ".gitignore").read_text()
        for item in (".env", "config/generated/", "config/wazuh_indexer_ssl_certs/"):
            self.assertIn(item, ignored)

    def test_ci_permissions_and_actions_are_pinned(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertRegex(workflow, r"actions/checkout@[0-9a-f]{40}")
        self.assertRegex(workflow, r"actions/setup-python@[0-9a-f]{40}")
        self.assertIn("3.14", workflow)
        self.assertIn("3.11", workflow)
        self.assertIn("3.13", workflow)
        self.assertIn("docker compose -f docker-compose.yml config --quiet", workflow)

    def test_required_repository_guides_exist(self):
        paths = [
            "README.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SUPPORT.md", "NOTICE.md", "LICENSE",
            "docs/ARCHITECTURE.md", "docs/DEPLOYMENT.md", "docs/OPERATIONS.md", "docs/UPGRADING.md",
            ".github/ISSUE_TEMPLATE/bug_report.yml", ".github/ISSUE_TEMPLATE/feature_request.yml",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file(), path)

    def test_readme_has_current_version_and_no_historical_terminology(self):
        readme = (ROOT / "README.md").read_text().lower()
        self.assertIn("4.14.9", readme)
        self.assertIn("scripts/bootstrap.py", readme)
        self.assertNotIn("legacy", readme)
        self.assertNotIn("second audit", readme)
        self.assertNotIn("audit", readme)
        self.assertNotIn("3.10.2", readme)

    def test_local_markdown_links_resolve(self):
        links = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
        count = 0
        for document in (ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md")), ROOT / "CONTRIBUTING.md"):
            for link in links.findall(document.read_text(encoding="utf-8")):
                if link.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                filepart, _, fragment = link.partition("#")
                target = (document.parent / filepart).resolve()
                self.assertTrue(target.is_relative_to(ROOT.resolve()), link)
                self.assertTrue(target.exists(), f"Broken local link: {document}: {link}")
                count += 1
        self.assertGreaterEqual(count, 15)


if __name__ == "__main__":
    unittest.main()
