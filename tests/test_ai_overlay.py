"""Config and documentation guardrails for the opt-in AI deployment overlay."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class AIDeploymentSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = yaml.safe_load((ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))
        cls.overlay = yaml.safe_load((ROOT / 'docker-compose.ai.yml').read_text(encoding='utf-8'))

    def test_core_stack_does_not_enable_ai(self):
        self.assertEqual(set(self.base['services']), {'wazuh.manager', 'wazuh.indexer', 'wazuh.dashboard'})
        self.assertNotIn('ai-triage', self.base['services'])
        self.assertNotIn('ai-ollama', self.base['services'])

    def test_opt_in_service_has_no_host_ports_and_restricted_capabilities(self):
        ai = self.overlay['services']['ai-triage']
        self.assertEqual(ai.get('profiles'), ['ai'])
        self.assertFalse(ai.get('ports'))
        self.assertTrue(ai['read_only'])
        self.assertIn('ALL', ai['cap_drop'])
        self.assertIn('no-new-privileges:true', ai['security_opt'])
        self.assertNotIn('privileged', ai)
        self.assertNotIn('pid', ai)
        self.assertNotIn('docker.sock', str(ai['volumes']))
        self.assertEqual(set(ai['networks']), {'default', 'ai-model-net'})
        self.assertTrue(any('root-ca.pem' in value and value.endswith(':ro') for value in ai['volumes']))
        self.assertTrue(any('ai-indexer-password' in value and value.endswith(':ro') for value in ai['volumes']))
        self.assertTrue(any('/app:ro' in value for value in ai['volumes']))

    def test_model_cannot_reach_wazuh_network_directly(self):
        model = self.overlay['services']['ai-ollama']
        self.assertEqual(model.get('profiles'), ['ai'])
        self.assertEqual(model['networks'], ['ai-model-net'])
        self.assertNotIn('default', model['networks'])
        self.assertFalse(model.get('ports'))
        self.assertFalse(model.get('privileged', False))
        self.assertTrue(model['image'].startswith('ollama/ollama:'))
        self.assertNotIn(':latest', model['image'])

    def test_overlay_contains_no_wazuh_service_override(self):
        self.assertEqual(set(self.overlay['services']), {'ai-triage', 'ai-ollama'})
        self.assertEqual(self.overlay['networks']['ai-model-net']['driver'], 'bridge')

    def test_local_credentials_and_outputs_ignored(self):
        ignore = (ROOT / '.gitignore').read_text()
        for path in ('local-secrets/', 'local-state/', '.ai.env'):
            self.assertIn(path, ignore)

    def test_docs_reference_code_security_and_offline_validation(self):
        readme = (ROOT / 'README.md').read_text()
        for name in ('AI_INTEGRATIONS.md', 'AI_HOWTO.md', 'AI_SECURITY.md', 'AI_VALIDATION.md'):
            self.assertIn(name, readme)
            self.assertTrue((ROOT / 'docs' / name).is_file())
        howto = (ROOT / 'docs/AI_HOWTO.md').read_text()
        self.assertIn('wazuh-ai-reader', howto)
        self.assertIn('no Wazuh configuration is edited', howto)
        self.assertIn('docker-compose.ai.yml', howto)


    def test_docs_describe_only_verifiable_self_hosted_capabilities(self):
        paths = [ROOT / 'README.md', ROOT / 'CHANGELOG.md']
        paths.extend(sorted((ROOT / 'docs').glob('AI_*.md')))
        combined = '\n'.join(p.read_text(encoding='utf-8') for p in paths)
        for unsupported_claim in ('Wazuh Cloud AI Analyst', 'Hosted ChatGPT',
                                  'Claude', 'Mindflow', 'AWS Bedrock'):
            with self.subTest(phrase=unsupported_claim):
                self.assertNotIn(unsupported_claim, combined)
        for required in ('local Ollama', 'Wazuh Indexer', 'human', 'not tested'):
            self.assertIn(required.lower(), combined.lower())
        evaluation = (ROOT / 'docs/AI_INTEGRATIONS.md').read_text(encoding='utf-8')
        self.assertIn('Live Wazuh 4.14.9 connection', evaluation)
        self.assertIn('not CI-verified', evaluation)

    def test_documented_indexer_role_grants_only_search(self):
        import re
        howto = (ROOT / 'docs/AI_HOWTO.md').read_text(encoding='utf-8')
        self.assertRegex(howto, r'"allowed_actions": \["search"\]')
        self.assertNotRegex(howto, r'"allowed_actions": \["read"\]')
        self.assertIn('field-level security', howto)
        self.assertIn('cannot enforce server-side least privilege', howto)


if __name__ == '__main__':
    unittest.main()
