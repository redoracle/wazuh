"""Offline checks for documentation, review quality and CI configuration."""

import re
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

from yaml_contract import StrictYamlLoader, load_yaml


ROOT = Path(__file__).resolve().parents[1]
LINK_PATTERN = re.compile(r'(?<!!)\[[^\]]+\]\(([^)]+)\)')
HEADING_PATTERN = re.compile(r'^#{1,6}\s+(.+?)\s*#*\s*$', re.MULTILINE)


def _markdown_slug(title: str) -> str:
    """Support the simple GitHub heading anchors used in our documentation."""
    title = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', title)
    title = title.replace('`', '').lower()
    title = ''.join(char for char in title
                    if char.isalnum() or char in ' -_')
    return re.sub(r'\s+', '-', title.strip())


class RepositoryQualityTests(unittest.TestCase):
    def test_strict_yaml_rejects_duplicates_and_parses_actions_on(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate YAML key'):
            yaml.load('key: one\nkey: two\n', Loader=StrictYamlLoader)
        self.assertEqual(yaml.load('on:\n  push: {}\n', Loader=StrictYamlLoader),
                         {'on': {'push': {}}})

    def test_all_configuration_files_have_valid_yaml(self):
        configuration_files = [
            ROOT / 'docker-compose.yml',
            ROOT / '.github/workflows/validate.yml',
            ROOT / '.github/dependabot.yml',
            *(ROOT / '.github/ISSUE_TEMPLATE').glob('*.yml'),
        ]
        for path in configuration_files:
            with self.subTest(path=path.name):
                self.assertTrue(load_yaml(path))

    def test_ci_permissions_triggers_and_non_destructive_commands(self):
        ci = load_yaml(ROOT / '.github/workflows/validate.yml')
        self.assertEqual(ci['permissions'], {'contents': 'read'})
        self.assertIn('pull_request', ci['on'])
        self.assertIn('push', ci['on'])
        self.assertIn('workflow_dispatch', ci['on'])
        self.assertEqual(ci['on']['push']['branches'], ['master'])
        jobs = ci['jobs']
        self.assertEqual(set(jobs), {'python-contracts', 'compose-model'})
        self.assertEqual(
            set(jobs['python-contracts']['strategy']['matrix']['python-version']),
            {'3.11', '3.13', '3.14'},
        )
        self.assertTrue(all(job['runs-on'] == 'ubuntu-24.04'
                            for job in jobs.values()))
        self.assertTrue(all(job['timeout-minutes'] <= 10
                            for job in jobs.values()))
        steps = [step for job in jobs.values() for step in job['steps']]
        commands = '\n'.join(step.get('run', '') for step in steps)
        self.assertIn('make lint test', commands)
        self.assertIn('make compose-check resolved-check', commands)
        self.assertNotRegex(commands, r'docker\s+compose\s+(?:up|down|pull)\b')
        for step in steps:
            if 'uses' in step:
                self.assertRegex(step['uses'],
                                 r'^actions/(?:checkout|setup-python)@[0-9a-f]{40}$')
        checkout = next(step for step in steps if
                        step.get('uses', '').startswith('actions/checkout@'))
        self.assertFalse(checkout['with']['persist-credentials'])

    def test_dependabot_tracks_only_tooling(self):
        bot = load_yaml(ROOT / '.github/dependabot.yml')
        self.assertEqual(bot['version'], 2)
        ecosystems = {entry['package-ecosystem'] for entry in bot['updates']}
        self.assertEqual(ecosystems, {'github-actions', 'pip'})
        self.assertTrue(all(entry['schedule']['interval'] == 'weekly'
                            for entry in bot['updates']))

    def test_docs_local_links_and_headings_resolve(self):
        docs = list(ROOT.rglob('*.md'))
        self.assertGreaterEqual(len(docs), 13)
        for doc in docs:
            if any(part == '.git' for part in doc.relative_to(ROOT).parts):
                continue
            text = doc.read_text(encoding='utf-8')
            for match in LINK_PATTERN.finditer(text):
                dest = match.group(1).strip().split(' ', 1)[0].strip('<>')
                if dest.startswith(('https:', 'http:', 'mailto:')):
                    continue
                parts = urlsplit(dest)
                if parts.scheme or parts.netloc:
                    continue
                rel = unquote(parts.path)
                target = (doc.parent / rel).resolve() if rel else doc.resolve()
                with self.subTest(document=str(doc.relative_to(ROOT)), link=dest):
                    self.assertTrue(target.is_relative_to(ROOT.resolve()),
                                    'Link escapes repository root')
                    self.assertTrue(target.exists(), 'Broken relative Markdown link')
                    if parts.fragment and target.suffix.lower() == '.md':
                        anchors = {
                            _markdown_slug(heading) for heading in
                            HEADING_PATTERN.findall(
                                target.read_text(encoding='utf-8'))
                        }
                        self.assertIn(unquote(parts.fragment), anchors,
                                      'Broken Markdown heading anchor')

    def test_source_hygiene_and_newlines(self):
        extensions = {'.md', '.yml', '.yaml', '.py', '.txt', '.example'}
        for path in ROOT.rglob('*'):
            if not path.is_file() or any(part in {'.git', '__pycache__', '.venv'}
                                             for part in path.relative_to(ROOT).parts):
                continue
            if path.suffix not in extensions and path.name not in {
                'Makefile', '.gitignore', '.editorconfig', '.gitattributes'}:
                continue
            with self.subTest(file=str(path.relative_to(ROOT))):
                text = path.read_text(encoding='utf-8')
                self.assertTrue(text.endswith('\n'), 'Missing final newline')
                self.assertNotIn('\r', text, 'Windows CRLF in source file')
                self.assertTrue(all(line == line.rstrip(' \t')
                                    for line in text.splitlines()),
                                'Trailing whitespace')

    def test_readme_clearly_labels_legacy_risk_and_validation(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8').lower()
        for term in ('not a supported', 'production-ready', '172.13.0',
                     'docker socket', 'restore', 'make check',
                     'documentation and contributions'):
            with self.subTest(term=term):
                self.assertIn(term, readme)

    def test_local_secrets_ignored_and_example_contains_no_values(self):
        ignore = (ROOT / '.gitignore').read_text(encoding='utf-8').splitlines()
        self.assertIn('.env', ignore)
        self.assertIn('.env.*', ignore)
        self.assertIn('!.env.example', ignore)
        self.assertIn('*.key', ignore)
        self.assertIn('*.p12', ignore)
        self.assertIn('*.pem', ignore)
        example = (ROOT / '.env.example').read_text(encoding='utf-8')
        self.assertRegex(example, r'(?m)^NGINX_CREDENTIALS=$')
        self.assertNotRegex(example, r'(?i)(?:password|token|secret)\s*[:=]\s*\S+')

    def test_issue_forms_conform_to_github_schema(self):
        folder = ROOT / '.github/ISSUE_TEMPLATE'
        configuration = load_yaml(folder / 'config.yml')
        self.assertFalse(configuration['blank_issues_enabled'])
        self.assertTrue(configuration.get('contact_links'))
        forms = list(folder.glob('*.yml'))
        self.assertGreaterEqual(len(forms), 3)
        for path in forms:
            if path.name == 'config.yml':
                continue
            form = load_yaml(path)
            with self.subTest(template=path.name):
                self.assertTrue(set(form) <= {
                    'name', 'description', 'title', 'labels', 'assignees',
                    'body', 'type',
                })
                self.assertTrue(form.get('name'))
                self.assertTrue(form.get('description'))
                self.assertTrue(form.get('body'))
                self.assertTrue(all(item.get('type') in {
                    'markdown', 'input', 'textarea', 'dropdown', 'checkboxes',
                } for item in form['body']))

    def test_supply_chain_and_governance_files_exist(self):
        for path in (
            '.gitattributes', 'CODE_OF_CONDUCT.md', 'SUPPORT.md',
            'CHANGELOG.md', 'docs/SECOND_AUDIT.md',
            'docs/THREAT_MODEL.md', 'docs/REPOSITORY_ADMIN.md',
        ):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())
        security = (ROOT / 'SECURITY.md').read_text(encoding='utf-8')
        self.assertIn('private', security.lower())
        self.assertIn('unsupported', security.lower())
        upgrades = (ROOT / 'docs/UPGRADE.md').read_text(encoding='utf-8')
        self.assertIn('rollback', upgrades.lower())

    def test_makefile_runs_only_non_destructive_checks(self):
        makefile = (ROOT / 'Makefile').read_text(encoding='utf-8')
        self.assertIn('.PHONY: lint test compose-check resolved-check check', makefile)
        self.assertIn('unittest discover -s tests -v', makefile)
        self.assertIn('config --quiet', makefile)
        self.assertIn('config --format json', makefile)
        self.assertIn('scripts.validate_resolved_compose', makefile)
        self.assertNotRegex(makefile, r'(?m)^\s*.*docker\s+compose\s+(?:up|down|pull)\b')


if __name__ == '__main__':
    unittest.main()
