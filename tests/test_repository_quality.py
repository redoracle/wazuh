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
        for path in (ROOT / 'docker-compose.yml',
                     ROOT / '.github/workflows/validate.yml',
                     ROOT / '.github/dependabot.yml'):
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
        self.assertEqual(set(jobs), {'static-validation'})
        steps = jobs['static-validation']['steps']
        commands = '\n'.join(step.get('run', '') for step in steps)
        self.assertIn('make test', commands)
        self.assertIn('make compose-check', commands)
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
        self.assertGreaterEqual(len(docs), 7)
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
                'Makefile', '.gitignore', '.editorconfig'}:
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
        example = (ROOT / '.env.example').read_text(encoding='utf-8')
        self.assertRegex(example, r'(?m)^NGINX_CREDENTIALS=$')
        self.assertNotRegex(example, r'(?i)(?:password|token|secret)\s*[:=]\s*\S+')

    def test_makefile_runs_only_non_destructive_checks(self):
        makefile = (ROOT / 'Makefile').read_text(encoding='utf-8')
        self.assertIn('.PHONY: test compose-check check', makefile)
        self.assertIn('unittest discover -s tests -v', makefile)
        self.assertIn('config --quiet', makefile)
        self.assertNotRegex(makefile, r'(?m)^\s*.*docker\s+compose\s+(?:up|down|pull)\b')


if __name__ == '__main__':
    unittest.main()
