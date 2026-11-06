#!/usr/bin/env python3
"""Offline Markdown link and heading verification for repository documentation.

Checks only local targets. External URLs are intentionally not fetched in CI: network
availability and mutable external pages must not make reproducible builds flaky.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'!?(?:\[[^\]\n]*\])\(([^\n)]*)\)')
FENCE = re.compile(r'^\s*(`{3,}|~{3,})')
HEADING = re.compile(r'^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$')
INLINE_CODE = re.compile(r'`([^`]*)`')
INLINE_MARKUP = re.compile(r'<[^>]*>')


def _without_fences(text: str) -> str:
    lines = []
    fence = None
    for line in text.splitlines():
        m = FENCE.match(line)
        if m:
            marker = m.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            lines.append('')
        else:
            lines.append('' if fence else line)
    return '\n'.join(lines)


def github_slug(text: str) -> str:
    """Conservative GitHub-style heading normalization for repository guides."""
    text = INLINE_CODE.sub(r'\1', text)
    text = INLINE_MARKUP.sub('', text)
    text = re.sub(r'[\[\]()*_!]', '', text)
    text = re.sub(r'[^\w\s-]', '', text.lower(), flags=re.UNICODE)
    return re.sub(r'\s', '-', text.strip())


def anchors(markdown: str) -> set[str]:
    seen: Counter[str] = Counter()
    result: set[str] = set()
    for line in _without_fences(markdown).splitlines():
        h = HEADING.match(line)
        if h:
            slug = github_slug(h.group(1))
            if slug:
                result.add(slug if seen[slug] == 0 else f'{slug}-{seen[slug]}')
                seen[slug] += 1
    return result


def markdown_files(root: Path) -> list[Path]:
    return sorted(set(root.glob('*.md')) | set((root / 'docs').rglob('*.md')) |
                  set((root / '.github').glob('*.md')))


def check(root: Path = ROOT) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    cache: dict[Path, set[str]] = {}
    for document in markdown_files(root):
        text = _without_fences(document.read_text(encoding='utf-8'))
        for match in LINK.finditer(text):
            raw = match.group(1).strip()
            # Link titles are optional; angle bracket paths protect spaces.
            raw = raw[1:raw.find('>')] if raw.startswith('<') and '>' in raw else raw.split(' "', 1)[0]
            if not raw:
                continue
            url = urlsplit(raw)
            if url.scheme or url.netloc or raw.startswith('//') or raw.startswith('mailto:'):
                continue
            path = unquote(url.path)
            fragment = unquote(url.fragment)
            target = (document.parent / path).resolve() if path else document.resolve()
            label = str(document.relative_to(root))
            try:
                relative = target.relative_to(root)
            except ValueError:
                errors.append(f'{label}: local link escapes repository: {raw}')
                continue
            if not target.is_file():
                errors.append(f'{label}: missing local file {relative} (from {raw})')
                continue
            if fragment and target.suffix.lower() == '.md':
                if target not in cache:
                    cache[target] = anchors(target.read_text(encoding='utf-8'))
                if fragment.lower() not in cache[target]:
                    errors.append(f'{label}: missing heading #{fragment} in {relative}')
    return errors


def main() -> int:
    errors = check()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f'Documentation validation failed: {len(errors)} broken local link(s)', file=sys.stderr)
        return 1
    print(f'Documentation links verified ({len(markdown_files(ROOT))} Markdown files; offline only)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
