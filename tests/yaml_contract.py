"""Strict, YAML-1.2-style booleans for offline repository contract tests.

PyYAML's default 1.1 resolver treats the GitHub Actions key ``on`` as boolean
True. Isolating the resolver prevents that bug without mutating global YAML
parsing behavior or modifying the production Compose configuration.
"""

import re
from pathlib import Path

import yaml


class StrictYamlLoader(yaml.SafeLoader):
    """Reject duplicate keys and avoid YAML 1.1's ``on`` / ``off`` booleans."""


StrictYamlLoader.yaml_implicit_resolvers = {
    key: [
        (tag, regex)
        for tag, regex in resolvers
        if tag != 'tag:yaml.org,2002:bool'
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
StrictYamlLoader.add_implicit_resolver(
    'tag:yaml.org,2002:bool',
    re.compile(r'^(?:true|True|TRUE|false|False|FALSE)$'),
    list('tTfF'),
)


def _unique_mapping(loader: StrictYamlLoader, node: yaml.MappingNode) -> dict:
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in mapping:
            raise ValueError(f'Duplicate YAML key: {key!r}')
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


StrictYamlLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping
)


def load_yaml(path: Path) -> dict:
    """Load a repository YAML document, rejecting duplicate mapping keys."""
    with path.open('r', encoding='utf-8') as handle:
        document = yaml.load(handle, Loader=StrictYamlLoader)
    if not isinstance(document, dict):
        raise ValueError(f'Expected mapping at YAML root: {path}')
    return document
