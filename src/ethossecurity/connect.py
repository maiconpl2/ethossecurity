"""Register local MCP and skills, preserving other client configuration."""
import json
import os
import sys
import tomllib
from importlib.metadata import version
from pathlib import Path
from .prepare import ASSETS, project_path, write_json

CLIENTS = ('codex', 'claude', 'antigravity')


def owned_text(root, relative, body):
    path = project_path(root, relative)
    if path.exists():
        if path.read_text(encoding='utf-8') != body:
            raise ValueError('Existing file differs; preserved: ' + relative)
        return str(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        stream.write(body)
    return str(path)


def merge_json(root, relative, entry):
    path = project_path(root, relative)
    data = json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
    servers = data.setdefault('mcpServers', {})
    if not isinstance(servers, dict):
        raise ValueError('Invalid existing MCP configuration; preserved')
    if 'ethossecurity' in servers:
        if servers['ethossecurity'] != entry:
            raise ValueError('An existing EthosSecurity connection differs; preserved')
        return str(path)
    if path.exists():
        backup = project_path(root, relative + '.ethossecurity-backup')
        if backup.exists():
            raise ValueError('A configuration backup already exists; preserved')
        backup.parent.mkdir(parents=True, exist_ok=True)
        with backup.open('xb') as stream:
            stream.write(path.read_bytes())
    servers['ethossecurity'] = entry
    write_json(path, data)
    return str(path)


def connect(root, client):
    root = Path(root).resolve(strict=True)
    if client not in CLIENTS:
        raise ValueError('Unknown client')
    entry = {'command': sys.executable, 'args': ['-m', 'ethossecurity.cli', 'mcp', '--root', str(root)]}
    local_cfg = root / 'ethossecurity.yaml'
    if local_cfg.exists():
        entry['args'] += ['--config', str(local_cfg)]
    skills_dir = '.claude/skills' if client == 'claude' else '.agents/skills'
    # Preflight all skill writes before changing a client configuration.
    plan = []
    for skill in (ASSETS / 'skills').glob('*/SKILL.md'):
        relative = skills_dir + '/ethossecurity-' + skill.parent.name + '/SKILL.md'
        body = skill.read_text(encoding='utf-8').replace('name: ' + skill.parent.name + '\n', 'name: ethossecurity-' + skill.parent.name + '\n', 1)
        path = project_path(root, relative)
        if path.exists() and path.read_text(encoding='utf-8') != body:
            raise ValueError('Existing skill differs; preserved')
        plan.append((relative, body))
    if client == 'codex':
        path = project_path(root, '.codex/config.toml')
        original = path.read_text(encoding='utf-8') if path.exists() else ''
        parsed = tomllib.loads(original)
        expected = entry | {'tool_timeout_sec': 3600}
        existing = parsed.get('mcp_servers', {}).get('ethossecurity')
        if existing is not None and existing != expected:
            raise ValueError('An existing EthosSecurity connection differs; preserved')
        if existing is None:
            if path.exists():
                owned_text(root, '.codex/config.toml.ethossecurity-backup', original)
            path.parent.mkdir(parents=True, exist_ok=True)
            block = '\n[mcp_servers.ethossecurity]\ncommand = ' + json.dumps(entry['command']) + '\nargs = ' + json.dumps(entry['args']) + '\ntool_timeout_sec = 3600\n'
            with path.open('a', encoding='utf-8') as stream:
                stream.write(block)
        configuration = str(path)
    else:
        configuration = merge_json(root, '.mcp.json' if client == 'claude' else '.agents/mcp_config.json', entry)
    skills = [owned_text(root, relative, body) for relative, body in plan]
    bundle = project_path(root, '.ethossecurity/plugin')
    metadata = {'name': 'ethossecurity', 'version': version('ethossecurity'),
                'description': 'Review bugs, application security and infrastructure risks in the configured project.'}
    # Export a bundle for native plugin loaders; registration here uses project MCP + skills.
    files = {'plugin.json': metadata,
             '.codex-plugin/plugin.json': metadata | {'skills': './skills/', 'mcpServers': './.mcp.json'},
             '.claude-plugin/plugin.json': metadata,
             '.mcp.json': {'mcpServers': {'ethossecurity': entry}},
             'mcp_config.json': {'mcpServers': {'ethossecurity': entry}}}
    for name, data in files.items():
        owned_text(root, '.ethossecurity/plugin/' + name, json.dumps(data, indent=2) + '\n')
    for skill in (ASSETS / 'skills').glob('*/SKILL.md'):
        owned_text(root, '.ethossecurity/plugin/skills/' + skill.parent.name + '/SKILL.md', skill.read_text(encoding='utf-8'))
    return {'client': client, 'configuration': configuration, 'skills': skills, 'plugin_bundle': str(bundle),
            'status': 'configured', 'activation': 'Reload the client and accept its connection permissions; use the CLI for the first scan in the current session.'}
