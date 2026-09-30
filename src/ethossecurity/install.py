"""Export packaged skills without requiring a clone or overwriting project files."""
import json
import sys
from pathlib import Path

def initialize(root, adapter):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Expected project directory')
    assets = Path(__file__).parent / 'assets'
    skills_dir = '.claude/skills' if adapter == 'anthropic' else '.agents/skills'
    plan = [(root / 'ethossecurity.yaml', (assets / 'ethossecurity.yaml').read_text())]
    for skill in (assets / 'skills').glob('*/SKILL.md'):
        plan.append((root / skills_dir / skill.parent.name / 'SKILL.md', skill.read_text()))
    argv = ['-m','ethossecurity.cli','mcp','--root',str(root),'--config',str(root / 'ethossecurity.yaml')]
    # Write a separate fragment: never replace or merge an existing provider config implicitly.
    if adapter == 'openai':
        body = '[mcp_servers.ethossecurity]\ncommand = ' + json.dumps(sys.executable) + '\nargs = ' + json.dumps(argv) + '\ntool_timeout_sec = 2100\n'
        name = 'openai.toml'
    else:
        body = json.dumps({'mcpServers':{'ethossecurity':{'command':sys.executable,'args':argv}}}, indent=2)
        name = adapter + '.json'
    plan.append((root / '.ethossecurity' / name, body))
    for path, _ in plan:
        if path.exists():
            raise ValueError('Refusing to overwrite existing files')
        if not path.resolve().is_relative_to(root):
            raise ValueError('Output escapes project through a symlink')
    for path, body in plan:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('x', encoding='utf-8') as stream:
            stream.write(body)
    return {'created':[str(path) for path, _ in plan], 'next_step':'Merge the generated MCP fragment into your client configuration, then reload the client.'}
