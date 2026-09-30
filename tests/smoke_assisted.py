"""Real installation and scanner smoke test. Run explicitly; uses publisher downloads."""
import json
import random
import string
import subprocess
import sys
import tempfile
from pathlib import Path
from ethossecurity.prepare import prepare
from ethossecurity.connect import connect
from ethossecurity.core import config, scan
from ethossecurity.report import html_report


def main():
    with tempfile.TemporaryDirectory(prefix='ethos-smoke-') as temp:
        root = Path(temp)
        secret = 'ghp_' + ''.join(random.Random(1040).choices(string.ascii_letters + string.digits, k=36))
        fixture = {'app.py': 'import subprocess\n\ndef run(command):\n    try:\n        return subprocess.run(command, shell=True)\n    except:\n        return None\n',
                   'requirements.txt': 'Django==2.2.0\n', 'credentials.txt': 'GITHUB_TOKEN=' + secret + '\n',
                   'Dockerfile': 'FROM ubuntu:latest\nRUN apt-get update\n'}
        for name, text in fixture.items():
            (root / name).write_text(text, encoding='utf-8')
        before = {name: (root / name).read_bytes() for name in fixture}
        prepared = prepare(root)
        assert prepared['ready'], prepared
        for client in ('codex', 'claude', 'antigravity'):
            connect(root, client)
            connect(root, client)
        cfg = config(root=root) | {'timeout_seconds': 600}
        report = scan(root, cfg=cfg)
        assert report['complete'], report['executions']
        sources = {f['scanner_source'] for f in report['findings']}
        assert {'semgrep', 'trivy', 'gitleaks', 'osv'}.issubset(sources), sources
        assert secret not in json.dumps(report)
        assert before == {name: (root / name).read_bytes() for name in fixture}
        html_report(report, root / '.ethossecurity/reports/smoke.html')
        # Re-run preparation to check receipts, probes and repeatability, without new downloads.
        assert prepare(root)['ready']
        print(json.dumps({'complete': report['complete'], 'sources': sorted(sources), 'findings': len(report['findings']),
                          'source_preserved': True, 'repeated_setup': True, 'secret_omitted': True}, indent=2))


if __name__ == '__main__':
    main()
