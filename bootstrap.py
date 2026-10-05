"""Agent entrypoint. Install the pinned wheel locally, connect, then scan."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
import venv
from pathlib import Path

VERSION = '0.3.0'
WHEEL = 'ethossecurity-' + VERSION + '-py3-none-any.whl'
WHEEL_SHA256 = '0ac7450573016c3dde56b6fbed4ac51aa69edd555a68be777aa903dff007892a'
BASE = 'https://github.com/maiconpl2/ethossecurity/releases/download/v' + VERSION + '/'


def main():
    parser = argparse.ArgumentParser(description='Prepare EthosSecurity inside the current AI-assisted project.')
    parser.add_argument('--project', required=True)
    parser.add_argument('--client', required=True, choices=['codex', 'claude', 'antigravity'])
    parser.add_argument('--language', choices=['pt-BR', 'en'], default='pt-BR')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    if not (3, 11) <= sys.version_info[:2] <= (3, 14):
        parser.exit(2, 'A Python runtime 3.11 through 3.14 is required; the assistant must prepare it first.\n')
    root = Path(args.project).resolve(strict=True)
    if not root.is_dir():
        parser.error('Expected an existing project directory')
    folder = root / '.ethossecurity/runtime'
    for parent in (folder, *folder.parents):
        if parent == root:
            break
        if parent.is_symlink():
            parser.error('Refusing a runtime path that uses symlinks')
    if not folder.resolve().is_relative_to(root):
        parser.error('Runtime path escapes project')
    folder.parent.mkdir(parents=True, exist_ok=True)
    lock = folder.parent / 'installation.lock'
    try:
        stream = lock.open('x', encoding='utf-8')
    except FileExistsError:
        parser.exit(2, 'An installation lock already exists. Check for another running installation before removing it.\n')
    try:
        with stream:
            stream.write(str(os.getpid()))
        print('Preparing EthosSecurity ' + VERSION + '...', flush=True)
        python = folder / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        marker = folder / 'ethossecurity-bootstrap.json'
        if folder.exists() and not marker.exists():
            parser.exit(2, 'An unmanaged or incomplete runtime already exists; preserved for inspection.\n')
        if not folder.exists():
            venv.EnvBuilder(with_pip=True).create(folder)
            with marker.open('x', encoding='utf-8') as receipt:
                receipt.write(json.dumps({'managed_by': 'EthosSecurity', 'version': None}))
        saved = json.loads(marker.read_text(encoding='utf-8'))
        if saved.get('version') != VERSION or saved.get('wheel_sha256') != WHEEL_SHA256:
            with tempfile.TemporaryDirectory(prefix='.wheel-', dir=folder.parent) as temp:
                wheel = Path(temp) / WHEEL
                request = urllib.request.Request(BASE + WHEEL, headers={'User-Agent': 'EthosSecurity-bootstrap'})
                digest = hashlib.sha256()
                total = 0
                with urllib.request.urlopen(request, timeout=60) as response, wheel.open('xb') as output:
                    while block := response.read(1024 * 1024):
                        total += len(block)
                        if total > 32 * 1024 * 1024:
                            raise ValueError('Wheel exceeds expected size limit')
                        digest.update(block)
                        output.write(block)
                if digest.hexdigest() != WHEEL_SHA256:
                    raise ValueError('EthosSecurity wheel checksum mismatch')
                subprocess.run([str(python), '-m', 'pip', 'install', '--quiet', '--disable-pip-version-check',
                                '--index-url', 'https://pypi.org/simple', str(wheel)], check=True, timeout=900)
            marker.write_text(json.dumps({'managed_by': 'EthosSecurity', 'version': VERSION, 'wheel_sha256': WHEEL_SHA256}), encoding='utf-8')
        action = 'setup' if args.prepare_only else 'start'
        run = subprocess.run([str(python), '-m', 'ethossecurity.cli', action, str(root), '--client', args.client,
                              '--language', args.language], shell=False)
        return run.returncode
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('Preparation incomplete: ' + type(error).__name__ + '. Inspect permissions and connectivity; do not report a successful installation.', file=sys.stderr)
        return 2
    finally:
        lock.unlink(missing_ok=True)


if __name__ == '__main__':
    raise SystemExit(main())
