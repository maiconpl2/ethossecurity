"""Provision a project-local toolchain from pinned, verified publisher releases."""
import hashlib
import json
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import venv
import zipfile
from pathlib import Path
from . import __version__

ASSETS = Path(__file__).parent / 'assets'


def project_path(root, relative):
    root = Path(root).resolve(strict=True)
    path = root / relative
    if not path.resolve().is_relative_to(root):
        raise ValueError('Installation path escapes the project')
    for parent in (path, *path.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError('Installation paths cannot use symlinks')
    return path


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     prefix='.ethos-', delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(data, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def platform_key():
    machine = platform.machine().lower()
    arch = {'amd64': 'x86_64', 'x86_64': 'x86_64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine, machine)
    return platform.system().lower() + '-' + arch


def download(url, path, expected_hash):
    if not url.startswith('https://github.com/'):
        raise ValueError('Only pinned HTTPS publisher release assets are allowed')
    request = urllib.request.Request(url, headers={'User-Agent': 'EthosSecurity/' + __version__})
    digest, size = hashlib.sha256(), 0
    with urllib.request.urlopen(request, timeout=60) as response, path.open('xb') as stream:
        while block := response.read(1024 * 1024):
            size += len(block)
            if size > 512 * 1024 * 1024:
                raise ValueError('Release asset exceeds size limit')
            digest.update(block)
            stream.write(block)
    if digest.hexdigest() != expected_hash:
        raise ValueError('Publisher release checksum mismatch')


def extract_executable(archive, asset, destination):
    # Read exactly one regular binary by basename; never extract archive paths.
    executable = asset['executable']
    if asset['url'].endswith('.zip'):
        with zipfile.ZipFile(archive) as bundle:
            members = [m for m in bundle.infolist() if Path(m.filename).name == executable and not m.is_dir()]
            if len(members) != 1 or members[0].file_size > 512 * 1024 * 1024:
                raise ValueError('Expected one executable in publisher archive')
            member = members[0]
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Archive executable cannot be a symlink')
            payload = bundle.read(member)
    elif asset['url'].endswith('.tar.gz'):
        with tarfile.open(archive, 'r:gz') as bundle:
            members = [m for m in bundle.getmembers() if Path(m.name).name == executable]
            if len(members) != 1 or not members[0].isfile() or members[0].size > 512 * 1024 * 1024:
                raise ValueError('Expected one regular executable in publisher archive')
            with bundle.extractfile(members[0]) as stream:
                payload = stream.read()
    else:
        payload = archive.read_bytes()
    with destination.open('xb') as stream:
        stream.write(payload)
    destination.chmod(destination.stat().st_mode | 0o700)


def binary_install(root, name, spec, key):
    if key not in spec['platforms']:
        raise ValueError('No pinned publisher binary for this operating system/architecture')
    asset = spec['platforms'][key]
    folder = project_path(root, '.ethossecurity/tools/' + name + '/' + spec['version'])
    executable = folder / asset['executable']
    receipt = folder / 'receipt.json'
    if executable.exists() and receipt.exists():
        saved = json.loads(receipt.read_text(encoding='utf-8'))
        if saved.get('asset_sha256') == asset['sha256'] and saved.get('binary_sha256') == hashlib.sha256(executable.read_bytes()).hexdigest():
            return str(executable)
        raise ValueError('Managed executable changed; refusing to execute or replace it')
    if executable.exists():
        raise ValueError('Unmanaged executable already exists')
    folder.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.download-', dir=folder) as temp:
        archive = Path(temp) / 'asset'
        download(asset['url'], archive, asset['sha256'])
        staged = Path(temp) / asset['executable']
        extract_executable(archive, asset, staged)
        os.replace(staged, executable)
    write_json(receipt, {'asset_sha256': asset['sha256'], 'binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'url': asset['url']})
    return str(executable)


def semgrep_install(root, version):
    folder = project_path(root, '.ethossecurity/tools/semgrep/' + version)
    python = folder / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    executable = folder / ('Scripts/semgrep.exe' if os.name == 'nt' else 'bin/semgrep')
    receipt = folder / 'receipt.json'
    if executable.exists() and receipt.exists():
        return str(executable)
    venv.EnvBuilder(with_pip=False).create(folder)
    environment = dict(os.environ)
    environment.pop('PYTHONPATH', None)
    environment.pop('PYTHONHOME', None)
    # Never inherit stdio: under MCP, a child sharing the server's pending stdin pipe hangs on Windows.
    # Isolated mode and the managed folder as cwd: "-m" would otherwise import a project's ensurepip/ or pip/ package
    # (the MCP server's cwd is the session project) ahead of the standard library.
    subprocess.run([str(python), '-I', '-m', 'ensurepip', '--upgrade', '--default-pip'], check=True, timeout=600, env=environment,
                   cwd=str(folder), stdin=subprocess.DEVNULL, stdout=sys.stderr)
    subprocess.run([str(python), '-I', '-m', 'pip', 'install', '--quiet', '--disable-pip-version-check', '--index-url',
                    'https://pypi.org/simple', 'semgrep==' + version], check=True, timeout=1200, env=environment,
                   cwd=str(folder), stdin=subprocess.DEVNULL, stdout=sys.stderr)  # stdout carries the MCP stdio protocol
    if not executable.is_file():
        raise ValueError('Semgrep entrypoint was not installed')
    write_json(receipt, {'version': version, 'source': 'https://pypi.org/project/semgrep/' + version + '/'})
    return str(executable)


def prepare(root, names=('semgrep', 'trivy', 'gitleaks', 'osv')):
    root = Path(root).resolve(strict=True)
    manifest = json.loads((ASSETS / 'tools.json').read_text(encoding='utf-8'))
    state_path = project_path(root, '.ethossecurity/runtime.json')
    state = json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else {}
    paths = state.get('tool_paths', {})
    if not isinstance(paths, dict):
        raise ValueError('Invalid managed tool configuration')
    records = []
    for name in names:
        print('Preparing ' + name + '...', file=sys.stderr, flush=True)
        record = {'scanner': name}
        try:
            path = semgrep_install(root, manifest['semgrep']['version']) if name == 'semgrep' else binary_install(root, name, manifest['binaries'][name], platform_key())
            # Version probes execute only the verified managed binaries and never project builds. The managed folder is
            # the cwd: semgrep resolves pysemgrep from its cwd first on Windows, and the MCP server's cwd is the project.
            probe = subprocess.run([path, '--version' if name != 'gitleaks' else 'version'], cwd=str(Path(path).parent),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            if probe.returncode != 0:
                raise ValueError('Installed scanner did not pass its version probe')
            paths[name] = path
            record.update(status='ready', executable=path)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            paths.pop(name, None)
            record.update(status='failed', reason=type(error).__name__ + ': installation or version verification failed')
        records.append(record)
        write_json(state_path, {'version': 1, 'tool_paths': paths, 'preparation': records})
    return {'ready': all(r['status'] == 'ready' for r in records), 'tools': records}
