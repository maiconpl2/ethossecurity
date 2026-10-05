"""Fixed argv scanner registry; no shell or arbitrary commands from MCP clients."""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse
import yaml
from jsonschema.exceptions import ValidationError
from .findings import normalize, relative, SEVERITIES

PROFILES = {'bug-hunter': ['semgrep', 'codeql'], 'app-security': ['semgrep', 'codeql', 'zap'],
            'infra-security': ['trivy', 'gitleaks', 'osv'],
            'full-scan': ['semgrep', 'codeql', 'trivy', 'gitleaks', 'osv', 'zap']}
DEFAULT = {'version': 1, 'scanners': ['semgrep', 'trivy', 'gitleaks', 'osv'],
           'timeout_seconds': 300, 'fail_on': 'high', 'authorized_targets': []}

# Shared per-user installation used by the Claude Code plugin: ~/.ethossecurity/{runtime.json,tools,cache,reports}.
GLOBAL_ROOT = Path.home()
GLOBAL_HOME = GLOBAL_ROOT / '.ethossecurity'

def config(path=None, root=None, trust_project=True):
    result = DEFAULT | (yaml.safe_load(Path(path).read_text(encoding='utf-8')) or {} if path else {})
    runtimes = [GLOBAL_HOME / 'runtime.json']
    # A scanned repository may be untrusted: its runtime state is honored only when explicitly trusted.
    if root is not None and trust_project:
        runtimes.append(Path(root) / '.ethossecurity/runtime.json')
    managed = {}
    for runtime in runtimes:
        if runtime.exists():
            managed |= json.loads(runtime.read_text(encoding='utf-8'))['tool_paths']
    if managed:
        result['tool_paths'] = managed | result.get('tool_paths', {})
    paths = result.get('tool_paths', {})
    if not isinstance(paths, dict) or any(k not in PROFILES['full-scan'] or not isinstance(v, str) or not Path(v).is_absolute() for k, v in paths.items()):
        raise ValueError('tool_paths must map scanner names to absolute executable paths')
    if result['version'] != 1 or result['fail_on'] not in SEVERITIES:
        raise ValueError('Unsupported config version or severity')
    if not isinstance(result['scanners'], list) or any(s not in PROFILES['full-scan'] for s in result['scanners']):
        raise ValueError('Unknown scanners')
    if not isinstance(result['timeout_seconds'], int) or not 1 <= result['timeout_seconds'] <= 3600:
        raise ValueError('timeout_seconds must be 1..3600')
    if not isinstance(result['authorized_targets'], list) or any(not isinstance(t, str) for t in result['authorized_targets']):
        raise ValueError('authorized_targets must be an array of URL strings')
    # Set after merging, so no configuration file can declare the scanned project trusted.
    result['trust_project'] = bool(trust_project)
    return result

def command(scanner, root, cfg, output):
    rules = str(Path(__file__).parent / 'rules/semgrep')
    # An untrusted project must not redirect or silence scanners through native config/ignore files: those are
    # replaced by the empty file scan() creates in its private folder, next to the reports.
    trusted, empty = cfg.get('trust_project') is True, str(output.parent / 'empty')
    if scanner == 'semgrep':
        # Semgrep matches --exclude against paths relative to the enclosing git root: a .ethossecurity folder between
        # that root and the project would exclude the whole project, so pin the root there (.gitignore is then not honored).
        git = next((p for p in (root, *root.parents) if (p / '.git').exists()), None)
        anchor = ['--project-root', str(root)] if git and '.ethossecurity' in root.relative_to(git).parts else []
        return ['semgrep', 'scan', '--config', rules, '--metrics=off', *anchor, '--exclude', '.ethossecurity', '--json', '--output', str(output), str(root)], {0}
    if scanner == 'trivy':
        # Trivy reads trivy.yaml/.trivyignore from its cwd, which is private: only a trusted project's own are named (an
        # explicit missing file is fatal). An untrusted one could set server.addr (uploading the package inventory) or skip files.
        if trusted:
            conf, ignore = ([flag, str(path)] if path.is_file() else [] for flag, path in (('--config', root / 'trivy.yaml'), ('--ignorefile', root / '.trivyignore')))
        else:
            conf, ignore = ['--config', empty], ['--ignorefile', empty]
        # Vulnerability data is not project-specific: one shared cache, never written into the scanned project.
        return ['trivy', *conf, '--cache-dir', str(GLOBAL_HOME / 'cache/trivy'), 'fs', '--scanners', 'vuln,misconfig', *ignore, '--skip-dirs', str(root / '.ethossecurity'), '--format', 'json', '--output', str(output), str(root)], {0}
    if scanner == 'gitleaks':
        # '.' is the project (gitleaks alone runs with cwd=root): project-relative paths let gitleaks.toml anchor its allowlist.
        # It still loads ./.gitleaksignore whatever -i says; scan() rescans what an untrusted project lists there.
        guard = [] if trusted else ['--gitleaks-ignore-path', empty]
        return ['gitleaks', 'dir', '.', '--config', str(Path(__file__).parent / 'rules/gitleaks.toml'), *guard, '--redact=100', '--report-format', 'json', '--report-path', str(output)], {0, 1}
    if scanner == 'osv':
        # An explicit --config replaces every per-directory osv-scanner.toml (IgnoredVulns, PackageOverrides).
        guard = [] if trusted else ['--config', empty]
        return ['osv-scanner', 'scan', 'source', *guard, '-r', str(root), '--experimental-exclude', '.ethossecurity',
                '--no-resolve', '--no-call-analysis', 'go', '--no-call-analysis', 'rust', '--allow-no-lockfiles',
                '--format', 'json', '--output-file', str(output)], {0, 1}
    if scanner == 'codeql':
        db, queries = cfg.get('codeql_database'), cfg.get('codeql_queries')
        if not db or not queries:
            return None, set()
        if trusted and (root / str(queries)).exists():
            queries = root / str(queries)  # a relative suite meant the project, codeql's cwd before scanners moved to a private one
        return ['codeql', 'database', 'analyze', str(Path(db).resolve()), str(queries), '--format=sarif-latest', '--output', str(output)], {0}
    if scanner == 'zap':
        target = cfg.get('zap_target')
        if not target:
            return None, set()
        parsed = urlparse(target)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or target not in cfg.get('authorized_targets', []):
            raise ValueError('ZAP requires an exact authorized HTTP(S) URL without credentials')
        return ['zap-baseline.py', '-t', target, '-J', str(output)], {0, 1, 2}
    raise ValueError('Unknown scanner')

def executable(scanner, name, cfg):
    configured = cfg.get('tool_paths', {}).get(scanner)
    if cfg.get('trust_project') is not True:
        # An untrusted project never selects the program: only operator-prepared absolute paths, no lookup by name.
        return configured if configured and Path(configured).is_file() else None
    found = shutil.which(configured or name)
    # On Windows, Python 3.11 searches the cwd (often the project) first and returns such a hit as a relative path.
    return found if found and os.path.isabs(found) else None

def stage_ignored(root, stage):
    # gitleaks always applies <source>/.gitleaksignore, keyed on project-relative paths, with no switch to disable it.
    # The files an untrusted project lists there are copied (same relative paths, minus the list) for a second scan.
    listed = root / '.gitleaksignore'
    if not listed.is_file():
        return False
    with listed.open('rb') as stream:
        data = stream.read((1 << 20) + 1)
    if len(data) > 1 << 20:
        # gitleaks honors every entry, so a list too long to check in full fails the scan instead of hiding secrets.
        raise ValueError('.gitleaksignore too large')
    stage.mkdir()
    names = set()
    for line in data.decode('utf-8', 'replace').splitlines():
        # file:rule:line (rule ids and line numbers hold no colon, POSIX file names may) or commit:file:rule:line.
        # Entries may spell the path with either separator, so both spellings are staged.
        parts = line.strip().split(':')
        if len(parts) >= 3:
            names |= {name for part in (':'.join(parts[:-2]), parts[-3]) for name in (part, part.replace('\\', '/'))}
    for name in names:
        try:
            source = (root / name).resolve()
            rel = source.relative_to(root)
            if source.is_file() and rel != Path('.gitleaksignore'):
                (stage / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, stage / rel)
        except (OSError, ValueError):
            continue  # outside the project or unreadable: gitleaks could not have matched it either
    return True

def scan(root, profile='full-scan', cfg=None):
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or profile not in PROFILES:
        raise ValueError('Expected directory and known profile')
    cfg = cfg or config(root=root)
    trusted = cfg.get('trust_project') is True
    findings, executions = [], []
    # Discard diagnostic text: scanners can log source secrets even when reports are redacted.
    environment = dict(os.environ)
    environment.pop('PYTHONPATH', None)
    environment.pop('PYTHONHOME', None)
    # Semgrep's Python CLI otherwise writes its JSON report in the Windows ANSI code page ("Gestão" breaks UTF-8).
    environment['PYTHONUTF8'] = '1'
    with tempfile.TemporaryDirectory(prefix='ethos-') as temp:
        (Path(temp) / 'empty').touch()
        for scanner in PROFILES[profile]:
            record = {'scanner': scanner, 'status': 'disabled', 'reason': 'Not enabled in configuration'}
            executions.append(record)
            if scanner not in cfg['scanners']:
                continue
            output = Path(temp) / (scanner + '.json')
            try:
                argv, accepted = command(scanner, root, cfg, output)
                if argv is None:
                    record.update(status='skipped', reason='Required scanner inputs not configured'); continue
                exe = executable(scanner, argv[0], cfg)
                if not exe:
                    record.update(status='unavailable', reason='Executable not installed'); continue
                # Never run a scanner from the project: Windows programs resolve helpers in their cwd first (semgrep finds
                # pysemgrep.exe there) and trivy reads trivy.yaml from it. Targets are absolute. gitleaks keeps cwd=root for
                # its '.' source: "gitleaks dir" starts no child process, and Go's os/exec never resolves names from the cwd.
                runs = [(argv, root if scanner == 'gitleaks' else Path(temp), output)]
                stage = Path(temp) / 'gitleaks-stage'
                if scanner == 'gitleaks' and not trusted and stage_ignored(root, stage):
                    runs.append((command(scanner, root, cfg, stage.with_suffix('.json'))[0], stage, stage.with_suffix('.json')))
                found = {}
                for args, cwd, report in runs:
                    args[0] = exe
                    run = subprocess.run(args, cwd=cwd, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=cfg['timeout_seconds'], env=environment)
                    record['exit_code'] = run.returncode
                    if run.returncode not in accepted:
                        raise ValueError('Scanner failed; exit code ' + str(run.returncode))
                    data = json.loads(report.read_text(encoding='utf-8-sig'))
                    found |= {f['id']: f for f in normalize(scanner, data, root)}
                found = list(found.values())
                findings.extend(found)
                partial = scanner == 'semgrep' and bool(data.get('errors'))
                record.update(status='partial' if partial else 'completed', reason='Scanner reported analysis errors' if partial else None,
                              finding_count=len(found))
                if partial:
                    # Name the files left unanalyzed (e.g. invalid YAML) so the gap is actionable, not just reported.
                    record['unanalyzed_files'] = sorted({relative(e['path'], root) for e in data['errors'] if isinstance(e, dict) and e.get('path')})
            except subprocess.TimeoutExpired:
                record.update(status='timeout', reason='Execution deadline exceeded')
            except (OSError, ValueError, KeyError, TypeError, AttributeError, ValidationError) as error:
                record.update(status='failed', reason=type(error).__name__ + ': report or invocation failed')
    required = [e for e in executions if e['scanner'] in cfg['scanners']]
    complete = bool(required) and all(e['status'] == 'completed' for e in required)
    threshold = SEVERITIES.index(cfg['fail_on'])
    return {'schema_version': '1.0', 'profile': profile, 'root': str(root), 'complete': complete,
            'executions': executions, 'findings': findings,
            'policy_failed': any(f['severity'] in SEVERITIES and SEVERITIES.index(f['severity']) >= threshold for f in findings),
            'policy_unknown': any(f['severity'] == 'unknown' for f in findings)}

def exit_code(report):
    return 2 if not report['complete'] or report.get('policy_unknown') else 1 if report['policy_failed'] else 0
