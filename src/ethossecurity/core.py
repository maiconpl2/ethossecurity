"""Fixed argv scanner registry; no shell or arbitrary commands from MCP clients."""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse
import yaml
from jsonschema.exceptions import ValidationError
from .findings import normalize, SEVERITIES

PROFILES = {'bug-hunter': ['semgrep', 'codeql'], 'app-security': ['semgrep', 'codeql', 'zap'],
            'infra-security': ['trivy', 'gitleaks', 'osv'],
            'full-scan': ['semgrep', 'codeql', 'trivy', 'gitleaks', 'osv', 'zap']}
DEFAULT = {'version': 1, 'scanners': ['semgrep', 'trivy', 'gitleaks', 'osv'],
           'timeout_seconds': 300, 'fail_on': 'high', 'authorized_targets': []}

def config(path=None):
    result = DEFAULT | (yaml.safe_load(Path(path).read_text()) or {} if path else {})
    if result['version'] != 1 or result['fail_on'] not in SEVERITIES:
        raise ValueError('Unsupported config version or severity')
    if not isinstance(result['scanners'], list) or any(s not in PROFILES['full-scan'] for s in result['scanners']):
        raise ValueError('Unknown scanners')
    if not isinstance(result['timeout_seconds'], int) or not 1 <= result['timeout_seconds'] <= 3600:
        raise ValueError('timeout_seconds must be 1..3600')
    if not isinstance(result['authorized_targets'], list) or any(not isinstance(t, str) for t in result['authorized_targets']):
        raise ValueError('authorized_targets must be an array of URL strings')
    return result

def command(scanner, root, cfg, output):
    rules = str(Path(__file__).parent / 'rules/default.yaml')
    if scanner == 'semgrep':
        return ['semgrep', 'scan', '--config', rules, '--json', '--output', str(output), str(root)], {0}
    if scanner == 'trivy':
        return ['trivy', 'fs', '--scanners', 'vuln,misconfig', '--format', 'json', '--output', str(output), str(root)], {0}
    if scanner == 'gitleaks':
        return ['gitleaks', 'dir', str(root), '--redact=100', '--report-format', 'json', '--report-path', str(output)], {0, 1}
    if scanner == 'osv':
        return ['osv-scanner', 'scan', 'source', '-r', str(root), '--format', 'json', '--output-file', str(output)], {0, 1}
    if scanner == 'codeql':
        db, queries = cfg.get('codeql_database'), cfg.get('codeql_queries')
        if not db or not queries:
            return None, set()
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

def scan(root, profile='full-scan', cfg=None):
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or profile not in PROFILES:
        raise ValueError('Expected directory and known profile')
    cfg = cfg or config()
    findings, executions = [], []
    with tempfile.TemporaryDirectory(prefix='ethos-') as temp:
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
                exe = shutil.which(argv[0])
                if not exe:
                    record.update(status='unavailable', reason='Executable not installed'); continue
                argv[0] = exe
                # Discard diagnostic text: scanners can log source secrets even when reports are redacted.
                run = subprocess.run(argv, cwd=root, shell=False, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=cfg['timeout_seconds'])
                record['exit_code'] = run.returncode
                if run.returncode not in accepted:
                    raise ValueError('Scanner failed; exit code ' + str(run.returncode))
                data = json.loads(output.read_text(encoding='utf-8-sig'))
                found = normalize(scanner, data)
                findings.extend(found)
                partial = scanner == 'semgrep' and bool(data.get('errors'))
                record.update(status='partial' if partial else 'completed', reason='Scanner reported analysis errors' if partial else None,
                              finding_count=len(found))
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
