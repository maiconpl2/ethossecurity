"""Normalize native reports without upgrading scanner hypotheses to proof."""
import hashlib
import json
import re
from pathlib import Path
from jsonschema import validate

SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']

def finding(source, rule, title, severity='medium', file=None, line=None,
            endpoint=None, evidence=None, cwe=None, owasp=None, recommendation=None):
    severity = {'error': 'high', 'warning': 'medium', 'note': 'info'}.get(str(severity).lower(), str(severity).lower())
    if severity not in SEVERITIES:
        severity = 'unknown'
    identity = json.dumps([source, rule, file, line, endpoint], sort_keys=True)
    result = dict(id=hashlib.sha256(identity.encode()).hexdigest()[:24], title=str(title),
        rule_id=str(rule), severity=severity, confidence='unknown', cwe=cwe or [], owasp=owasp or [],
        file=file, line=line, endpoint=endpoint, evidence=evidence or 'Scanner rule matched; inspect local source.',
        impact='Requires contextual assessment.', exploitability='unknown',
        recommendation=recommendation or 'Review reachability and apply a narrowly scoped fix with regression tests.',
        suggested_patch=None, scanner_source=source, validation_status='unvalidated')
    validate(result, json.loads((Path(__file__).parent / 'schemas/finding.json').read_text()))
    return result

def relative(path, root):
    # Report project-relative POSIX paths: stable ids across machines and no user directories in reports.
    if not path or root is None:
        return path
    try:
        candidate = Path(path)
        return (candidate.resolve().relative_to(Path(root).resolve()) if candidate.is_absolute() else candidate).as_posix()
    except (ValueError, OSError):
        return str(path)

def rule_id(check_id):
    # Semgrep prefixes ids of rules loaded from a directory with that directory's dotted path.
    # The rule name has no dots, so a user folder called "ethos" in that path cannot match first.
    match = re.search(r'ethos\.[a-z]+\.[A-Za-z0-9_-]+$', check_id)
    return match.group(0) if match else check_id

def strings(value):
    if not value:
        return []
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]

def normalize(source, data, root=None):
    out = []
    if source == 'semgrep':
        for r in data['results']:
            e = r['extra']; m = e.get('metadata', {})
            out.append(finding(source, rule_id(r['check_id']), e['message'], e.get('severity', 'medium'),
                relative(r['path'], root), r['start']['line'], cwe=strings(m.get('cwe')), owasp=strings(m.get('owasp'))))
    elif source == 'gitleaks':
        if not isinstance(data, list):
            raise ValueError('Gitleaks report must be an array')
        for r in data:
            out.append(finding(source, r['RuleID'], r['Description'], 'high', relative(r['File'], root), r['StartLine'],
                evidence='Secret detected; value deliberately omitted.', cwe=['CWE-798'],
                recommendation='Revoke and rotate the credential; remove it from source and history.'))
    elif source == 'trivy':
        if 'Results' not in data and 'SchemaVersion' not in data:
            raise ValueError('Not a Trivy report')
        for group in data.get('Results') or []:
            for r in group.get('Vulnerabilities', []):
                out.append(finding(source, r['VulnerabilityID'], r.get('Title') or r['VulnerabilityID'],
                    r.get('Severity', 'unknown'), relative(group.get('Target'), root), evidence=f"Package {r.get('PkgName')} version {r.get('InstalledVersion')}",
                    cwe=strings(r.get('CweIDs')), recommendation=f"Upgrade to {r.get('FixedVersion') or 'a vendor-supported fixed release; none specified'}."))
            for r in group.get('Misconfigurations', []):
                out.append(finding(source, r['ID'], r['Title'], r.get('Severity', 'unknown'), relative(group.get('Target'), root),
                    r.get('CauseMetadata', {}).get('StartLine') or None, recommendation=r.get('Resolution')))
    elif source == 'osv':
        for group in data['results']:
            for package in group.get('packages', []):
                p = package['package']
                for r in package.get('vulnerabilities', []):
                    # OSV frequently supplies CVSS vectors, not ordinal severities. Do not invent a score.
                    sev = r.get('database_specific', {}).get('severity', 'unknown')
                    out.append(finding(source, r['id'], r.get('summary') or r['id'], sev,
                        relative(group.get('source', {}).get('path'), root), evidence=f"Package {p.get('name')} version {p.get('version')}"))
    elif source == 'codeql':
        for run in data['runs']:
            rules = {r['id']: r for r in run.get('tool', {}).get('driver', {}).get('rules', [])}
            for r in run.get('results', []):
                loc = (r.get('locations') or [{}])[0].get('physicalLocation', {})
                rule = rules.get(r['ruleId'], {})
                tags = rule.get('properties', {}).get('tags', [])
                score = rule.get('properties', {}).get('security-severity')
                sev = r.get('level', 'warning')
                if score is not None:
                    score = float(score); sev = 'critical' if score >= 9 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low'
                out.append(finding(source, r['ruleId'], r['message']['text'], sev,
                    relative(loc.get('artifactLocation', {}).get('uri'), root), loc.get('region', {}).get('startLine'),
                    cwe=[t.upper().split('/')[-1] for t in tags if 'cwe-' in t.lower()]))
    elif source == 'zap':
        for site in data['site']:
            for r in site.get('alerts', []):
                for instance in r.get('instances') or [{}]:
                    out.append(finding(source, r['pluginid'], r['name'],
                        {'0':'info','1':'low','2':'medium','3':'high'}.get(str(r.get('riskcode')), 'info'),
                        endpoint=instance.get('uri') or site.get('@name'),
                        cwe=['CWE-' + str(r['cweid'])] if str(r.get('cweid', '0')) != '0' else [],
                        recommendation=r.get('solution')))
    else:
        raise ValueError('Unknown scanner')
    out = list({f['id']: f for f in out}.values())
    return collapse(out) if source == 'semgrep' else out

def collapse(found):
    # Several Semgrep rules can flag one weakness on one line (a tainted-source rule and a generic sink rule): keep only
    # the most severe finding per file, line and shared CWE. Other scanners report distinct facts and are never merged.
    rank = lambda f: SEVERITIES.index(f['severity']) if f['severity'] in SEVERITIES else -1
    kept = {}
    for f in sorted(found, key=rank, reverse=True):
        cwes = set(re.findall(r'CWE-\d+', ' '.join(f['cwe']).upper()))
        group = kept.setdefault((f['file'], f['line']), [])
        if not any(cwes & other for other, _ in group):
            group.append((cwes, f))
    keep = {id(f) for group in kept.values() for _, f in group}
    return [f for f in found if id(f) in keep]
