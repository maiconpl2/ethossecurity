"""Normalize native reports without upgrading scanner hypotheses to proof."""
import hashlib
import json
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

def strings(value):
    if not value:
        return []
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]

def normalize(source, data):
    out = []
    if source == 'semgrep':
        for r in data['results']:
            e = r['extra']; m = e.get('metadata', {})
            out.append(finding(source, r['check_id'], e['message'], e.get('severity', 'medium'),
                r['path'], r['start']['line'], cwe=strings(m.get('cwe')), owasp=strings(m.get('owasp'))))
    elif source == 'gitleaks':
        if not isinstance(data, list):
            raise ValueError('Gitleaks report must be an array')
        for r in data:
            out.append(finding(source, r['RuleID'], r['Description'], 'high', r['File'], r['StartLine'],
                evidence='Secret detected; value deliberately omitted.', cwe=['CWE-798'],
                recommendation='Revoke and rotate the credential; remove it from source and history.'))
    elif source == 'trivy':
        if 'Results' not in data and 'SchemaVersion' not in data:
            raise ValueError('Not a Trivy report')
        for group in data.get('Results') or []:
            for r in group.get('Vulnerabilities', []):
                out.append(finding(source, r['VulnerabilityID'], r.get('Title') or r['VulnerabilityID'],
                    r.get('Severity', 'unknown'), group.get('Target'), evidence=f"Package {r.get('PkgName')} version {r.get('InstalledVersion')}",
                    cwe=strings(r.get('CweIDs')), recommendation=f"Upgrade to {r.get('FixedVersion') or 'a vendor-supported fixed release; none specified'}."))
            for r in group.get('Misconfigurations', []):
                out.append(finding(source, r['ID'], r['Title'], r.get('Severity', 'unknown'), group.get('Target'),
                    r.get('CauseMetadata', {}).get('StartLine') or None, recommendation=r.get('Resolution')))
    elif source == 'osv':
        for group in data['results']:
            for package in group.get('packages', []):
                p = package['package']
                for r in package.get('vulnerabilities', []):
                    # OSV frequently supplies CVSS vectors, not ordinal severities. Do not invent a score.
                    sev = r.get('database_specific', {}).get('severity', 'unknown')
                    out.append(finding(source, r['id'], r.get('summary') or r['id'], sev,
                        group.get('source', {}).get('path'), evidence=f"Package {p.get('name')} version {p.get('version')}"))
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
                    loc.get('artifactLocation', {}).get('uri'), loc.get('region', {}).get('startLine'),
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
    return list({f['id']: f for f in out}.values())
