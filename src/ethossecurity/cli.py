import argparse
import json
from pathlib import Path
from jsonschema.exceptions import ValidationError
from .core import config, scan, exit_code, PROFILES
from .findings import normalize

def main():
    parser = argparse.ArgumentParser(prog='ethos-sec')
    sub = parser.add_subparsers(dest='command', required=True)
    s = sub.add_parser('scan'); s.add_argument('root'); s.add_argument('--profile', choices=PROFILES, default='full-scan')
    s.add_argument('--config'); s.add_argument('--output')
    i = sub.add_parser('import'); i.add_argument('scanner', choices=PROFILES['full-scan']); i.add_argument('report'); i.add_argument('--output')
    m = sub.add_parser('mcp'); m.add_argument('--root', required=True); m.add_argument('--config'); m.add_argument('--http', action='store_true')
    init = sub.add_parser('init'); init.add_argument('root'); init.add_argument('--adapter', choices=['openai','anthropic','antigravity'], default='openai')
    for name in ('setup', 'start'):
        action = sub.add_parser(name)
        action.add_argument('root'); action.add_argument('--client', choices=['codex', 'claude', 'antigravity'], required=True)
        action.add_argument('--tools', nargs='+', choices=['semgrep', 'trivy', 'gitleaks', 'osv'], default=['semgrep', 'trivy', 'gitleaks', 'osv'])
        action.add_argument('--language', choices=['pt-BR', 'en'], default='pt-BR')
    s.add_argument('--html'); s.add_argument('--language', choices=['pt-BR', 'en'], default='pt-BR')
    args = parser.parse_args()
    try:
        if args.command in ('setup', 'start'):
            from .prepare import prepare, project_path, write_json
            from .connect import connect
            from .report import html_report
            preparation = prepare(args.root, args.tools)
            connection = connect(args.root, args.client)
            result = {'preparation': preparation, 'connection': connection}
            if args.command == 'start':
                path = Path(args.root) / 'ethossecurity.yaml'
                cfg = config(path if path.exists() else None, args.root)
                # Onboarding never runs project builds or live-target scans implicitly.
                cfg['scanners'] = [s for s in cfg['scanners'] if s in ('semgrep', 'trivy', 'gitleaks', 'osv')]
                report = scan(args.root, 'full-scan', cfg)
                json_path = project_path(args.root, '.ethossecurity/reports/latest.json')
                html_path = project_path(args.root, '.ethossecurity/reports/latest.html')
                write_json(json_path, report)
                html_report(report, html_path, args.language)
                result.update(report_json=str(json_path), report_html=str(html_path), complete=report['complete'], findings=len(report['findings']))
                code = exit_code(report) if preparation['ready'] else 2
            else:
                code = 0 if preparation['ready'] else 2
            print(json.dumps(result, indent=2, ensure_ascii=False)); raise SystemExit(code)
        if args.command == 'init':
            from .install import initialize
            print(json.dumps(initialize(args.root, args.adapter), indent=2)); return
        if args.command == 'mcp':
            from .server import serve
            serve(args.root, args.config, args.http); return
        if args.command == 'scan':
            path = args.config or (str(Path(args.root) / 'ethossecurity.yaml') if (Path(args.root) / 'ethossecurity.yaml').exists() else None)
            result = scan(args.root, args.profile, config(path, args.root)); code = exit_code(result)
            if args.html:
                from .report import html_report
                html_report(result, args.html, args.language)
        else:
            result = {'schema_version': '1.0', 'findings': normalize(args.scanner, json.loads(Path(args.report).read_text(encoding='utf-8-sig')))}; code = 0
        content = json.dumps(result, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(content, encoding='utf-8')
        else:
            print(content)
        raise SystemExit(code)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ValidationError) as e:
        parser.exit(2, 'ethos-sec: ' + type(e).__name__ + '; check configuration or report format\n')

if __name__ == '__main__':
    main()
