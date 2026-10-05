import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch
from ethossecurity.core import command, config, scan, exit_code
from ethossecurity.findings import normalize

def managed(tool):
    try:
        return shutil.which(config().get('tool_paths', {}).get(tool, tool))
    except (OSError, ValueError, KeyError):
        return None

def plant(root, *files, text='x\n'):
    for name in files:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)

CSC = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'

def marker_exe(folder):
    # A native program that only records its own execution next to itself (marker.txt) and exits with 7.
    source = folder / 'marker.cs'
    source.write_text('using System; using System.IO; class M { static int Main(string[] a) { string e = System.Reflection.Assembly.GetExecutingAssembly().Location; '
                      'File.AppendAllText(Path.Combine(Path.GetDirectoryName(e), "marker.txt"), e + " " + string.Join(" ", a) + Environment.NewLine); return 7; } }')
    subprocess.run([str(CSC), '-nologo', '-out:' + str(folder / 'marker.exe'), str(source)], check=True, capture_output=True)
    return folder / 'marker.exe'

def tool_text(result):
    # FastMCP returns (content blocks, structured content) for dict results; the first block is the JSON text.
    return json.loads((result[0] if isinstance(result, tuple) else result)[0].text)

class CoreTests(unittest.TestCase):
    def test_secret_not_exposed(self):
        result = normalize('gitleaks', [{'RuleID':'token','Description':'Credential','File':'x','StartLine':2,'Secret':'never-print-this','Match':'never-print-this'}])
        self.assertNotIn('never-print-this', json.dumps(result))
        self.assertEqual(result[0]['validation_status'], 'unvalidated')

    def test_formats(self):
        reports = {
          'semgrep': {'results':[{'check_id':'r','path':'x','start':{'line':1},'extra':{'message':'m','severity':'ERROR'}}]},
          'trivy': {'Results':[{'Target':'x','Vulnerabilities':[{'VulnerabilityID':'CVE-test','Severity':'CRITICAL'}], 'Misconfigurations':[{'ID':'AVD-test','Title':'m','Severity':'HIGH'}]}]},
          'osv': {'results':[{'source':{'path':'lock'},'packages':[{'package':{'name':'pkg','version':'1'},'vulnerabilities':[{'id':'OSV-test'}]}]}]},
          'codeql': {'runs':[{'results':[{'ruleId':'r','message':{'text':'m'}}]}]},
          'zap': {'site':[{'@name':'https://example.test','alerts':[{'pluginid':'r','name':'m','riskcode':'3','cweid':'79'}]}]}}
        for scanner, data in reports.items():
            with self.subTest(scanner=scanner):
                self.assertTrue(normalize(scanner, data))

    def test_unknown_osv_severity_not_invented(self):
        data = {'results':[{'packages':[{'package':{},'vulnerabilities':[{'id':'x','severity':[{'type':'CVSS_V3','score':'CVSS:3.1/AV:N'}]}]}]}]}
        self.assertEqual(normalize('osv', data)[0]['severity'], 'unknown')

    def test_missing_scanner_is_incomplete(self):
        with tempfile.TemporaryDirectory() as d, patch('ethossecurity.core.shutil.which', return_value=None):
            result = scan(d, cfg=config())
        self.assertFalse(result['complete']); self.assertEqual(exit_code(result), 2)

    def test_zap_requires_authorization(self):
        with self.assertRaises(ValueError):
            command('zap', Path('.'), {'zap_target':'https://example.test','authorized_targets':[]}, Path('out'))

    def test_no_shell_interpolation(self):
        args, _ = command('semgrep', Path('project;echo unsafe'), config(), Path('out'))
        self.assertEqual(args[-1], 'project;echo unsafe')

    def test_gitleaks_scans_project_relative_paths(self):
        args, _ = command('gitleaks', Path('/work/.ethossecurity/app'), config(), Path('out'))
        self.assertEqual(args[1:3], ['dir', '.'])
        self.assertNotIn(str(Path('/work/.ethossecurity/app')), args)

    def test_gitleaks_allowlist_only_matches_inside_project(self):
        toml = tomllib.loads((Path(__file__).resolve().parents[1] / 'src/ethossecurity/rules/gitleaks.toml').read_text(encoding='utf-8'))
        patterns = [re.compile(p) for a in toml['allowlists'] for p in a['paths']]
        skipped = lambda path: any(p.search(path) for p in patterns)
        for path in ('.ethossecurity/reports/latest.json', '.ethossecurity', './.ethossecurity/tools/x.py', '.ethossecurity\\runtime.json',
                     'apps/api/.ethossecurity/tools/jwt.py', 'node_modules/pkg/index.js', 'apps/web/node_modules/a.js', '.git/config', '.venv/lib/site.py', 'venv/x.py', 'src/__pycache__/a.pyc'):
            with self.subTest(skipped=path):
                self.assertTrue(skipped(path))
        for path in ('src/app.py', '.ethossecurity-notes.txt', 'src/my.ethossecurity.d/a.py', 'dist/assets/index.js',
                     'build/main.js', 'src/venv_utils.py', 'docs/node_modules.md', '.env'):
            with self.subTest(scanned=path):
                self.assertFalse(skipped(path))

    def test_semgrep_pins_project_root_only_when_git_root_is_above_an_ethossecurity_folder(self):
        with tempfile.TemporaryDirectory() as d:
            nested, own, plain = (Path(d) / 'outer/.ethossecurity/inner/app', Path(d) / 'repo/.ethossecurity/inner/app', Path(d) / 'plain/app')
            plant(Path(d), 'outer/.git/HEAD', 'repo/.ethossecurity/inner/app/.git/HEAD', 'plain/.git/HEAD')
            nested.mkdir(parents=True); plain.mkdir(parents=True)
            args = command('semgrep', nested, config(), Path('out'))[0]
            self.assertEqual(args[args.index('--project-root') + 1], str(nested)); self.assertEqual(args[-1], str(nested))
            for root in (own, plain):
                with self.subTest(root=root):
                    self.assertNotIn('--project-root', command('semgrep', root, config(), Path('out'))[0])

    @unittest.skipUnless(managed('gitleaks'), 'gitleaks is not installed')
    def test_gitleaks_real_binary_ignores_parent_folder_but_skips_vendor_and_runtime(self):
        key = 'AKIA' + 'Z7QF3KXN2PLW5MJD'  # Fake, high-entropy AWS access key id; split so this file is not itself a finding.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / '.ethossecurity/.ethossecurity/Gestão de Contas'
            plant(root, 'src/config.py', 'dist/assets/index.js', '.ethossecurity-notes.txt', '.ethossecurity/reports/old.py',
                  'apps/api/.ethossecurity/tools/x.py', 'node_modules/pkg/index.js', 'apps/web/node_modules/a/index.js',
                  '.venv/lib/settings.py', text=f'aws_access_key_id = "{key}"\n')
            result = scan(root, 'infra-security', config() | {'scanners': ['gitleaks']})
        execution = next(e for e in result['executions'] if e['scanner'] == 'gitleaks')
        self.assertEqual(execution['status'], 'completed')
        self.assertEqual(sorted(f['file'] for f in result['findings']), ['.ethossecurity-notes.txt', 'dist/assets/index.js', 'src/config.py'])
        self.assertNotIn(key, json.dumps(result))

    @unittest.skipUnless(managed('semgrep'), 'semgrep is not installed')
    def test_semgrep_real_binary_reads_accented_project_under_parent_folder(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / '.ethossecurity/Gestão de Contas'
            plant(root, 'src/app.py', '.ethossecurity/tools/old.py', 'sub/.ethossecurity/x.py', text='import subprocess\nsubprocess.run(cmd, shell=True)\n')
            result = scan(root, 'bug-hunter', config() | {'scanners': ['semgrep']})
        self.assertEqual(next(e for e in result['executions'] if e['scanner'] == 'semgrep')['status'], 'completed')
        hits = [f['file'] for f in result['findings'] if f['rule_id'] == 'ethos.python.shell-input']
        self.assertEqual(hits, ['src/app.py'])

    def test_failure_and_partial_reports(self):
        for failure in ('exit','partial','malformed','timeout'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as d:
                def execute(argv, **kwargs):
                    self.assertEqual(kwargs['stdin'], subprocess.DEVNULL); self.assertEqual(kwargs['env']['PYTHONUTF8'], '1')
                    self.assertNotEqual(Path(kwargs['cwd']).resolve(), Path(d).resolve())  # never the scanned project
                    if failure == 'timeout':
                        raise subprocess.TimeoutExpired(argv, 1)
                    output = Path(argv[argv.index('--output')+1])
                    output.write_text('broken' if failure == 'malformed' else json.dumps({'results':[], 'errors':['parse error'] if failure == 'partial' else []}))
                    return subprocess.CompletedProcess(argv, 2 if failure == 'exit' else 0)
                with patch('ethossecurity.core.shutil.which', return_value=os.path.abspath('semgrep')), patch('ethossecurity.core.subprocess.run', side_effect=execute):
                    result = scan(d, 'bug-hunter', config() | {'scanners':['semgrep']})
                self.assertEqual(exit_code(result), 2)

    def test_completed_policy_gate(self):
        self.assertEqual(exit_code({'complete':True,'policy_failed':True}), 1)
        self.assertEqual(exit_code({'complete':True,'policy_failed':False}), 0)

    def test_init_exports_and_preserves_existing_files(self):
        from ethossecurity.install import initialize
        with tempfile.TemporaryDirectory() as d:
            result = initialize(d, 'openai')
            self.assertEqual(len(result['created']), 6)
            skill = Path(d) / '.agents/skills/bug-hunter/SKILL.md'
            original = skill.read_text()
            with self.assertRaises(ValueError):
                initialize(d, 'openai')
            self.assertEqual(skill.read_text(), original)

    def test_mcp_exposes_only_fixed_tools(self):
        import asyncio
        from ethossecurity.server import create_server
        with tempfile.TemporaryDirectory() as d:
            server = create_server(d)
            tools = asyncio.run(server.list_tools())
            self.assertEqual({t.name for t in tools}, {'security_scan','security_profiles'})
            scan_tool = next(t for t in tools if t.name == 'security_scan')
            self.assertEqual(set(scan_tool.inputSchema['properties']), {'profile'})

    def test_plugin_mode_uses_session_project_and_distrusts_its_runtime(self):
        import asyncio
        from ethossecurity import core, server as srv
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as d:
            planted = Path(d) / '.ethossecurity/runtime.json'
            planted.parent.mkdir()
            planted.write_text(json.dumps({'tool_paths': {'semgrep': str(Path(d).resolve() / 'evil.exe')}}))
            with patch.object(core, 'GLOBAL_HOME', Path(home)), patch.object(srv, 'GLOBAL_HOME', Path(home)), \
                 patch.dict('os.environ', {'CLAUDE_PROJECT_DIR': d}):
                self.assertEqual(srv.workspace_root(), d)
                self.assertNotIn('tool_paths', config(root=d, trust_project=False))
                self.assertIn('semgrep', config(root=d)['tool_paths'])
                tools = asyncio.run(srv.create_server().list_tools())
                self.assertEqual({t.name for t in tools}, {'security_scan', 'security_profiles', 'security_setup'})
            with patch.dict('os.environ', {'CLAUDE_PROJECT_DIR': '${CLAUDE_PROJECT_DIR}'}):
                self.assertEqual(srv.workspace_root(), str(Path.cwd()))

    def test_claude_marketplace_is_consistent(self):
        repo = Path(__file__).resolve().parents[1]
        market = json.loads((repo / '.claude-plugin/marketplace.json').read_text(encoding='utf-8'))
        names = {p['name'] for p in market['plugins']}
        for plugin in market['plugins']:
            self.assertTrue(set(plugin.get('dependencies', [])) <= names)
            for skill in plugin.get('skills', []):
                self.assertTrue((repo / skill / 'SKILL.md').is_file())
        # Only the engine carries the MCP server; a default skills/ folder would leak every skill into it.
        self.assertEqual(sum('mcpServers' in p for p in market['plugins']), 1)
        self.assertFalse((repo / 'skills').exists())
        # Isolated interpreter, no console-script trampoline: the session project (cwd) never shadows ethossecurity, yaml
        # or mcp. "uv run --isolated" gives every session its own ephemeral environment from uv's cache: no shared venv
        # that a running session keeps locked during an update, or that an uninstall leaves half deleted.
        server = next(p for p in market['plugins'] if 'mcpServers' in p)['mcpServers']['ethossecurity']
        args = server['args']
        self.assertIn('--isolated', args[:args.index('--project')])
        self.assertNotIn('UV_PROJECT_ENVIRONMENT', server.get('env', {}))
        self.assertEqual(args[args.index('${CLAUDE_PLUGIN_ROOT}') + 1:], ['python', '-I', '-m', 'ethossecurity.cli', 'mcp'])
        from ethossecurity import __version__
        self.assertEqual({p['version'] for p in market['plugins']}, {__version__})

    def test_semgrep_preparation_never_inherits_stdin(self):
        from ethossecurity import prepare
        calls = []
        def execute(argv, **kwargs):
            calls.append(kwargs | {'argv': argv})
            if 'pip' in argv:
                exe = Path(argv[0]).parent / ('semgrep.exe' if Path(argv[0]).suffix else 'semgrep')
                exe.write_text('')
            return subprocess.CompletedProcess(argv, 0)
        with tempfile.TemporaryDirectory() as d, patch.object(prepare.venv, 'EnvBuilder') as builder, \
             patch.object(prepare.subprocess, 'run', side_effect=execute):
            builder.return_value.create.side_effect = lambda folder: (Path(folder) / ('Scripts' if os.name == 'nt' else 'bin')).mkdir(parents=True)
            prepare.semgrep_install(d, '0.0.0')
        builder.assert_called_once_with(with_pip=False)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(c['stdin'] == subprocess.DEVNULL for c in calls))
        folder = Path(d).resolve() / '.ethossecurity/tools/semgrep/0.0.0'
        self.assertTrue(all(c['argv'][1:3] == ['-I', '-m'] and Path(c['cwd']) == folder for c in calls))

    def test_findings_use_clean_rule_ids_and_project_relative_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'ethos' / 'app'
            (root / 'src').mkdir(parents=True)
            prefix = '.'.join(part.strip(':/\\') for part in root.parts) + '.rules.semgrep.'
            data = {'results': [{'check_id': prefix + 'ethos.python.os-command-dynamic', 'path': str(root / 'src' / 'app.py'),
                                 'start': {'line': 3}, 'extra': {'message': 'm', 'severity': 'WARNING'}}]}
            found = normalize('semgrep', data, root)[0]
            self.assertEqual(found['rule_id'], 'ethos.python.os-command-dynamic')
            self.assertEqual(found['file'], 'src/app.py')
            leaks = normalize('gitleaks', [{'RuleID': 'aws', 'Description': 'd', 'File': str(Path('src') / 'cfg.py'), 'StartLine': 1}], root)
            self.assertEqual(leaks[0]['file'], 'src/cfg.py')
            outside = normalize('semgrep', {'results': [dict(data['results'][0], path=str(Path(d) / 'other.py'))]}, root)
            self.assertEqual(outside[0]['file'], str(Path(d) / 'other.py'))

    def test_semgrep_preparation_ignores_project_ensurepip_and_pip(self):
        from ethossecurity import prepare
        real = subprocess.run
        with tempfile.TemporaryDirectory() as project, tempfile.TemporaryDirectory() as home:
            marker = Path(project) / 'marker.txt'
            for package in ('ensurepip', 'pip'):
                plant(Path(project), package + '/__main__.py', text='')
                plant(Path(project), package + '/__init__.py', text=f'open({str(marker)!r}, "a").write("{package}")\n')
            def execute(argv, **kwargs):
                # Same interpreter flags, module and working directory, with a harmless --version instead of an installation.
                module = argv.index('-m') + 1
                real([sys.executable, *argv[1:module + 1], '--version'], cwd=kwargs['cwd'], stdin=subprocess.DEVNULL, capture_output=True)
                if argv[module] == 'pip':
                    (Path(argv[0]).parent / ('semgrep.exe' if os.name == 'nt' else 'semgrep')).write_text('')
                return subprocess.CompletedProcess(argv, 0)
            cwd = os.getcwd()
            os.chdir(project)  # the MCP server's cwd is the session project
            try:
                with patch.object(prepare.venv, 'EnvBuilder') as builder, patch.object(prepare.subprocess, 'run', side_effect=execute):
                    builder.return_value.create.side_effect = lambda folder: (Path(folder) / ('Scripts' if os.name == 'nt' else 'bin')).mkdir(parents=True)
                    prepare.semgrep_install(home, '0.0.0')
            finally:
                os.chdir(cwd)
            self.assertFalse(marker.exists())
            # Control: the planted packages do shadow the standard library under a plain "-m" from the project.
            real([sys.executable, '-m', 'pip', '--version'], cwd=project, stdin=subprocess.DEVNULL, capture_output=True)
            self.assertEqual(marker.read_text(), 'pip')

    def test_version_probes_run_from_the_managed_tool_folder(self):
        from ethossecurity import prepare
        calls = []
        with tempfile.TemporaryDirectory() as d:
            tool = Path(d).resolve() / 'tools/gitleaks.exe'
            def execute(argv, **kwargs):
                calls.append(kwargs)
                return subprocess.CompletedProcess(argv, 0)
            with patch.object(prepare, 'binary_install', return_value=str(tool)), patch.object(prepare.subprocess, 'run', side_effect=execute):
                self.assertTrue(prepare.prepare(d, ['gitleaks'])['ready'])
        self.assertEqual([Path(c['cwd']) for c in calls], [tool.parent])

    def test_untrusted_mode_runs_only_prepared_absolute_executables(self):
        from ethossecurity import core
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as d:
            policy = Path(home) / 'ethossecurity.yaml'
            policy.write_text('trust_project: true\n')
            with patch.object(core, 'GLOBAL_HOME', Path(home)), patch('ethossecurity.core.shutil.which', side_effect=AssertionError('lookup by name')):
                cfg = config(policy, d, trust_project=False)
                self.assertFalse(cfg['trust_project'])  # no configuration file can declare the project trusted
                result = scan(d, 'infra-security', cfg)
        self.assertEqual({e['status'] for e in result['executions']}, {'unavailable'})
        self.assertFalse(result['complete'])

    @unittest.skipUnless(os.name == 'nt' and CSC.is_file() and managed('semgrep'), 'needs Windows, csc.exe and the managed semgrep')
    def test_untrusted_project_cannot_plant_scanner_executables(self):
        from ethossecurity import prepare
        with tempfile.TemporaryDirectory() as build, tempfile.TemporaryDirectory() as d:
            root, marker = Path(d).resolve(), marker_exe(Path(build))
            for name in ('pysemgrep.exe', 'semgrep.exe', 'trivy.exe'):
                shutil.copyfile(marker, root / name)
            (root / 'trivy.bat').write_text('@echo bat >> "%~dp0marker.txt"\r\n@exit /b 7\r\n')
            plant(root, 'src/app.py', text='import subprocess\nsubprocess.run(cmd, shell=True)\n')
            # trivy is not prepared yet: it must never be looked up by name.
            cfg = config(root=root, trust_project=False) | {'scanners': ['semgrep', 'trivy'], 'tool_paths': {'semgrep': managed('semgrep')}}
            # A host without NoDefaultCurrentDirectoryInExePath (os.environ keys are upper-case on Windows).
            host = {k: v for k, v in os.environ.items() if k.upper() != 'NODEFAULTCURRENTDIRECTORYINEXEPATH'}
            cwd = os.getcwd()
            os.chdir(root)  # the MCP server's cwd is the session project
            try:
                with patch.dict(os.environ, host, clear=True):
                    result = scan(root, 'full-scan', cfg)
                    with patch.object(prepare, 'semgrep_install', return_value=cfg['tool_paths']['semgrep']):
                        setup = prepare.prepare(build, ['semgrep'])
            finally:
                os.chdir(cwd)
            planted_ran = (root / 'marker.txt').exists()
        status = {e['scanner']: e['status'] for e in result['executions']}
        self.assertFalse(planted_ran)
        self.assertEqual((status['semgrep'], status['trivy']), ('completed', 'unavailable'))
        self.assertIn('src/app.py', [f['file'] for f in result['findings']])
        self.assertTrue(setup['ready'])  # the version probe ran the managed semgrep, not the planted pysemgrep.exe

    def test_untrusted_project_native_scanner_configs_are_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            root, output = Path(d), Path(d) / 'private/trivy.json'
            empty = str(output.parent / 'empty')
            trusted, untrusted = config(root=root), config(root=root, trust_project=False)
            value = lambda args, flag: args[args.index(flag) + 1] if flag in args else None
            plant(root, 'trivy.yaml', '.trivyignore')
            trivy = command('trivy', root, untrusted, output)[0]
            self.assertEqual((value(trivy, '--config'), value(trivy, '--ignorefile')), (empty, empty))
            self.assertEqual(value(command('gitleaks', root, untrusted, output)[0], '--gitleaks-ignore-path'), empty)
            self.assertEqual(value(command('osv', root, untrusted, output)[0], '--config'), empty)
            # Trusted (CLI) projects keep their own files, now named explicitly because the cwd is private.
            trivy = command('trivy', root, trusted, output)[0]
            self.assertEqual((value(trivy, '--config'), value(trivy, '--ignorefile')), (str(root / 'trivy.yaml'), str(root / '.trivyignore')))
            self.assertNotIn('--gitleaks-ignore-path', command('gitleaks', root, trusted, output)[0])
            self.assertNotIn('--config', command('osv', root, trusted, output)[0])
            (root / 'trivy.yaml').unlink(); (root / '.trivyignore').unlink()
            trivy = command('trivy', root, trusted, output)[0]
            self.assertFalse({'--config', '--ignorefile'} & set(trivy))  # an explicit missing file is fatal for trivy

    def test_trusted_relative_codeql_suite_still_names_the_project_file(self):
        with tempfile.TemporaryDirectory() as d:
            root, output = Path(d), Path(d) / 'private/codeql.sarif'
            plant(root, 'suite.qls')
            cfg = {'codeql_database': str(root / 'db'), 'codeql_queries': 'suite.qls'}
            analyze = lambda base, extra={}: command('codeql', root, base | cfg | extra, output)[0][4]
            self.assertEqual(analyze(config(root=root)), str(root / 'suite.qls'))  # codeql no longer runs from the project
            self.assertEqual(analyze(config(root=root), {'codeql_queries': 'codeql/python-queries'}), 'codeql/python-queries')
            self.assertEqual(analyze(config(root=root, trust_project=False)), 'suite.qls')  # never a project-supplied suite

    @unittest.skipUnless(managed('gitleaks'), 'gitleaks is not installed')
    def test_untrusted_gitleaksignore_cannot_hide_secrets(self):
        key = 'AKIA' + 'Z7QF3KXN2PLW5MJD'  # Fake, high-entropy AWS access key id; split so this file is not itself a finding.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / '.ethossecurity/app'
            plant(root, 'src/config.py', 'src/other.py', 'node_modules/pkg/a.js', text=f'aws_access_key_id = "{key}"\n')
            # Padding first: every entry counts, not only the first ones.
            plant(root, '.gitleaksignore', text=''.join(f'junk/{i}.py:aws-access-token:1\n' for i in range(1500)) +
                                                'src/config.py:aws-access-token:1\nnode_modules/pkg/a.js:aws-access-token:1\n'
                                                '../outside.py:aws-access-token:1\n.gitleaksignore:aws-access-token:1\nnot an entry\n')
            files = lambda cfg: sorted(f['file'] for f in scan(root, 'infra-security', cfg | {'scanners': ['gitleaks']})['findings'])
            trusted, untrusted = files(config()), files(config(root=root, trust_project=False))
        self.assertEqual(trusted, ['src/other.py'])  # control: gitleaks applies the project's own list
        self.assertEqual(untrusted, ['src/config.py', 'src/other.py'])  # still skips managed vendor folders

    def test_gitleaksignore_staging_reads_every_entry(self):
        from ethossecurity.core import stage_ignored
        with tempfile.TemporaryDirectory() as d:
            root, stage = Path(d).resolve() / 'p', Path(d).resolve() / 'stage'
            names = ['src/a.py', 'src/b.py'] + (['src/c:d.py'] if os.name != 'nt' else [])  # POSIX names may hold colons
            plant(root, *names)
            entries = ['src\\a.py:r:1', *(f'junk/{i}.py:r:1' for i in range(1500)), 'src/b.py:r:1', *(n + ':r:1' for n in names[2:])]
            plant(root, '.gitleaksignore', text='\n'.join(entries) + '\n')
            self.assertTrue(stage_ignored(root, stage))
            self.assertEqual(sorted(p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_file()), sorted(names))
            plant(root, '.gitleaksignore', text='x' * (1 << 20) + '\n')
            with self.assertRaises(ValueError):  # too long to check in full: the scan fails instead of trusting it
                stage_ignored(root, Path(d) / 'stage2')

    @unittest.skipUnless(managed('trivy'), 'trivy is not installed')
    def test_untrusted_trivy_config_cannot_redirect_or_silence_findings(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            plant(root, 'Dockerfile', text='FROM ubuntu:latest\nRUN apt-get update\n')
            plant(root, 'requirements.txt', text='Django==2.2.0\n')
            # server.addr would upload the package inventory and take results from that server; skip-files hides everything.
            plant(root, 'trivy.yaml', text='server:\n  addr: http://127.0.0.1:9\nscan:\n  skip-files:\n    - "**/*"\n')
            plant(root, '.trivyignore', text='CVE-2019-14234\n')
            result = scan(root, 'infra-security', config(root=root, trust_project=False) | {'scanners': ['trivy']})
        self.assertEqual(next(e for e in result['executions'] if e['scanner'] == 'trivy')['status'], 'completed')
        self.assertIn('CVE-2019-14234', {f['rule_id'] for f in result['findings']})
        self.assertIn('Dockerfile', {f['file'] for f in result['findings']})

    @unittest.skipUnless(managed('osv'), 'osv-scanner is not installed')
    def test_untrusted_osv_config_cannot_silence_findings(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            plant(root, 'requirements.txt', 'sub/requirements.txt', text='Django==2.2.0\n')
            plant(root, 'osv-scanner.toml', 'sub/osv-scanner.toml', text='[[PackageOverrides]]\nname = "django"\necosystem = "PyPI"\nignore = true\nreason = "x"\n')
            result = scan(root, 'infra-security', config(root=root, trust_project=False) | {'scanners': ['osv']})
        self.assertEqual(next(e for e in result['executions'] if e['scanner'] == 'osv')['status'], 'completed')
        self.assertEqual({f['file'] for f in result['findings']}, {'requirements.txt', 'sub/requirements.txt'})

    def test_plugin_reports_use_a_short_portable_folder_and_never_lose_a_scan(self):
        import asyncio
        from ethossecurity import core, server as srv
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as d:
            with patch.object(core, 'GLOBAL_HOME', Path(home)), patch.object(srv, 'GLOBAL_HOME', Path(home)):
                files = srv.save_reports(Path(d) / ('Gestão de Contas (v2) ' + 'p' * 230), {'root': d, 'complete': True, 'executions': [], 'findings': []})
                self.assertTrue(Path(files['json']).is_file())
                self.assertRegex(Path(files['json']).parent.name, r'^Gest_o_de_Contas_v2_p{20}-[0-9a-f]{8}$')
                shutil.rmtree(Path(home) / 'reports')
                (Path(home) / 'reports').write_text('not a folder')
                with patch.dict('os.environ', {'CLAUDE_PROJECT_DIR': d}):
                    report = tool_text(asyncio.run(srv.create_server().call_tool('security_scan', {'profile': 'bug-hunter'})))
        self.assertIn('error', report['report_files'])
        self.assertEqual(next(e for e in report['executions'] if e['scanner'] == 'semgrep')['status'], 'unavailable')

    def test_semgrep_findings_on_one_line_with_a_shared_cwe_are_collapsed(self):
        hit = lambda rule, severity, line, cwe: {'check_id': 'ethos.js.' + rule, 'path': 'Comp.jsx', 'start': {'line': line},
                                                 'extra': {'message': rule, 'severity': severity, 'metadata': {'cwe': cwe}}}
        found = normalize('semgrep', {'results': [hit('react-dangerously-set-inner-html', 'WARNING', 7, ['CWE-79']),
            hit('dom-xss-untrusted-source', 'ERROR', 7, ["CWE-79: Improper Neutralization of Input During Web Page Generation"]),
            hit('open-redirect', 'WARNING', 7, ['CWE-601']), hit('dom-xss-unescaped-html', 'WARNING', 8, ['CWE-79']),
            hit('no-cwe', 'INFO', 7, [])]})
        self.assertEqual([(f['line'], f['rule_id'], f['severity']) for f in found],
                         [(7, 'ethos.js.dom-xss-untrusted-source', 'high'), (7, 'ethos.js.open-redirect', 'medium'),
                          (8, 'ethos.js.dom-xss-unescaped-html', 'medium'), (7, 'ethos.js.no-cwe', 'info')])
        # Other scanners report distinct facts: two gitleaks rules on one line stay two findings.
        leaks = normalize('gitleaks', [{'RuleID': rule, 'Description': 'd', 'File': 'a.py', 'StartLine': 1} for rule in ('aws', 'generic')])
        self.assertEqual(len(leaks), 2)

if __name__ == '__main__':
    unittest.main()
