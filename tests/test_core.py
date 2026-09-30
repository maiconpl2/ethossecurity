import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ethossecurity.core import command, config, scan, exit_code
from ethossecurity.findings import normalize

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

    def test_failure_and_partial_reports(self):
        for failure in ('exit','partial','malformed','timeout'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as d:
                def execute(argv, **kwargs):
                    import subprocess
                    self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
                    if failure == 'timeout':
                        raise subprocess.TimeoutExpired(argv, 1)
                    output = Path(argv[argv.index('--output')+1])
                    output.write_text('broken' if failure == 'malformed' else json.dumps({'results':[], 'errors':['parse error'] if failure == 'partial' else []}))
                    return subprocess.CompletedProcess(argv, 2 if failure == 'exit' else 0)
                with patch('ethossecurity.core.shutil.which', return_value='semgrep'), patch('ethossecurity.core.subprocess.run', side_effect=execute):
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

    def test_semgrep_preparation_never_inherits_stdin(self):
        import subprocess
        from ethossecurity import prepare
        calls = []
        def execute(argv, **kwargs):
            calls.append(kwargs)
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

if __name__ == '__main__':
    unittest.main()
