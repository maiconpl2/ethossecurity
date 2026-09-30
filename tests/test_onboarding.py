import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from ethossecurity.connect import connect
from ethossecurity.prepare import binary_install, download, extract_executable
from ethossecurity.report import html_report


class OnboardingTests(unittest.TestCase):
    def test_all_clients_preserve_config_and_are_idempotent(self):
        for client, relative in [('claude', '.mcp.json'), ('antigravity', '.agents/mcp_config.json'), ('codex', '.codex/config.toml')]:
            with self.subTest(client=client), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                original = 'model = "example"\n[mcp_servers.other]\ncommand = "other"\n' if client == 'codex' else json.dumps({'mcpServers': {'other': {'command': 'other'}}, 'custom': True})
                path.write_text(original, encoding='utf-8')
                result = connect(temp, client)
                content = path.read_text(encoding='utf-8')
                self.assertIn('other', content)
                self.assertEqual(Path(str(path) + '.ethossecurity-backup').read_text(encoding='utf-8'), original)
                self.assertEqual(len(result['skills']), 4)
                connect(temp, client)
                self.assertEqual(path.read_text(encoding='utf-8'), content)

    def test_conflicting_connection_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / '.mcp.json'
            original = json.dumps({'mcpServers': {'ethossecurity': {'command': 'user-managed'}}})
            path.write_text(original)
            with self.assertRaises(ValueError):
                connect(temp, 'claude')
            self.assertEqual(path.read_text(), original)
            self.assertFalse((Path(temp) / '.claude').exists())

    def test_download_rejects_hash_mismatch(self):
        import io
        with tempfile.TemporaryDirectory() as temp, patch('urllib.request.urlopen', return_value=io.BytesIO(b'wrong')):
            with self.assertRaises(ValueError):
                download('https://github.com/vendor/release', Path(temp) / 'asset', '0' * 64)

    def test_archive_never_extracts_arbitrary_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / 'asset.zip'
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('../../outside', 'do not extract')
                bundle.writestr('nested/gitleaks.exe', b'binary')
            output = Path(temp) / 'gitleaks.exe'
            extract_executable(archive, {'url': 'https://github.com/vendor/file.zip', 'executable': 'gitleaks.exe'}, output)
            self.assertEqual(output.read_bytes(), b'binary')
            self.assertEqual(set(p.name for p in Path(temp).iterdir()), {'asset.zip', 'gitleaks.exe'})

    def test_changed_binary_is_not_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / '.ethossecurity/tools/gitleaks/v1'
            folder.mkdir(parents=True)
            (folder / 'gitleaks.exe').write_bytes(b'changed')
            (folder / 'receipt.json').write_text(json.dumps({'asset_sha256': 'a' * 64, 'binary_sha256': hashlib.sha256(b'original').hexdigest()}))
            with self.assertRaises(ValueError):
                binary_install(temp, 'gitleaks', {'version': 'v1', 'platforms': {'windows-x86_64': {'executable': 'gitleaks.exe', 'sha256': 'a' * 64}}}, 'windows-x86_64')

    def test_report_escapes_untrusted_values_and_discloses_gaps(self):
        with tempfile.TemporaryDirectory() as temp:
            report = {'root': '<script>alert(1)</script>', 'complete': False, 'executions': [{'scanner': 'osv', 'status': 'failed', 'reason': '<img src=x onerror=alert(1)>'}], 'findings': []}
            path = Path(temp) / 'report.html'
            html_report(report, path)
            content = path.read_text(encoding='utf-8')
            self.assertNotIn('<script>', content)
            self.assertNotIn('<img', content)
            self.assertIn('Análise incompleta', content)
            self.assertIn('Content-Security-Policy', content)


if __name__ == '__main__':
    unittest.main()
