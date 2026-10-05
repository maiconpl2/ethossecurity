from pathlib import Path
import hashlib
import os
import re
import threading
from mcp.server.fastmcp import FastMCP
from .core import config, scan, PROFILES, GLOBAL_ROOT, GLOBAL_HOME

def workspace_root():
    # The plugin passes ${CLAUDE_PROJECT_DIR}; fall back to the session directory if the host left it unresolved.
    project = os.environ.get('CLAUDE_PROJECT_DIR', '')
    return project if project and '${' not in project else os.getcwd()

def save_reports(root, report):
    from .prepare import write_json
    from .report import html_report
    # Reports stay in the user's private folder; the scanned project is never modified. The folder name is short and
    # portable (Windows MAX_PATH, reserved characters); the hash of the full path keeps it unique.
    name = re.sub(r'[^A-Za-z0-9._-]+', '_', root.name)[:40]
    folder = GLOBAL_HOME / 'reports' / (name + '-' + hashlib.sha256(str(root).encode()).hexdigest()[:8])
    write_json(folder / 'latest.json', report)
    return {'json': str(folder / 'latest.json'), 'html': html_report(report, folder / 'latest.html')}

def create_server(root=None, config_path=None):
    # Without an explicit root (plugin mode) the current workspace is scanned and treated as untrusted.
    workspace = root is None
    root = Path(root or workspace_root()).resolve(strict=True)
    if workspace and config_path is None and (GLOBAL_HOME / 'ethossecurity.yaml').exists():
        config_path = GLOBAL_HOME / 'ethossecurity.yaml'
    # Configuration is supplied by the operator, never by a tool caller or target repository.
    def load():
        return config(config_path, root, trust_project=not workspace)
    cfg = load()
    lock = threading.Lock()
    server = FastMCP('EthosSecurity', host='127.0.0.1')

    @server.tool()
    def security_scan(profile: str = 'full-scan') -> dict:
        """Analyze the operator-configured workspace. Reports incomplete scanner coverage. In plugin mode, call security_setup first when scanners are reported unavailable."""
        if profile not in PROFILES:
            raise ValueError('Unknown profile')
        with lock:
            if not workspace:
                return scan(root, profile, cfg)
            report = scan(root, profile, load())
            try:
                report['report_files'] = save_reports(root, report)
            except OSError as error:
                # A finished scan is still returned when its local copy cannot be written (disk full, permissions).
                report['report_files'] = {'error': type(error).__name__ + ': report could not be saved under ~/.ethossecurity/reports'}
            return report

    @server.tool()
    def security_profiles() -> dict:
        """List available profiles, scanner routes and installed configuration."""
        current = load() if workspace else cfg
        return {'profiles': PROFILES, 'enabled_scanners': current['scanners'], 'workspace': str(root),
                'prepared_scanners': sorted(current.get('tool_paths', {}))}

    if workspace:
        @server.tool()
        def security_setup() -> dict:
            """Download and verify the pinned scanners once for this user (~/.ethossecurity). Use when security_scan reports unavailable scanners."""
            from .prepare import prepare
            with lock:
                return prepare(GLOBAL_ROOT)

    return server

def serve(root=None, config_path=None, http=False):
    # Windows program lookups must not search the current directory (in plugin mode, the untrusted session project).
    os.environ.setdefault('NoDefaultCurrentDirectoryInExePath', '1')
    create_server(root, config_path).run(transport='streamable-http' if http else 'stdio')
