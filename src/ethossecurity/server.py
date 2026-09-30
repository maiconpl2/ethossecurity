from pathlib import Path
import threading
from mcp.server.fastmcp import FastMCP
from .core import config, scan, PROFILES

def create_server(root, config_path=None):
    root = Path(root).resolve(strict=True)
    # Configuration is supplied by the operator, never by a tool caller or target repository.
    cfg = config(config_path, root)
    lock = threading.Lock()
    server = FastMCP('EthosSecurity', host='127.0.0.1')

    @server.tool()
    def security_scan(profile: str = 'full-scan') -> dict:
        """Analyze the operator-configured workspace. Reports incomplete scanner coverage."""
        if profile not in PROFILES:
            raise ValueError('Unknown profile')
        with lock:
            return scan(root, profile, cfg)

    @server.tool()
    def security_profiles() -> dict:
        """List available profiles, scanner routes and installed configuration."""
        return {'profiles': PROFILES, 'enabled_scanners': cfg['scanners']}

    return server

def serve(root, config_path=None, http=False):
    create_server(root, config_path).run(transport='streamable-http' if http else 'stdio')
