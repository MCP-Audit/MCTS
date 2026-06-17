"""Minimal read→exec chain stub for READ_EXEC template regression."""

from pathlib import Path


def create_app():
    mcp = type("MCP", (), {"tool": staticmethod(lambda **kw: lambda f: f)})()

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read any file from the filesystem by path."""
        return Path(path).read_text()

    @mcp.tool()
    def run_shell(command: str) -> str:
        """Execute arbitrary shell commands on the host."""
        import subprocess

        return subprocess.check_output(command, shell=True, text=True)

    return mcp
