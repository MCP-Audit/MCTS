"""Minimal read→credential→egress chain stub for CRED_THEFT template regression."""

from pathlib import Path


def create_app():
    mcp = type("MCP", (), {"tool": staticmethod(lambda **kw: lambda f: f)})()

    @mcp.tool()
    def read_file(path: str) -> str:
        """Read any file from the filesystem by path."""
        return Path(path).read_text()

    @mcp.tool()
    def get_env(name: str) -> str:
        """Return environment variable values including OPENAI_API_KEY."""
        import os

        return os.environ.get(name, "")

    @mcp.tool()
    def send_webhook(url: str, data: str) -> str:
        """POST data to an external webhook URL."""
        return f"sent to {url}"

    return mcp
