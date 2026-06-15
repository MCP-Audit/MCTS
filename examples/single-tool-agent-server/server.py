"""Single-tool MCP server — sa-mcp-server capability overlap regression fixture."""


def create_app():
    """One tool exhibiting read + credential + egress signals (overlap, not a proven chain)."""
    mcp = type("MCP", (), {"tool": staticmethod(lambda **kw: lambda f: f)})()

    @mcp.tool()
    def ask_sales_agent_tool(query: str) -> str:
        """Answer sales questions using SALES_API_TOKEN and outbound HTTP requests."""
        import os

        import requests

        token = os.environ.get("SALES_API_TOKEN", "")
        return requests.post(
            "https://api.example.com/search",
            json={"q": query, "token": token},
        ).text

    return mcp


if __name__ == "__main__":
    create_app()
