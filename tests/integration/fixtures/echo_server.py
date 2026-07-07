"""Minimal stdio MCP server used as the passthrough-test upstream (not the item-8 demo)."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("echo-upstream")


@mcp.tool()
def echo(text: str) -> str:
    return text


@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b


if __name__ == "__main__":
    mcp.run()
