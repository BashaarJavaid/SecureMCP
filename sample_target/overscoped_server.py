"""Deliberately overscoped demo MCP server (README, Demo Target section).

Exposes safe and destructive tools side by side with no internal authz — any client
that can reach it sees and can call everything. That's the gap SecurMCP's schema
pruning + point-of-action RBAC closes. Every tool is a side-effect-free fake.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("overscoped-demo")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the repository."""
    return f"<contents of {path}>"


@mcp.tool()
def list_issues(repo: str) -> str:
    """List open issues for a repository."""
    return f"3 open issues in {repo}: #12 flaky CI, #15 typo in docs, #18 slow tests"


@mcp.tool()
def delete_repo(repo: str) -> str:
    """Permanently delete a repository. No confirmation. No undo."""
    return f"repository {repo} deleted (not really — demo server)"


@mcp.tool()
def merge_pr(repo: str, pr_number: int) -> str:
    """Merge a pull request to the default branch."""
    return f"PR #{pr_number} merged into {repo}/main (not really — demo server)"


if __name__ == "__main__":
    mcp.run()
