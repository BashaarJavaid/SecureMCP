"""Connection to the upstream MCP server: a stdio subprocess with SDK-framed messages.

The `mcp` SDK's stdio_client doesn't expose its subprocess handle, which the Session
Manager needs for the SIGTERM cleanup registry (ARCHITECTURE.md §4.8) — so the process
is spawned here directly. The wire format stays SDK-defined: newline-delimited
JSONRPCMessage JSON, exactly as mcp.client.stdio encodes it.
"""

import asyncio
import shlex
from collections.abc import AsyncIterator

from mcp.types import JSONRPCMessage

# readline() ceiling for a single JSON-RPC message from upstream (asyncio default is 64KB,
# too small for large tools/list responses).
_STREAM_LIMIT = 4 * 1024 * 1024


async def spawn(command: str) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        *shlex.split(command),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        limit=_STREAM_LIMIT,
    )


def encode(message: JSONRPCMessage) -> bytes:
    return (message.model_dump_json(by_alias=True, exclude_none=True) + "\n").encode()


async def read_messages(process: asyncio.subprocess.Process) -> AsyncIterator[JSONRPCMessage]:
    assert process.stdout is not None
    while line := await process.stdout.readline():
        yield JSONRPCMessage.model_validate_json(line)


async def write_message(process: asyncio.subprocess.Process, message: JSONRPCMessage) -> None:
    assert process.stdin is not None
    process.stdin.write(encode(message))
    await process.stdin.drain()
