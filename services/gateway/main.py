"""FastAPI app entrypoint."""

from fastapi import FastAPI

app = FastAPI(title="SecurMCP Gateway")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
