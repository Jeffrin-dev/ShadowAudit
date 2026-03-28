"""FastAPI-based HTTP proxy for routing OpenAI API calls through ShadowAudit."""

from __future__ import annotations

from typing import Any

try:  # pragma: no cover - optional dependency.
    import httpx
    from fastapi import FastAPI, Request, Response
except Exception:  # pragma: no cover
    httpx = None
    FastAPI = None
    Request = Any  # type: ignore[assignment]
    Response = Any  # type: ignore[assignment]


def create_app(target: str) -> Any:
    """Build a lightweight HTTP proxy app forwarding requests to ``target``."""

    if FastAPI is None or httpx is None:
        raise RuntimeError("Proxy mode requires optional dependencies: fastapi and httpx")

    app = FastAPI(title="ShadowAudit Proxy")
    base = target.rstrip("/")

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def proxy(path: str, request: Request) -> Response:
        url = f"{base}/{path}" if path else base
        query = request.url.query
        if query:
            url = f"{url}?{query}"

        body = await request.body()
        headers = dict(request.headers)
        headers.pop("host", None)

        async with httpx.AsyncClient(follow_redirects=False, timeout=60.0) as client:
            upstream = await client.request(
                method=request.method,
                url=url,
                content=body,
                headers=headers,
            )

        response_headers = {
            key: value
            for key, value in upstream.headers.items()
            if key.lower() not in {"content-encoding", "transfer-encoding", "connection"}
        }

        return Response(content=upstream.content, status_code=upstream.status_code, headers=response_headers)

    return app


def run_proxy_server(*, port: int, target: str) -> None:
    """Run the local proxy server via Uvicorn."""

    if FastAPI is None:
        raise RuntimeError("Proxy mode requires optional dependencies: fastapi, httpx, and uvicorn")

    import uvicorn

    app = create_app(target)
    uvicorn.run(app, host="127.0.0.1", port=port)
