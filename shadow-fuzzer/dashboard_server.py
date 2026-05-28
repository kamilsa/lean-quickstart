"""FastAPI backend for the Shadow fuzzer dashboard."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import threading
import zipfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from dashboard_db import DashboardDB, utc_now

FUZZER_ROOT = Path(__file__).resolve().parent
_BACKGROUND_TASKS: set[asyncio.Task[None]] = set()


class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        with contextlib.suppress(ValueError):
            self.active.remove(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        if not self.active:
            return
        message = json.dumps(payload)
        for websocket in list(self.active):
            try:
                await websocket.send_text(message)
            except Exception:
                self.disconnect(websocket)


def _find_static_dir() -> Path | None:
    candidates = [
        FUZZER_ROOT / "web" / "dist",
        Path.cwd() / "shadow-fuzzer" / "web" / "dist",
        Path.cwd() / "web" / "dist",
    ]
    for candidate in candidates:
        if candidate.is_dir() and (candidate / "index.html").is_file():
            return candidate
    return None


def _zip_directory(directory: Path, arc_root: str | Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for file_path in sorted(directory.rglob("*")):
            if file_path.is_file():
                archive.write(file_path, Path(arc_root) / file_path.relative_to(directory))
    return buf.getvalue()


def _download_response(data: bytes, filename: str) -> Response:
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def create_app(
    output_dir: str | Path,
    static_dir: str | Path | None = None,
    *,
    reindex: bool = True,
) -> FastAPI:
    output_path = Path(output_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    db = DashboardDB(output_path / "runs.db")
    if reindex:
        indexed = db.reindex_output_dir(output_path)
        if indexed:
            print(f"Dashboard indexed {indexed} existing run(s) from {output_path}")

    static_path = Path(static_dir).resolve() if static_dir else _find_static_dir()
    manager = ConnectionManager()

    async def watch_database() -> None:
        last_event_id = db.get_max_event_id()
        last_run_cursor = utc_now()
        while True:
            try:
                new_events = db.get_events_since(last_event_id)
                if new_events:
                    last_event_id = max(event["id"] for event in new_events)
                    await manager.broadcast({"type": "events", "events": new_events})

                updated_runs = db.get_updated_runs_since(last_run_cursor)
                last_run_cursor = utc_now()
                if updated_runs:
                    await manager.broadcast({"type": "runs", "runs": updated_runs})
            except Exception as exc:
                await manager.broadcast(
                    {
                        "type": "warning",
                        "message": f"dashboard database watcher failed: {exc}",
                    }
                )
            await asyncio.sleep(1)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        task = asyncio.create_task(watch_database())
        _BACKGROUND_TASKS.add(task)
        task.add_done_callback(_BACKGROUND_TASKS.discard)
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="Shadow Fuzzer Dashboard", lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/stats")
    async def get_stats() -> dict[str, Any]:
        return db.get_stats()

    @app.get("/api/runs")
    async def get_runs(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return db.get_runs(limit=max(1, min(limit, 500)), offset=max(0, offset))

    @app.get("/api/run/{run_id}")
    async def get_run(run_id: str) -> dict[str, Any]:
        run = db.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        return run

    @app.get("/api/run/{run_id}/progress")
    async def get_progress(run_id: str) -> dict[str, Any]:
        progress = db.get_progress(run_id)
        if not progress:
            raise HTTPException(status_code=404, detail="Run not found")
        return progress

    @app.get("/api/run/{run_id}/slots")
    async def get_slots(run_id: str) -> dict[str, Any]:
        slots = db.get_slots(run_id)
        if not slots:
            raise HTTPException(status_code=404, detail="Run not found")
        return slots

    @app.get("/api/run/{run_id}/slot/{slot}")
    async def get_slot(run_id: str, slot: int) -> dict[str, Any]:
        detail = db.get_slot_detail(run_id, slot)
        if not detail:
            raise HTTPException(status_code=404, detail="Run not found")
        return detail

    @app.get("/api/run/{run_id}/events")
    async def get_events(
        run_id: str,
        kind: str | None = None,
        slot: int | None = None,
        host: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not db.get_run(run_id):
            raise HTTPException(status_code=404, detail="Run not found")
        return db.get_events(
            run_id,
            kind=kind or None,
            slot=slot,
            host=host or None,
            limit=max(1, min(limit, 1000)),
        )

    @app.get("/api/run/{run_id}/chain")
    async def get_chain(run_id: str, slot: int | None = None) -> dict[str, Any]:
        chain = db.get_chain(run_id, slot=slot)
        if chain is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return chain

    @app.get("/api/run/{run_id}/shadow.yaml")
    async def download_shadow_yaml(run_id: str) -> FileResponse:
        run = db.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        path = Path(run["run_dir"]) / "shadow.yaml"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="shadow.yaml not found")
        return FileResponse(path, filename=f"{run_id}-shadow.yaml")

    @app.get("/api/run/{run_id}/logs.zip")
    async def download_logs(run_id: str) -> Response:
        run = db.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        shadow_data = Path(run["run_dir"]) / "shadow.data"
        if not shadow_data.is_dir():
            raise HTTPException(status_code=404, detail="shadow.data not found")
        return _download_response(
            _zip_directory(shadow_data, "shadow.data"),
            f"{run_id}-shadow.data.zip",
        )

    @app.get("/api/run/{run_id}/node/{node}/logs.zip")
    async def download_node_logs(run_id: str, node: str) -> Response:
        run = db.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        hosts_dir = (Path(run["run_dir"]) / "shadow.data" / "hosts").resolve()
        node_dir = (hosts_dir / node).resolve()
        try:
            node_dir.relative_to(hosts_dir)
        except ValueError:
            raise HTTPException(status_code=404, detail="node logs not found") from None
        if not node_dir.is_dir():
            raise HTTPException(status_code=404, detail="node logs not found")
        return _download_response(
            _zip_directory(node_dir, Path("shadow.data") / "hosts" / node),
            f"{run_id}-{node}-logs.zip",
        )

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await manager.connect(websocket)
        await websocket.send_text(json.dumps({"type": "stats", "stats": db.get_stats()}))
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(websocket)

    if static_path and (static_path / "index.html").is_file():
        assets = static_path / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{path:path}")
        async def serve_spa(path: str) -> FileResponse:
            file_path = static_path / path
            if file_path.is_file():
                return FileResponse(file_path)
            return FileResponse(static_path / "index.html")

    else:

        @app.get("/")
        async def missing_frontend() -> HTMLResponse:
            return HTMLResponse(
                """
                <!doctype html>
                <title>Shadow Fuzzer Dashboard</title>
                <body style="font-family: system-ui; margin: 40px">
                  <h1>Shadow Fuzzer Dashboard API</h1>
                  <p>The API is running. Build the frontend with
                  <code>cd shadow-fuzzer/web && npm install && npm run build</code>.</p>
                </body>
                """
            )

    return app


def run_server(
    output_dir: str | Path,
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    reindex: bool = True,
) -> None:
    import uvicorn

    static_dir = _find_static_dir()
    app = create_app(output_dir, static_dir=static_dir, reindex=reindex)
    print(f"Shadow fuzzer dashboard: http://{host}:{port}")
    print(f"Indexing output dir: {Path(output_dir).resolve()}")
    if static_dir:
        print(f"Serving frontend: {static_dir}")
    else:
        print("Frontend dist not found; API is still available.")
    uvicorn.run(app, host=host, port=port)


def start_server_background(
    output_dir: str | Path,
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    reindex: bool = True,
) -> threading.Thread:
    import uvicorn

    static_dir = _find_static_dir()
    app = create_app(output_dir, static_dir=static_dir, reindex=reindex)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    print(f"Shadow fuzzer dashboard: http://{host}:{port}")
    if static_dir:
        print(f"  Serving frontend: {static_dir}")
    else:
        print("  Frontend dist not found; API is available.")
    return thread


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Serve the Shadow fuzzer dashboard")
    parser.add_argument("output_dir", nargs="?", default="fuzzer-output")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run_server(args.output_dir, host=args.host, port=args.port)
