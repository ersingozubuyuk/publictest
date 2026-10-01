"""Test dashboard: upload an inventory CSV, browse fleet and host results.

This is an operator tool for validating the analysis engine, not the final
client report (that is Phase 3). It runs entirely on the operator's server;
nothing is sent to third parties.

Environment:
    KERNELASSESS_DATA     data directory (cache/ and runs/ live here), default "."
    DASHBOARD_USER        basic-auth user, default "admin"
    DASHBOARD_PASSWORD    basic-auth password; auth is disabled when unset
    REFRESH_HOURS         how often to re-check the SUSE feed, default 24 (0 disables)
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import logging
import os
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .. import __version__, runner
from ..analysis import SEVERITIES
from ..inventory import load_inventory
from ..sources import oval

log = logging.getLogger(__name__)

DATA = Path(os.environ.get("KERNELASSESS_DATA", "."))
CACHE = DATA / "cache"
RUNS = DATA / "runs"
MAX_UPLOAD = 5 * 1024 * 1024
_RUN_RE = re.compile(r"^\d{8}-\d{6}$")
_HOST_RE = re.compile(r"^HOST-\d{4,}$")



@asynccontextmanager
async def lifespan(_app):
    RUNS.mkdir(parents=True, exist_ok=True)
    state.refresh("15")
    hours = float(os.environ.get("REFRESH_HOURS", "24"))
    if hours > 0:
        def periodic():
            while True:
                time.sleep(hours * 3600)
                state.refresh("15")
        threading.Thread(target=periodic, daemon=True).start()
    yield


app = FastAPI(title="kernelassess", docs_url=None, redoc_url=None, lifespan=lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals.update(version=__version__, severities=SEVERITIES)


# --- auth ------------------------------------------------------------------------------

@app.middleware("http")
async def basic_auth(request: Request, call_next):
    password = os.environ.get("DASHBOARD_PASSWORD")
    if password and request.url.path != "/healthz":
        user = os.environ.get("DASHBOARD_USER", "admin")
        ok = False
        header = request.headers.get("authorization", "")
        if header.lower().startswith("basic "):
            try:
                u, _, p = base64.b64decode(header[6:]).decode().partition(":")
                ok = secrets.compare_digest(u, user) & secrets.compare_digest(p, password)
            except (binascii.Error, UnicodeDecodeError):
                ok = False
        if not ok:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="kernelassess"'})
    return await call_next(request)


# --- SUSE data state ---------------------------------------------------------------------

class DataState:
    def __init__(self):
        self.lock = threading.Lock()
        self.indexes: dict[str, dict] = {}
        self.status = "idle"
        self.message = ""

    def refresh(self, major: str = "15") -> None:
        with self.lock:
            if self.status == "refreshing":
                return
            self.status, self.message = "refreshing", "SUSE verisi indiriliyor / indeksleniyor"

        def work():
            try:
                index = oval.load_index(major, CACHE, refresh=True)
                with self.lock:
                    self.indexes[major] = index
                    self.status, self.message = "ready", ""
            except Exception as e:  # surfaced on the dashboard
                log.exception("Refresh failed")
                with self.lock:
                    self.status, self.message = "error", f"Güncelleme başarısız: {e}"

        threading.Thread(target=work, daemon=True).start()

    def summary(self) -> dict:
        idx = self.indexes.get("15")
        return {
            "status": self.status,
            "message": self.message,
            "advisories": len(idx["advisories"]) if idx else None,
            "last_modified": idx.get("source_last_modified") if idx else None,
        }


state = DataState()


# --- helpers -------------------------------------------------------------------------------

def _runs() -> list[str]:
    if not RUNS.exists():
        return []
    return sorted((p.name for p in RUNS.iterdir() if _RUN_RE.match(p.name)
                   and (p / "fleet-summary.json").exists()), reverse=True)


def _run_dir(run_id: str) -> Path:
    if not _RUN_RE.match(run_id) or not (RUNS / run_id).is_dir():
        raise HTTPException(404, "Run not found")
    return RUNS / run_id


def _error(message: str) -> RedirectResponse:
    return RedirectResponse(f"/?error={quote(message)}", status_code=303)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _hostnames(run: Path) -> dict[str, str]:
    p = run / "private" / "masking-map.json"
    return _load(p) if p.exists() else {}


# --- routes ------------------------------------------------------------------------------

@app.get("/healthz")
def healthz():
    return {"ok": True, "data": state.summary()}


@app.get("/")
def index(request: Request, run: str | None = None):
    runs = _runs()
    run_id = run or (runs[0] if runs else None)
    summary = names = None
    if run_id:
        d = _run_dir(run_id)
        summary, names = _load(d / "fleet-summary.json"), _hostnames(d)
    return templates.TemplateResponse(request, "index.html", {
        "runs": runs, "run_id": run_id, "summary": summary, "names": names or {},
        "data": state.summary(), "error": request.query_params.get("error"),
    })


@app.post("/assess")
async def assess(file: UploadFile = File(...), date: str | None = Form(None)):
    raw = await file.read(MAX_UPLOAD + 1)
    if len(raw) > MAX_UPLOAD:
        return _error("Dosya 5 MB sınırını aşıyor")
    if "15" not in state.indexes and state.status == "refreshing":
        return _error("SUSE verisi henüz hazır değil, biraz sonra tekrar deneyin")

    run_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = RUNS / run_id
    inv_path = out / "private" / "inventory.csv"
    inv_path.parent.mkdir(parents=True, exist_ok=True)
    inv_path.write_bytes(raw)
    try:
        hosts = load_inventory(inv_path)
        if not hosts:
            raise ValueError("Envanter boş")
        on = dt.date.fromisoformat(date) if date else dt.date.today()
        runner.run(hosts, CACHE, out, on, refresh=False, indexes=state.indexes)
    except Exception as e:
        log.exception("Assessment failed")
        return _error(f"Analiz başarısız: {str(e)[:200]}")
    return RedirectResponse(f"/?run={run_id}", status_code=303)


@app.post("/refresh")
def refresh():
    state.refresh("15")
    return RedirectResponse("/", status_code=303)


@app.get("/runs/{run_id}/hosts/{host_id}.json")
def host_json(run_id: str, host_id: str):
    d = _run_dir(run_id)
    if not _HOST_RE.match(host_id):
        raise HTTPException(404)
    p = d / "hosts" / f"{host_id}.json"
    if not p.exists():
        raise HTTPException(404)
    return FileResponse(p, media_type="application/json", filename=f"{run_id}-{host_id}.json")


@app.get("/runs/{run_id}/hosts/{host_id}")
def host(request: Request, run_id: str, host_id: str, sev: str | None = None, limit: int = 300):
    d = _run_dir(run_id)
    if not _HOST_RE.match(host_id) or not (d / "hosts" / f"{host_id}.json").exists():
        raise HTTPException(404, "Host not found")
    r = _load(d / "hosts" / f"{host_id}.json")
    cves = r.get("security", {}).get("missing_cves", [])
    if sev in SEVERITIES:
        cves = [c for c in cves if c["severity"] == sev]
    return templates.TemplateResponse(request, "host.html", {
        "run_id": run_id, "r": r, "hostname": _hostnames(d).get(host_id),
        "cves": cves[:limit], "cve_total": len(cves), "sev": sev, "limit": limit,
    })
