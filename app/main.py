from pathlib import Path

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import agents, injector, scenarios, store
from .llm import LLMError, settings

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="SOC Two-Agent Prototype")


class NewRun(BaseModel):
    scenario_id: str | None = None
    logs: list[dict] | None = None          # uploaded / pasted logs
    attack_class: str = "none"              # none | direct_override | persona_hijack | ...
    field: str = "user_agent"
    event_index: int = 0


@app.exception_handler(LLMError)
async def llm_error(_, exc: LLMError):
    return JSONResponse({"detail": str(exc)}, status_code=502)


@app.get("/api/config")
def config():
    return {
        "llm": settings(),
        "scenarios": [{"id": k, "name": v["name"]} for k, v in scenarios.SCENARIOS.items()],
        "attacks": [{"id": k, "name": v["name"]} for k, v in injector.ATTACKS.items()],
        "fields": injector.INJECTABLE_FIELDS,
    }


@app.post("/api/runs")
def create_run(req: NewRun):
    """Prepare logs (+ optional injection) and run the Detection Agent."""
    truth = None
    if req.scenario_id:
        if req.scenario_id not in scenarios.SCENARIOS:
            raise HTTPException(404, "unknown scenario")
        logs, truth = scenarios.load(req.scenario_id)
        source = f"scenario:{req.scenario_id}"
    elif req.logs:
        logs = [dict(e) for e in req.logs]
        for i, e in enumerate(logs, 1):
            e.setdefault("id", f"e{i}")
        source = "uploaded"
    else:
        raise HTTPException(400, "provide scenario_id or logs")

    injection = None
    if req.attack_class != "none":
        try:
            logs, injection = injector.inject(logs, req.attack_class, req.field, req.event_index)
        except ValueError as e:
            raise HTTPException(400, str(e))

    record = store.create({
        "source": source, "status": "created", "logs": logs, "injection": injection,
        "ground_truth": truth,  # evaluation only; never passed to agents
        "detection": None, "investigation": None, "combined": None,
    })
    msgs, det = agents.run_detection(logs)
    record.update(status="detected", detection={"input": msgs, "output": det})
    store.save(record)
    return record


@app.post("/api/runs/{run_id}/investigate")
def investigate(run_id: str, record: dict | None = Body(default=None)):
    """Serverless-safe: the client sends the run back, so no shared server state is needed."""
    record = record or store.get(run_id)
    if not record or not record.get("detection"):
        raise HTTPException(404, "run not found or detection not done")
    det = record["detection"]["output"]
    msgs, inv = agents.run_investigation(record["logs"], det)
    record.update(
        status="complete",
        investigation={"input": msgs, "output": inv},
        combined=agents.combine(det, inv),
    )
    store.save(record)
    return record


@app.get("/api/runs")
def runs():
    return store.list_runs()


@app.get("/api/runs/{run_id}")
def run(run_id: str):
    record = store.get(run_id)
    if not record:
        raise HTTPException(404, "not found")
    return record


@app.get("/")
def index():
    return FileResponse(ROOT / "public" / "index.html")


