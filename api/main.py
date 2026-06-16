"""AI-SOC FastAPI Application."""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.config import get_settings
from core.orchestrator import orchestrator
from core.agent_registry import registry

CONFIG_JSON = Path("data/provider_config.json")


def _load_persisted_config() -> None:
    """Apply saved provider config from JSON before settings are cached."""
    if not CONFIG_JSON.exists():
        return
    try:
        data = json.loads(CONFIG_JSON.read_text())
        if "active_provider" in data:
            os.environ["AI_PROVIDER"] = data["active_provider"]
        for key, value in data.items():
            if key != "active_provider" and isinstance(value, str) and value:
                os.environ[key.upper()] = value
    except Exception:
        pass


_load_persisted_config()

# Import all agents to register them
from agents.monitoring import *  # noqa: F401, F403
from agents.os_analysis import *  # noqa: F401, F403
from agents.cloud import *  # noqa: F401, F403
from agents.containers import *  # noqa: F401, F403
from agents.threats import *  # noqa: F401, F403
from agents.intelligence import *  # noqa: F401, F403
from agents.incident_response import *  # noqa: F401, F403
from agents.compliance import *  # noqa: F401, F403
from agents.specialized import *  # noqa: F401, F403
from agents.analytics import *  # noqa: F401, F403

# In-memory scan store — survives page reloads, lost on backend restart
_scans: dict[str, dict[str, Any]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_settings()
    await orchestrator.start()
    yield
    await orchestrator.stop()


app = FastAPI(
    title="AI-SOC — Centro de Operaciones de Ciberseguridad Autónomo",
    description="126 AI agents for autonomous cybersecurity operations",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ────────────────────────────────────────────────────────────────────

class AnalysisRequest(BaseModel):
    data: dict[str, Any]
    max_agents: int = 10


class AgentPayload(BaseModel):
    name: str
    label: str
    data: dict[str, Any]


class ScanRequest(BaseModel):
    target: str
    target_type: str = "domain"
    agents: list[AgentPayload]


class ConfigUpdateRequest(BaseModel):
    provider: str
    api_key: str = ""
    model: str = ""
    base_url: str = ""


# ── Background scan runner ────────────────────────────────────────────────────

async def _run_scan(scan_id: str, agents: list[AgentPayload]) -> None:
    for i, payload in enumerate(agents):
        if _scans.get(scan_id, {}).get("cancelled"):
            break

        _scans[scan_id]["agents"][i]["status"] = "running"

        try:
            agent = registry.instantiate(payload.name)
            if agent is None:
                raise ValueError(f"Agent {payload.name} not found")
            result = await orchestrator.dispatch(agent, payload.data)
            _scans[scan_id]["agents"][i]["status"] = "done"
            _scans[scan_id]["agents"][i]["result"] = result.model_dump()
        except Exception as exc:
            _scans[scan_id]["agents"][i]["status"] = "error"
            _scans[scan_id]["agents"][i]["error"] = str(exc)

    _scans[scan_id]["status"] = "complete"
    _scans[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "AI-SOC"}


@app.get("/api/v1/config")
async def get_config():
    s = get_settings()
    return {
        "provider": s.ai_provider.value,
        "model": getattr(s, f"{s.ai_provider.value}_model", ""),
        "max_tokens": s.ai_max_tokens,
        "temperature": s.ai_temperature,
    }


@app.put("/api/v1/config")
async def update_config(update: ConfigUpdateRequest):
    provider_key = update.provider.lower().replace("-", "_")

    # Persist to JSON
    CONFIG_JSON.parent.mkdir(exist_ok=True)
    data: dict[str, str] = {}
    if CONFIG_JSON.exists():
        try:
            data = json.loads(CONFIG_JSON.read_text())
        except Exception:
            pass

    data["active_provider"] = update.provider
    if update.api_key:
        data[f"{provider_key}_api_key"] = update.api_key
    if update.model:
        data[f"{provider_key}_model"] = update.model
    if update.base_url:
        data[f"{provider_key}_base_url"] = update.base_url

    CONFIG_JSON.write_text(json.dumps(data, indent=2))

    # Update env vars so next get_settings() picks them up
    os.environ["AI_PROVIDER"] = update.provider
    if update.api_key:
        os.environ[f"{provider_key.upper()}_API_KEY"] = update.api_key
    if update.model:
        os.environ[f"{provider_key.upper()}_MODEL"] = update.model
    if update.base_url:
        os.environ[f"{provider_key.upper()}_BASE_URL"] = update.base_url

    get_settings.cache_clear()
    return {"ok": True, "provider": update.provider}


@app.get("/api/v1/agents")
async def list_agents():
    return {"agents": registry.list_available(), "stats": registry.get_stats()}


@app.post("/api/v1/analyze/{category}")
async def analyze_by_category(category: str, request: AnalysisRequest):
    results = await orchestrator.dispatch_to_category(category, request.data)
    return {"category": category, "results": [r.model_dump() for r in results]}


@app.post("/api/v1/analyze/agent/{agent_name}")
async def analyze_by_agent(agent_name: str, request: AnalysisRequest):
    agents = registry.get_by_name(agent_name)
    if not agents:
        agent = registry.instantiate(agent_name)
        if agent is None:
            raise HTTPException(status_code=404, detail=f"Agent {agent_name} not found")
    else:
        agent = agents[0]
    result = await orchestrator.dispatch(agent, request.data)
    return result.model_dump()


# ── Persistent scan endpoints ─────────────────────────────────────────────────

@app.post("/api/v1/scan")
async def create_scan(request: ScanRequest):
    scan_id = uuid.uuid4().hex[:12]
    _scans[scan_id] = {
        "id": scan_id,
        "target": request.target,
        "target_type": request.target_type,
        "status": "running",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "cancelled": False,
        "agents": [
            {"name": a.name, "label": a.label, "status": "pending", "result": None, "error": None}
            for a in request.agents
        ],
    }
    asyncio.create_task(_run_scan(scan_id, request.agents))
    return {"scan_id": scan_id}


@app.get("/api/v1/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.delete("/api/v1/scan/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id in _scans:
        _scans[scan_id]["cancelled"] = True
        _scans.pop(scan_id, None)
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
