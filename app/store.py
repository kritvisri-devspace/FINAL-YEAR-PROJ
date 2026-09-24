"""SQLite run store. One row per run; the whole record (inputs + outputs of both agents) is a JSON blob."""
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "data" / "runs.db"


def _conn():
    DB.parent.mkdir(exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created TEXT, record TEXT)")
    return c


def create(record: dict) -> dict:
    record["id"] = uuid.uuid4().hex[:8]
    record["created"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save(record)
    return record


def save(record: dict):
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?)",
                  (record["id"], record["created"], json.dumps(record)))


def get(run_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT record FROM runs WHERE id=?", (run_id,)).fetchone()
    return json.loads(row[0]) if row else None


def list_runs(limit: int = 30) -> list[dict]:
    with _conn() as c:
        rows = c.execute("SELECT record FROM runs ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for (r,) in rows:
        rec = json.loads(r)
        out.append({
            "id": rec["id"], "created": rec["created"], "source": rec.get("source"),
            "attack_class": (rec.get("injection") or {}).get("attack_class", "none"),
            "status": rec.get("status"),
            "agreement": (rec.get("combined") or {}).get("agreement"),
            "final_threat_class": (rec.get("combined") or {}).get("final_threat_class"),
        })
    return out
