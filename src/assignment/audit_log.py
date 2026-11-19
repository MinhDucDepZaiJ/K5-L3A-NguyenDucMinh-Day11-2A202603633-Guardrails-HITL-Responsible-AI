"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations
import time
import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")



class AuditLogPlugin:
    """Record input, output, decisions and latency."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(
        self,
        *,
        user_id: str,
        text: str,
        request_id: str | None = None,
    ):
        key = request_id or user_id

        self._open[key] = {
            "user_id": user_id,
            "input": text,
            "timestamp": utc_now_iso(),
            "start_time": time.perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        key = request_id or user_id
        started = self._open.pop(key, None)

        latency_ms = None
        input_text = None
        input_timestamp = None

        if started is not None:
            latency_ms = round(
                (time.perf_counter() - started["start_time"])
                * 1000,
                3,
            )
            input_text = started["input"]
            input_timestamp = started["timestamp"]

        entry = {
            "request_id": request_id,
            "user_id": user_id,
            "input": input_text,
            "output": text,
            "input_timestamp": input_timestamp,
            "output_timestamp": utc_now_iso(),
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        }

        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as f:
            json.dump(
                self.logs,
                f,
                indent=2,
                ensure_ascii=False,
            )

        return str(path)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
