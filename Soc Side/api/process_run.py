from __future__ import annotations

import sys
from pathlib import Path

from llm.clients.deepseek_r1_client import call_deepseek_r1
from api.render_report import render_md
from api.render_docx_report import render_docx

BASE = Path(__file__).resolve().parents[1]
INTAKE = BASE / "logs" / "intake"
REPORTS_JSON = BASE / "reports" / "json"
REPORTS_MD = BASE / "reports" / "md"
REPORTS_DOCX = BASE / "reports" / "docx"


def ensure_required_input(run_id: str) -> Path:
    src = INTAKE / f"{run_id}.json"
    if not src.exists():
        raise FileNotFoundError(f"Input intake file not found: {src}")
    return src


def process(run_id: str) -> dict:
    ensure_required_input(run_id)

    print(f"[PROCESS] Starting run_id={run_id}")
    print(f"[PROCESS] Using raw intake JSON directly (normalization disabled)")

    report = call_deepseek_r1(run_id)
    print(f"[PROCESS] LLM JSON report saved: {REPORTS_JSON / f'{run_id}_report.json'}")

    md_path = render_md(run_id)
    print(f"[PROCESS] Markdown report saved: {md_path}")

    docx_path = render_docx(run_id)
    print(f"[PROCESS] DOCX report saved: {docx_path}")

    print(f"[PROCESS] run {run_id} completed successfully")

    return {
        "run_id": run_id,
        "raw_input_path": str(INTAKE / f"{run_id}.json"),
        "json_report_path": str(REPORTS_JSON / f"{run_id}_report.json"),
        "md_report_path": str(REPORTS_MD / f"{run_id}_report.md"),
        "docx_report_path": str(REPORTS_DOCX / f"{run_id}_report.docx"),
        "status": "completed",
        "model": "deepseek-reasoner",
        "normalization": "disabled",
    }


if __name__ == "__main__":
    run_id = sys.argv[1] if len(sys.argv) > 1 else "run_001"

    try:
        result = process(run_id)
        print(result)
        raise SystemExit(0)
    except Exception as exc:
        print(f"[PROCESS][ERROR] run_id={run_id} failed: {exc}")
        raise SystemExit(1)
