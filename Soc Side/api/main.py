from fastapi import FastAPI, Header, HTTPException, Body
from pathlib import Path
from datetime import datetime
import json
import os

from api.process_run import process
from api.ingest_adapter import normalize_payload

app = FastAPI()

API_TOKEN = os.getenv("SOC_API_TOKEN", "change_me")
BASE = Path(__file__).resolve().parents[1]
INTAKE = BASE / "logs" / "intake"
NORMALIZED = BASE / "logs" / "normalized"
REPORTS_JSON = BASE / "reports" / "json"
REPORTS_MD = BASE / "reports" / "md"
REPORTS_DOCX = BASE / "reports" / "docx"

INTAKE.mkdir(parents=True, exist_ok=True)
NORMALIZED.mkdir(parents=True, exist_ok=True)
REPORTS_JSON.mkdir(parents=True, exist_ok=True)
REPORTS_MD.mkdir(parents=True, exist_ok=True)
REPORTS_DOCX.mkdir(parents=True, exist_ok=True)

def check_api_key(x_api_key: str):
    if x_api_key != API_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "soc-side",
        "intake_dir": str(INTAKE),
        "reports_dir": str(REPORTS_JSON),
        "accepted_schemas": [
            "canonical_soc_intake",
            "summary_style_v2",
            "pentestgpt_session_v2"
        ]
    }

@app.post("/soc/intake")
def intake(payload: dict = Body(...), x_api_key: str = Header(default="")):
    check_api_key(x_api_key)

    try:
        canonical = normalize_payload(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Payload normalization failed: {str(e)}")

    run_id = canonical.get("run_id", f"run_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
    out = INTAKE / f"{run_id}.json"
    out.write_text(json.dumps(canonical, indent=2), encoding="utf-8")

    try:
        process(run_id)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Run accepted but processing failed: {str(e)}"
        )

    return {
        "accepted": True,
        "run_id": run_id,
        "saved_to": str(out),
        "received_at": datetime.utcnow().isoformat() + "Z",
        "processed": True,
        "normalized_schema": canonical.get("meta", {}).get("source_schema", "canonical_soc_intake")
    }

@app.get("/soc/report/{run_id}")
def get_report(run_id: str, x_api_key: str = Header(default="")):
    check_api_key(x_api_key)

    report_path = REPORTS_JSON / f"{run_id}_report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return json.loads(report_path.read_text(encoding="utf-8"))

@app.get("/soc/report/{run_id}/markdown")
def get_report_markdown(run_id: str, x_api_key: str = Header(default="")):
    check_api_key(x_api_key)

    report_path = REPORTS_MD / f"{run_id}_report.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Markdown report not found")

    return {
        "run_id": run_id,
        "format": "markdown",
        "content": report_path.read_text(encoding="utf-8")
    }

@app.get("/soc/run/{run_id}/status")
def get_run_status(run_id: str, x_api_key: str = Header(default="")):
    check_api_key(x_api_key)

    intake_file = INTAKE / f"{run_id}.json"
    normalized_file = NORMALIZED / f"{run_id}_normalized.json"
    report_json_file = REPORTS_JSON / f"{run_id}_report.json"
    report_md_file = REPORTS_MD / f"{run_id}_report.md"
    report_docx_file = REPORTS_DOCX / f"{run_id}_report.docx"

    return {
        "run_id": run_id,
        "intake_exists": intake_file.exists(),
        "normalized_exists": normalized_file.exists(),
        "report_json_exists": report_json_file.exists(),
        "report_md_exists": report_md_file.exists(),
        "report_docx_exists": report_docx_file.exists(),
        "completed": all([
            intake_file.exists(),
            normalized_file.exists(),
            report_json_file.exists(),
            report_md_file.exists(),
            report_docx_file.exists()
        ])
    }

@app.get("/soc/runs")
def list_runs(x_api_key: str = Header(default="")):
    check_api_key(x_api_key)

    runs = []
    for file in sorted(INTAKE.glob("*.json")):
        run_id = file.stem
        runs.append({
            "run_id": run_id,
            "intake_exists": True,
            "normalized_exists": (NORMALIZED / f"{run_id}_normalized.json").exists(),
            "report_json_exists": (REPORTS_JSON / f"{run_id}_report.json").exists(),
            "report_md_exists": (REPORTS_MD / f"{run_id}_report.md").exists(),
            "report_docx_exists": (REPORTS_DOCX / f"{run_id}_report.docx").exists()
        })

    return {"count": len(runs), "runs": runs}
