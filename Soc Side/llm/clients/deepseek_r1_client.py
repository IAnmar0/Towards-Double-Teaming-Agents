from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from openai import OpenAI
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parents[2]
load_dotenv(BASE / ".env")

PROMPT_PATH = BASE / "llm" / "prompts" / "soc_system_prompt.txt"
INTAKE_DIR = BASE / "logs" / "intake"

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")

# forced model only
FORCED_MODEL = "deepseek-reasoner"

if not DEEPSEEK_API_KEY:
    raise RuntimeError("DEEPSEEK_API_KEY is not set")

client = OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url=DEEPSEEK_BASE_URL,
)


def _load_system_prompt() -> str:
    if not PROMPT_PATH.exists():
        raise FileNotFoundError(f"Prompt file not found: {PROMPT_PATH}")
    return PROMPT_PATH.read_text(encoding="utf-8").strip()


def _load_raw_run(run_id: str) -> dict[str, Any]:
    path = INTAKE_DIR / f"{run_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Raw intake file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_json_text(raw_text: str) -> str:
    text = raw_text.strip()

    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start:end + 1]

    return text


def call_deepseek_r1(run_id: str) -> dict[str, Any]:
    system_prompt = _load_system_prompt()
    raw_input = _load_raw_run(run_id)

    user_prompt = (
        "Analyze the following RAW security assessment JSON and return ONLY valid JSON "
        "matching the required report schema. Use the evidence exactly as provided. "
        "Do not invent facts, and do not assume the scan failed if the JSON contains "
        "successful exploitation, exposed services, retrieved files, or explicit findings.\n\n"
        f"{json.dumps(raw_input, indent=2, ensure_ascii=False)}"
    )

    print(f"[LLM] run_id={run_id} model={FORCED_MODEL}")

    response = client.chat.completions.create(
        model=FORCED_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.1,
    )

    raw_content = response.choices[0].message.content or ""
    cleaned = _extract_json_text(raw_content)

    try:
        report = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Model returned invalid JSON for run_id={run_id}: {e}\n\nRaw output:\n{raw_content}"
        )

    out = BASE / "reports" / "json" / f"{run_id}_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    return report
