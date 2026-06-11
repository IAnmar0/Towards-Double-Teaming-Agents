import json
import os
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI
from retrieval.find_context import retrieve

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

BASE = Path.home() / "soc_side"
SYSTEM_PROMPT = (BASE / "llm/prompts/soc_system_prompt.txt").read_text()

def build_user_prompt(incident: dict, context: list) -> str:
    return (
        "Analyze the following SOC incident and return JSON only.\n\n"
        f"Normalized Incident:\n{json.dumps(incident, indent=2)}\n\n"
        f"Retrieved Context:\n{json.dumps(context, indent=2)}\n"
    )

def call_gpt5(run_id: str):
    path = BASE / f"logs/normalized/{run_id}_normalized.json"
    incident = json.loads(path.read_text())

    context = retrieve(
        incident.get("services", []),
        incident.get("versions", []),
        incident.get("candidate_cves", [])
    )

    response = client.responses.create(
        model="gpt-5",
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(incident, context)}
        ]
    )

    result = json.loads(response.output_text)

    out = BASE / f"reports/json/{run_id}_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    return out

if __name__ == "__main__":
    out = call_gpt5("run_001")
    print(f"saved to {out}")
