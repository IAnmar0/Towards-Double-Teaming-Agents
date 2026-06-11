import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]

def render_md(run_id: str):
    src = BASE / "reports" / "json" / f"{run_id}_report.json"
    data = json.loads(src.read_text(encoding="utf-8"))

    lines = []
    lines.append("# Security Incident Report")
    lines.append("")
    lines.append(f"## Verdict\n{data.get('verdict', '')}")
    lines.append("")
    lines.append(f"## Targeted Service\n{data.get('targeted_service', '')}")
    lines.append("")
    lines.append(f"## Likely Vulnerability\n{data.get('likely_vulnerability', '')}")
    lines.append("")
    lines.append(f"## Likely CVE\n{data.get('likely_cve', '')}")
    lines.append("")
    lines.append(f"## Attack Outcome\n{data.get('attack_outcome', '')}")
    lines.append("")
    lines.append(f"## Confidence\n{data.get('confidence', '')}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append(data.get("executive_summary", ""))
    lines.append("")

    lines.append("## Plain-Language Summary")
    lines.append(data.get("plain_language_summary", ""))
    lines.append("")

    lines.append("## Proven Impact")
    lines.append(data.get("proven_impact", ""))
    lines.append("")

    lines.append("## Why This Matters")
    lines.append(data.get("risk_explanation", ""))
    lines.append("")

    lines.append("## Business Impact")
    lines.append(data.get("business_impact", ""))
    lines.append("")

    lines.append("## Evidence Summary")
    evidence = data.get("evidence_summary", [])
    if isinstance(evidence, list):
        for item in evidence:
            lines.append(f"- {item}")
    else:
        lines.append(str(evidence))
    lines.append("")

    lines.append("## Immediate Actions")
    for item in data.get("immediate_actions", []):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Recommended Mitigations")
    for item in data.get("mitigations", []):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Long-Term Recommendations")
    for item in data.get("long_term_recommendations", []):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Full Analyst Report")
    lines.append(data.get("analyst_report", ""))

    out = BASE / "reports" / "md" / f"{run_id}_report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out

if __name__ == "__main__":
    out = render_md("run_001")
    print(f"saved to {out}")
