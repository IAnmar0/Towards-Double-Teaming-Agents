import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DB = BASE / "retrieval" / "cves" / "cve_notes.json"

def retrieve(service_names, version_hints, cves):
    items = json.loads(DB.read_text(encoding="utf-8"))
    results = []

    for item in items:
        service_match = any(item["service"].lower() == s.lower() for s in service_names)
        version_match = any(item["version_hint"].lower() in v.lower() for v in version_hints)
        cve_match = item["cve"] in cves

        if service_match or version_match or cve_match:
            results.append(item)

    return results

if __name__ == "__main__":
    print(retrieve(
        ["Apache HTTP Server"],
        ["Apache/2.4.49"],
        ["CVE-2021-41773"]
    ))
