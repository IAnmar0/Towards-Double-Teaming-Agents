import json
import re
from datetime import datetime

def _safe_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]

def _uniq(seq):
    out = []
    seen = set()
    for x in seq:
        if x is None:
            continue
        s = str(x).strip()
        if not s:
            continue
        if s not in seen:
            out.append(s)
            seen.add(s)
    return out

def _payload_text(payload):
    return json.dumps(payload, ensure_ascii=False)

def _all_step_text(steps):
    joined = []
    for step in _safe_list(steps):
        joined.extend([
            str(step.get("type", "")),
            str(step.get("tool", "")),
            str(step.get("command", "")),
            str(step.get("description", "")),
            str(step.get("content", "")),
            str(step.get("status", "")),
            str(step.get("location", "")),
            str(step.get("method", "")),
            str(step.get("file_path", ""))
        ])
    return " ".join(joined)

def _session_timestamp(payload):
    session = payload.get("session", {})
    date = session.get("date")
    end_time = session.get("end_time")
    if date and end_time:
        return f"{date}T{end_time}Z"

    for entry in _safe_list(payload.get("initialization", {}).get("log_entries", [])):
        ts = str(entry.get("timestamp", ""))
        m = re.match(r'(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})', ts)
        if m:
            return f"{m.group(1)}T{m.group(2)}Z"

    # fallback to today-like placeholder if unavailable
    return "1970-01-01T00:00:00Z"

def _collect_logs(payload):
    logs = []

    for item in _safe_list(payload.get("initialization", {}).get("log_entries", [])):
        msg = item.get("message")
        if msg:
            logs.append(msg)

    for item in _safe_list(payload.get("initialization", {}).get("agent_events", [])):
        ev = item.get("event")
        if ev:
            logs.append(ev)

    for step in _safe_list(payload.get("steps", [])):
        for key in ("content", "description"):
            val = step.get(key)
            if val:
                logs.append(val)

    for item in _safe_list(payload.get("summary", {}).get("lessons_learned", [])):
        logs.append(item)

    for item in _safe_list(payload.get("summary", {}).get("techniques_used", [])):
        logs.append(item)

    notes = payload.get("notes")
    if notes:
        logs.append(notes)

    session_notes = payload.get("session", {}).get("notes")
    if session_notes:
        logs.append(session_notes)

    return _uniq(logs)

def _extract_open_ports(payload, steps, text):
    ports = set()

    for p in re.findall(r'port\s+(\d{1,5})', text, flags=re.IGNORECASE):
        try:
            p = int(p)
            if 1 <= p <= 65535:
                ports.add(p)
        except:
            pass

    for p in re.findall(r'(\d{1,5})/tcp', text, flags=re.IGNORECASE):
        try:
            p = int(p)
            if 1 <= p <= 65535:
                ports.add(p)
        except:
            pass

    for step in _safe_list(steps):
        cmd = str(step.get("command", ""))
        for p in re.findall(r'(?:^|[\s,])(\d{1,5})(?:[\s,]|$)', cmd):
            try:
                p = int(p)
                if 1 <= p <= 65535:
                    ports.add(p)
            except:
                pass

    low = text.lower()
    if "ftp" in low:
        ports.add(21)
    if "telnet" in low:
        ports.add(23)
    if "ssh" in low or "openssh" in low:
        ports.add(22)
    if "tomcat" in low:
        ports.add(8080)
    if "apache http server" in low or "apache httpd" in low:
        ports.add(80)
    if "http" in low and "8080" in low:
        ports.add(8080)

    return sorted(list(ports))

def _extract_services_and_versions(payload, steps, logs):
    text = (_payload_text(payload) + " " + _all_step_text(steps) + " " + " ".join(logs)).lower()

    services = []
    versions = []

    # application hints first
    if any(x in text for x in ["search.jsp", "login.jsp", "web application", "/search", "/login", "bodgeit"]):
        services.append("HTTP Web Application")

    if "ftp" in text or "anonymous ftp" in text:
        services.append("FTP")
    if "telnet" in text:
        services.append("Telnet")
    if "openssh" in text or "ssh" in text:
        services.append("OpenSSH")
    if "apache http server" in text or "apache httpd" in text:
        services.append("Apache HTTP Server")
    if "tomcat" in text:
        services.append("Apache Tomcat")

    raw = _payload_text(payload) + " " + _all_step_text(steps) + " " + " ".join(logs)

    version_patterns = [
        r'Apache/?\s?2\.\d+\.\d+',
        r'Apache httpd\s?2\.\d+\.\d+',
        r'Tomcat/?\s?9\.\d+\.\d+',
        r'OpenSSH[_ ]\d+\.\d+',
        r'OpenSSH[_ ]\d+\.\d+p?\d*'
    ]
    for pat in version_patterns:
        for m in re.findall(pat, raw, flags=re.IGNORECASE):
            versions.append(m.strip())

    services = _uniq(services)
    if "HTTP Web Application" in services:
        services = ["HTTP Web Application"] + [s for s in services if s != "HTTP Web Application"]

    versions = _uniq(versions) if versions else ["Unknown"]
    return services if services else ["Unknown"], versions

def _extract_target_hints(payload, services, steps, logs):
    text = (_payload_text(payload) + " " + _all_step_text(steps) + " " + " ".join(logs)).lower()
    hints = []

    if any(x in text for x in ["search.jsp", "/search", "search parameter", "search functionality"]):
        hints.append("Primary suspicious behavior appears tied to search functionality")
    if any(x in text for x in ["login.jsp", "/login", "login form", "authentication probe"]):
        hints.append("Authentication-related behavior observed on application login functionality")
    if "tomcat manager" in text or "/manager/html" in text:
        hints.append("Tomcat manager was probed but may represent secondary noise unless direct compromise evidence exists")
    if "apache http server" in text and ("path traversal" in text or "/etc/passwd" in text or ".%2e" in text):
        hints.append("Apache infrastructure behavior may be directly relevant in traversal-style cases")
    if "telnet" in text:
        hints.append("Remote access service itself appears to be the primary attack surface")
    if "ftp" in text and "anonymous" in text:
        hints.append("FTP service likely represents the primary attack surface due to anonymous access behavior")

    if "HTTP Web Application" in services:
        hints.append("Prefer application endpoint attribution if exploit evidence is tied to specific pages or parameters")

    return _uniq(hints)

def _extract_application_endpoint_hints(payload, steps, logs):
    raw = _payload_text(payload) + " " + _all_step_text(steps) + " " + " ".join(logs)
    endpoints = []

    patterns = [
        r'(/[A-Za-z0-9_\-./]*search\.jsp)',
        r'(/[A-Za-z0-9_\-./]*login\.jsp)',
        r'(/[A-Za-z0-9_\-./]*manager/html)',
        r'(/[A-Za-z0-9_\-./]*flag\.txt)',
        r'(/[A-Za-z0-9_\-./]*etc/passwd)'
    ]
    for pat in patterns:
        for m in re.findall(pat, raw, flags=re.IGNORECASE):
            endpoints.append(m)

    if "/bodgeit/search.jsp" in raw:
        endpoints.append("/bodgeit/search.jsp")
    if "/login.jsp" in raw:
        endpoints.append("/login.jsp")
    if "/manager/html" in raw:
        endpoints.append("/manager/html")
    if "/root/flag.txt" in raw:
        endpoints.append("/root/flag.txt")

    return _uniq(endpoints)

def _infer_weaknesses(payload):
    text = _payload_text(payload).lower()
    weaknesses = []

    if "anonymous ftp" in text or "anonymous login" in text:
        weaknesses.extend(["Anonymous FTP Access", "Weak Authentication Controls"])

    if "blank password" in text or "empty password" in text:
        weaknesses.extend(["Blank Password Authentication", "Weak Authentication Controls"])

    if "telnet" in text:
        weaknesses.append("Insecure Remote Access Service")

    if "sql injection" in text or "sql-style error" in text or "union select" in text or "database-style error" in text:
        weaknesses.append("SQL Injection")

    if "path traversal" in text or "/etc/passwd" in text or ".%2e" in text:
        weaknesses.append("Path Traversal")

    if "cross site scripting" in text or "xss" in text:
        weaknesses.append("Cross Site Scripting")

    if "login redirect" in text or "authentication weakness" in text or "login bypass" in text:
        weaknesses.append("Authentication Weakness")

    if "manager" in text:
        weaknesses.append("Administrative Exposure")

    if "error message" in text or "sql-like error fragment" in text or "database-style error" in text:
        weaknesses.append("Information Disclosure")

    return _uniq(weaknesses) if weaknesses else ["Unknown Security Weakness"]

def _infer_candidate_cves(payload, services, weaknesses):
    text = _payload_text(payload).lower()
    cves = []

    if "cve-2021-41773" in text:
        cves.append("CVE-2021-41773")

    if "apache http server" in text and "2.4.49" in text and ("path traversal" in text or "/etc/passwd" in text or ".%2e" in text):
        # only promote if stronger exploit-aligned evidence exists
        if any(x in text for x in ["sensitive file", "file disclosure", "/etc/passwd", "sensitive content", "file content disclosed"]):
            cves.append("CVE-2021-41773")

    return _uniq(cves)

def _collect_attempted_actions(steps):
    actions = []
    for step in _safe_list(steps):
        if step.get("description"):
            actions.append(step["description"])
        elif step.get("content"):
            actions.append(step["content"])
        elif step.get("type"):
            actions.append(step["type"])
    return _uniq(actions)

def _collect_observed_responses(payload, steps):
    text = _payload_text(payload).lower()
    out = []

    for step in _safe_list(steps):
        content = str(step.get("content", ""))
        if content and any(k in content.lower() for k in [
            "open", "accepted", "denied", "forbidden", "unauthorized",
            "error", "redirect", "flag", "shell", "uid=0", "successful"
        ]):
            out.append(content)

    known = [
        ("ftp port 21 is open", "FTP service accessible on port 21"),
        ("port 23/tcp open", "Telnet service accessible on port 23"),
        ("telnet service accepted connection", "Telnet service accepted connection"),
        ("root account accepted blank password", "Root account accepted blank password"),
        ("interactive shell access obtained", "Interactive shell access obtained"),
        ("root-level access confirmed", "Root-level access confirmed"),
        ("uid=0", "Root-level access confirmed"),
        ("flag file successfully read", "Sensitive file successfully read"),
        ("sql-style error", "Application returned SQL-style error behavior"),
        ("database-style error", "Application returned database-style error behavior"),
        ("500 internal server error", "Application returned server error during crafted input testing"),
        ("302 redirect", "Redirect observed after authentication-related request"),
        ("401 unauthorized", "Administrative endpoint denied access"),
        ("403 forbidden", "Request blocked with HTTP 403"),
        ("anonymous ftp login successful", "Anonymous FTP login succeeded")
    ]
    for needle, label in known:
        if needle in text:
            out.append(label)

    return _uniq(out)

def _collect_success_indicators(payload):
    text = _payload_text(payload).lower()
    out = []

    if "flag found" in text or "flag successfully" in text:
        out.append("Target objective achieved and flag captured")
    if "uid=0" in text or "root shell" in text or "root-level access confirmed" in text:
        out.append("Root-level shell access obtained")
    if "blank password" in text and ("accepted" in text or "successful" in text):
        out.append("Blank password authentication succeeded")
    if "anonymous ftp login successful" in text or ("anonymous ftp" in text and "flag" in text):
        out.append("Anonymous FTP access succeeded")
    if "/root/flag.txt" in text or "flag.txt" in text:
        out.append("Sensitive file accessed")
    if "sql error" in text or "sql-like error" in text or "database-style error" in text:
        out.append("Application exposed SQL-related error behavior")
    if "altered response length" in text or "altered application responses" in text:
        out.append("Application behavior changed after crafted input")
    if "sensitive file content" in text or "file disclosure" in text:
        out.append("Sensitive content exposure observed")

    return _uniq(out)

def _collect_failure_indicators(payload):
    text = _payload_text(payload).lower()
    out = []

    if "401 unauthorized" in text:
        out.append("Authentication denied on probed administrative interface")
    if "403 forbidden" in text:
        out.append("Exploit attempt blocked with HTTP 403")
    if "no confirmed database extraction" in text:
        out.append("No confirmed database extraction")
    if "no confirmed login bypass" in text:
        out.append("No confirmed authentication bypass")
    if "no verified authenticated session" in text:
        out.append("No verified authenticated session established")
    if "no successful exploitation" in text or "no exploitation observed" in text:
        out.append("No confirmed successful exploitation observed")
    if "tomcat manager remained protected" in text:
        out.append("Administrative interface remained protected")

    return _uniq(out)

def _collect_commands(steps):
    cmds = []
    for step in _safe_list(steps):
        cmd = step.get("command")
        if cmd:
            cmds.append(cmd)
    return _uniq(cmds)

def _infer_http_artifacts(payload, steps):
    requests = []
    responses = []

    for step in _safe_list(steps):
        cmd = str(step.get("command", ""))
        if any(x in cmd.lower() for x in ["curl", "http", "search.jsp", "login.jsp", "manager/html", "ftp://", "telnet"]):
            requests.append(cmd)

    text = _payload_text(payload).lower()
    if "200 ok" in text:
        responses.append("200 OK")
    if "500 internal server error" in text:
        responses.append("500 Internal Server Error")
    if "302 redirect" in text:
        responses.append("302 Redirect")
    if "401 unauthorized" in text:
        responses.append("401 Unauthorized")
    if "403 forbidden" in text:
        responses.append("403 Forbidden")

    return _uniq(requests), _uniq(responses)

def _infer_confidence(payload, weaknesses, success_indicators, failure_indicators):
    text = _payload_text(payload).lower()

    if any(x in text for x in ["uid=0", "root-level access confirmed", "flag successfully read", "sensitive file accessed"]):
        return 0.95

    if "sql injection" in text or "sql-style error" in text or "database-style error" in text:
        if "no confirmed database extraction" in text:
            return 0.78
        return 0.85

    if "path traversal" in text or ".%2e" in text or "/etc/passwd" in text:
        if "403 forbidden" in text or "no confirmed file disclosure" in text:
            return 0.70
        return 0.85

    if weaknesses:
        return 0.70

    return 0.45

def _infer_final_status(payload):
    text = _payload_text(payload).lower()

    if any(x in text for x in ["uid=0", "root-level access confirmed", "flag successfully read", "sensitive file accessed"]):
        return "likely_success"
    if "no confirmed database extraction" in text or "uncertain" in text:
        return "uncertain"
    if "403 forbidden" in text or "401 unauthorized" in text or "denied" in text:
        return "failed"
    if "success" in text or "complete" in text:
        return "likely_success"
    return "unknown"

def _infer_exploit_signal_strength(payload):
    text = _payload_text(payload).lower()

    strong = 0
    medium = 0

    if any(x in text for x in ["uid=0", "root shell", "root-level access confirmed"]):
        strong += 3
    if any(x in text for x in ["flag successfully read", "sensitive file accessed", "file disclosure", "data extraction"]):
        strong += 3
    if any(x in text for x in ["sql-style error", "database-style error", "altered response length", "altered application response"]):
        medium += 2
    if any(x in text for x in ["401 unauthorized", "403 forbidden", "no confirmed database extraction", "no verified authenticated session"]):
        medium += 1

    score = strong + medium
    if score >= 6:
        return "high"
    if score >= 3:
        return "moderate"
    return "low"

def is_canonical_payload(payload: dict) -> bool:
    required = {"run_id", "target", "timestamp", "recon_summary", "vulnerability_analysis", "execution_summary", "artifacts", "meta"}
    return required.issubset(set(payload.keys()))

def is_pentestgpt_session_payload(payload: dict) -> bool:
    return "session" in payload and "steps" in payload

def is_summary_style_payload(payload: dict) -> bool:
    return "attack_summary" in payload and "vulnerabilities" in payload

def convert_pentestgpt_session(payload: dict) -> dict:
    session = payload.get("session", {})
    steps = _safe_list(payload.get("steps", []))
    logs = _collect_logs(payload)

    target = session.get("target") or payload.get("target") or "unknown"
    services, versions = _extract_services_and_versions(payload, steps, logs)
    weaknesses = _infer_weaknesses(payload)
    cves = _infer_candidate_cves(payload, services, weaknesses)
    open_ports = _extract_open_ports(payload, steps, _payload_text(payload))
    success_indicators = _collect_success_indicators(payload)
    failure_indicators = _collect_failure_indicators(payload)
    http_requests, http_responses = _infer_http_artifacts(payload, steps)

    return {
        "run_id": session.get("session_id", "session_ingest"),
        "target": {
            "input_type": "ip_or_domain",
            "value": target
        },
        "timestamp": _session_timestamp(payload),
        "recon_summary": {
            "open_ports": open_ports if open_ports else [],
            "services": services if services else ["Unknown"],
            "service_versions": versions if versions else ["Unknown"]
        },
        "vulnerability_analysis": {
            "suspected_weaknesses": weaknesses,
            "candidate_cves": cves,
            "confidence": _infer_confidence(payload, weaknesses, success_indicators, failure_indicators)
        },
        "execution_summary": {
            "attempted_actions": _collect_attempted_actions(steps),
            "observed_responses": _collect_observed_responses(payload, steps),
            "success_indicators": success_indicators,
            "failure_indicators": failure_indicators,
            "final_status": _infer_final_status(payload)
        },
        "artifacts": {
            "http_requests": http_requests,
            "http_responses": http_responses,
            "command_outputs": _collect_commands(steps),
            "screenshots": [],
            "logs": logs[:60]
        },
        "meta": {
            "toolset": _uniq(
                ([session.get("tool")] if session.get("tool") else []) +
                _safe_list(payload.get("summary", {}).get("techniques_used", []))
            ),
            "agent_version": str(session.get("version", "1.0")),
            "notes": f"Adapted automatically from PentestGPT session schema. Original session status: {session.get('status', 'unknown')}. Flags captured: {session.get('flags_captured', 0)}.",
            "source_schema": "pentestgpt_session_v2",
            "target_hints": _extract_target_hints(payload, services, steps, logs),
            "application_endpoint_hints": _extract_application_endpoint_hints(payload, steps, logs),
            "exploit_signal_strength": _infer_exploit_signal_strength(payload)
        }
    }

def convert_summary_style_payload(payload: dict) -> dict:
    text = _payload_text(payload)
    target = payload.get("target", "unknown")

    services = []
    if "telnet" in text.lower():
        services.append("Telnet")
    if "ftp" in text.lower():
        services.append("FTP")
    if not services:
        services.append("Unknown")

    ports = []
    if "port 23" in text.lower():
        ports.append(23)
    if "port 21" in text.lower():
        ports.append(21)

    weaknesses = []
    for v in _safe_list(payload.get("vulnerabilities", [])):
        issue = v.get("issue")
        if issue:
            weaknesses.append(issue)

    success = bool(payload.get("success"))
    success_indicators = []
    if success:
        success_indicators.append("Attack objective achieved")
    if payload.get("access_level"):
        success_indicators.append(f"Access level obtained: {payload.get('access_level')}")
    if payload.get("flag"):
        success_indicators.append("Sensitive file or objective artifact accessed")

    return {
        "run_id": payload.get("session_id", "summary_ingest"),
        "target": {
            "input_type": "ip_or_domain",
            "value": target
        },
        "timestamp": (payload.get("timestamp", "1970-01-01") + "T00:00:00Z") if len(str(payload.get("timestamp", ""))) == 10 else "1970-01-01T00:00:00Z",
        "recon_summary": {
            "open_ports": ports,
            "services": _uniq(services),
            "service_versions": ["Unknown"]
        },
        "vulnerability_analysis": {
            "suspected_weaknesses": _uniq(weaknesses) if weaknesses else _infer_weaknesses(payload),
            "candidate_cves": [],
            "confidence": 0.95 if success else 0.70
        },
        "execution_summary": {
            "attempted_actions": _uniq(list(payload.get("attack_summary", {}).values())),
            "observed_responses": _uniq(list(payload.get("attack_summary", {}).values())),
            "success_indicators": _uniq(success_indicators),
            "failure_indicators": [],
            "final_status": "likely_success" if success else "unknown"
        },
        "artifacts": {
            "http_requests": [],
            "http_responses": [],
            "command_outputs": _uniq(_safe_list(payload.get("tools_used", []))),
            "screenshots": [],
            "logs": _uniq(_safe_list(payload.get("recommendations", [])) + [payload.get("notes", "")])
        },
        "meta": {
            "toolset": _uniq(_safe_list(payload.get("tools_used", []))),
            "agent_version": "1.0",
            "notes": "Adapted automatically from summary-style payload.",
            "source_schema": "summary_style_v2",
            "target_hints": ["Service-level compromise indicators should be prioritized"],
            "application_endpoint_hints": [],
            "exploit_signal_strength": "high" if success else "moderate"
        }
    }

def normalize_payload(payload: dict) -> dict:
    if is_canonical_payload(payload):
        # preserve canonical and enrich meta if possible
        payload.setdefault("meta", {})
        payload["meta"].setdefault("source_schema", "canonical_soc_intake")
        payload["meta"].setdefault("target_hints", [])
        payload["meta"].setdefault("application_endpoint_hints", [])
        payload["meta"].setdefault("exploit_signal_strength", "unknown")
        return payload

    if is_pentestgpt_session_payload(payload):
        return convert_pentestgpt_session(payload)

    if is_summary_style_payload(payload):
        return convert_summary_style_payload(payload)

    raise ValueError("Unsupported payload format. Expected canonical schema, PentestGPT session schema, or summary-style attack log.")
