"""
AI Security Assessment Platform - Flask Backend + Frontend  v6.1
=================================================================

WHAT'S FIXED IN v6.1:
  OK build_remote_soc_command now cd's into the SOC script directory
     before calling python3, so relative imports like
     `from api.process_run import process` resolve correctly.
  OK All features from v6.0 retained.

Pipeline flow:
  STEP 1 -> bash run_pentest.sh <target>           (subprocess + xterm popup tail)
  STEP 2 -> docker cp log out of container          (to Generated_logs/)
  STEP 3 -> python3 claude_log_to_json.py <l> <j>  (log -> JSON)
  STEP 4 -> rsync JSON to SOC machine               (SOC MAACHINE TAILSCALE IP ADDRESS)
  STEP 5 -> ssh -T -> python3 run_soc.py on SOC     (generates DOCX)
  STEP 6 -> rsync DOCX back to pentest machine      (Deop/soc_report/ or your prefered location)
  STEP 7 -> Flask serves DOCX for download

Install:
  pip install flask flask-cors

Run:
  python3 app.py
  Then open http://localhost:5000 in any browser.
"""

import os
import uuid
import subprocess
import threading
import time
import logging
import queue
import json
import shlex
import shutil
import signal
import ipaddress
import re
import hmac
import contextlib
from datetime import datetime
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import msvcrt
except ImportError:
    msvcrt = None

from flask import Flask, jsonify, request, send_file, Response, stream_with_context
from flask_cors import CORS

# Flask setup
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# ANSI COLORS (terminal only)
class C:
    RESET = "\033[0m";  BOLD = "\033[1m";   DIM  = "\033[2m"
    BRED  = "\033[91m"; BGREEN = "\033[92m"; BYELLOW = "\033[93m"
    BBLUE = "\033[94m"; BMAGENTA = "\033[95m"; BWHITE = "\033[97m"
    CYAN  = "\033[36m"; BG_RED = "\033[41m"

LOG_LOCK  = threading.Lock()
JOBS_LOCK = threading.RLock()
SSE_LOCK  = threading.Lock()
PERSIST_LOCK = threading.Lock()

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(job_id, level, msg, sub=False):
    short  = job_id[:8] if job_id else "--------"
    indent = "    |  " if sub else ""
    PFX = {
        "step":  f"{C.BOLD}{C.BBLUE}[STEP]{C.RESET}",
        "cmd":   f"{C.DIM}{C.CYAN}[ CMD]{C.RESET}",
        "out":   f"{C.DIM}[ OUT]{C.RESET}",
        "ok":    f"{C.BOLD}{C.BGREEN}[  OK]{C.RESET}",
        "warn":  f"{C.BOLD}{C.BYELLOW}[WARN]{C.RESET}",
        "error": f"{C.BOLD}{C.BRED}[ ERR]{C.RESET}",
        "fatal": f"{C.BOLD}{C.BG_RED}{C.BWHITE}[FAIL]{C.RESET}",
        "retry": f"{C.BOLD}{C.BYELLOW}[ RTY]{C.RESET}",
        "info":  f"{C.DIM}[INFO]{C.RESET}",
        "beat":  f"{C.DIM}{C.CYAN}[BEAT]{C.RESET}",
    }
    prefix = PFX.get(level, PFX["info"])
    line = f"{C.DIM}{ts()}{C.RESET}  {prefix}  {C.DIM}[{short}]{C.RESET}  {indent}{msg}"
    with LOG_LOCK:
        print(line, flush=True)

def log_banner(title, color=C.BBLUE):
    with LOG_LOCK:
        print(f"\n{C.BOLD}{color}{title}{C.RESET}\n", flush=True)

def log_success(t): log_banner(f"OK  {t}", C.BGREEN)
def log_fail(t):    log_banner(f"FAIL  {t}", C.BRED)

# PATH CONFIGURATION

# Please edit the necessary paths and names before launching the app

APP_DIR            = Path(__file__).resolve().parent
HOME               = str(Path.home())
PENTEST_SCRIPT     = os.environ.get("PENTEST_SCRIPT", str(APP_DIR / "run_pentest.sh"))
JSON_CONVERTER     = os.environ.get("JSON_CONVERTER", str(APP_DIR / "claude_log_to_json.py"))
GENERATED_LOGS_DIR = os.environ.get("GENERATED_LOGS_DIR", str(APP_DIR / "Generated_logs"))
LOG_ON_DESKTOP     = os.environ.get("PENTEST_LIVE_LOG", str(Path(GENERATED_LOGS_DIR) / "pentest_full_output.log"))
JOB_STORE_PATH     = os.environ.get("JOB_STORE_PATH", str(Path(GENERATED_LOGS_DIR) / "jobs_state.json"))
REPORT_LOCAL_DIR   = os.environ.get("REPORT_LOCAL_DIR", str(APP_DIR / "soc_report"))
SOC_USER           = os.environ.get("SOC_USER", "enter your machines/OS username")
SOC_HOST           = os.environ.get("SOC_HOST", "your Tailscale/any secure VPN IP")
SOC_SAMPLES_DIR    = os.environ.get("SOC_SAMPLES_DIR", "Replace this with your samples directory")
SOC_REPORTS_DIR    = os.environ.get("SOC_REPORTS_DIR", "Replace this with your generated documents directory")
SOC_RUN_SCRIPT     = os.environ.get("SOC_RUN_SCRIPT", "Replace this with your the path for your downloaded run_soc.py path")
MAX_RETRIES        = int(os.environ.get("MAX_RETRIES", "3"))
RETRY_DELAY        = int(os.environ.get("RETRY_DELAY", "5"))

# ─────────────────────────────────────────────────────────────────────────────
# PENTEST DURATION CONTROL
# ─────────────────────────────────────────────────────────────────────────────
# PENTEST_DURATION_MINUTES is the single knob you turn.
# Common values:
#   5   →  quick test / debug
#   30  →  default short scan
#   60  →  medium (1 hour)
#   120 →  thorough (2 hours)
#   300 →  deep / overnight (5 hours)
#
# The pipeline will NOT move past Step 1 until at least this many minutes
# have elapsed OR PentestGPT exits on its own (whichever comes last),
# guaranteeing the log file has time to accumulate real output.
# ─────────────────────────────────────────────────────────────────────────────
PENTEST_DURATION_MINUTES: int = 40      # ← CHANGE THIS VALUE

# Derived timeouts (do not edit these directly – adjust PENTEST_DURATION_MINUTES above)
_DURATION_SECONDS    = PENTEST_DURATION_MINUTES * 60
PENTEST_TIMEOUT      = _DURATION_SECONDS          # hard kill after this many seconds
PENTEST_MIN_RUNTIME  = _DURATION_SECONDS          # never exit early before min runtime
PENTEST_IDLE_TIMEOUT = max(60, _DURATION_SECONDS) # idle grace = full duration (disable early-idle-exit)
PENTEST_MIN_LOG_BYTES = int(os.environ.get("PENTEST_MIN_LOG_BYTES", "2048"))
PENTEST_ALLOW_PARTIAL_LOG = os.environ.get("PENTEST_ALLOW_PARTIAL_LOG", "1").lower() in ("1", "true", "yes")
DOCKER_TIMEOUT     = int(os.environ.get("DOCKER_TIMEOUT", "60"))
SOC_TIMEOUT        = int(os.environ.get("SOC_TIMEOUT", "600"))
TRANSFER_TIMEOUT   = int(os.environ.get("TRANSFER_TIMEOUT", "120"))
JSON_TIMEOUT       = int(os.environ.get("JSON_TIMEOUT", "600"))
JSON_VERIFY_RETRIES = int(os.environ.get("JSON_VERIFY_RETRIES", "10000"))
JSON_VERIFY_DELAY = int(os.environ.get("JSON_VERIFY_DELAY", "2"))
STALE_AFTER_MS     = int(os.environ.get("STALE_AFTER_MS", "120000"))
MAX_TARGET_LEN     = int(os.environ.get("MAX_TARGET_LEN", "255"))
API_KEY            = os.environ.get("APP_API_KEY", "").strip()
SKIP_PREFLIGHT     = os.environ.get("SKIP_PREFLIGHT", "0").lower() in ("1", "true", "yes")
ALLOW_PRIVATE_TARGETS = os.environ.get("ALLOW_PRIVATE_TARGETS", "1").lower() in ("1", "true", "yes")
ALLOW_LOCAL_TARGETS   = os.environ.get("ALLOW_LOCAL_TARGETS", "0").lower() in ("1", "true", "yes")
ALLOW_REMOTE_LATEST_FALLBACK = os.environ.get("ALLOW_REMOTE_LATEST_FALLBACK", "1").lower() in ("1", "true", "yes")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

# Stage keys - SINGLE SOURCE OF TRUTH shared by backend + embedded frontend JS
STAGE_PENTEST   = "pentest_running"
STAGE_COPY_LOG  = "securing_log"
STAGE_JSON      = "structuring_findings"
STAGE_SEND_SOC  = "transmitting_soc"
STAGE_SOC_RUN   = "soc_analysis"
STAGE_FETCH_DOC = "fetching_report"
STAGE_DONE      = "completed"
STAGE_FAILED    = "failed"

# In-memory job store  +  per-job SSE subscriber queues
jobs: dict = {}
sse_subscribers: dict = {}   # job_id -> list[queue.Queue]

# JOB STATE + SSE PUSH
def _status_payload(snapshot):
    """Return the exact JSON shape used by /status and SSE."""
    return {
        "job_id":          snapshot.get("job_id"),
        "target":          snapshot.get("target"),
        "mode":            snapshot.get("mode"),
        "status":          snapshot.get("status"),
        "stage":           snapshot.get("stage"),
        "message":         snapshot.get("message"),
        "progress":        snapshot.get("progress"),
        "ready":           snapshot.get("status") == "completed",
        "report_filename": snapshot.get("report_filename"),
        "error":           snapshot.get("error"),
        "created_at":      snapshot.get("created_at"),
        "updated_at":      snapshot.get("updated_at"),
    }


def set_stage(job_id, stage, message, progress=None, status=None):
    """Thread-safe job state update. Pushes update to all SSE subscribers."""
    with JOBS_LOCK:
        if job_id not in jobs:
            return
        update = {"stage": stage, "message": message, "updated_at": time.time()}
        if status is not None:
            update["status"] = status
        if progress is not None:
            current = int(jobs[job_id].get("progress") or 0)
            new_progress = max(0, min(100, int(progress)))
            if stage != STAGE_FAILED:
                new_progress = max(current, new_progress)
            update["progress"] = new_progress
        jobs[job_id].update(update)
        snapshot = dict(jobs[job_id])

    _sse_push(job_id, snapshot)
    persist_jobs()


def _sse_push(job_id, snapshot):
    """Send snapshot to every SSE queue registered for this job."""
    payload = json.dumps(_status_payload(snapshot))
    with SSE_LOCK:
        queues = list(sse_subscribers.get(job_id, []))
    for q in queues:
        try:
            q.put_nowait(payload)
        except queue.Full:
            try:
                q.get_nowait()
                q.put_nowait(payload)
            except queue.Empty:
                pass
            except queue.Full:
                pass


@contextlib.contextmanager
def job_store_file_lock():
    """Best-effort cross-process lock around the JSON state file."""
    directory = os.path.dirname(os.path.abspath(JOB_STORE_PATH))
    os.makedirs(directory, exist_ok=True)
    lock_path = f"{JOB_STORE_PATH}.lock"
    with PERSIST_LOCK:
        with open(lock_path, "a+", encoding="utf-8") as lock_fh:
            lock_kind = None
            try:
                if os.name == "nt" and msvcrt is not None:
                    lock_fh.seek(0)
                    msvcrt.locking(lock_fh.fileno(), msvcrt.LK_LOCK, 1)
                    lock_kind = "msvcrt"
                elif fcntl is not None:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
                    lock_kind = "fcntl"
                yield
            finally:
                try:
                    if lock_kind == "msvcrt":
                        lock_fh.seek(0)
                        msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
                    elif lock_kind == "fcntl":
                        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
                except Exception as exc:
                    log(None, "warn", f"Could not unlock job state file: {exc}")


def persist_jobs():
    """Persist job state atomically so status survives Flask restarts."""
    try:
        with JOBS_LOCK:
            payload = {
                "saved_at": time.time(),
                "jobs": {job_id: dict(job) for job_id, job in jobs.items()},
            }
        with job_store_file_lock():
            tmp_path = f"{JOB_STORE_PATH}.{os.getpid()}.{threading.get_ident()}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, JOB_STORE_PATH)
    except Exception as exc:
        log(None, "warn", f"Could not persist job state: {exc}")


def load_jobs_from_disk():
    """Load previous job state; active jobs cannot resume, so mark them failed."""
    if not os.path.exists(JOB_STORE_PATH):
        return
    try:
        with job_store_file_lock():
            with open(JOB_STORE_PATH, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        loaded = payload.get("jobs", {})
        if not isinstance(loaded, dict):
            return
        now = time.time()
        with JOBS_LOCK:
            jobs.clear()
            for job_id, job in loaded.items():
                if not isinstance(job, dict):
                    continue
                if job.get("status") in ("queued", "running"):
                    job["status"] = "failed"
                    job["message"] = "Server restarted before this assessment finished."
                    job["error"] = "Server restarted before this assessment finished."
                    job["updated_at"] = now
                jobs[job_id] = job
        with SSE_LOCK:
            sse_subscribers.clear()
            for job_id in jobs:
                sse_subscribers[job_id] = []
        persist_jobs()
        log(None, "ok", f"Loaded {len(jobs)} persisted job(s) from {JOB_STORE_PATH}")
    except Exception as exc:
        log(None, "warn", f"Could not load persisted job state: {exc}")

# HEARTBEAT (progress bar during long pentest)
def _progress_heartbeat(job_id, stop_event, start_pct=8, end_pct=55, interval=8):
    pct = start_pct
    while not stop_event.is_set():
        time.sleep(interval)
        if stop_event.is_set():
            break
        with JOBS_LOCK:
            if job_id not in jobs:
                break
            if jobs[job_id].get("stage") != STAGE_PENTEST:
                break
            pct = min(max(int(jobs[job_id].get("progress") or pct), start_pct) + 1, end_pct)
            jobs[job_id]["progress"]   = pct
            jobs[job_id]["updated_at"] = time.time()
            snapshot = dict(jobs[job_id])
        _sse_push(job_id, snapshot)
        persist_jobs()
        log(job_id, "beat", f"Heartbeat -> progress={pct}%")

# POPUP TERMINAL  (read-only tail - pentest runs once in subprocess)
def _stage_heartbeat(job_id, stage, stop_event, end_pct, interval=10):
    """Keep the browser synced while a long backend step is still running."""
    while not stop_event.is_set():
        time.sleep(interval)
        if stop_event.is_set():
            break
        with JOBS_LOCK:
            if job_id not in jobs:
                break
            job = jobs[job_id]
            if job.get("stage") != stage or job.get("status") in ("completed", "failed"):
                break
            current = int(job.get("progress") or 0)
            if current < end_pct:
                job["progress"] = min(current + 1, end_pct)
            job["updated_at"] = time.time()
            snapshot = dict(job)
        _sse_push(job_id, snapshot)
        persist_jobs()
        log(job_id, "beat", f"{stage} heartbeat -> progress={snapshot.get('progress')}%")


def launch_popup_terminal(title, tail_file):
    tail_file_arg = _shell_quote(tail_file)
    tail_script = f"while [ ! -f {tail_file_arg} ]; do sleep 1; done; tail -F {tail_file_arg} 2>/dev/null"
    xterm_cmd = [
        "xterm", "-title", title, "-geometry", "140x45",
        "-bg", "#050d1a", "-fg", "#4ade80", "-fa", "Monospace", "-fs", "11",
        "-e", "bash", "-lc", tail_script,
    ]
    try:
        proc = subprocess.Popen(
            xterm_cmd,
            env={**os.environ, "DISPLAY": os.environ.get("DISPLAY", ":0")},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        log(None, "ok", f"xterm popup launched (PID {proc.pid})")
        return proc
    except Exception as exc:
        log(None, "warn", f"xterm popup failed: {exc} - continuing without it")
        return None

# COMMAND RUNNER
def _signal_process_tree(process, sig):
    if os.name != "nt" and getattr(process, "_kill_process_group", False):
        try:
            os.killpg(os.getpgid(process.pid), sig)
            return
        except Exception:
            pass
    if sig == signal.SIGTERM:
        process.terminate()
    else:
        process.kill()


def _terminate_process(process, grace=5):
    if process.poll() is not None:
        return
    try:
        _signal_process_tree(process, signal.SIGTERM)
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            _signal_process_tree(process, signal.SIGKILL)
        except Exception:
            pass
    except Exception:
        try:
            _signal_process_tree(process, signal.SIGKILL)
        except Exception:
            pass


def _shell_quote(value):
    return shlex.quote(str(value))


def _cmd_text(cmd):
    if isinstance(cmd, (list, tuple)):
        return " ".join(_shell_quote(part) for part in cmd)
    return str(cmd)


def _has_control_chars(value):
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in str(value))


def validate_target(target):
    target = (target or "").strip()
    if not target:
        return None, "Target is required."
    if len(target) > MAX_TARGET_LEN:
        return None, f"Target is too long. Maximum length is {MAX_TARGET_LEN} characters."
    if _has_control_chars(target):
        return None, "Target contains invalid control characters."
    if any(ch.isspace() for ch in target) or any(ch in target for ch in "/\\"):
        return None, "Target must be a plain IP address or domain name, not a URL or path."

    try:
        ip = ipaddress.ip_address(target.strip("[]"))
        if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            return None, "Target IP is not routable for this workflow."
        if (ip.is_loopback or ip.is_link_local) and not ALLOW_LOCAL_TARGETS:
            return None, "Local or link-local targets are disabled. Set ALLOW_LOCAL_TARGETS=1 to allow them."
        if ip.is_private and not ALLOW_PRIVATE_TARGETS:
            return None, "Private-range targets are disabled. Set ALLOW_PRIVATE_TARGETS=1 to allow lab targets."
        return str(ip), None
    except ValueError:
        if re.fullmatch(r"[0-9.]+", target):
            return None, "Target looks like an IP address but is not valid IPv4/IPv6."

    hostname = target.rstrip(".")
    if hostname.lower() == "localhost" and not ALLOW_LOCAL_TARGETS:
        return None, "localhost is disabled. Set ALLOW_LOCAL_TARGETS=1 to allow it."
    if not DOMAIN_RE.fullmatch(target):
        return None, "Target must be a valid IPv4/IPv6 address or DNS hostname."
    labels = hostname.split(".")
    if len(labels) > 1 and labels[-1].isdigit():
        return None, "Domain top-level label cannot be all numeric."

    # Try to resolve hostname using host machine's /etc/hosts.
    # If resolution fails, pass the hostname as-is and let PentestGPT handle it.
    try:
        import socket
        resolved_ip = socket.gethostbyname(target)
        log(None, "info", f"Resolved {target} -> {resolved_ip}")
        return resolved_ip, None
    except socket.gaierror:
        log(None, "warn", f"Could not resolve '{target}' on host — passing hostname as-is to PentestGPT.")
        return target, None


def _which(name):
    return shutil.which(name) is not None


def preflight_checks():
    if SKIP_PREFLIGHT:
        return []
    problems = []
    try:
        os.makedirs(GENERATED_LOGS_DIR, exist_ok=True)
        os.makedirs(REPORT_LOCAL_DIR, exist_ok=True)
    except Exception as exc:
        problems.append(f"Could not create runtime directories: {exc}")
    if not os.path.isfile(PENTEST_SCRIPT):
        problems.append(f"Pentest script not found: {PENTEST_SCRIPT}")
    if not os.path.isfile(JSON_CONVERTER):
        problems.append(f"JSON converter not found: {JSON_CONVERTER}")
    if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
        problems.append("ANTHROPIC_API_KEY environment variable is required for PentestGPT.")
    for binary in ("bash", "docker", "python3", "rsync", "ssh"):
        if not _which(binary):
            problems.append(f"Required command not found on PATH: {binary}")
    return problems


def _extract_api_key():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return (
        request.headers.get("X-API-Key")
        or request.args.get("api_key")
        or ""
    ).strip()


def _route_requires_auth(path):
    protected_prefixes = (
        "/api/start",
        "/api/status/",
        "/api/stream/",
        "/api/download/",
    )
    return any(path == prefix or path.startswith(prefix) for prefix in protected_prefixes)


@app.before_request
def enforce_optional_api_key():
    if request.method == "OPTIONS" or not API_KEY or not _route_requires_auth(request.path):
        return None
    supplied = _extract_api_key()
    if supplied and hmac.compare_digest(supplied, API_KEY):
        return None
    return jsonify({
        "error": "Unauthorized. Provide X-API-Key, Authorization: Bearer token, or api_key query parameter.",
    }), 401


def _tail_lines(path, max_lines=20):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return []
    return [line.rstrip() for line in lines[-max_lines:]]


def run_pentest_subprocess(job_id, target, timeout=1800, step_name="STEP 1"):
    """Run PentestGPT and stop waiting once a usable log is idle."""
    cmd = ["bash", PENTEST_SCRIPT, target]
    output_path = os.path.join(GENERATED_LOGS_DIR, f"pentest_runner_{job_id[:8]}.out")
    log(job_id, "cmd", f"{C.CYAN}{_cmd_text(cmd)}{C.RESET}")
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    process = None
    accepted_partial = False
    started = time.time()
    deadline = started + timeout
    last_size = -1
    last_change = started

    try:
        with open(output_path, "w", encoding="utf-8", errors="replace") as out:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                start_new_session=(os.name != "nt"),
            )
            process._kill_process_group = (os.name != "nt")
            while True:
                now = time.time()
                try:
                    size = os.path.getsize(output_path)
                except FileNotFoundError:
                    size = 0
                if size != last_size:
                    last_size = size
                    last_change = now

                if process.poll() is not None:
                    break

                if now >= deadline:
                    if PENTEST_ALLOW_PARTIAL_LOG and size >= PENTEST_MIN_LOG_BYTES:
                        accepted_partial = True
                        log(job_id, "warn",
                            f"{step_name} reached {timeout}s; continuing with captured log ({size} bytes).")
                        _terminate_process(process, grace=3)
                        break
                    _terminate_process(process, grace=3)
                    raise subprocess.TimeoutExpired(cmd, timeout)

                idle_for = now - last_change
                ran_for = now - started
                if (PENTEST_ALLOW_PARTIAL_LOG
                        and size >= PENTEST_MIN_LOG_BYTES
                        and ran_for >= PENTEST_MIN_RUNTIME
                        and idle_for >= PENTEST_IDLE_TIMEOUT):
                    accepted_partial = True
                    log(job_id, "warn",
                        f"{step_name} log idle for {int(idle_for)}s; continuing with captured log ({size} bytes).")
                    _terminate_process(process, grace=3)
                    break

                time.sleep(1)
    except FileNotFoundError as exc:
        raise RuntimeError(f"{step_name}: required command not found: {exc.filename}") from exc
    except subprocess.TimeoutExpired:
        log(job_id, "error", f"{step_name} timed out after {timeout}s")
        raise

    for line in _tail_lines(output_path, max_lines=30):
        if line:
            log(job_id, "out", f"{C.DIM}{line}{C.RESET}", sub=True)

    returncode = process.returncode if process is not None else None
    if returncode not in (None, 0) and not accepted_partial:
        last = "\n".join(_tail_lines(output_path, max_lines=20)) or "no output captured"
        raise RuntimeError(f"{step_name} exited {returncode}.\nLast output:\n{last}")
    return output_path


def run_cmd_streaming(cmd, job_id, timeout=600, step_name="cmd", extra_env=None):
    log(job_id, "cmd", f"{C.CYAN}{_cmd_text(cmd)}{C.RESET}")
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    if extra_env:
        env.update({str(k): str(v) for k, v in extra_env.items()})
    use_shell = isinstance(cmd, str)
    try:
        process = subprocess.Popen(
            cmd, shell=use_shell,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"{step_name}: required command not found: {exc.filename}") from exc
    reader_queue = queue.Queue()

    def _reader():
        try:
            for raw in process.stdout:
                reader_queue.put(raw)
        finally:
            reader_queue.put(None)

    threading.Thread(target=_reader, daemon=True).start()

    output_lines = []
    deadline = time.time() + timeout

    try:
        while True:
            if time.time() > deadline:
                _terminate_process(process, grace=1)
                raise subprocess.TimeoutExpired(cmd, timeout)
            if process.poll() is not None and reader_queue.empty():
                break
            try:
                raw_line = reader_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if raw_line is None:
                break
            line = raw_line.rstrip()
            if line:
                output_lines.append(line)
                log(job_id, "out", f"{C.DIM}{line}{C.RESET}", sub=True)
        process.wait(timeout=max(1, int(deadline - time.time())))
    except subprocess.TimeoutExpired:
        _terminate_process(process, grace=1)
        raise
    if process.returncode != 0:
        last = "\n".join(output_lines[-20:]) or "no output captured"
        raise RuntimeError(f"{step_name} exited {process.returncode}.\nLast output:\n{last}")
    return "\n".join(output_lines)


def run_with_retry(cmd, job_id, timeout=600, step_name="Step",
                   max_retries=MAX_RETRIES, retry_delay=RETRY_DELAY,
                   extra_env=None):
    last_error = None
    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            log(job_id, "retry", f"{step_name} - retry {attempt}/{max_retries}")
            time.sleep(retry_delay)
        log(job_id, "info", f"{step_name} - attempt {attempt}/{max_retries}")
        try:
            out = run_cmd_streaming(cmd, job_id, timeout=timeout, step_name=step_name, extra_env=extra_env)
            log(job_id, "ok", f"{C.BGREEN}{step_name} - OK (attempt {attempt}){C.RESET}")
            return out
        except subprocess.TimeoutExpired:
            last_error = f"{step_name} timed out after {timeout}s."
            log(job_id, "error", f"{step_name} - attempt {attempt} timed out after {timeout}s")
            if attempt == max_retries:
                break
        except RuntimeError as exc:
            last_error = str(exc)
            log(job_id, "error", f"{step_name} - attempt {attempt} failed: {last_error}")
            if attempt == max_retries:
                break
    raise RuntimeError(f"{step_name} failed after {max_retries} attempts. Last: {last_error}")


def run_with_stage_heartbeat(cmd, job_id, stage, end_pct, timeout=600, step_name="Step",
                             max_retries=MAX_RETRIES, retry_delay=RETRY_DELAY,
                             interval=10, extra_env=None):
    stop_event = threading.Event()
    threading.Thread(
        target=_stage_heartbeat,
        args=(job_id, stage, stop_event, end_pct, interval),
        daemon=True,
    ).start()
    try:
        return run_with_retry(
            cmd, job_id, timeout=timeout, step_name=step_name,
            max_retries=max_retries, retry_delay=retry_delay,
            extra_env=extra_env,
        )
    finally:
        stop_event.set()


def wait_for_file(filepath, job_id, step_name="File check", retries=6, delay=3):
    for attempt in range(1, retries + 1):
        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            log(job_id, "ok", f"{C.BGREEN}{step_name} - verified: {filepath}{C.RESET}")
            return True
        log(job_id, "warn", f"{step_name} - not found yet ({attempt}/{retries}): {filepath}")
        if attempt < retries:
            time.sleep(delay)
    raise RuntimeError(f"{step_name}: file missing after {retries} checks: {filepath}")


def _json_paths_from_converter_output(output):
    candidates = []
    for line in (output or "").splitlines():
        match = re.search(r"JSON written:\s+(.+?)(?:\s+\(\d+\s+bytes\)|$)", line)
        if match:
            candidates.append(Path(match.group(1).strip().strip("\"'")))
        match = re.search(r"JSON_PATH\s*=\s*(.+)$", line)
        if match:
            candidates.append(Path(match.group(1).strip().strip("\"'")))
    return candidates


def _unique_paths(paths):
    seen = set()
    result = []
    for path in paths:
        try:
            key = str(Path(path).expanduser().resolve())
        except Exception:
            key = str(path)
        if key not in seen:
            seen.add(key)
            result.append(Path(path))
    return result


def _json_candidate_dirs(expected):
    dirs = [
        expected.parent,
        Path(GENERATED_LOGS_DIR),
        Path(GENERATED_LOGS_DIR).parent,
        APP_DIR,
        APP_DIR / "Generated_logs",
        Path(HOME) / "Desktop",
    ]
    return [p for p in _unique_paths(dirs) if p.exists() and p.is_dir()]


def _looks_like_job_json(candidate, expected):
    if candidate.name == "jobs_state.json":
        return False
    if candidate.suffix.lower() != ".json":
        return False
    if candidate.name == expected.name:
        return True
    if candidate.name == "pentest_full_output.json":
        return True
    return expected.stem in candidate.stem or candidate.stem in expected.stem


def _dynamic_json_candidates(expected, newer_than=0):
    candidates = []
    for directory in _json_candidate_dirs(expected):
        try:
            for path in directory.glob("*.json"):
                if not _looks_like_job_json(path, expected):
                    continue
                if newer_than and path.stat().st_mtime < newer_than:
                    continue
                candidates.append(path)
        except Exception:
            continue
    return sorted(
        _unique_paths(candidates),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )


def wait_for_json_file(filepath, job_id, step_name="JSON check",
                       retries=JSON_VERIFY_RETRIES, delay=JSON_VERIFY_DELAY,
                       newer_than=0, converter_output=""):
    """Wait for JSON and recover files written to a nearby/Deop path."""
    expected = Path(filepath)
    fallback_paths = _unique_paths([
        expected,
        APP_DIR / expected.name,
        APP_DIR / "Generated_logs" / expected.name,
        Path(GENERATED_LOGS_DIR).parent / expected.name,
        Path(HOME) / "Deop" / expected.name,
        Path(GENERATED_LOGS_DIR) / "pentest_full_output.json",
        APP_DIR / "Generated_logs" / "pentest_full_output.json",
        APP_DIR / "pentest_full_output.json",
        Path(HOME) / "Deop" / "pentest_full_output.json",
    ])

    attempt = 0
    while retries <= 0 or attempt < retries:
        attempt += 1
        if expected.exists() and expected.stat().st_size > 0:
            log(job_id, "ok", f"{C.BGREEN}{step_name} - verified: {expected}{C.RESET}")
            return True

        output_candidates = _json_paths_from_converter_output(converter_output)
        dynamic_candidates = _dynamic_json_candidates(expected, newer_than=newer_than)
        for candidate in _unique_paths([*output_candidates, *fallback_paths, *dynamic_candidates]):
            try:
                if not candidate.exists() or candidate.stat().st_size <= 0:
                    continue
                if newer_than and candidate.stat().st_mtime < newer_than:
                    continue
                if candidate.resolve() != expected.resolve():
                    expected.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(candidate, expected)
                    log(job_id, "warn",
                        f"{step_name} - recovered JSON from {candidate} -> {expected}")
                log(job_id, "ok", f"{C.BGREEN}{step_name} - verified: {expected}{C.RESET}")
                return True
            except Exception as exc:
                log(job_id, "warn", f"{step_name} - candidate check failed for {candidate}: {exc}")

        limit_text = "unlimited" if retries <= 0 else str(retries)
        log(job_id, "warn", f"{step_name} - not found yet ({attempt}/{limit_text}): {expected}")
        set_stage(
            job_id, STAGE_JSON,
            f"Waiting for JSON output from claude_log_to_json.py ({attempt}/{limit_text})...",
            progress=75,
        )
        time.sleep(delay)
    raise RuntimeError(f"{step_name}: file missing after {retries} checks: {expected}")


def validate_json_file(filepath, job_id):
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        raise RuntimeError(f"Invalid JSON generated at {filepath}: {exc}") from exc
    if not isinstance(data, (dict, list)):
        raise RuntimeError(f"Invalid JSON generated at {filepath}: top-level value must be object or list.")
    count = len(data) if hasattr(data, "__len__") else 0
    log(job_id, "ok", f"JSON validated -> {filepath} ({type(data).__name__}, {count} item(s))")
    return data


def safe_filename(value, max_len=80):
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in str(value))
    return safe.strip("._")[:max_len] or "target"


def local_job_artifacts(job_id, target):
    safe = safe_filename(target)
    short = job_id[:8]
    log_path = os.path.join(GENERATED_LOGS_DIR, f"pentest_{safe}_{short}.log")
    json_path = os.path.join(GENERATED_LOGS_DIR, f"pentest_{safe}_{short}.json")
    report_filename = f"pentest_{safe}_{short}_report.docx"
    local_report_path = os.path.join(REPORT_LOCAL_DIR, report_filename)
    remote_report_path = f"{SOC_REPORTS_DIR.rstrip('/')}/{report_filename}"
    return log_path, json_path, local_report_path, remote_report_path, report_filename


def build_remote_soc_command(job_id, remote_json_path, remote_docx_path):
    """
    Run SOC report generation with an exact output path and safe fallback rules.

    KEY FIX (v6.1): We cd into the directory containing run_soc.py before
    invoking python3, so that relative imports like `from api.process_run import
    process` resolve correctly regardless of the SSH login directory.
    """
    marker_path = f"/tmp/soc_report_{job_id[:8]}.marker"
    latest_fallback = "1" if ALLOW_REMOTE_LATEST_FALLBACK else "0"

    # Directory that contains run_soc.py  (e.g. /home/akhasib/soc_side)
    soc_script_dir = _shell_quote(str(Path(SOC_RUN_SCRIPT).parent))

    env_prefix = (
        'SOC_REPORT_OUTPUT="$out_path" '
        'REPORT_OUTPUT_PATH="$out_path" '
        'OUTPUT_DOCX="$out_path" '
    )
    return (
        "set -e; "
        # ── v6.1 FIX: cd to the script's directory so relative imports work ──
        f"cd {soc_script_dir}; "
        # ─────────────────────────────────────────────────────────────────────
        f"reports_dir={_shell_quote(SOC_REPORTS_DIR.rstrip('/'))}; "
        f"json_path={_shell_quote(remote_json_path)}; "
        f"out_path={_shell_quote(remote_docx_path)}; "
        f"run_script={_shell_quote(SOC_RUN_SCRIPT)}; "
        f"marker={_shell_quote(marker_path)}; "
        "mkdir -p \"$reports_dir\"; "
        "rm -f \"$out_path\"; "
        "touch \"$marker\"; "
        "trap 'rm -f \"$marker\"' EXIT; "
        f"{env_prefix}python3 \"$run_script\" once \"$json_path\" \"$out_path\" "
        f"|| {{ [ -s \"$out_path\" ] || {env_prefix}python3 \"$run_script\" once \"$json_path\"; }} "
        f"|| {{ [ -s \"$out_path\" ] || {env_prefix}python3 \"$run_script\" once; }}; "
        "if [ -s \"$out_path\" ]; then exit 0; fi; "
        "matches=$(find \"$reports_dir\" -maxdepth 1 -type f -name '*.docx' -newer \"$marker\" -print 2>/dev/null || true); "
        "count=$(printf '%s\n' \"$matches\" | sed '/^$/d' | wc -l | tr -d ' '); "
        "if [ \"$count\" = \"1\" ]; then "
        "found=$(printf '%s\n' \"$matches\" | sed '/^$/d' | head -n 1); "
        "cp -f \"$found\" \"$out_path\"; exit 0; "
        "fi; "
        "if [ \"$count\" != \"0\" ]; then "
        "echo \"SOC report ambiguity: $count DOCX files created after this job marker.\" >&2; exit 42; "
        "fi; "
        f"if [ {_shell_quote(latest_fallback)} = \"1\" ]; then "
        "latest=$(find \"$reports_dir\" -maxdepth 1 -type f -name '*.docx' "
        "-printf '%T@ %p\\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-); "
        "test -n \"$latest\"; cp -f \"$latest\" \"$out_path\"; exit 0; "
        "fi; "
        "echo \"SOC report not found at expected path and no unique new DOCX was created.\" >&2; exit 43"
    )


def path_is_inside(path, directory):
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(directory)]) == os.path.abspath(directory)
    except ValueError:
        return False

# PIPELINE
def assessment_pipeline(job_id, target, mode):
    try:
        job_log_path, job_json_path, expected_docx_path, remote_docx_path, report_filename = local_job_artifacts(job_id, target)
        with JOBS_LOCK:
            jobs[job_id].update({
                "status": "running",
                "log_path": job_log_path,
                "json_path": job_json_path,
                "docx_path": expected_docx_path,
                "report_filename": report_filename,
                "updated_at": time.time(),
            })
            snapshot = dict(jobs[job_id])
        _sse_push(job_id, snapshot)
        persist_jobs()

        log_banner(f"PIPELINE START  |  target={target}  |  job={job_id[:8]}")
        os.makedirs(GENERATED_LOGS_DIR, exist_ok=True)
        os.makedirs(REPORT_LOCAL_DIR,   exist_ok=True)

        # -- STEP 1 -- PentestGPT ---------------------------------------------
        log(job_id, "step", f"{C.BOLD}STEP 1/6{C.RESET} - PentestGPT -> {C.BYELLOW}{target}{C.RESET}")
        set_stage(job_id, STAGE_PENTEST,
                  f"PentestGPT agent conducting authorized assessment on {target}...",
                  progress=8)

        # xterm popup tails the log (read-only); pentest runs ONCE below
        launch_popup_terminal(title=f"PentestGPT - {target}", tail_file=LOG_ON_DEOP)

        stop_heartbeat = threading.Event()
        threading.Thread(
            target=_progress_heartbeat,
            args=(job_id, stop_heartbeat, 8, 55, 8),
            daemon=True,
        ).start()

        pentest_success = False
        pentest_err     = None
        pentest_output_path = None
        for attempt in range(1, MAX_RETRIES + 1):
            if attempt > 1:
                log(job_id, "retry", f"PentestGPT retry {attempt}/{MAX_RETRIES}")
                time.sleep(RETRY_DELAY)
                with JOBS_LOCK:
                    current_progress = jobs.get(job_id, {}).get("progress", 8)
                set_stage(job_id, STAGE_PENTEST,
                          f"PentestGPT retrying ({attempt}/{MAX_RETRIES})...",
                          progress=current_progress)
            try:
                pentest_output_path = run_pentest_subprocess(
                    job_id, target, timeout=PENTEST_TIMEOUT,
                    step_name=f"STEP 1 attempt {attempt}",
                )
                pentest_success = True
                break
            except subprocess.TimeoutExpired:
                pentest_err = f"PentestGPT timed out after {PENTEST_TIMEOUT}s."
                break
            except RuntimeError as exc:
                pentest_err = str(exc)
                log(job_id, "error", f"Attempt {attempt}: {pentest_err}")
                if attempt == MAX_RETRIES:
                    break

        stop_heartbeat.set()

        if not pentest_success:
            raise RuntimeError(f"STEP 1 failed after {MAX_RETRIES} attempts. {pentest_err}")
        log(job_id, "ok", f"{C.BGREEN}STEP 1 - PentestGPT completed{C.RESET}")

        # -- STEP 2 -- docker cp -----------------------------------------------
        log(job_id, "step", f"{C.BOLD}STEP 2/6{C.RESET} - docker cp log from container")
        set_stage(job_id, STAGE_COPY_LOG,
                  "Retrieving assessment log from Docker container...", progress=60)

        # Try multiple container names in case the container was started under a different name
        _docker_cp_success = False
        for _container_name in ("pentestgpt", "pentest-gpt", "pentest_gpt"):
            try:
                run_with_stage_heartbeat(
                    ["docker", "cp", f"{_container_name}:/workspace/pentest_full_output.log", job_log_path],
                    job_id, STAGE_COPY_LOG, 65, timeout=DOCKER_TIMEOUT,
                    step_name=f"STEP 2 (docker cp from {_container_name})", interval=5)
                _docker_cp_success = True
                log(job_id, "ok", f"docker cp succeeded from container '{_container_name}'")
                break
            except Exception as _cp_exc:
                log(job_id, "warn", f"docker cp from '{_container_name}' failed: {_cp_exc}")

        if not _docker_cp_success:
            # Fallback: use the subprocess stdout captured in run_pentest_subprocess
            if (pentest_output_path and os.path.isfile(pentest_output_path)
                    and os.path.getsize(pentest_output_path) >= PENTEST_MIN_LOG_BYTES):
                shutil.copyfile(pentest_output_path, job_log_path)
                log(job_id, "warn",
                    "STEP 2: all docker cp attempts failed; falling back to captured subprocess output.")
            else:
                raise RuntimeError(
                    "STEP 2: docker cp failed for all container names and no usable fallback log exists.")

        # ── Strip ANSI escape codes from the log so the JSON converter and
        #    any human reading the file sees clean text (not raw terminal codes).
        _ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[()][0-9A-Za-z]|\x1b=|\r")
        try:
            with open(job_log_path, "r", encoding="utf-8", errors="replace") as _fh:
                _raw_log = _fh.read()
            _clean_log = _ANSI_RE.sub("", _raw_log)
            # Remove cursor-position sequences like [8;1H that survive the first pass
            _clean_log = re.sub(r"\[\d+;\d+H", "", _clean_log)
            # Collapse 3+ blank lines to 2
            _clean_log = re.sub(r"\n{3,}", "\n\n", _clean_log)
            with open(job_log_path, "w", encoding="utf-8") as _fh:
                _fh.write(_clean_log)
            log(job_id, "ok", f"ANSI codes stripped from log ({len(_raw_log)} → {len(_clean_log)} bytes)")
        except Exception as _strip_exc:
            log(job_id, "warn", f"ANSI strip step failed (non-fatal): {_strip_exc}")

        # Mirror the cleaned log to LOG_ON_DEOP so the xterm tail shows real content
        try:
            os.makedirs(os.path.dirname(LOG_ON_DEOP), exist_ok=True)
            shutil.copyfile(job_log_path, LOG_ON_DEOP)
            log(job_id, "ok", f"Live log updated at {LOG_ON_DEOP}")
        except Exception as _mirror_exc:
            log(job_id, "warn", f"Could not mirror log to {LOG_ON_DEOP}: {_mirror_exc}")

        wait_for_file(job_log_path, job_id, step_name="STEP 2 - log verification")
        log(job_id, "ok", f"{C.BGREEN}STEP 2 - Log extracted and cleaned{C.RESET}")

        # -- STEP 3 -- log -> JSON ----------------------------------------------
        log(job_id, "step", f"{C.BOLD}STEP 3/6{C.RESET} - Converting log -> JSON")
        set_stage(job_id, STAGE_JSON,
                  "Parsing and converting raw assessment log to structured JSON...",
                  progress=70)
        json_conversion_started = time.time()
        converter_output = run_with_stage_heartbeat(
            ["python3", JSON_CONVERTER, job_log_path, job_json_path],
            job_id, STAGE_JSON, 75, timeout=JSON_TIMEOUT,
            step_name="STEP 3 (claude_log_to_json.py)", interval=8,
            extra_env={"LOG_PATH": job_log_path, "JSON_PATH": job_json_path})
        wait_for_json_file(
            job_json_path, job_id,
            step_name="STEP 3 - JSON verification",
            retries=JSON_VERIFY_RETRIES, delay=JSON_VERIFY_DELAY,
            newer_than=max(0, json_conversion_started - 5),
            converter_output=converter_output)
        validate_json_file(job_json_path, job_id)
        remote_json_path = f"{SOC_SAMPLES_DIR.rstrip('/')}/{os.path.basename(job_json_path)}"
        log(job_id, "ok", f"{C.BGREEN}STEP 3 - JSON ready{C.RESET}")

        # -- STEP 4 -- rsync JSON -> SOC ----------------------------------------
        log(job_id, "step", f"{C.BOLD}STEP 4/6{C.RESET} - Sending JSON to SOC {C.BYELLOW}{SOC_HOST}{C.RESET}")
        set_stage(job_id, STAGE_SEND_SOC,
                  f"Transmitting structured findings to SOC machine ({SOC_HOST})...",
                  progress=78)
        run_with_stage_heartbeat(
            ["rsync", "-avz", "--progress", job_json_path, f"{SOC_USER}@{SOC_HOST}:{SOC_SAMPLES_DIR}/"],
            job_id, STAGE_SEND_SOC, 82, timeout=TRANSFER_TIMEOUT, step_name="STEP 4 (rsync JSON -> SOC)", interval=8)
        log(job_id, "ok", f"{C.BGREEN}STEP 4 - JSON delivered{C.RESET}")

        # -- STEP 5 -- SSH run_soc.py ------------------------------------------
        log(job_id, "step", f"{C.BOLD}STEP 5/6{C.RESET} - SOC Analysis on {C.BYELLOW}{SOC_HOST}{C.RESET}")
        set_stage(job_id, STAGE_SOC_RUN,
                  "SOC Analysis Agent generating professional security report...",
                  progress=85)
        remote_soc_cmd = build_remote_soc_command(job_id, remote_json_path, remote_docx_path)
        run_with_stage_heartbeat(
            [
                "ssh", "-T",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=20",
                "-o", "BatchMode=yes",
                f"{SOC_USER}@{SOC_HOST}",
                remote_soc_cmd,
            ],
            job_id, STAGE_SOC_RUN, 92, timeout=SOC_TIMEOUT, step_name="STEP 5 (SSH run_soc.py)", interval=10)
        log(job_id, "ok", f"{C.BGREEN}STEP 5 - SOC report generated{C.RESET}")

        # -- STEP 6 -- rsync DOCX <- SOC ---------------------------------------
        log(job_id, "step", f"{C.BOLD}STEP 6/6{C.RESET} - Fetching DOCX from {C.BYELLOW}{SOC_HOST}{C.RESET}")
        set_stage(job_id, STAGE_FETCH_DOC,
                  "Retrieving completed DOCX report from SOC machine...", progress=92)
        run_with_stage_heartbeat(
            ["rsync", "-avz", "--progress", f"{SOC_USER}@{SOC_HOST}:{remote_docx_path}", expected_docx_path],
            job_id, STAGE_FETCH_DOC, 99, timeout=TRANSFER_TIMEOUT, step_name="STEP 6 (rsync DOCX <- SOC)", interval=8)

        wait_for_file(expected_docx_path, job_id, step_name="STEP 6 - DOCX verification", retries=3, delay=2)
        log(job_id, "ok", f"{C.BGREEN}STEP 6 - Report ready: {report_filename}{C.RESET}")

        # -- DONE -------------------------------------------------------------
        with JOBS_LOCK:
            jobs[job_id].update({
                "status": "completed", "stage": STAGE_DONE,
                "message": "All stages complete. Your security report is ready.",
                "progress": 100, "docx_path": expected_docx_path,
                "report_filename": report_filename,
                "error": None, "updated_at": time.time(),
            })
            snapshot = dict(jobs[job_id])
        _sse_push(job_id, snapshot)
        persist_jobs()
        log_success(f"PIPELINE COMPLETE  |  job={job_id[:8]}  |  {report_filename}")

    except Exception as exc:
        msg = str(exc)
        log_fail(f"PIPELINE FAILED - {msg}")
        with JOBS_LOCK:
            failed_stage = jobs.get(job_id, {}).get("stage") or STAGE_FAILED
            jobs[job_id].update({
                "status": "failed", "stage": failed_stage,
                "message": f"Pipeline failed: {msg}",
                "error": msg, "updated_at": time.time(),
            })
            snapshot = dict(jobs[job_id])
        _sse_push(job_id, snapshot)
        persist_jobs()

# EMBEDDED FRONTEND HTML
# Stage config is injected as JSON so the JS is always in sync with Python constants.
STAGE_CONFIG = json.dumps([
    {"key": STAGE_PENTEST,   "label": "Penetration Assessment",        "minPct": 5,   "maxPct": 55},
    {"key": STAGE_COPY_LOG,  "label": "Securing Assessment Log",       "minPct": 58,  "maxPct": 65},
    {"key": STAGE_JSON,      "label": "Structuring Findings",          "minPct": 67,  "maxPct": 75},
    {"key": STAGE_SEND_SOC,  "label": "Transmitting to SOC Agent",     "minPct": 76,  "maxPct": 82},
    {"key": STAGE_SOC_RUN,   "label": "SOC Analysis & Report Generation", "minPct": 83, "maxPct": 92},
    {"key": STAGE_FETCH_DOC, "label": "Retrieving Final Report",       "minPct": 93,  "maxPct": 99},
    {"key": STAGE_DONE,      "label": "Assessment Complete",           "minPct": 100, "maxPct": 100},
])

FRONTEND_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AI Security Assessment Platform</title>
<style>
  /* -- Reset & base -- */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg:        #030b18;
    --bg2:       #071223;
    --bg3:       #0c1e38;
    --border:    #1a3a5c;
    --accent:    #3b82f6;
    --accent2:   #06b6d4;
    --green:     #22c55e;
    --red:       #ef4444;
    --yellow:    #eab308;
    --text:      #e2e8f0;
    --text-dim:  #64748b;
    --text-mid:  #94a3b8;
    --glow:      0 0 24px rgba(59,130,246,0.25);
    --radius:    10px;
  }}

  html, body {{
    height: 100%;
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 14px;
    overflow-x: hidden;
  }}

  /* -- Background grid -- */
  body::before {{
    content: '';
    position: fixed; inset: 0; z-index: 0;
    background-image:
      linear-gradient(rgba(59,130,246,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(59,130,246,0.04) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
  }}

  .wrap {{
    position: relative; z-index: 1;
    min-height: 100vh;
    display: flex; flex-direction: column; align-items: center;
    padding: 48px 24px 80px;
    gap: 32px;
  }}

  /* -- Header -- */
  header {{
    text-align: center;
  }}
  .logo-row {{
    display: flex; align-items: center; justify-content: center; gap: 14px;
    margin-bottom: 8px;
  }}
  .logo-icon {{
    width: 44px; height: 44px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px;
    box-shadow: var(--glow);
  }}
  h1 {{
    font-size: 22px; font-weight: 700; letter-spacing: 0.05em;
    color: var(--text);
  }}
  .subtitle {{
    color: var(--text-dim); font-size: 12px; letter-spacing: 0.1em;
    text-transform: uppercase;
  }}

  /* -- Card -- */
  .card {{
    width: 100%; max-width: 620px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 28px 28px;
    box-shadow: 0 4px 40px rgba(0,0,0,0.5);
  }}

  /* -- Input panel -- */
  .section-label {{
    font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase;
    color: var(--text-dim); margin-bottom: 10px;
  }}
  .target-row {{
    display: flex; gap: 10px;
  }}
  .target-row input {{
    flex: 1;
    background: var(--bg3); border: 1px solid var(--border);
    border-radius: 6px; color: var(--text);
    font-family: inherit; font-size: 14px;
    padding: 10px 14px; outline: none;
    transition: border-color .2s;
  }}
  .target-row input:focus {{
    border-color: var(--accent);
    box-shadow: 0 0 0 2px rgba(59,130,246,0.15);
  }}
  .target-row input::placeholder {{ color: var(--text-dim); }}

  .btn {{
    padding: 10px 22px;
    border-radius: 6px; border: none; cursor: pointer;
    font-family: inherit; font-size: 13px; font-weight: 600;
    letter-spacing: 0.04em; transition: all .15s;
  }}
  .btn-primary {{
    background: var(--accent);
    color: #fff;
    box-shadow: 0 0 16px rgba(59,130,246,0.3);
  }}
  .btn-primary:hover {{ background: #2563eb; box-shadow: 0 0 24px rgba(59,130,246,0.5); }}
  .btn-primary:disabled {{ opacity: .4; cursor: not-allowed; }}
  .btn-success {{
    background: var(--green);
    color: #fff;
    box-shadow: 0 0 16px rgba(34,197,94,0.3);
  }}
  .btn-success:hover {{ background: #16a34a; }}

  /* -- Active target banner -- */
  .target-banner {{
    display: none;
    align-items: center;
    gap: 8px;
    margin-bottom: 18px;
    padding: 8px 14px;
    background: rgba(59,130,246,0.08);
    border: 1px solid rgba(59,130,246,0.25);
    border-radius: 6px;
    font-size: 12px; color: var(--accent2);
  }}
  .target-banner .dot {{
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--accent2);
    animation: pulse 1.4s infinite;
  }}

  /* -- Stage list -- */
  .stages {{
    list-style: none;
    display: flex; flex-direction: column; gap: 10px;
    margin-bottom: 22px;
  }}
  .stages li {{
    display: flex; align-items: center; gap: 12px;
    padding: 10px 14px;
    border-radius: 8px;
    border: 1px solid transparent;
    transition: all .3s;
    opacity: .55;
  }}
  .stages li.stage-done {{
    opacity: 1;
    border-color: rgba(34,197,94,0.2);
    background: rgba(34,197,94,0.04);
  }}
  .stages li.stage-active {{
    opacity: 1;
    border-color: rgba(59,130,246,0.4);
    background: rgba(59,130,246,0.08);
    box-shadow: 0 0 12px rgba(59,130,246,0.1);
  }}
  .stages li.stage-failed {{
    opacity: 1;
    border-color: rgba(239,68,68,0.45);
    background: rgba(239,68,68,0.08);
  }}
  .stages li.stage-pending {{ opacity: .55; }}

  .stage-icon {{
    width: 28px; height: 28px; flex-shrink: 0;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 13px;
    border: 1px solid var(--border);
    background: var(--bg3);
    transition: all .3s;
  }}
  .stage-done .stage-icon {{
    background: rgba(34,197,94,0.15);
    border-color: var(--green);
    color: var(--green);
  }}
  .stage-active .stage-icon {{
    background: rgba(59,130,246,0.15);
    border-color: var(--accent);
    animation: spin-ring .9s linear infinite;
  }}
  .stage-failed .stage-icon {{
    background: rgba(239,68,68,0.16);
    border-color: var(--red);
    color: var(--red);
  }}
  .stage-label {{ font-size: 13px; color: var(--text-mid); transition: color .3s; }}
  .stage-active .stage-label {{ color: var(--text); font-weight: 600; }}
  .stage-done  .stage-label {{ color: var(--text); }}
  .stage-failed .stage-label {{ color: #fecaca; font-weight: 600; }}

  /* -- Progress bar -- */
  .progress-wrap {{
    margin-bottom: 14px;
  }}
  .progress-header {{
    display: flex; justify-content: space-between;
    font-size: 11px; color: var(--text-dim);
    margin-bottom: 6px;
  }}
  .progress-track {{
    height: 6px;
    background: var(--bg3);
    border-radius: 99px; overflow: hidden;
  }}
  .progress-fill {{
    height: 100%; width: 0%;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
    border-radius: 99px;
    transition: width .6s cubic-bezier(.4,0,.2,1);
    box-shadow: 0 0 10px rgba(59,130,246,0.5);
  }}

  /* -- Status message ticker -- */
  .ticker {{
    font-size: 11px; color: var(--text-dim);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    margin-bottom: 18px;
    min-height: 18px;
  }}
  .ticker::before {{ content: '> '; color: var(--accent); }}

  /* -- Download / Error -- */
  .download-row {{ display: none; justify-content: center; margin-top: 6px; }}
  .error-banner {{
    display: none;
    margin-top: 12px;
    padding: 10px 14px;
    background: rgba(239,68,68,0.08);
    border: 1px solid rgba(239,68,68,0.3);
    border-radius: 6px;
    font-size: 12px; color: #fca5a5;
  }}
  .stale-banner {{
    display: none;
    margin-top: 8px;
    padding: 8px 12px;
    background: rgba(234,179,8,0.08);
    border: 1px solid rgba(234,179,8,0.25);
    border-radius: 6px;
    font-size: 11px; color: var(--yellow);
  }}

  /* -- Health pill -- */
  .health {{
    font-size: 11px; color: var(--text-dim);
    display: flex; align-items: center; gap: 6px;
  }}
  .health-dot {{
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--green);
    animation: pulse 2s infinite;
  }}

  /* -- Animations -- */
  @keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50%       {{ opacity: .35; }}
  }}
  @keyframes spin-ring {{
    to {{ transform: rotate(360deg); }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <!-- Header -->
  <header>
    <div class="logo-row">
      <div class="logo-icon"></div>
      <h1>AI Security Assessment</h1>
    </div>
    <div class="subtitle">Autonomous Penetration Testing &amp; SOC Analysis Platform</div>
  </header>

  <!-- Input card -->
  <div class="card" id="inputCard">
    <div class="section-label">Target</div>
    <div class="target-row">
      <input id="targetInput" type="text"
             placeholder="111.111.111.111"
             autocomplete="off" spellcheck="false"/>
      <button class="btn btn-primary" id="startBtn" onclick="startAssessment()">
        Launch
      </button>
    </div>
    <div class="error-banner" id="startErrorBanner"></div>
  </div>

  <!-- Progress card (hidden until assessment starts) -->
  <div class="card" id="progressCard" style="display:none">

    <!-- Active target banner -->
    <div class="target-banner" id="targetBanner">
      <span class="dot"></span>
      ACTIVE TARGET: <strong id="activeTarget"></strong>
    </div>

    <!-- Stage list (generated by JS from STAGE_CONFIG) -->
    <ul class="stages" id="stageList"></ul>

    <!-- Progress bar -->
    <div class="progress-wrap">
      <div class="progress-header">
        <span>Assessment Progress</span>
        <span id="progressLabel">0%</span>
      </div>
      <div class="progress-track">
        <div class="progress-fill" id="progressFill"></div>
      </div>
    </div>

    <!-- Ticker -->
    <div class="ticker" id="ticker">Initialising...</div>

    <!-- Download button -->
    <div class="download-row" id="downloadRow">
      <button class="btn btn-success" id="downloadBtn" onclick="downloadReport()">
        Download Security Report
      </button>
    </div>

    <!-- Error banner -->
    <div class="error-banner" id="errorBanner"></div>

    <!-- Stale banner -->
    <div class="stale-banner" id="staleBanner">
      No update from backend in 120s. Check server logs.
    </div>
  </div>

  <!-- Health indicator -->
  <div class="health">
    <span class="health-dot"></span>
    Backend online - v6.1
  </div>

</div>

<script>
// --- Stage config injected from Python (single source of truth) -----------
const STAGES = {STAGE_CONFIG};

// --- State ----------------------------------------------------------------
let _jobId       = null;
let _pollTimer   = null;
let _sseSource   = null;
let _sseReconnectTimer = null;
let _lastUpdated = Date.now();
let _staleTimer  = null;
let _lastStage   = null;
let _done        = false;
const STALE_AFTER_MS = {STALE_AFTER_MS};
const AUTH_ENABLED = {str(bool(API_KEY)).lower()};
const API_KEY_STORAGE = 'gp2AppApiKey';

// --- Build stage list DOM -------------------------------------------------
(function buildStageList() {{
  const ul = document.getElementById('stageList');
  STAGES.forEach(s => {{
    const li = document.createElement('li');
    li.dataset.stage = s.key;
    li.className = 'stage-pending';
    li.innerHTML = `
      <span class="stage-icon">o</span>
      <span class="stage-label">${{s.label}}</span>`;
    ul.appendChild(li);
  }});
}})();

// --- Start assessment -----------------------------------------------------
function currentApiKey() {{
  if (!AUTH_ENABLED) return '';
  return (localStorage.getItem(API_KEY_STORAGE) || '').trim();
}}

function promptApiKey(force = false) {{
  if (!AUTH_ENABLED) return '';
  let key = currentApiKey();
  if (!key || force) {{
    key = (window.prompt('Enter the assessment platform API key') || '').trim();
    if (key) localStorage.setItem(API_KEY_STORAGE, key);
  }}
  return key;
}}

function authHeaders(base = {{}}) {{
  const key = promptApiKey(false);
  return key ? {{...base, 'X-API-Key': key}} : base;
}}

function authQuery() {{
  const key = currentApiKey();
  return AUTH_ENABLED && key ? `?api_key=${{encodeURIComponent(key)}}` : '';
}}

async function fetchWithAuth(url, options = {{}}) {{
  const firstOptions = {{...options, headers: authHeaders(options.headers || {{}})}};
  let res = await fetch(url, firstOptions);
  if (res.status === 401 && AUTH_ENABLED) {{
    localStorage.removeItem(API_KEY_STORAGE);
    const key = promptApiKey(true);
    if (key) {{
      res = await fetch(url, {{...options, headers: {{...(options.headers || {{}}), 'X-API-Key': key}}}});
    }}
  }}
  return res;
}}

async function startAssessment() {{
  const target = document.getElementById('targetInput').value.trim();
  if (!target) {{ showError('Please enter a target IP or hostname.'); return; }}

  clearError();
  document.getElementById('downloadRow').style.display = 'none';
  document.getElementById('startBtn').disabled = true;

  try {{
    const res = await fetchWithAuth('/api/start', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{ target, mode: 'ip' }}),
    }});
    if (!res.ok) {{ throw new Error(await readApiError(res)); }}
    const data = await res.json();
    _jobId = data.job_id;
    _done = false;
    _lastStage = null;

    document.getElementById('inputCard').style.display   = 'none';
    document.getElementById('progressCard').style.display = 'block';
    document.getElementById('activeTarget').textContent   = target;
    document.getElementById('targetBanner').style.display = 'flex';

    applyUpdate(data);
    connectSSE();          // push updates via SSE
    startPollingFallback(); // polling fallback (takes over if SSE closes)
    startStaleWatcher();

  }} catch (err) {{
    document.getElementById('startBtn').disabled = false;
    showError('Failed to start: ' + err.message);
  }}
}}

// --- SSE (Server-Sent Events) - instant push from backend -----------------
function connectSSE() {{
  if (!_jobId || _done) return;
  clearTimeout(_sseReconnectTimer);
  if (_sseSource) {{ _sseSource.close(); }}
  _sseSource = new EventSource(`/api/stream/${{_jobId}}${{authQuery()}}`);
  _sseSource.onmessage = e => {{
    try {{ applyUpdate(JSON.parse(e.data)); }} catch(_) {{}}
  }};
  _sseSource.onerror = () => {{
    // SSE dropped - polling fallback is already running
    _sseSource.close();
    _sseSource = null;
    if (!_done && _jobId) {{
      clearTimeout(_sseReconnectTimer);
      _sseReconnectTimer = setTimeout(connectSSE, 3000);
    }}
  }};
}}

// --- Polling fallback -----------------------------------------------------
function startPollingFallback() {{
  clearInterval(_pollTimer);
  _pollTimer = setInterval(async () => {{
    if (!_jobId || _done) return;
    try {{
      const res  = await fetchWithAuth(`/api/status/${{_jobId}}`);
      if (!res.ok) return;
      const data = await res.json();
      applyUpdate(data);
    }} catch(_) {{}}
  }}, 4000);
}}

function stopAll() {{
  clearInterval(_pollTimer);
  clearTimeout(_sseReconnectTimer);
  clearInterval(_staleTimer);
  if (_sseSource) {{ _sseSource.close(); _sseSource = null; }}
}}

async function readApiError(res) {{
  try {{
    const e = await res.json();
    if (Array.isArray(e.details) && e.details.length) {{
      return `${{e.error || `HTTP ${{res.status}}`}} ${{e.details.join(' ')}}`;
    }}
    return e.error || `HTTP ${{res.status}}`;
  }} catch (_) {{
    return `HTTP ${{res.status}}`;
  }}
}}

// --- Stale watcher --------------------------------------------------------
function startStaleWatcher() {{
  clearInterval(_staleTimer);
  _staleTimer = setInterval(() => {{
    if (_done) return;
    if (Date.now() - _lastUpdated > STALE_AFTER_MS) {{
      document.getElementById('staleBanner').style.display = 'block';
    }}
  }}, 5000);
}}

// --- Apply state update from backend -------------------------------------
function applyUpdate(data) {{
  if (!data) return;
  if (_done) return;

  _lastUpdated = Date.now();
  document.getElementById('staleBanner').style.display = 'none';

  const stage = data.stage || _lastStage || STAGES[0].key;
  if (stage && stage !== 'failed') _lastStage = stage;

  updateProgressBar(data.progress);
  updateStageList(stage, data.status);
  updateTicker(data.message);

  if (data.status === 'completed') {{
    _done = true;
    stopAll();
    showCompletion(data.report_filename);
  }} else if (data.status === 'failed') {{
    _done = true;
    stopAll();
    showError('Assessment failed: ' + (data.error || data.message));
  }}
}}

// --- UI helpers -----------------------------------------------------------
function updateProgressBar(pct) {{
  const p = Math.min(100, Math.max(0, pct || 0));
  document.getElementById('progressFill').style.width = p + '%';
  document.getElementById('progressLabel').textContent = p + '%';
}}

function updateStageList(currentStage, status) {{
  const keys = STAGES.map(s => s.key);
  const effectiveStage = currentStage === 'failed' ? (_lastStage || keys[0]) : currentStage;
  const ci   = Math.max(0, keys.indexOf(effectiveStage));
  STAGES.forEach((s, i) => {{
    const el = document.querySelector(`[data-stage="${{s.key}}"]`);
    if (!el) return;
    el.className = '';
    const icon = el.querySelector('.stage-icon');
    if (status === 'completed' || currentStage === 'completed' || i < ci) {{
      el.classList.add('stage-done');
      icon.textContent = 'OK';
    }} else if (status === 'failed' && i === ci) {{
      el.classList.add('stage-failed');
      icon.textContent = '!';
    }} else if (i === ci) {{
      el.classList.add('stage-active');
      icon.textContent = 'o';
    }} else {{
      el.classList.add('stage-pending');
      icon.textContent = 'o';
    }}
  }});
}}

function updateTicker(msg) {{
  if (msg) document.getElementById('ticker').textContent = msg;
}}

function showCompletion(filename) {{
  updateProgressBar(100);
  updateStageList('completed', 'completed');
  updateTicker('Assessment complete. Your security report is ready for download.');
  document.getElementById('downloadRow').style.display = 'flex';
  if (filename) document.getElementById('downloadBtn').title = filename;
}}

function showError(msg) {{
  const progressVisible = document.getElementById('progressCard').style.display !== 'none';
  const el = document.getElementById(progressVisible ? 'errorBanner' : 'startErrorBanner');
  el.textContent = msg;
  el.style.display = 'block';
}}

function clearError() {{
  ['errorBanner', 'startErrorBanner'].forEach(id => {{
    const el = document.getElementById(id);
    if (el) {{
      el.textContent = '';
      el.style.display = 'none';
    }}
  }});
}}

function downloadReport() {{
  if (!_jobId) return;
  promptApiKey(false);
  window.location.href = `/api/download/${{_jobId}}${{authQuery()}}`;
}}

// --- Allow Enter key to start ---------------------------------------------
document.getElementById('targetInput').addEventListener('keydown', e => {{
  if (e.key === 'Enter') startAssessment();
}});
</script>
</body>
</html>"""

# FLASK ROUTES

@app.route("/", methods=["GET"])
def index():
    """Serve the full UI."""
    return Response(FRONTEND_HTML, mimetype="text/html")


@app.route("/api/start", methods=["POST"])
def api_start():
    data   = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body must be an object."}), 400

    target, target_error = validate_target(data.get("target"))
    mode = str(data.get("mode") or "ip").strip() or "ip"

    if target_error:
        return jsonify({"error": target_error}), 400

    problems = preflight_checks()
    if problems:
        return jsonify({
            "error": "Server preflight check failed.",
            "details": problems,
        }), 503

    job_id = str(uuid.uuid4())
    with JOBS_LOCK:
        jobs[job_id] = {
            "job_id": job_id, "target": target, "mode": mode,
            "status": "queued", "stage": STAGE_PENTEST,
            "message": "Assessment queued - pipeline starting...",
            "progress": 3, "docx_path": None,
            "report_filename": None, "error": None,
            "created_at": time.time(), "updated_at": time.time(),
        }
        snapshot = dict(jobs[job_id])
    with SSE_LOCK:
        sse_subscribers[job_id] = []
    persist_jobs()

    threading.Thread(
        target=assessment_pipeline, args=(job_id, target, mode),
        daemon=True, name=f"assessment-{job_id[:8]}",
    ).start()

    log(job_id, "info", f"Job queued -> {C.BYELLOW}target={target}{C.RESET}")
    return jsonify(_status_payload(snapshot)), 202


@app.route("/api/stream/<job_id>", methods=["GET"])
def api_stream(job_id):
    """
    SSE endpoint - pushes JSON state updates to the browser instantly.
    Browser connects once; backend pushes whenever state changes.
    """
    with JOBS_LOCK:
        if job_id not in jobs:
            return jsonify({"error": "Job not found."}), 404

    q = queue.Queue(maxsize=64)
    with SSE_LOCK:
        sse_subscribers.setdefault(job_id, []).append(q)
    with JOBS_LOCK:
        # Send current state immediately so browser doesn't wait for next change
        snapshot = dict(jobs[job_id])

    def generate():
        # Push current state right away
        yield f"data: {json.dumps(_status_payload(snapshot))}\n\n"

        try:
            while True:
                try:
                    payload = q.get(timeout=25)
                    yield f"data: {payload}\n\n"
                    # Stop streaming once terminal state reached
                    data = json.loads(payload)
                    if data.get("status") in ("completed", "failed"):
                        break
                except queue.Empty:
                    with JOBS_LOCK:
                        current = jobs.get(job_id)
                        if not current:
                            break
                        heartbeat_payload = json.dumps(_status_payload(dict(current)))
                    yield f"data: {heartbeat_payload}\n\n"
                    if current.get("status") in ("completed", "failed"):
                        break
        finally:
            with SSE_LOCK:
                try:
                    sse_subscribers.get(job_id, []).remove(q)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/status/<job_id>", methods=["GET"])
def api_status(job_id):
    """Polling fallback - returns current job state as JSON."""
    with JOBS_LOCK:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found."}), 404
        snapshot = dict(job)

    return jsonify(_status_payload(snapshot))


@app.route("/api/download/<job_id>", methods=["GET"])
def api_download(job_id):
    with JOBS_LOCK:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found."}), 404
        snapshot = dict(job)

    if snapshot["status"] != "completed":
        return jsonify({"error": f"Report not ready - stage: {snapshot['stage']}"}), 425

    docx_path = snapshot.get("docx_path")
    if not docx_path or not os.path.exists(docx_path):
        return jsonify({"error": f"Report file not found in {REPORT_LOCAL_DIR}/"}), 404
    if not path_is_inside(docx_path, REPORT_LOCAL_DIR):
        log(job_id, "error", f"Blocked report path outside report dir: {docx_path}")
        return jsonify({"error": "Invalid report path."}), 500

    safe = safe_filename(snapshot["target"]).replace(".", "_")
    download_name = f"Security_Assessment_{safe}.docx"
    log(job_id, "info", f"Serving download -> {download_name}")

    return send_file(
        docx_path, as_attachment=True, download_name=download_name,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


@app.route("/api/health", methods=["GET"])
def api_health():
    with JOBS_LOCK:
        job_count = len(jobs)
    preflight = preflight_checks()
    return jsonify({
        "status": "ok" if not preflight else "degraded",
        "version": "6.1.0", "jobs": job_count,
        "auth": "enabled" if API_KEY else "disabled",
        "allow_private_targets": ALLOW_PRIVATE_TARGETS,
        "allow_local_targets": ALLOW_LOCAL_TARGETS,
        "allow_remote_latest_fallback": ALLOW_REMOTE_LATEST_FALLBACK,
        "preflight": preflight,
        "paths": {
            "pentest_script": PENTEST_SCRIPT,
            "json_converter": JSON_CONVERTER,
            "log_path":       LOG_ON_DEOP,
            "json_dir":       GENERATED_LOGS_DIR,
            "job_store":      JOB_STORE_PATH,
            "report_dir":     REPORT_LOCAL_DIR,
            "soc":            f"{SOC_USER}@{SOC_HOST}",
        },
    })


# STARTUP
if __name__ == "__main__":
    os.makedirs(GENERATED_LOGS_DIR, exist_ok=True)
    os.makedirs(REPORT_LOCAL_DIR,   exist_ok=True)
    load_jobs_from_disk()

    print("")
    print(f"{C.BOLD}AI Security Assessment Platform - v6.1{C.RESET}")
    print(f"Open: {C.CYAN}http://localhost:5000{C.RESET}")
    print("")
    print(f"{C.BOLD}{C.BYELLOW}Pentest Duration:{C.RESET} {PENTEST_DURATION_MINUTES} minute(s)  "
          f"({C.DIM}edit PENTEST_DURATION_MINUTES in source to change{C.RESET})")
    print(f"  Timeout    : {PENTEST_TIMEOUT}s  |  Min runtime: {PENTEST_MIN_RUNTIME}s  |  Idle grace: {PENTEST_IDLE_TIMEOUT}s")
    print("")
    print("Using:")
    print(f"  Pentest script : {PENTEST_SCRIPT}")
    print(f"  JSON converter : {JSON_CONVERTER}")
    print(f"  Logs folder    : {GENERATED_LOGS_DIR}")
    print(f"  Reports folder : {REPORT_LOCAL_DIR}")
    print(f"  SOC machine    : {SOC_USER}@{SOC_HOST}")
    print("")
    print("Stages:")
    print("  1. Penetration Assessment")
    print("  2. Securing Assessment Log")
    print("  3. Structuring Findings")
    print("  4. Transmitting to SOC Agent")
    print("  5. SOC Analysis and Report Generation")
    print("  6. Retrieving Final Report")
    print("")
    print("Fix in v6.1: SSH command now cd's into SOC script directory")
    print("             before invoking python3, fixing relative imports.")
    print("")
    print("Updates: SSE with polling backup every 4 seconds")
    print("")

    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
