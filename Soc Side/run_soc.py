from __future__ import annotations

import os
import sys
import time
import json
import shutil
from pathlib import Path

from dotenv import load_dotenv

SOC_BASE = Path("'your path'/soc_side")
load_dotenv(SOC_BASE / ".env")

WATCH_DIR_DEFAULT = SOC_BASE / "samples"
INTAKE_DIR = SOC_BASE / "logs" / "intake"
EXPORT_DIR = SOC_BASE / "public_reports"
DOCX_DIR = SOC_BASE / "reports" / "docx"


def safe_stem(path: Path) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in path.stem)[:80] or "run"


def save_raw_to_intake(raw_json_path: Path, run_id: str) -> Path:
    """Copy the raw JSON into intake/ as the working copy for the pipeline."""
    INTAKE_DIR.mkdir(parents=True, exist_ok=True)
    intake_path = INTAKE_DIR / f"{run_id}.json"
    shutil.copy2(raw_json_path, intake_path)
    print(f"[+] Raw intake saved: {intake_path}")
    return intake_path


def move_to_processed(raw_json_path: Path, watch_dir: Path) -> Path:
    """Move the original file into samples/processed/ after a successful run."""
    processed_dir = watch_dir / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)
    dest = processed_dir / raw_json_path.name
    # avoid collision if a file with the same name already exists
    if dest.exists():
        stem = raw_json_path.stem
        suffix = raw_json_path.suffix
        dest = processed_dir / f"{stem}_{int(time.time())}{suffix}"
    shutil.move(str(raw_json_path), str(dest))
    print(f"[+] Moved to processed: {dest}")
    return dest


def move_to_failed(raw_json_path: Path, watch_dir: Path) -> Path:
    """Move the original file into samples/failed/ after a failed run."""
    failed_dir = watch_dir / "failed"
    failed_dir.mkdir(parents=True, exist_ok=True)
    dest = failed_dir / raw_json_path.name
    if dest.exists():
        stem = raw_json_path.stem
        suffix = raw_json_path.suffix
        dest = failed_dir / f"{stem}_{int(time.time())}{suffix}"
    shutil.move(str(raw_json_path), str(dest))
    print(f"[!] Moved to failed: {dest}")
    return dest


def wait_for_report(run_id: str, timeout_seconds: int = 300) -> Path:
    deadline = time.time() + timeout_seconds
    report_path = DOCX_DIR / f"{run_id}_report.docx"

    while time.time() < deadline:
        if report_path.exists() and report_path.stat().st_size > 0:
            print(f"[+] Report ready: {report_path}")
            return report_path
        time.sleep(2)

    raise TimeoutError(f"Timed out waiting for DOCX report for run_id={run_id}")


def export_report(report_path: Path, output_path: Path | None = None) -> Path:
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(report_path, output_path)
        print(f"[+] Copied final report to: {output_path}")
        return output_path

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EXPORT_DIR / report_path.name
    shutil.copy2(report_path, out_path)
    print(f"[+] Exported for UI download: {out_path}")
    return out_path


def process_raw_json(
    raw_json_path: Path,
    explicit_output: Path | None = None,
    watch_dir: Path | None = None,
) -> int:
    """
    Full pipeline for one JSON file.
    - Copies to intake/ for the pipeline to consume.
    - On success: moves original to samples/processed/
    - On failure: moves original to samples/failed/
    No file is ever touched in processed/ or failed/ before the outcome is known.
    """
    if not raw_json_path.exists():
        raise FileNotFoundError(f"JSON file not found: {raw_json_path}")

    raw = json.loads(raw_json_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Top-level JSON must be an object")

    run_id = safe_stem(raw_json_path)
    _watch_dir = watch_dir or WATCH_DIR_DEFAULT

    # 1) copy into intake/ — this is the pipeline's working copy, not a "processed" archive
    save_raw_to_intake(raw_json_path, run_id)

    # 2) run the SOC pipeline
    from api.process_run import process
    result = process(run_id)
    print(f"[+] SOC process result: {result}")

    # 3) wait for report and export
    report_path = wait_for_report(run_id)
    export_report(report_path, explicit_output)

    # 4) only now that everything succeeded, move original to processed/
    if raw_json_path.exists():
        move_to_processed(raw_json_path, _watch_dir)

    return 0


def watch_folder(folder: Path, poll_seconds: int = 3) -> None:
    print(f"[+] Watching folder: {folder}")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "processed").mkdir(exist_ok=True)
    (folder / "failed").mkdir(exist_ok=True)

    while True:
        json_files = sorted([p for p in folder.glob("*.json") if p.is_file()])

        for json_file in json_files:
            print(f"[+] Found JSON file: {json_file}")
            try:
                process_raw_json(json_file, watch_dir=folder)

            except Exception as e:
                print(f"[!] Processing failed for {json_file.name}: {e}")
                # only move to failed/ if the original still exists in the watch folder
                if json_file.exists():
                    move_to_failed(json_file, folder)

        time.sleep(poll_seconds)


def print_startup_banner() -> None:
    print("=" * 70)
    print(" AI Security Assessment Platform - SOC Automation ")
    print("=" * 70)
    print(f"[+] Watch folder         : {WATCH_DIR_DEFAULT}")
    print(f"[+] Processed folder     : {WATCH_DIR_DEFAULT / 'processed'}")
    print(f"[+] Failed folder        : {WATCH_DIR_DEFAULT / 'failed'}")
    print(f"[+] Intake folder        : {INTAKE_DIR}")
    print(f"[+] DOCX export folder   : {EXPORT_DIR}")
    print(f"[+] Mode                 : RAW JSON direct to process_run")
    print("=" * 70)


def main() -> int:
    try:
        print_startup_banner()

        if len(sys.argv) == 1:
            print("[+] No mode provided. Starting default WATCH mode...")
            watch_folder(WATCH_DIR_DEFAULT)
            return 0

        mode = sys.argv[1].strip().lower()

        if mode == "once":
            if len(sys.argv) < 3:
                print("[-] Missing JSON file path")
                return 1
            raw_json_path = Path(sys.argv[2]).expanduser().resolve()
            output_path = Path(sys.argv[3]).expanduser().resolve() if len(sys.argv) >= 4 else None
            return process_raw_json(raw_json_path, explicit_output=output_path)

        elif mode == "watch":
            folder = Path(sys.argv[2]).expanduser().resolve() if len(sys.argv) >= 3 else WATCH_DIR_DEFAULT
            watch_folder(folder)
            return 0

        else:
            print(f"[-] Unknown mode: {mode}")
            print("Usage:")
            print("  python run_soc.py")
            print("  python run_soc.py once /path/to/raw.json [/path/to/output.docx]")
            print("  python run_soc.py watch /path/to/folder")
            return 1

    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
        return 0
    except Exception as e:
        print(f"[!] Error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
