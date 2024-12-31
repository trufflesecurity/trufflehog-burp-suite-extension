#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional

def redact_secret(redacted: str, secret: str) -> str:
    """Partially redact a secret unless already provided."""
    if redacted:
        return redacted
    length = len(secret)
    if length < 10:
        return "*****"
    return (
        secret[:min(10, int(length * 0.2))] +
        "*****" +
        secret[min(10, int(length * 0.8)):])

def build_raw_secret(raw: str, raw_v2: str) -> str:
    """Combine or return raw secrets appropriately."""
    if not raw_v2 or not raw_v2.strip():
        return raw
    return raw_v2 if raw in raw_v2 else f"{raw}:{raw_v2}"

def custom_print(msg: str, error: bool = False) -> None:
    """Print a message with optional stderr output."""
    if error:
        print(msg, file=sys.stderr, flush=True)
    else:
        print(msg, flush=True)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TruffleHog burp scanner")
    parser.add_argument("--only-verified", action="store_true", help="Only return verified secrets")
    parser.add_argument("--allow-verification-overlap", action="store_true", help="Allow verification overlap")
    parser.add_argument("--tempdir", required=True, help="Temporary directory for scanning")
    parser.add_argument("--trufflehog-path", required=True, help="Path to trufflehog binary")
    return parser.parse_args()

def get_all_files(temp_dir: str) -> List[str]:
    """Get all files in temp_dir."""
    all_files = []
    for root, _, files in os.walk(temp_dir):
        for f in files:
            all_files.append(os.path.join(root, f))
    return all_files

def parse_req_id_from_filename(base: str) -> Optional[str]:
    """Extract req_id from basename like '{req_id}_headers.txt'."""
    parts = base.split("_", 1)
    return parts[0] if len(parts) == 2 else None

def get_req_files(all_files: List[str]) -> Dict[str, List[str]]:
    """Group files by req_id."""
    req_files = {}
    for path in all_files:
        base = os.path.basename(path)
        req_id = parse_req_id_from_filename(base)
        if req_id is not None:
            req_files.setdefault(req_id, []).append(path)
    return req_files

def filter_req_files(req_files: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Only keep req_files with exactly two files: one headers, one body."""
    final_req_files = {}
    for req_id, paths in req_files.items():
        if len(paths) == 2:
            final_req_files[req_id] = paths
    return final_req_files

def create_subdir(temp_dir: str) -> str:
    """Create a subdirectory in temp_dir."""
    return tempfile.mkdtemp(dir=temp_dir)

def move_req_files(final_req_files: Dict[str, List[str]], subdir: str) -> None:
    """Move the final_req_files into the subdirectory."""
    for paths in final_req_files.values():
        for path in paths:
            shutil.move(path, os.path.join(subdir, os.path.basename(path)))

def reverse_move_req_files(final_req_files: Dict[str, List[str]], subdir: str) -> None:
    """Reverse the move_req_files operation."""
    for paths in final_req_files.values():
        for path in paths:
            shutil.move(os.path.join(subdir, os.path.basename(path)), path)

def scan_req_files(final_req_files: Dict[str, List[str]], args: argparse.Namespace, subdir: str) -> Optional[str]:
    """Scan the subdirectory with trufflehog."""
    cmd = [args.trufflehog_path, "filesystem", subdir, "--json"]
    if args.only_verified:
        cmd.append("--only-verified")
    if args.allow_verification_overlap:
        cmd.append("--allow-verification-overlap")
    try:
        return subprocess.check_output(cmd, stderr=subprocess.PIPE, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        custom_print(f"TruffleHog Process Error: Error running trufflehog: {e}", error=True)
        reverse_move_req_files(final_req_files, subdir)
        return None

def get_req_id_from_metadata(metadata: dict) -> Optional[str]:
    """Extract req_id from metadata."""
    file_meta = metadata.get("SourceMetadata", {}) \
                       .get("Data", {}) \
                       .get("Filesystem", {}) \
                       .get("file", "")
    base = os.path.basename(file_meta)
    return parse_req_id_from_filename(base)

def build_result_obj(res: dict) -> dict:
    """Build a result object from the trufflehog JSON output."""
    raw = build_raw_secret(res.get("Raw", ""), res.get("RawV2", ""))
    redacted = redact_secret(res.get("Redacted", ""), raw)
    return {
        "secretType": res.get("DetectorName", ""),
        "raw": raw,
        "redacted": redacted,
        "decoderType": res.get("DecoderName", ""),
        "verified": res.get("Verified", False),
        "extraData": res.get("ExtraData", {}),
        "detectorDescription": res.get("DetectorDescription", "")
    }

def parse_results(output: str, args: argparse.Namespace) -> Dict[str, List[dict]]:
    """Parse the trufflehog output into a dictionary of results by req_id."""
    results_by_req_id = {}
    for line in output.strip().split("\n"):
        try:
            res = json.loads(line)
        except json.JSONDecodeError:
            continue
        req_id = get_req_id_from_metadata(res)
        if req_id is None:
            continue
        # Skip if only_verified is true and the secret is not verified
        if args.only_verified and not res.get("Verified", False):
            print(f"Skipping {req_id} because it is not verified")
            continue
        results_by_req_id.setdefault(req_id, []).append(build_result_obj(res))
    return results_by_req_id

def main() -> None:
    """Main sleeps, looks for new files, scans them with trufflehog, and loops forever."""
    custom_print("TruffleHog Secret Scanner Started!")
    args = parse_args()

    while True:
        time.sleep(10)
        all_files = get_all_files(args.tempdir)
        req_files = get_req_files(all_files)
        final_req_files = filter_req_files(req_files)
        if not final_req_files:
            continue

        subdir = create_subdir(args.tempdir)
        move_req_files(final_req_files, subdir)
        output = scan_req_files(final_req_files, args, subdir)
        shutil.rmtree(subdir)

        # If trufflehog fails, continue
        if output is None:
            continue

        # Parse results
        results_by_req_id = parse_results(output, args)
        
        for req_id in final_req_files:
            print(json.dumps({
                "id": req_id,
                "results": results_by_req_id.get(req_id, [])
            }), flush=True)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        custom_print(f"Fatal Error in main: {e}", error=True)
        sys.exit(1)
