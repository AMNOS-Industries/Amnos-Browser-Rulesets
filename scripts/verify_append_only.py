#!/usr/bin/env python3
"""Block mutation/removal of any previously published QA or release content."""
import json, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def cmd(*args):
    p=subprocess.run(["git","-C",str(ROOT),*args],capture_output=True,check=False)
    if p.returncode:raise RuntimeError("Git comparison failed")
    return p.stdout
def git_file(revision, path):
    check = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", f"{revision}:{path}"],
                           capture_output=True, check=False)
    if check.returncode:
        return None
    return cmd("show", f"{revision}:{path}")

def parse_manifest_sequence(data):
    if data is None:
        return None
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise RuntimeError("Duplicate manifest field")
            result[name] = value
        return result
    try:
        record = json.loads(data.decode("utf8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("Invalid Git-tracked signed manifest JSON") from error
    if not isinstance(record, dict):
        raise RuntimeError("Unexpected signed manifest JSON")
    value = record.get("ruleset_version")
    if type(value) is not int or value <= 0:
        raise RuntimeError("Invalid signed manifest sequence")
    return value

def verify(base):
    if not base or base.strip("0")=="":
        raise RuntimeError("Missing git history baseline")
    cmd("rev-parse","--verify",base+"^{commit}")
    output=cmd("diff","--name-status","-z","--no-renames",base,"HEAD","--","releases","qa","release-evidence","trust","compliance/licenses")
    parts=output.split(b"\x00")
    if parts[-1:]==[b""]:parts.pop()
    if len(parts)%2:raise RuntimeError("Malformed git name-status response")
    for status,path in zip(parts[::2],parts[1::2]):
        p=path.decode("utf8",errors="strict")
        if status!=b"A":
            raise RuntimeError("Previously published immutable content was altered: "+p)
    prior = git_file(base, "latest.manifest.json")
    current = git_file("HEAD", "latest.manifest.json")
    old_sequence = parse_manifest_sequence(prior)
    new_sequence = parse_manifest_sequence(current)
    if old_sequence is not None:
        if new_sequence is None:
            raise RuntimeError("Previously published signed manifest was removed")
        if current != prior and new_sequence <= old_sequence:
            raise RuntimeError("Signed production manifest sequence must strictly increase")
    print("Previously published signed releases, QA fixtures, trust and license evidence are append-only")
    print("Signed production manifest sequence is monotonic")
if __name__=="__main__":
    try:
        if len(sys.argv)!=2:raise RuntimeError("Usage: verify_append_only.py BASE_COMMIT")
        verify(sys.argv[1])
    except (RuntimeError,OSError,UnicodeError) as error:
        print("APPEND-ONLY VERIFICATION FAILED:",error,file=sys.stderr)
        sys.exit(1)
