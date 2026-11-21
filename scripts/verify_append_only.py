#!/usr/bin/env python3
"""Block mutation/removal of any previously published QA or release content."""
import subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def cmd(*args):
    p=subprocess.run(["git","-C",str(ROOT),*args],capture_output=True,check=False)
    if p.returncode:raise RuntimeError("Git comparison failed")
    return p.stdout
def verify(base):
    if not base or base.strip("0")=="":
        raise RuntimeError("Missing git history baseline")
    cmd("rev-parse","--verify",base+"^{commit}")
    output=cmd("diff","--name-status","-z","--no-renames",base,"HEAD","--","releases","qa")
    parts=output.split(b"\x00")
    if parts[-1:]==[b""]:parts.pop()
    if len(parts)%2:raise RuntimeError("Malformed git name-status response")
    for status,path in zip(parts[::2],parts[1::2]):
        p=path.decode("utf8",errors="strict")
        if status!=b"A":
            raise RuntimeError("Previously published immutable content was altered: "+p)
    print("Existing versioned release and QA paths are append-only")
if __name__=="__main__":
    try:
        if len(sys.argv)!=2:raise RuntimeError("Usage: verify_append_only.py BASE_COMMIT")
        verify(sys.argv[1])
    except (RuntimeError,OSError,UnicodeError) as error:
        print("APPEND-ONLY VERIFICATION FAILED:",error,file=sys.stderr)
        sys.exit(1)
