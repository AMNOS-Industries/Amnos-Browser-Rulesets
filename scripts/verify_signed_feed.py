#!/usr/bin/env python3
"""Fail-closed validation of AMNOS's signed public ruleset feed."""
import base64, hashlib, json, re, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PEM=ROOT/"trust/prod-p256-2026-11-public.pem"
FINGERPRINT="06cdbb0744db68bb9b9763739a8db9b8c7ed086d9f61aa2653b2395a7e29c95a"
FIELDS={"schema_version","ruleset_version","issued_at","minimum_browser_version","payload_sha256","signature_algorithm","signing_key_id","signature"}
PAYLOAD={"schema_version","version","blocked_domains","blocked_search_roots","blocked_search_phrases","blocked_url_fragments"}
class Rejected(Exception): pass
def unique(pairs):
    output={}
    for k,v in pairs:
        if k in output: raise Rejected("duplicate JSON key")
        output[k]=v
    return output
def get(path,limit):
    if not path.is_file() or path.is_symlink(): raise Rejected("missing/unsafe file")
    b=path.read_bytes()
    if not (0<len(b)<=limit): raise Rejected("file size out of bounds")
    try: v=json.loads(b.decode("utf8"),object_pairs_hook=unique)
    except (ValueError,UnicodeError) as e: raise Rejected("invalid JSON") from e
    if not isinstance(v,dict): raise Rejected("expected JSON object")
    return v,b
def openssl(*args):
    p=subprocess.run(["openssl",*args],capture_output=True,check=False)
    if p.returncode:raise Rejected("OpenSSL verification failed")
    return p.stdout
def pinned_key():
    if hashlib.sha256(openssl("pkey","-pubin","-in",str(PEM),"-outform","DER")).hexdigest()!=FINGERPRINT:
        raise Rejected("pinned public key mismatch")
def verify(manifest,payload):
    m,rawm=get(manifest,16384);p,rawp=get(payload,4*1024*1024)
    if set(m)!=FIELDS or set(p)!=PAYLOAD:raise Rejected("unexpected JSON fields")
    seq=m["ruleset_version"]
    if type(seq)!=int or seq<=0 or m["schema_version"]!=1 or p["schema_version"]!=1 or p["version"]!=str(seq):
        raise Rejected("signed sequence mismatch")
    if m["signing_key_id"]!="prod-p256-2026-11" or m["signature_algorithm"]!="ecdsa-p256-sha256-der":
        raise Rejected("unexpected signer")
    if not isinstance(m["issued_at"],str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",m["issued_at"]):
        raise Rejected("unexpected issued_at")
    ver=m["minimum_browser_version"]
    if not isinstance(ver,str) or re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)",ver) is None:
        raise Rejected("unexpected minimum version")
    digest=m["payload_sha256"]
    if not isinstance(digest,str) or re.fullmatch(r"[0-9a-f]{64}",digest) is None or hashlib.sha256(rawp).hexdigest()!=digest:
        raise Rejected("payload SHA-256 mismatch")
    for name in PAYLOAD-{"schema_version","version"}:
        v=p[name]
        if not isinstance(v,list) or len(v)>100000 or any(not isinstance(x,str) for x in v):
            raise Rejected("rule values out of bounds")
    try: sig=base64.b64decode(m["signature"],validate=True)
    except (ValueError,TypeError) as e:raise Rejected("malformed signature base64") from e
    if not 8<=len(sig)<=72 or sig[0]!=0x30:raise Rejected("invalid signature DER")
    fields=["AMNOS-RULESET-V1","1",str(seq),m["issued_at"],ver,digest,m["signature_algorithm"],m["signing_key_id"]]
    with tempfile.TemporaryDirectory() as tmp:
        s=Path(tmp)/"signature.der";message=Path(tmp)/"message.bin"
        s.write_bytes(sig);message.write_bytes(("\n".join(fields)+"\n").encode("utf8"))
        if b"Verified OK" not in openssl("dgst","-sha256","-verify",str(PEM),"-signature",str(s),str(message)):
            raise Rejected("signature mismatch")
    return seq,rawm
def check():
    pinned_key()
    qa=ROOT/"qa/20261121-hsm-synthetic-v1"
    n,_=verify(qa/"latest.manifest.json",qa/"releases/1/ruleset.json")
    if n!=1:raise Rejected("QA fixture sequence mismatch")
    print("QA HSM signature: PASS")
    evidence={}
    for path in sorted((ROOT/"release-evidence").glob("*/approved.manifest.json")):
        number=path.parent.name
        if not number.isdecimal() or str(int(number))!=number:raise Rejected("invalid evidence sequence")
        seq,bytes_=verify(path,ROOT/f"releases/{number}/ruleset.json")
        if seq!=int(number):raise Rejected("evidence path mismatch")
        evidence[seq]=bytes_
        print("Approved signed release evidence verified:",seq)
    # Payloads may be deployed before the active manifest, but only alongside
    # independently verified signed evidence for the exact immutable sequence.
    for payload_path in sorted((ROOT/"releases").glob("*/ruleset.json")):
        seq_name = payload_path.parent.name
        if not seq_name.isdecimal() or str(int(seq_name)) != seq_name or int(seq_name) not in evidence:
            raise Rejected("Unsigned production payload or invalid release path")
    live=ROOT/"latest.manifest.json"
    if live.exists():
        meta,_=get(live,16384);seq=meta.get("ruleset_version")
        if type(seq)!=int or seq not in evidence:raise Rejected("missing approved manifest evidence")
        _,actual=verify(live,ROOT/f"releases/{seq}/ruleset.json")
        if actual!=evidence[seq]:raise Rejected("live manifest differs from approved bytes")
        print("Production manifest cryptographically verified:",seq)
    else:print("Production feed not activated (fail closed)")
if __name__=="__main__":
    try:check()
    except (Rejected,OSError,subprocess.SubprocessError) as error:
        print("SIGNED FEED REJECTED:",error,file=sys.stderr);sys.exit(1)
