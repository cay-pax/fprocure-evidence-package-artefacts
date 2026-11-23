#!/usr/bin/env python3
"""Standalone verifier for F-Procure Tender Evidence Packages (TEP).

Needs only: the exported ZIP, a JSON-RPC endpoint for the anchoring chain, the
anchor contract address and the anchor transaction hash. It does not contact
F-Procure or its database. Dependencies: Python 3.9+ standard library and
pycryptodome (Keccak-256 for the event topic and tender reference).

Ten steps:
  1  package digest: SHA-256 of the ZIP bytes
  2  archive readable, entry names unique and plain (no paths)
  3  manifest.json present, parseable, package_type and schema_version known
  4  every file listed in the manifest is present            (missing file)
  5  every listed file's SHA-256 matches the manifest          (modified file)
  6  every file in the archive is listed in the manifest       (added file)
  7  manifest tender_id/version agree with tender.json and with the claim
  8  anchor transaction: right chain, mined, successful, sent to the anchor contract
  9  EvidenceAnchored event from the anchor contract carries this package digest
     (v2 event: also this tender reference and version; v1 event: digest only)
 10  anchor state: contract still maps (tender, version) to this digest and
     reports whether a later version supersedes it (v2 contract only)
"""
import argparse, hashlib, io, json, sys, urllib.request, zipfile
from Crypto.Hash import keccak

def k256(b: bytes) -> str:
    h = keccak.new(digest_bits=256); h.update(b); return "0x" + h.hexdigest()

TOPIC_V2 = k256(b"EvidenceAnchored(bytes32,uint32,bytes32,address,uint256)")
TOPIC_V1 = k256(b"EvidenceAnchored(bytes32,address,uint256)")
SEL_ANCHORS = k256(b"anchors(bytes32,uint32)")[:10]
SEL_LATEST = k256(b"latestVersion(bytes32)")[:10]

def rpc(url, method, params):
    req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    if "error" in out: raise RuntimeError(out["error"])
    return out["result"]

def verify(zip_bytes, rpc_url=None, chain_id=None, contract=None, tx=None, tender=None, version=None):
    res = []
    def rec(step, name, ok, detail=""):
        res.append({"step": step, "check": name, "status": "passed" if ok is True else ("skipped" if ok is None else "failed"), "detail": detail})
        return ok
    digest = "0x" + hashlib.sha256(zip_bytes).hexdigest()
    rec(1, "package_digest", True, digest)
    try:
        z = zipfile.ZipFile(io.BytesIO(zip_bytes))
        names = [i.filename for i in z.infolist()]
        ok = len(names) == len(set(names)) and all("/" not in n and "\\" not in n for n in names)
        rec(2, "archive_readable", ok, f"{len(names)} entries")
    except Exception as e:
        rec(2, "archive_readable", False, str(e)); return digest, res
    if "manifest.json" not in names:
        rec(3, "manifest_valid", False, "manifest.json missing"); return digest, res
    try:
        m = json.loads(z.read("manifest.json"))
        ok = m.get("package_type") == "tender_evidence_package" and m.get("schema_version") == "1.0.0" and isinstance(m.get("files"), list)
        rec(3, "manifest_valid", ok, f"schema {m.get('schema_version')}, {len(m.get('files', []))} files listed")
    except Exception as e:
        rec(3, "manifest_valid", False, str(e)); return digest, res
    listed = {f["name"]: f["sha256"] for f in m["files"]}
    missing = [n for n in listed if n not in names]
    rec(4, "listed_files_present", not missing, "missing: " + ", ".join(missing) if missing else f"all {len(listed)} present")
    bad = [n for n in listed if n in names and "0x" + hashlib.sha256(z.read(n)).hexdigest() != listed[n]]
    rec(5, "file_hashes_match", not bad, "mismatch: " + ", ".join(bad) if bad else "all match")
    extra = [n for n in names if n != "manifest.json" and n not in listed]
    rec(6, "no_unlisted_files", not extra, "unlisted: " + ", ".join(extra) if extra else "none")
    try:
        t = json.loads(z.read("tender.json")) if "tender.json" in names else {}
    except Exception:
        t = {}
    probs = []
    if t.get("id") != m.get("tender_id"): probs.append("tender.json id differs from manifest")
    if tender and m.get("tender_id") != tender: probs.append("manifest tender_id differs from claimed tender")
    if version is not None and m.get("package_version") != version: probs.append("manifest version differs from claim")
    rec(7, "identity_consistent", not probs, "; ".join(probs) or f"tender {m.get('tender_id')} v{m.get('package_version')}")
    if not (rpc_url and contract and tx):
        for s, n in [(8, "anchor_tx_valid"), (9, "anchor_event_matches"), (10, "anchor_state_current")]:
            rec(s, n, None, "no anchor reference supplied")
        return digest, res
    contract = contract.lower()
    try:
        cid = int(rpc(rpc_url, "eth_chainId", []), 16)
        rcpt = rpc(rpc_url, "eth_getTransactionReceipt", [tx])
    except Exception as e:
        rec(8, "anchor_tx_valid", False, f"RPC error: {e}"); return digest, res
    probs = []
    if chain_id is not None and cid != chain_id: probs.append(f"chain {cid} != expected {chain_id}")
    if not rcpt: probs.append("transaction not found")
    else:
        if int(rcpt["status"], 16) != 1: probs.append("transaction reverted")
        if (rcpt.get("to") or "").lower() != contract: probs.append("transaction not sent to anchor contract")
    blk = int(rcpt["blockNumber"], 16) if rcpt else None
    if not rec(8, "anchor_tx_valid", not probs, "; ".join(probs) or f"chain {cid}, block {blk}, status 1"):
        rec(9, "anchor_event_matches", False, "no valid anchor transaction"); rec(10, "anchor_state_current", None, "skipped"); return digest, res
    tref = k256(m.get("tender_id", "").encode())
    ver = int(m.get("package_version", 0))
    found, kind = False, None
    for lg in rcpt["logs"]:
        if lg["address"].lower() != contract: continue
        tp = [x.lower() for x in lg["topics"]]
        if tp[0] == TOPIC_V2 and len(tp) == 4:
            kind = "v2"
            if tp[1] == tref and int(tp[2], 16) == ver and tp[3] == digest: found = True
        elif tp[0] == TOPIC_V1 and len(tp) >= 2:
            kind = "v1"
            if tp[1] == digest: found = True
    rec(9, "anchor_event_matches", found, (f"{kind} event binds this digest" + (", tender and version" if kind == "v2" else "")) if found else f"no {kind or 'EvidenceAnchored'} event for this digest/tender/version")
    if kind != "v2":
        rec(10, "anchor_state_current", None, "v1 anchor keeps no state"); return digest, res
    data = SEL_ANCHORS + tref[2:] + ver.to_bytes(32, "big").hex()
    stored = rpc(rpc_url, "eth_call", [{"to": contract, "data": data}, "latest"]).lower()
    latest = int(rpc(rpc_url, "eth_call", [{"to": contract, "data": SEL_LATEST + tref[2:]}, "latest"]), 16)
    ok = stored == digest
    rec(10, "anchor_state_current", ok, (f"contract maps v{ver} to this digest; latest version v{latest}" + (" (superseded)" if latest > ver else "")) if ok else "contract maps this tender/version to a different digest")
    return digest, res

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zip"); ap.add_argument("--rpc"); ap.add_argument("--chain-id", type=int)
    ap.add_argument("--contract"); ap.add_argument("--tx"); ap.add_argument("--tender"); ap.add_argument("--version", type=int)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    digest, res = verify(open(a.zip, "rb").read(), a.rpc, a.chain_id, a.contract, a.tx, a.tender, a.version)
    failed = [r for r in res if r["status"] == "failed"]
    if a.json: print(json.dumps({"package_digest": digest, "result": "failed" if failed else "passed", "steps": res}, indent=2))
    else:
        for r in res: print(f"{r['step']:>2} {r['status']:<7} {r['check']:<22} {r['detail']}")
        print("RESULT:", "FAILED" if failed else "PASSED")
    sys.exit(1 if failed else 0)
