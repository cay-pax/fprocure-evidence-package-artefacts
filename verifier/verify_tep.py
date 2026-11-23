#!/usr/bin/env python3
"""Standalone verifier for F-Procure Tender Evidence Packages (TEP).

Needs only the exported ZIP and, for the on-chain steps, a JSON-RPC endpoint
for the chain the tender ran on. It does not contact F-Procure or its database.
Dependencies: Python 3.9+, pycryptodome (Keccak-256) and cryptography (P-256).

Steps:
  1  package digest: SHA-256 of the ZIP bytes (the value anchored on chain)
  2  archive readable, entry names unique and plain (no paths)
  3  manifest.json present, parseable, package_type and schema_version known
  4  every file the schema version requires is listed in the manifest
  5  every listed file is present                               (missing file)
  6  every listed file's SHA-256 matches the manifest             (modified file)
  7  every file in the archive is listed in the manifest          (added file)
  8  manifest tender/version agree with tender.json, chain_context.json and the claim
  9  anchor transaction: right chain, mined, successful, sent to the anchor contract
 10  EvidenceAnchored event from the anchor contract carries this package digest
     (v2 event: also this tender reference and version; v1 event: digest only)
 11  anchor state: contract still maps (tender, version) to this digest and
     reports whether a later version supersedes it (v2 contract only)
 12  on-chain lifecycle: the procurement contract's commit, reveal and award
     events for this tender all appear in bids.json/events.json with the same
     vendor, commitment, amount and transaction
 13  passkey assertions: each bid's commit signature verifies against its
     passkey in passkeys.json (WebAuthn type, challenge = commit digest,
     user present and verified flags, low-s P-256 signature)

Steps 1 to 8 and 13 need no network. Steps 9 to 12 are skipped when the
RPC, contract or anchor transaction they need is not supplied.
"""
import argparse, base64, hashlib, io, json, sys, urllib.request, zipfile
from Crypto.Hash import keccak
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def k256(b: bytes) -> str:
    h = keccak.new(digest_bits=256); h.update(b); return "0x" + h.hexdigest()


FILES_V1 = sorted([
    "anomalies.json", "audit_export.json", "bids.json", "erp_sync.json",
    "escrow.json", "events.json", "governance_notes.json",
    "onchain_references.json", "passkeys.json", "tender.json",
    "verifier_instructions.json",
])
# Early 1.0.0 packages predate passkeys.json.
REQUIRED_FILES = {"1.0.0": [n for n in FILES_V1 if n != "passkeys.json"], "1.1.0": sorted(FILES_V1 + ["chain_context.json"])}

TOPIC_V2 = k256(b"EvidenceAnchored(bytes32,uint32,bytes32,address,uint256)")
TOPIC_V1 = k256(b"EvidenceAnchored(bytes32,address,uint256)")
SEL_ANCHORS = k256(b"anchors(bytes32,uint32)")[:10]
SEL_LATEST = k256(b"latestVersion(bytes32)")[:10]
T_COMMITTED = k256(b"BidCommitted(uint256,bytes32,bytes32,bytes32)")
T_REVEALED = k256(b"BidRevealed(uint256,bytes32,uint256)")
T_AWARDED = k256(b"TenderAwarded(uint256,bytes32,uint256)")
T_CREATED = k256(b"TenderCreated(uint256,bytes32,bytes3,uint64,uint64)")
COMMIT_TYPEHASH = k256(b"FProcureCommit(uint256 chainId,address verifyingContract,uint256 tenderId,bytes32 vendorId,bytes32 commitHash)")
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def rpc(url, method, params):
    req = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    if "error" in out: raise RuntimeError(out["error"])
    return out["result"]


def word(v) -> bytes:
    if isinstance(v, int): return v.to_bytes(32, "big")
    b = bytes.fromhex(v[2:] if v.startswith("0x") else v)
    return b.rjust(32, b"\0")


def vendor_id(uuid: str) -> str:
    return "0x" + uuid.replace("-", "").lower().rjust(64, "0")


def commit_digest(chain_id, contract, tender_id, vid, commit_hash) -> bytes:
    data = b"".join(word(x) for x in (COMMIT_TYPEHASH, chain_id, contract, tender_id, vid, commit_hash))
    return bytes.fromhex(k256(data)[2:])


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def verify_assertion(challenge: bytes, a: dict, qx: str, qy: str) -> str:
    """Mirrors OpenZeppelin WebAuthn.verify(requireUV = true). Returns '' or the failure."""
    cd = a["clientDataJSON"]
    auth = bytes.fromhex(a["authenticatorData"][2:])
    if len(auth) <= 36: return "authenticatorData too short"
    t = '"type":"webauthn.get"'
    if cd[a["typeIndex"]:a["typeIndex"] + len(t)] != t: return "type is not webauthn.get"
    c = f'"challenge":"{b64url(challenge)}"'
    if cd[a["challengeIndex"]:a["challengeIndex"] + len(c)] != c: return "challenge is not this bid's commit digest"
    f = auth[32]
    if not f & 0x01 or not f & 0x04: return "user present/verified flag not set"
    if f & 0x10 and not f & 0x08: return "backup state without backup eligibility"
    r, s = int(a["r"], 16), int(a["s"], 16)
    if not 0 < r < P256_N or not 0 < s <= P256_N // 2: return "signature out of range or high s"
    try:
        key = ec.EllipticCurvePublicNumbers(int(qx, 16), int(qy, 16), ec.SECP256R1()).public_key()
        key.verify(encode_dss_signature(r, s), auth + hashlib.sha256(cd.encode()).digest(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return "P-256 signature does not verify"
    return ""


def get_logs(url, contract, topics, start, end, span):
    logs, b = [], start
    while b <= end:
        e = min(b + span - 1, end)
        logs += rpc(url, "eth_getLogs", [{"address": contract, "topics": topics, "fromBlock": hex(b), "toBlock": hex(e)}])
        b = e + 1
    return logs


def lifecycle_check(url, procure, t, bids, events, span, from_block=None, end_block=None):
    """Compares the tender's on-chain commit/reveal/award events with the package."""
    tid = t.get("contract_tender_id")
    if tid is None: return None, "tender.json has no contract_tender_id"
    tid_topic = "0x" + word(int(tid)).hex()
    # Search from the earliest block of any transaction the package records
    # (or from_block) to the anchor block (or the chain tip). The range must hold
    # the tender's TenderCreated event, which precedes all of its bids, so a
    # package that omits its earliest transactions cannot narrow the search.
    hashes = {t.get("create_tx_hash"), t.get("award_tx_hash")}
    hashes |= {b.get("commit_tx_hash") for b in bids} | {e.get("tx_hash") for e in events}
    blocks = []
    for h in sorted(x for x in hashes if isinstance(x, str) and x.startswith("0x") and len(x) == 66):
        rc = rpc(url, "eth_getTransactionReceipt", [h])
        if rc: blocks.append(int(rc["blockNumber"], 16))
    start = from_block if from_block is not None else (min(blocks) if blocks else 0)
    end = end_block if end_block is not None else int(rpc(url, "eth_blockNumber", []), 16)
    logs = get_logs(url, procure, [[T_CREATED, T_COMMITTED, T_REVEALED, T_AWARDED], tid_topic], start, end, span)
    if not any(lg["topics"][0].lower() == T_CREATED for lg in logs):
        return False, f"TenderCreated for on-chain tender {tid} not in blocks {start}-{end}: the package omits its earliest transactions, or pass --from-block"
    logs = [lg for lg in logs if lg["topics"][0].lower() != T_CREATED]
    by_vendor = {}
    for b in bids:
        if b.get("vendor_id"): by_vendor.setdefault(vendor_id(b["vendor_id"]), []).append(b)
    pkg_txs = {(e.get("tx_hash") or "").lower() for e in events}
    pkg_txs |= {(b.get("commit_tx_hash") or "").lower() for b in bids}
    pkg_txs |= {(t.get(k) or "").lower() for k in ("create_tx_hash", "award_tx_hash")}
    probs, last_commit = [], {}
    for lg in logs:
        topic, vid = lg["topics"][0].lower(), lg["topics"][2].lower()
        tx = lg["transactionHash"].lower()
        data = lg["data"][2:]
        if tx not in pkg_txs: probs.append(f"tx {tx[:12]}… ({'commit' if topic == T_COMMITTED else 'reveal' if topic == T_REVEALED else 'award'}) not in package")
        vb = by_vendor.get(vid, [])
        if topic == T_COMMITTED:
            last_commit[vid] = "0x" + data[:64]
        elif topic == T_REVEALED:
            amt = int(data[:64], 16)
            if not any(b.get("revealed_bid_minor") is not None and int(b["revealed_bid_minor"]) == amt for b in vb):
                probs.append(f"on-chain reveal of {amt} by vendor {vid[-32:]} missing from bids.json")
        elif topic == T_AWARDED:
            amt = int(data[:64], 16)
            win = [b for b in bids if b.get("is_winner")]
            if not win or vendor_id(win[0]["vendor_id"]) != vid or int(win[0].get("revealed_bid_minor") or -1) != amt:
                probs.append(f"on-chain award ({vid[-32:]}, {amt}) differs from bids.json winner")
            if t.get("winning_vendor_id") and vendor_id(t["winning_vendor_id"]) != vid:
                probs.append("on-chain award differs from tender.json winning_vendor_id")
    for vid, ch in last_commit.items():
        if not any((b.get("commit_hash") or "").lower() == ch.lower() for b in by_vendor.get(vid, [])):
            probs.append(f"on-chain commitment {ch[:12]}… by vendor {vid[-32:]} missing from bids.json")
    onchain_vendors = set(last_commit)
    for b in bids:
        if b.get("commit_tx_hash") and b.get("vendor_id") and vendor_id(b["vendor_id"]) not in onchain_vendors:
            probs.append(f"bid {b['id']} claims an on-chain commit with no BidCommitted event")
    n = {k: sum(1 for l in logs if l["topics"][0].lower() == k) for k in (T_COMMITTED, T_REVEALED, T_AWARDED)}
    ok_detail = f"tender {tid}: {n[T_COMMITTED]} commits, {n[T_REVEALED]} reveals, {n[T_AWARDED]} award, blocks {start}-{end}"
    return (not probs), "; ".join(probs) or ok_detail


def passkey_check(bids, passkeys, chain_id, procure, tid):
    keys = {(p.get("key_id") or "").lower(): p for p in passkeys}
    keys.update({p.get("id"): p for p in passkeys if p.get("id")})
    signed, probs = 0, []
    for b in bids:
        a = b.get("commit_signature")
        if not a: continue
        signed += 1
        p = keys.get((a.get("key_id") or "").lower()) or keys.get(b.get("passkey_id"))
        if not p: probs.append(f"bid {b['id']}: passkey not in passkeys.json"); continue
        if p.get("vendor_id") and p["vendor_id"] != b.get("vendor_id"): probs.append(f"bid {b['id']}: passkey belongs to another vendor"); continue
        qx, qy = p["public_key_x"], p["public_key_y"]
        if p.get("key_id") and k256(word(qx) + word(qy)).lower() != p["key_id"].lower(): probs.append(f"bid {b['id']}: key_id is not keccak256(qx, qy)"); continue
        if p.get("active_at") and b.get("created_at") and b["created_at"] < p["active_at"]: probs.append(f"bid {b['id']}: signed before the passkey was active")
        if p.get("revoked_at") and b.get("created_at") and b["created_at"] >= p["revoked_at"]: probs.append(f"bid {b['id']}: signed after the passkey was revoked")
        why = verify_assertion(commit_digest(chain_id, procure, int(tid), vendor_id(b["vendor_id"]), b["commit_hash"]), a, qx, qy)
        if why: probs.append(f"bid {b['id']}: {why}")
    if not signed: return None, "no passkey-signed bids"
    return (not probs), "; ".join(probs) or f"{signed} passkey assertions verify"


def verify(zip_bytes, rpc_url=None, chain_id=None, contract=None, tx=None, tender=None, version=None, procure=None, log_span=30, from_block=None):
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
        ok = m.get("package_type") == "tender_evidence_package" and m.get("schema_version") in REQUIRED_FILES and isinstance(m.get("files"), list)
        rec(3, "manifest_valid", ok, f"schema {m.get('schema_version')}, {len(m.get('files', []))} files listed")
        if not ok: return digest, res
    except Exception as e:
        rec(3, "manifest_valid", False, str(e)); return digest, res
    listed = {f["name"]: f["sha256"] for f in m["files"]}
    req_missing = [n for n in REQUIRED_FILES[m["schema_version"]] if n not in listed]
    rec(4, "required_files_listed", not req_missing, "not listed: " + ", ".join(req_missing) if req_missing else f"all {len(REQUIRED_FILES[m['schema_version']])} required files listed")
    missing = [n for n in listed if n not in names]
    rec(5, "listed_files_present", not missing, "missing: " + ", ".join(missing) if missing else f"all {len(listed)} present")
    norm = lambda h: (h or "").lower().removeprefix("0x")
    bad = [n for n in listed if n in names and hashlib.sha256(z.read(n)).hexdigest() != norm(listed[n])]
    rec(6, "file_hashes_match", not bad, "mismatch: " + ", ".join(bad) if bad else "all match")
    extra = [n for n in names if n != "manifest.json" and n not in listed]
    rec(7, "no_unlisted_files", not extra, "unlisted: " + ", ".join(extra) if extra else "none")

    def load(n, default):
        try: return json.loads(z.read(n)) if n in names else default
        except Exception: return default
    t, cc = load("tender.json", {}), load("chain_context.json", {})
    bids, events, passkeys = load("bids.json", []), load("events.json", []), load("passkeys.json", [])
    probs = []
    if t.get("id") != m.get("tender_id"): probs.append("tender.json id differs from manifest")
    if tender and m.get("tender_id") != tender: probs.append("manifest tender_id differs from claimed tender")
    if version is not None and m.get("package_version") != version: probs.append("manifest version differs from claim")
    if chain_id is not None and cc.get("chain_id") not in (None, chain_id): probs.append(f"chain_context.json chain {cc.get('chain_id')} != expected {chain_id}")
    rec(8, "identity_consistent", not probs, "; ".join(probs) or f"tender {m.get('tender_id')} v{m.get('package_version')}" + (f" on {cc.get('chain_name')} ({cc.get('chain_id')})" if cc else ""))

    # Contracts named by the package are hints only: a supplier could name its
    # own contract, so the on-chain steps need addresses the verifier supplies.
    domain_chain = chain_id if chain_id is not None else cc.get("chain_id")
    unpinned = lambda flag, name: f"{name} contract not supplied" + (f" (package names {cc[name + '_contract']}; check it independently, then pass {flag})" if cc.get(name + "_contract") else f"; pass {flag}")

    anchor_block = None
    if not (rpc_url and contract and tx):
        why = unpinned("--contract", "anchor") if rpc_url and tx else "no anchor reference supplied"
        for s, n in [(9, "anchor_tx_valid"), (10, "anchor_event_matches"), (11, "anchor_state_current")]:
            rec(s, n, None, why)
    else:
        anchor_block = anchor_steps(rec, rpc_url, chain_id, contract.lower(), tx, digest, m)

    if rpc_url and procure:
        try:
            ok, detail = lifecycle_check(rpc_url, procure.lower(), t, bids, events, log_span, from_block, anchor_block)
        except Exception as e:
            ok, detail = False, f"RPC error: {e}"
        rec(12, "onchain_lifecycle_matches", ok, detail)
    else:
        rec(12, "onchain_lifecycle_matches", None, unpinned("--procure-contract", "procure") if rpc_url else "no RPC supplied")

    domain_procure = procure or cc.get("procure_contract")
    tender_uuid = (t.get("id") or "").replace("-", "").lower()
    if t.get("contract_tender_id") is None and len(tender_uuid) == 32 and all(c in "0123456789abcdef" for c in tender_uuid):
        # Simulated or On-Prem tender: offChainDomain binds bids to the tender UUID.
        ok, detail = passkey_check(bids, passkeys, 0, "0x" + "00" * 20, int(tender_uuid, 16))
        rec(13, "passkey_assertions_valid", ok, detail + " (off-chain domain)")
    elif t.get("contract_tender_id") is None:
        rec(13, "passkey_assertions_valid", False, "tender has no on-chain ID and its ID is not a UUID")
    elif domain_chain is None or not domain_procure:
        rec(13, "passkey_assertions_valid", None, "chain ID or procurement contract unknown")
    else:
        ok, detail = passkey_check(bids, passkeys, int(domain_chain), domain_procure, t["contract_tender_id"])
        rec(13, "passkey_assertions_valid", ok, detail + ("" if procure else " (domain contract from chain_context.json)"))
    return digest, res


def anchor_steps(rec, rpc_url, chain_id, contract, tx, digest, m):
    try:
        cid = int(rpc(rpc_url, "eth_chainId", []), 16)
        rcpt = rpc(rpc_url, "eth_getTransactionReceipt", [tx])
    except Exception as e:
        rec(9, "anchor_tx_valid", False, f"RPC error: {e}"); return None
    probs = []
    if chain_id is not None and cid != chain_id: probs.append(f"chain {cid} != expected {chain_id}")
    if not rcpt: probs.append("transaction not found")
    else:
        if int(rcpt["status"], 16) != 1: probs.append("transaction reverted")
        if (rcpt.get("to") or "").lower() != contract: probs.append("transaction not sent to anchor contract")
    blk = int(rcpt["blockNumber"], 16) if rcpt else None
    if not rec(9, "anchor_tx_valid", not probs, "; ".join(probs) or f"chain {cid}, block {blk}, status 1"):
        rec(10, "anchor_event_matches", False, "no valid anchor transaction"); rec(11, "anchor_state_current", None, "skipped"); return None
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
    rec(10, "anchor_event_matches", found, (f"{kind} event binds this digest" + (", tender and version" if kind == "v2" else "")) if found else f"no {kind or 'EvidenceAnchored'} event for this digest/tender/version")
    if kind != "v2":
        rec(11, "anchor_state_current", None, "v1 anchor keeps no state"); return blk if found else None
    data = SEL_ANCHORS + tref[2:] + ver.to_bytes(32, "big").hex()
    stored = rpc(rpc_url, "eth_call", [{"to": contract, "data": data}, "latest"]).lower()
    latest = int(rpc(rpc_url, "eth_call", [{"to": contract, "data": SEL_LATEST + tref[2:]}, "latest"]), 16)
    ok = stored == digest
    rec(11, "anchor_state_current", ok, (f"contract maps v{ver} to this digest; latest version v{latest}" + (" (superseded)" if latest > ver else "")) if ok else "contract maps this tender/version to a different digest")
    return blk if found else None


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zip"); ap.add_argument("--rpc"); ap.add_argument("--chain-id", type=int)
    ap.add_argument("--contract", help="evidence anchor contract, from a source other than the package")
    ap.add_argument("--tx", help="anchor transaction hash")
    ap.add_argument("--procure-contract", help="procurement contract, from a source other than the package")
    ap.add_argument("--log-span", type=int, default=30, help="blocks per eth_getLogs call (public Flare RPCs cap the range)")
    ap.add_argument("--from-block", type=int, help="first block to search for the tender's events (default: earliest block the package records)")
    ap.add_argument("--tender"); ap.add_argument("--version", type=int)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    digest, res = verify(open(a.zip, "rb").read(), a.rpc, a.chain_id, a.contract, a.tx, a.tender, a.version, a.procure_contract, a.log_span, a.from_block)
    failed = [r for r in res if r["status"] == "failed"]
    if a.json: print(json.dumps({"package_digest": digest, "result": "failed" if failed else "passed", "steps": res}, indent=2))
    else:
        for r in res: print(f"{r['step']:>2} {r['status']:<7} {r['check']:<26} {r['detail']}")
        print("RESULT:", "FAILED" if failed else "PASSED")
    sys.exit(1 if failed else 0)
