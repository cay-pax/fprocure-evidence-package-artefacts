"""Tamper and reference-mismatch matrix for the 13-step standalone verifier (local Anvil)."""
import io, json, zipfile, glob, os, sys, hashlib
from collections import defaultdict
sys.path.insert(0, "/home/ubuntu/wt-e2e/tools/evidence-verifier")
from verify_tep import verify
P = os.environ.get("PKG", "/home/ubuntu/paper2/eval/v2/final")
RPC, CID = os.environ.get("RPC", "http://127.0.0.1:8545"), int(os.environ.get("CID", "31337"))

def rezip(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in entries: z.writestr(zipfile.ZipInfo(n, (2024, 1, 1, 0, 0, 0)), d)
    return b.getvalue()

def entries(zb):
    z = zipfile.ZipFile(io.BytesIO(zb)); return [(i.filename, z.read(i.filename)) for i in z.infolist()]

def edit(E, name, fn, rewrite=True, drop_from_manifest=False):
    """Apply fn to one JSON file; optionally rewrite the manifest so steps 5-7 still pass."""
    out = []
    for n, d in E:
        if n == name and fn: d = json.dumps(fn(json.loads(d)), indent=2, sort_keys=True).encode()
        if n == name and drop_from_manifest: continue
        out.append((n, d))
    if rewrite:
        files = dict(out); mf = json.loads(files["manifest.json"])
        mf["files"] = [{"name": f["name"], "sha256": "0x" + hashlib.sha256(files[f["name"]]).hexdigest()} for f in mf["files"] if f["name"] in files]
        out = [(n, json.dumps(mf, indent=2).encode() if n == "manifest.json" else d) for n, d in out]
    return rezip(out)

def edit_raw(E, name, fn):
    return [(n, json.dumps(fn(json.loads(d)), indent=2, sort_keys=True).encode() if n == name else d) for n, d in E]

def bids_with(fn):
    def f(bids):
        for b in bids:
            if b.get("commit_signature") and b.get("revealed_bid_minor") is not None: fn(b); break
        return bids
    return f

def flip_r(b): b["commit_signature"]["r"] = hex(int(b["commit_signature"]["r"], 16) ^ 1)
def alter_commit(b): b["commit_hash"] = "0x" + ("0" if b["commit_hash"][2] != "0" else "1") + b["commit_hash"][3:]
def alter_amount(b): b["revealed_bid_minor"] = int(b["revealed_bid_minor"]) - 100; b["revealed_bid_amount"] = b["revealed_bid_minor"]
def drop_reveal(b): b["revealed_bid_minor"] = None; b["revealed_bid_amount"] = None
def schema(m): m["schema_version"] = "9.9.9"; return m

pk = sorted(glob.glob(f"{P}/S*.zip"))
metas = {os.path.basename(p)[:-4]: json.load(open(p[:-4] + ".anchor.json")) for p in pk}
names = list(metas); rows = []
for i, name in enumerate(names):
    m = metas[name]; zb = open(f"{P}/{name}.zip", "rb").read(); E = entries(zb)
    other = metas[names[(i + 1) % len(names)]]
    tx, con = m["anchor_tx_hash"], m["anchor_contract_address"]
    one_byte = [(n, d[:-1] + b" " + d[-1:] if n == "bids.json" else d) for n, d in E]
    cases = {
        "T0 unmodified": (zb, tx, con, CID),
        "T1 one file altered (bids.json, 1 byte)": (rezip(one_byte), tx, con, CID),
        "T2 listed file removed (events.json)": (rezip([e for e in E if e[0] != "events.json"]), tx, con, CID),
        "T3 unlisted file added": (rezip(E + [("extra_note.txt", b"inserted after anchoring")]), tx, con, CID),
        "T4 file altered and manifest rewritten to match": (edit(E, "bids.json", lambda b: b + [{"id": "inserted"}]), tx, con, CID),
        "T5 anchor tx of another package": (zb, other["anchor_tx_hash"], con, CID),
        "T6 wrong anchor contract": (zb, tx, os.environ.get("WRONG_CONTRACT", "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"), CID),
        "T7 wrong chain expected": (zb, tx, con, int(os.environ.get("WRONG_CID", 14 if CID == 114 else 114))),
        "T8 non-existent anchor tx": (zb, "0x" + "11" * 32, con, CID),
        "T9 required file removed from archive and manifest": (edit(E, "governance_notes.json", None, drop_from_manifest=True), tx, con, CID),
        "T10 unknown schema version in manifest": (edit(E, "manifest.json", schema, rewrite=False), tx, con, CID),
        "T11 bid commitment altered, manifest rewritten": (edit(E, "bids.json", bids_with(alter_commit)), tx, con, CID),
        "T12 revealed amount altered, manifest rewritten": (edit(E, "bids.json", bids_with(alter_amount)), tx, con, CID),
        "T13 passkey signature forged, manifest rewritten": (edit(E, "bids.json", bids_with(flip_r)), tx, con, CID),
        "T14 reveal removed from bids.json, manifest rewritten": (edit(E, "bids.json", bids_with(drop_reveal)), tx, con, CID),
        "T15 tender creation tx removed, manifest rewritten": (edit(edit_raw(E, "tender.json", lambda t: t | {"create_tx_hash": None}), "events.json", lambda ev: [e for e in ev if e.get("event_type") != "TENDER_CREATED"]), tx, con, CID),
    }
    for c, (data, t, k, cid) in cases.items():
        d, res = verify(data, RPC, cid, k, t, procure=m.get("procure_contract", "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"))
        failed = [f"{r['step']}:{r['check']}" for r in res if r["status"] == "failed"]
        rows.append({"package": name, "case": c, "result": "failed" if failed else "passed", "failed_steps": failed,
                     "skipped": [f"{r['step']}" for r in res if r["status"] == "skipped"]})
json.dump(rows, open(f"{P}/tamper_results.json", "w"), indent=2)
agg = defaultdict(lambda: [0, 0, set()])
for r in rows:
    a = agg[r["case"]]; a[0] += 1; a[1] += r["result"] == "failed"; a[2].update(r["failed_steps"])
for c, (n, f, s) in agg.items(): print(f"{c:<55} runs={n} rejected={f} steps={sorted(s, key=lambda x: int(x.split(':')[0]))}")
neg = [r for r in rows if not r["case"].startswith("T0")]
print(f"negative cases: {len(neg)}, rejected: {sum(r['result'] == 'failed' for r in neg)}; unmodified passed: {sum(r['result'] == 'passed' for r in rows if r['case'].startswith('T0'))}/{len(names)}")
