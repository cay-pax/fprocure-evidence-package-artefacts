import io, json, zipfile, glob, os, sys, hashlib
sys.path.insert(0, "/home/ubuntu/paper2/eval/tool")
from verify_tep import verify
P = "/home/ubuntu/paper2/eval/packages"
RPC, CID = "http://127.0.0.1:8545", 31337
def rezip(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in entries: z.writestr(zipfile.ZipInfo(n, (2024, 1, 1, 0, 0, 0)), d)
    return b.getvalue()
def entries(zb):
    z = zipfile.ZipFile(io.BytesIO(zb)); return [(i.filename, z.read(i.filename)) for i in z.infolist()]
pk = sorted(glob.glob(f"{P}/S*.zip"))
metas = {os.path.basename(p)[:-4]: json.load(open(p[:-4] + ".anchor.json")) for p in pk}
names = list(metas)
rows = []
for i, name in enumerate(names):
    m = metas[name]; zb = open(f"{P}/{name}.zip", "rb").read(); E = entries(zb)
    other = metas[names[(i + 1) % len(names)]]
    def mod_bids(add_manifest):
        out = []; new = None
        for n, d in E:
            if n == "bids.json": d = d.replace(b'"', b"'", 1) if False else d[:-2] + (b" " if d[-2:-1] != b" " else b"\t") + d[-1:]; new = d
            out.append((n, d))
        if add_manifest:
            mf = json.loads(dict(out)["manifest.json"])
            for f in mf["files"]:
                if f["name"] == "bids.json": f["sha256"] = "0x" + hashlib.sha256(new).hexdigest()
            out = [(n, json.dumps(mf, indent=2).encode() if n == "manifest.json" else d) for n, d in out]
        return rezip(out)
    cases = {
        "T0 unmodified": (zb, m["anchor_tx_hash"], m["anchor_contract_address"], CID),
        "T1 one file altered (bids.json, 1 byte)": (mod_bids(False), m["anchor_tx_hash"], m["anchor_contract_address"], CID),
        "T2 listed file removed (events.json)": (rezip([e for e in E if e[0] != "events.json"]), m["anchor_tx_hash"], m["anchor_contract_address"], CID),
        "T3 unlisted file added": (rezip(E + [("extra_note.txt", b"inserted after anchoring")]), m["anchor_tx_hash"], m["anchor_contract_address"], CID),
        "T4 file altered and manifest rewritten to match": (mod_bids(True), m["anchor_tx_hash"], m["anchor_contract_address"], CID),
        "T5 anchor tx of another package": (zb, other["anchor_tx_hash"], m["anchor_contract_address"], CID),
        "T6 wrong anchor contract": (zb, m["anchor_tx_hash"], "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707", CID),
        "T7 wrong chain expected (Coston2, 114)": (zb, m["anchor_tx_hash"], m["anchor_contract_address"], 114),
        "T8 non-existent anchor tx": (zb, "0x" + "11" * 32, m["anchor_contract_address"], CID),
    }
    for c, (data, tx, con, cid) in cases.items():
        d, res = verify(data, RPC, cid, con, tx)
        failed = [f"{r['step']}:{r['check']}" for r in res if r["status"] == "failed"]
        note = [r["detail"] for r in res if r["step"] == 10][0] if res and res[-1]["step"] == 10 else ""
        rows.append({"package": name, "case": c, "result": "failed" if failed else "passed", "failed_steps": failed, "step10": note})
json.dump(rows, open(f"{P}/tamper_results.json", "w"), indent=2)
from collections import defaultdict
agg = defaultdict(lambda: [0, 0, set()])
for r in rows:
    a = agg[r["case"]]; a[0] += 1; a[1] += r["result"] == "failed"; a[2].update(r["failed_steps"])
for c, (n, f, s) in agg.items(): print(f"{c:<50} runs={n} rejected={f} steps={sorted(s)}")
print([ (r["package"], r["step10"]) for r in rows if r["case"].startswith("T0")])
