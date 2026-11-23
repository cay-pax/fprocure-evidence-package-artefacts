"""App-side checks: app verifier on tampered copies (A4) and changed-data regeneration (A1)."""
import io, json, hashlib, subprocess, sys, urllib.request
sys.path.insert(0, "/home/ubuntu/wt-e2e/tools/evidence-verifier"); sys.path.insert(0, "/home/ubuntu/paper2/eval/v2")
from verify_tep import verify
import tamper_matrix as tm
env = dict(l.split("=", 1) for l in subprocess.run(["npx", "supabase", "status", "-o", "env"], cwd="/home/ubuntu/wt-e2e", capture_output=True, text=True).stdout.replace('"', "").split("\n") if "=" in l)
U, ANON, SVC = env["API_URL"], env["ANON_KEY"], env["SERVICE_ROLE_KEY"]
P = "/home/ubuntu/paper2/eval/v2/final"
RES = json.load(open(f"{P}/scenario_results.json")); RUN = RES[0]["tender_ref"].split("-")[-1]
def req(method, url, body=None, headers=None, raw=False):
    h = {"apikey": ANON, **(headers or {})}
    data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
    if data is not None and "Content-Type" not in h: h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data, h, method=method)
    try:
        with urllib.request.urlopen(r) as resp: out = resp.read()
    except urllib.error.HTTPError as e: out = e.read()
    return out if raw else json.loads(out or b"null")
def jwt(name): return req("POST", f"{U}/auth/v1/token?grant_type=password", {"email": f"{name}-{RUN}@paper2-eval.test", "password": "paper2-eval-local-only"})["access_token"]
ADM, AUD = jwt("admin"), jwt("auditor")
S = {"apikey": SVC, "Authorization": f"Bearer {SVC}"}
fn = lambda f, tok, body: req("POST", f"{U}/functions/v1/{f}", body, {"Authorization": f"Bearer {tok}"})
pkgrow = lambda pid: req("GET", f"{U}/rest/v1/tender_evidence_packages?id=eq.{pid}&select=*", headers=S)[0]
def upload(path, data): return req("POST", f"{U}/storage/v1/object/evidence-packages/{path}", data, {**S, "Content-Type": "application/zip", "x-upsert": "true"})
def download(path): return req("GET", f"{U}/storage/v1/object/evidence-packages/{path}", headers=S, raw=True)
def appver(pid):
    r = fn("verify-tender-evidence", AUD, {"package_id": pid})
    return [c["check"] for c in r.get("checks", []) if c["status"] == "failed"] or ["(none failed)"]
out = {"run": RUN}
m = json.load(open(f"{P}/S03.anchor.json")); row = pkgrow(m["package_id"]); orig = open(f"{P}/S03.zip", "rb").read(); E = tm.entries(orig)
one_byte = [(n, d[:-1] + b" " + d[-1:] if n == "bids.json" else d) for n, d in E]
app = {}
for label, data in {
    "T1 one file altered": tm.rezip(one_byte),
    "T2 listed file removed": tm.rezip([e for e in E if e[0] != "events.json"]),
    "T3 unlisted file added": tm.rezip(E + [("extra_note.txt", b"x")]),
    "T4 altered + manifest rewritten": tm.edit(E, "bids.json", lambda b: b + [{"id": "inserted"}]),
    "T9 required file removed from archive and manifest": tm.edit(E, "governance_notes.json", None, drop_from_manifest=True),
}.items():
    upload(row["storage_path"], data); app[label] = appver(m["package_id"])
upload(row["storage_path"], orig); app["T0 restored original"] = appver(m["package_id"])
out["app_verifier_on_tampered_S03"] = app
# A1: unchanged regeneration returns the same package; a real change gives a new version and digest.
m2 = json.load(open(f"{P}/S02.anchor.json"))
same = fn("generate-tender-evidence", ADM, {"tender_id": m2["tender_uuid"]})
admin_id = req("GET", f"{U}/rest/v1/tenders?id=eq.{m2['tender_uuid']}&select=created_by", headers=S)[0]["created_by"]
req("POST", f"{U}/rest/v1/governance_notes", {"tender_id": m2["tender_uuid"], "author_user_id": admin_id, "author_role": "admin", "note_type": "general", "text": "Post-award review note added after v1"}, {**S, "Prefer": "return=minimal"}, raw=True)
new = fn("generate-tender-evidence", ADM, {"tender_id": m2["tender_uuid"]})
anc = fn("anchor-evidence", ADM, {"package_id": new["package_id"]}); r3 = pkgrow(new["package_id"]); z3 = download(r3["storage_path"])
open(f"{P}/S02_v2_changed.zip", "wb").write(z3)
json.dump({"scenario": "S02", "tender_uuid": m2["tender_uuid"], "package_id": r3["id"], "package_version": r3["package_version"], "package_hash": r3["package_hash"], "manifest_hash": r3["manifest_hash"], "anchor_tx_hash": r3["anchor_tx_hash"], "anchor_contract_address": r3["anchor_contract_address"], "chain_id": 31337, "rpc_url": "http://127.0.0.1:8545"}, open(f"{P}/S02_v2_changed.anchor.json", "w"), indent=2)
h = lambda zb: {n: hashlib.sha256(d).hexdigest() for n, d in tm.entries(zb)}
h1, h2 = h(open(f"{P}/S02.zip", "rb").read()), h(z3)
d3, res3 = verify(z3, "http://127.0.0.1:8545", 31337, r3["anchor_contract_address"], r3["anchor_tx_hash"])
out["regeneration_S02"] = {
    "unchanged": {"same_package": same.get("package_id") == m2["package_id"], "same_digest": same.get("package_hash") == m2["package_hash"], "unchanged_flag": same.get("unchanged")},
    "after_governance_note": {"v1": m2["package_hash"], "v2": r3["package_hash"], "v2_version": r3["package_version"], "files_changed": sorted(n for n in h1 if h1[n] != h2.get(n)), "v2_standalone": "failed" if any(r["status"] == "failed" for r in res3) else "passed"},
}
json.dump(out, open(f"{P}/app_side_results.json", "w"), indent=2); print(json.dumps(out, indent=1))
