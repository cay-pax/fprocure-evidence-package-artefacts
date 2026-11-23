import io, json, zipfile, hashlib, subprocess, sys, urllib.request
sys.path.insert(0, "/home/ubuntu/paper2/eval/tool"); sys.path.insert(0, "/home/ubuntu/paper2/eval")
from verify_tep import verify
env = dict(l.split("=", 1) for l in subprocess.run(["supabase", "status", "-o", "env"], cwd="/home/ubuntu/repos/Fprocure-OGcode-X", capture_output=True, text=True).stdout.replace('"', "").split("\n") if "=" in l)
U, ANON, SVC = env["API_URL"], env["ANON_KEY"], env["SERVICE_ROLE_KEY"]
P = "/home/ubuntu/paper2/eval/packages"; RUN = "e981f9"
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
    return [f"{c['check']}" for c in r.get("checks", []) if c["status"] == "failed"]
out = {}
# A. app verifier on tampered copies of S03 (stored ZIP replaced locally, then restored)
import tamper_matrix as tm  # noqa: re-run is cheap; reuse helpers
m = json.load(open(f"{P}/S03.anchor.json")); row = pkgrow(m["package_id"]); orig = open(f"{P}/S03.zip", "rb").read(); E = tm.entries(orig)
def altered(rewrite):
    o = []; new = None
    for n, d in E:
        if n == "bids.json": d = d[:-1] + b" " + d[-1:]; new = d
        o.append((n, d))
    if rewrite:
        mf = json.loads(dict(o)["manifest.json"])
        for f in mf["files"]:
            if f["name"] == "bids.json": f["sha256"] = "0x" + hashlib.sha256(new).hexdigest()
        o = [(n, json.dumps(mf, indent=2).encode() if n == "manifest.json" else d) for n, d in o]
    return tm.rezip(o)
app = {}
for label, data in {"T1 one file altered": altered(False), "T2 listed file removed": tm.rezip([e for e in E if e[0] != "events.json"]), "T3 unlisted file added": tm.rezip(E + [("extra_note.txt", b"x")]), "T4 altered + manifest rewritten": altered(True)}.items():
    upload(row["storage_path"], data); app[label] = appver(m["package_id"]) or ["(none failed)"]
upload(row["storage_path"], orig); app["T0 restored original"] = appver(m["package_id"]) or ["(none failed)"]
out["app_verifier_on_tampered_S03"] = app
# B. determinism: regenerate S03 with no data change and compare per-file hashes
g = fn("generate-tender-evidence", ADM, {"tender_id": m["tender_uuid"]}); r2 = pkgrow(g["package_id"]); z2 = download(r2["storage_path"])
open(f"{P}/S03_regenerated_unanchored.zip", "wb").write(z2)
h = lambda zb: {n: hashlib.sha256(d).hexdigest() for n, d in tm.entries(zb)}
h1, h2 = h(orig), h(z2)
out["determinism_S03"] = {"v1_package_hash": m["package_hash"], "v2_package_hash": r2["package_hash"], "files_changed": sorted(n for n in h1 if h1[n] != h2.get(n)), "files_unchanged": sorted(n for n in h1 if h1[n] == h2.get(n))}
# C. omission: S05, delete one event row from the operational database, then generate+anchor v2
m5 = json.load(open(f"{P}/S05.anchor.json"))
ev = req("GET", f"{U}/rest/v1/events?tender_id=eq.{m5['tender_uuid']}&select=id,event_type,created_at&order=created_at", headers=S)
victim = [e for e in ev if "reveal" in (e.get("event_type") or "").lower()] or ev
victim = victim[0]
req("DELETE", f"{U}/rest/v1/events?id=eq.{victim['id']}", headers={**S, "Prefer": "return=minimal"}, raw=True)
g5 = fn("generate-tender-evidence", ADM, {"tender_id": m5["tender_uuid"]}); a5 = fn("anchor-evidence", ADM, {"package_id": g5["package_id"]}); r5 = pkgrow(g5["package_id"]); z5 = download(r5["storage_path"])
open(f"{P}/S05_v2_after_omission.zip", "wb").write(z5)
d5, res5 = verify(z5, "http://127.0.0.1:8545", 31337, r5["anchor_contract_address"], r5["anchor_tx_hash"])
d5v1, res5v1 = verify(open(f"{P}/S05.zip", "rb").read(), "http://127.0.0.1:8545", 31337, m5["anchor_contract_address"], m5["anchor_tx_hash"])
cnt = lambda zb: len(json.loads(dict(tm.entries(zb))["events.json"]))
out["omission_S05"] = {"events_in_db_before": len(ev), "deleted_event_type": victim.get("event_type"), "v2_standalone": [f"{r['step']}:{r['status']}" for r in res5], "v2_app_failed": appver(g5["package_id"]) or ["(none failed)"], "v1_step10_now": res5v1[-1]["detail"], "events_json_count_v1": cnt(open(f"{P}/S05.zip", "rb").read()), "events_json_count_v2": cnt(z5)}
json.dump(out, open(f"{P}/app_side_results.json", "w"), indent=2); print(json.dumps(out, indent=1))
