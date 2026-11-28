// Paper 2 research run on the Coston2 research deployment (contracts v2). MODE=fork rehearses on an
// Anvil fork with fresh vendors and time warps; MODE=live uses c2/state.json vendors and real deadlines.
// Drives the real F-Procure edge functions for 10 synthetic tenders, then exports each
// evidence package ZIP plus a small metadata file for the standalone verifier.
import { createClient } from "npm:@supabase/supabase-js@2.87.1";
import { ethers } from "npm:ethers@6.16.0";
import {
  bidCommitment, commitDigest, type CommitDomain, PASSKEY_DELAY_MS, paymentRefHash,
  recordedRefundDigest, registrationChallenge, vendorIdFromUuid,
} from "/home/ubuntu/wt-e2e/supabase/functions/_lib/passkey.ts";
import { createTestPasskey, type TestPasskey } from "/home/ubuntu/wt-e2e/supabase/functions/_lib/passkey-test-utils.ts";
import { loadPk } from "./pk.ts";

const env = (k: string) => Deno.env.get(k) ?? "";
const url = env("SB_URL"), anonKey = env("SB_ANON"), serviceKey = env("SB_SERVICE");
const rpcUrl = env("RPC") || "http://127.0.0.1:8545";
const procureAddress = env("PROCURE"), escrowAddress = env("ESCROW"), anchorAddress = env("ANCHOR");
const OUT = env("OUT") || "/home/ubuntu/paper2/eval/v2/packages";
Deno.mkdirSync(OUT, { recursive: true });
const CHAIN_ID = BigInt(env("CHAIN_ID") || "114");
const LIVE = env("MODE") === "live";
const DA = "https://ctn2-data-availability.flare.network/api/v0/ftso/anchor-feeds-with-proof";
const FTSO_PRICE = 2_000_000n, FTSO_DECIMALS = 8;
const noSession = { auth: { persistSession: false, autoRefreshToken: false } };
const MN = "test test test test test test test test test test test junk";
const devKey = (i: number) => ethers.HDNodeWallet.fromPhrase(MN, undefined, `m/44'/60'/0'/0/${i}`).privateKey;
const abi = (n: string) => JSON.parse(Deno.readTextFileSync(`/home/ubuntu/wt-e2e/contracts/out/${n}.sol/${n}.json`)).abi;

type Reveal = "ok" | "none" | "wrong";
interface Scenario {
  id: string; title: string; currency: string; settlement: "recorded" | "flr";
  bids: { v: number; amount: bigint; reveal?: Reveal }[];
  escrow: "none" | "release" | "refund"; regenerate?: boolean;
  omit?: "reveal" | "governance_note";
  commitSec?: number; revealSec?: number; crossSig?: boolean; duplicate?: boolean; revoke?: number; group?: string;
}
const S: Scenario[] = [
  { id: "S01", title: "Single bidder, recorded escrow released", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 48_500_00n }], escrow: "release" },
  { id: "S02", title: "Two bidders, recorded escrow released", currency: "EUR", settlement: "recorded", bids: [{ v: 0, amount: 1_650_000_00n }, { v: 1, amount: 1_720_000_00n }], escrow: "release" },
  { id: "S03", title: "Three bidders, no escrow step", currency: "GBP", settlement: "recorded", bids: [{ v: 0, amount: 125_000_00n }, { v: 1, amount: 98_000_00n }, { v: 2, amount: 110_500_00n }], escrow: "none" },
  { id: "S04", title: "Five bidders, recorded escrow released", currency: "KYD", settlement: "recorded", bids: [{ v: 0, amount: 310_000_00n }, { v: 1, amount: 295_250_00n }, { v: 2, amount: 301_000_00n }, { v: 3, amount: 287_900_00n }, { v: 4, amount: 322_400_00n }], escrow: "release" },
  { id: "S05", title: "Tie on lowest bid (lower vendor ID wins)", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 75_000_00n }, { v: 1, amount: 75_000_00n }, { v: 2, amount: 80_000_00n }], escrow: "none" },
  { id: "S06", title: "Lowest bidder never reveals (excluded)", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 50_000_00n, reveal: "none" }, { v: 1, amount: 61_000_00n }, { v: 2, amount: 64_500_00n }], escrow: "none" },
  { id: "S07", title: "Reveal with wrong amount rejected", currency: "EUR", settlement: "recorded", bids: [{ v: 0, amount: 40_000_00n, reveal: "wrong" }, { v: 1, amount: 42_000_00n }], escrow: "none" },
  { id: "S08", title: "FLR escrow funded by buyer and released", currency: "USD", settlement: "flr", bids: [{ v: 0, amount: 4n }, { v: 1, amount: 5n }], escrow: "release" },
  { id: "S09", title: "Recorded escrow refunded with winner's passkey approval", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 22_000_00n }, { v: 1, amount: 19_750_00n }], escrow: "refund" },
  { id: "S10", title: "Evidence regenerated after escrow (v1 then v2 anchored)", currency: "GBP", settlement: "recorded", bids: [{ v: 2, amount: 9_900_00n }, { v: 3, amount: 9_450_00n }], escrow: "release", regenerate: true },
  { id: "S11", title: "Losing reveal deleted from the database before package generation", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 70_000_00n }, { v: 1, amount: 66_000_00n }, { v: 2, amount: 72_500_00n }], escrow: "none", omit: "reveal" },
  { id: "S12", title: "Governance note deleted before package generation (off-chain only)", currency: "EUR", settlement: "recorded", bids: [{ v: 3, amount: 15_000_00n }, { v: 4, amount: 14_200_00n }], escrow: "none", omit: "governance_note" },
  { id: "S13", title: "No bids submitted (no award)", currency: "USD", settlement: "recorded", bids: [], escrow: "none" },
  { id: "S14", title: "Bids committed but none revealed (no valid bid)", currency: "EUR", settlement: "recorded", bids: [{ v: 0, amount: 12_000_00n, reveal: "none" }, { v: 1, amount: 11_500_00n, reveal: "none" }], escrow: "none" },
  { id: "S15", title: "Commit signed with another vendor's passkey rejected", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 33_000_00n }, { v: 2, amount: 31_250_00n }], escrow: "none", crossSig: true },
  { id: "S16", title: "Second commit by the same vendor rejected", currency: "GBP", settlement: "recorded", bids: [{ v: 1, amount: 27_400_00n }, { v: 3, amount: 26_900_00n }], escrow: "none", duplicate: true },
  { id: "S17a", title: "Concurrent tender A (overlapping windows)", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 18_000_00n }, { v: 1, amount: 17_250_00n }], escrow: "release", group: "S17" },
  { id: "S17b", title: "Concurrent tender B (overlapping windows)", currency: "EUR", settlement: "recorded", bids: [{ v: 1, amount: 52_000_00n }, { v: 2, amount: 49_900_00n }, { v: 3, amount: 50_500_00n }], escrow: "none", group: "S17" },
  { id: "S17c", title: "Concurrent tender C (overlapping windows)", currency: "KYD", settlement: "recorded", bids: [{ v: 0, amount: 7_800_00n }, { v: 4, amount: 7_650_00n }], escrow: "release", group: "S17" },
  { id: "S18a", title: "Short windows (5 min commit, 5 min reveal)", currency: "USD", settlement: "recorded", bids: [{ v: 2, amount: 64_000_00n }, { v: 3, amount: 61_800_00n }], escrow: "release", commitSec: 300, revealSec: 300 },
  { id: "S18b", title: "Long windows (60 min commit, 60 min reveal)", currency: "GBP", settlement: "recorded", bids: [{ v: 0, amount: 140_000_00n }, { v: 2, amount: 138_750_00n }, { v: 4, amount: 142_100_00n }], escrow: "release", commitSec: 3600, revealSec: 3600 },
  { id: "S19", title: "Passkey revoked, then the vendor's bid is rejected", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 21_000_00n }, { v: 1, amount: 20_400_00n }], escrow: "none", revoke: 4 },
];

const svc = createClient(url, serviceKey, noSession);
const provider = new ethers.JsonRpcProvider(rpcUrl, undefined, { cacheTimeout: -1, pollingInterval: 250 });
const relayer = new ethers.Wallet(LIVE ? env("RELAYER_KEY") : devKey(0), provider);
// The contract admin (relayer) may not fund escrow, so live FLR escrow needs a separate buyer wallet.
const buyer = new ethers.Wallet(LIVE ? (env("BUYER_KEY") || env("RELAYER_KEY")) : devKey(3), provider);
const procure = new ethers.Contract(procureAddress, abi("FProcure"), relayer);
const escrow = new ethers.Contract(escrowAddress, abi("FProcureEscrow"), provider);
const anchor = new ethers.Contract(anchorAddress, abi("EvidenceAnchor"), relayer);
const run = crypto.randomUUID().slice(0, 6);
const log: Record<string, unknown>[] = [];

async function call(fn: string, jwt: string, body: unknown) {
  const res = await fetch(`${url}/functions/v1/${fn}`, { method: "POST", headers: { apikey: anonKey, Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const text = await res.text(); let json: Record<string, unknown> = {};
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: res.status, json };
}
async function ok(fn: string, jwt: string, body: unknown) {
  const r = await call(fn, jwt, body);
  if (r.status !== 200) throw new Error(`${fn} -> ${r.status} ${JSON.stringify(r.json)}`);
  return r.json;
}
const chainNow = async () => Number((await provider.getBlock("latest"))!.timestamp);
const barriers = new Map<string, { n: number; ts: number; done: Promise<void>; release: () => void }>();
async function groupWarp(sc: Scenario, phase: string, ts: number) {
  if (LIVE || !sc.group) return warpTo(ts);
  const size = S.filter((x) => x.group === sc.group).length, key = sc.group + phase;
  let b = barriers.get(key);
  if (!b) { let release = () => {}; const done = new Promise<void>((r) => (release = r)); b = { n: 0, ts: 0, done, release }; barriers.set(key, b); }
  b.n++; b.ts = Math.max(b.ts, ts);
  if (b.n === size) { await warpTo(b.ts); b.release(); }
  await b.done;
}
async function warpTo(ts: number) {
  if (LIVE) {
    while ((await chainNow()) < ts) await new Promise((r) => setTimeout(r, 5000));
    return;
  }
  const now = await chainNow();
  await provider.send("evm_setNextBlockTimestamp", [Math.max(ts, now + 1)]);
  await provider.send("evm_mine", []);
}
async function actor(name: string, role: string) {
  const email = `${name}-${run}@paper2-eval.test`, password = "paper2-eval-local-only";
  const { data, error } = await svc.auth.admin.createUser({ email, password, email_confirm: true });
  if (error) throw error;
  await svc.from("user_roles").delete().eq("user_id", data.user.id);
  await svc.from("user_roles").insert({ user_id: data.user.id, role });
  const c = createClient(url, anonKey, noSession);
  const s = await c.auth.signInWithPassword({ email, password });
  if (s.error) throw s.error;
  return { id: data.user.id, email, jwt: s.data.session!.access_token };
}
const tenderRow = async (id: string) => (await svc.from("tenders").select("*").eq("id", id).single()).data;
const ms = (t0: number) => Math.round(performance.now() - t0);

await svc.from("blockchain_nonces").delete().eq("wallet_address", relayer.address.toLowerCase());
if (!LIVE) await provider.send("anvil_setBalance", [buyer.address, ethers.toQuantity(ethers.parseEther("1000000"))]);
const signedIn: { u: { jwt: string }; email: string; password: string }[] = [];
async function signIn(email: string, password: string) {
  const s = await createClient(url, anonKey, noSession).auth.signInWithPassword({ email, password });
  if (s.error) throw s.error;
  const u = { id: s.data.user!.id, email, jwt: s.data.session!.access_token };
  signedIn.push({ u, email, password });
  return u;
}
// Local auth issues 15-minute JWTs; live scenarios run for hours, so refresh every actor's token every 10 minutes.
Deno.unrefTimer(setInterval(async () => {
  for (const a of signedIn) {
    const s = await createClient(url, anonKey, noSession).auth.signInWithPassword({ email: a.email, password: a.password });
    if (!s.error) a.u.jwt = s.data.session!.access_token; else console.error(`token refresh failed for ${a.email}: ${s.error.message}`);
  }
}, 600_000));
const ST = LIVE ? JSON.parse(Deno.readTextFileSync("" + (env("STATE") || "/home/ubuntu/paper2/eval/c2/state2.json") + "")) : null;
const admin = LIVE ? await signIn(ST.admin, ST.password) : await actor("admin", "admin");
const auditor = LIVE ? await signIn(ST.auditor, ST.password) : await actor("auditor", "auditor");
const NAMES = ["ALDER", "BIRCH", "CEDAR", "DOGWOOD", "ELM"];
const vendors: { user: Awaited<ReturnType<typeof actor>>; id: string; v32: string; key: TestPasskey; wallet: { address: string } }[] = [];
if (LIVE) {
  for (const v of ST.vendors) vendors.push({ user: await signIn(v.email, ST.password), id: v.vendor_id, v32: v.v32, key: await loadPk(v.jwk) as unknown as TestPasskey, wallet: { address: v.wallet } });
} else {
for (let i = 0; i < NAMES.length; i++) {
  const user = await actor(`vendor${i}`, "vendor");
  const wallet = new ethers.Wallet(devKey(4 + i), provider);
  const { data, error } = await svc.from("vendors").insert({ user_id: user.id, name: `${NAMES[i]} Ltd ${run}`, vendor_identifier: `${NAMES[i]}-${run}`, email: user.email, wallet_address: wallet.address }).select("id").single();
  if (error) throw error;
  vendors.push({ user, id: data.id, v32: vendorIdFromUuid(data.id), key: await createTestPasskey(), wallet });
}
let latest = 0;
for (const v of vendors) {
  await ok("manage-passkey", v.user.jwt, { action: "register", vendor_id: v.id, credential_id: `cred-${v.id.replaceAll("-", "")}`, public_key_x: v.key.qx, public_key_y: v.key.qy, assertion: await v.key.sign(registrationChallenge(v.v32, v.key.keyId)) });
  latest = Math.max(latest, Number((await procure.getPasskey(v.v32, v.key.keyId)).activeAt));
}
for (const v of vendors) {
  const k = await procure.getPasskey(v.v32, v.key.keyId);
  const activeAt = Math.min(Number(k.activeAt) * 1000, Date.now() - 1000);
  await svc.from("vendor_passkeys").update({ created_at: new Date(activeAt - PASSKEY_DELAY_MS).toISOString(), active_at: new Date(activeAt).toISOString() }).eq("vendor_id", v.id);
}
await warpTo(Math.max(latest, Math.floor(Date.now() / 1000)));
}
console.log(`setup done: ${vendors.length} vendors with active passkeys`);

async function evidence(sc: Scenario, tenderId: string, rec: Record<string, unknown>, tag: string) {
  let t0 = performance.now();
  const gen = await ok("generate-tender-evidence", admin.jwt, { tender_id: tenderId });
  const genMs = ms(t0);
  const packageId = String(gen.package_id);
  t0 = performance.now();
  const anc = await ok("anchor-evidence", admin.jwt, { package_id: packageId });
  const anchorMs = ms(t0);
  t0 = performance.now();
  const ver = await ok("verify-tender-evidence", auditor.jwt, { package_id: packageId });
  const verifyMs = ms(t0);
  const { data: pkg } = await svc.from("tender_evidence_packages").select("*").eq("id", packageId).single();
  const { data: blob, error } = await svc.storage.from(pkg.storage_bucket || "evidence-packages").download(pkg.storage_path);
  if (error) throw error;
  const zipPath = `${OUT}/${sc.id}${tag}.zip`;
  Deno.writeFileSync(zipPath, new Uint8Array(await blob.arrayBuffer()));
  const meta = { scenario: sc.id, tender_uuid: tenderId, package_id: packageId, package_version: pkg.package_version, package_hash: pkg.package_hash, manifest_hash: pkg.manifest_hash, anchor_tx_hash: pkg.anchor_tx_hash, anchor_block_number: pkg.anchor_block_number, anchor_contract_address: pkg.anchor_contract_address, chain_id: Number(CHAIN_ID), rpc_url: rpcUrl, procure_contract: procureAddress };
  Deno.writeTextFileSync(`${OUT}/${sc.id}${tag}.anchor.json`, JSON.stringify(meta, null, 2));
  const checks = (ver.checks ?? []) as { check: string; status: string }[];
  rec[`evidence${tag}`] = { ...meta, app_verification_status: ver.overall_status ?? ver.status ?? ver.verification_status, app_checks: checks.map((c) => `${c.check}:${c.status}`), timings_ms: { generate: genMs, anchor: anchorMs, app_verify: verifyMs }, anchor_response: anc.message ?? "anchored" };
  return { packageId, pkg };
}

async function runOne(sc: Scenario) {
  const rec: Record<string, unknown> = { scenario: sc.id, title: sc.title, currency: sc.currency, settlement: sc.settlement, bidders: sc.bids.length };
  try {
    const now = await chainNow();
    const commitDeadline = now + (sc.commitSec ?? 600), revealDeadline = commitDeadline + (sc.revealSec ?? 600);
    const { data: draft, error } = await svc.from("tenders").insert({ tender_id: `EVAL-${sc.id}-${run}`, title: `Paper 2 evaluation ${sc.id}: ${sc.title}`, status: "Open", created_by: admin.id, currency: sc.currency, settlement_mode: sc.settlement, commit_deadline: new Date(commitDeadline * 1000).toISOString(), reveal_deadline: new Date(revealDeadline * 1000).toISOString() }).select("id").single();
    if (error) throw error;
    const id = draft.id as string; rec.tender_uuid = id; rec.tender_ref = `EVAL-${sc.id}-${run}`;
    const pub = await ok("create-tender-onchain", admin.jwt, { tender_id: id });
    const contractId = String(pub.contract_tender_id); rec.contract_tender_id = contractId;
    const dom: CommitDomain = { chainId: CHAIN_ID, contract: procureAddress, tenderId: BigInt(contractId) };
    const nonce = (i: number) => `${sc.id}-${i}-${run}`;
    if (sc.revoke !== undefined) {
      const v = vendors[sc.revoke];
      const { data: pk } = await svc.from("vendor_passkeys").select("id").eq("vendor_id", v.id).is("revoked_at", null).single();
      const rv = await call("manage-passkey", v.user.jwt, { action: "revoke", passkey_id: pk!.id });
      const h = bidCommitment(dom, v.v32, 19_999_00n, ethers.keccak256(ethers.toUtf8Bytes(nonce(99))));
      const after = await call("blockchain-commit", v.user.jwt, { tender_id: id, vendor_id: v.id, commit_hash: h, key_id: v.key.keyId, assertion: await v.key.sign(commitDigest(dom, v.v32, h)) });
      let chainCheck = "accepted";
      try { await procure.commitBid.staticCall(BigInt(contractId), v.v32, h, v.key.keyId, await v.key.sign(commitDigest(dom, v.v32, h))); } catch (err) { chainCheck = "reverted: " + String((err as Error).message).slice(0, 90); }
      rec.revocation = { vendor: NAMES[sc.revoke], revoke_http: rv.status, revoke_tx: rv.json.tx_hash ?? null, commit_after_revoke_http: after.status, commit_error: String(after.json.error ?? "").slice(0, 120), contract_static_call: chainCheck };
    }
    if (sc.crossSig) {
      const v = vendors[sc.bids[0].v], other = vendors[(sc.bids[0].v + 1) % vendors.length];
      const h = bidCommitment(dom, v.v32, 1n, ethers.keccak256(ethers.toUtf8Bytes(nonce(98))));
      const r = await call("blockchain-commit", v.user.jwt, { tender_id: id, vendor_id: v.id, commit_hash: h, key_id: other.key.keyId, assertion: await other.key.sign(commitDigest(dom, v.v32, h)) });
      let chainCheck = "accepted";
      try { await procure.commitBid.staticCall(BigInt(contractId), v.v32, h, other.key.keyId, await other.key.sign(commitDigest(dom, v.v32, h))); } catch (err) { chainCheck = "reverted: " + String((err as Error).message).slice(0, 90); }
      rec.cross_signature = { vendor: NAMES[sc.bids[0].v], signer: NAMES[vendors.indexOf(other)], http: r.status, error: String(r.json.error ?? "").slice(0, 120), contract_static_call: chainCheck };
    }
    for (const [i, b] of sc.bids.entries()) {
      const v = vendors[b.v];
      const h = bidCommitment(dom, v.v32, b.amount, ethers.keccak256(ethers.toUtf8Bytes(nonce(i))));
      await ok("blockchain-commit", v.user.jwt, { tender_id: id, vendor_id: v.id, commit_hash: h, key_id: v.key.keyId, assertion: await v.key.sign(commitDigest(dom, v.v32, h)) });
    }
    if (sc.duplicate) {
      const v = vendors[sc.bids[0].v];
      const h = bidCommitment(dom, v.v32, 1n, ethers.keccak256(ethers.toUtf8Bytes(nonce(97))));
      const sig = await v.key.sign(commitDigest(dom, v.v32, h));
      const r = await call("blockchain-commit", v.user.jwt, { tender_id: id, vendor_id: v.id, commit_hash: h, key_id: v.key.keyId, assertion: sig });
      let chainCheck = "accepted";
      try { await procure.commitBid.staticCall(BigInt(contractId), v.v32, h, v.key.keyId, sig); } catch (err) { chainCheck = "reverted: " + String((err as Error).message).slice(0, 90); }
      rec.duplicate_commit = { vendor: NAMES[sc.bids[0].v], http: r.status, error: String(r.json.error ?? "").slice(0, 120), contract_static_call: chainCheck };
    }
    await groupWarp(sc, "commitDeadline", commitDeadline + 1);
    await ok("close-commit-phase", admin.jwt, { tender_id: id });
    const reveals: string[] = [];
    for (const [i, b] of sc.bids.entries()) {
      const v = vendors[b.v];
      const mode = b.reveal ?? "ok";
      if (mode === "none") { reveals.push(`${NAMES[b.v]}: not revealed`); continue; }
      const { data: bid } = await svc.from("bids").select("id").eq("tender_id", id).eq("vendor_id", v.id).single();
      const amt = mode === "wrong" ? b.amount + 1n : b.amount;
      const r = await call("blockchain-reveal", v.user.jwt, { bid_id: bid!.id, bid_amount: Number(amt), nonce: nonce(i) });
      reveals.push(`${NAMES[b.v]}: ${mode} -> HTTP ${r.status}${r.status !== 200 ? " " + String(r.json.error ?? "").slice(0, 80) : ""}`);
      if (mode === "ok" && r.status !== 200) throw new Error(`reveal failed ${JSON.stringify(r.json)}`);
    }
    rec.reveals = reveals;
    await groupWarp(sc, "revealDeadline", revealDeadline + 1);
    await ok("close-reveal-phase", admin.jwt, { tender_id: id });
    const evalR = await call("evaluate-tender-onchain", admin.jwt, { tender_id: id });
    rec.evaluate = { http: evalR.status, error: evalR.status === 200 ? null : String(evalR.json.error ?? "").slice(0, 160) };
    const row = await tenderRow(id);
    const chainT = await procure.getTender(contractId);
    // Expected: lowest correctly revealed bid, ties to the lower bytes32 vendor ID.
    const valid = sc.bids.filter((b) => (b.reveal ?? "ok") === "ok");
    valid.sort((a, b) => a.amount !== b.amount ? (a.amount < b.amount ? -1 : 1) : (BigInt(vendors[a.v].v32) < BigInt(vendors[b.v].v32) ? -1 : 1));
    const exp = valid[0];
    if (!exp) {
      const r0 = await tenderRow(id), c0 = await procure.getTender(contractId);
      rec.award = { db_status: r0?.status, chain_status: Number(c0.status), chain_winner: c0.winner };
    } else {
    if (evalR.status !== 200) throw new Error(`evaluate failed ${JSON.stringify(evalR.json)}`);
    rec.award = { db_status: row?.status, db_winner: NAMES[vendors.findIndex((v) => v.id === row?.winning_vendor_id)], db_winning_bid_minor: row?.winning_bid_minor, chain_status: Number(chainT.status), chain_winner_matches_db: chainT.winner === vendorIdFromUuid(row?.winning_vendor_id), chain_winning_bid: chainT.winningBid.toString(), expected_winner: NAMES[exp.v], expected_bid: exp.amount.toString(), matches_expected: chainT.winner === vendors[exp.v].v32 && chainT.winningBid === exp.amount };
    const winner = vendors[exp.v];
    if (sc.regenerate) await evidence(sc, id, rec, "_v1");
    if (sc.escrow !== "none") {
      if (sc.settlement === "recorded") {
        await ok("fund-escrow", admin.jwt, { tender_id: id, payment_reference: `BANK-${sc.id}-${run}` });
        if (sc.escrow === "release") await ok("release-escrow", admin.jwt, { tender_id: id, payment_reference: `PAY-${sc.id}-${run}` });
        else {
          const ref = `REFUND-${sc.id}-${run}`;
          await ok("refund-escrow", admin.jwt, { action: "request", tender_id: id, payment_reference: ref });
          const digest = recordedRefundDigest({ chainId: CHAIN_ID, contract: escrowAddress, tenderId: BigInt(contractId) }, winner.v32, paymentRefHash(ref));
          await ok("refund-escrow", winner.user.jwt, { action: "approve", tender_id: id, key_id: winner.key.keyId, assertion: await winner.key.sign(digest) });
        }
      } else {
        if (!LIVE) throw new Error("FLR escrow skipped on fork: real FTSO proofs are stale after the 72 h warp");
        const digest = await escrow.payeeDigest(contractId, winner.v32, buyer.address);
        const auth = await winner.key.sign(digest);
        const [fd] = await (await fetch(DA, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ feed_ids: ["0x01464c522f55534400000000000000000000000000"] }) })).json();
        const priceData = ethers.AbiCoder.defaultAbiCoder().encode(["tuple(bytes32[] proof, tuple(uint32 votingRoundId, bytes21 id, int32 value, uint16 turnoutBIPS, int8 decimals) body)"], [[fd.proof, [fd.body.votingRoundId, fd.body.id, fd.body.value, fd.body.turnoutBIPS, fd.body.decimals]]]);
        const amountWei = await escrow.toWei(exp.amount, BigInt(fd.body.value), fd.body.decimals);
        rec.ftso = { voting_round: fd.body.votingRoundId, value: fd.body.value, decimals: fd.body.decimals };
        const tx = await (escrow.connect(buyer) as ethers.Contract).fundEscrow(contractId, buyer.address, winner.key.keyId, auth, priceData, { value: amountWei + amountWei / 50n });
        await tx.wait(1);
        await ok("fund-escrow", admin.jwt, { tender_id: id, funding_tx_hash: tx.hash });
        await ok("release-escrow", admin.jwt, { tender_id: id });
        rec.flr_amount_wei = amountWei.toString();
      }
      rec.escrow_status = (await tenderRow(id))?.escrow_status;
    }
    }
    if (sc.omit === "reveal") {
      const loser = vendors[sc.bids.find((b) => b.v !== exp.v)!.v];
      const { data: lb } = await svc.from("bids").select("id").eq("tender_id", id).eq("vendor_id", loser.id).single();
      await svc.from("bids").update({ revealed_bid_amount: null, revealed_bid_minor: null, status: "committed" }).eq("id", lb!.id);
      const { data: evs } = await svc.from("events").select("id, payload").eq("tender_id", id).eq("event_type", "BID_REVEAL");
      const gone = (evs ?? []).filter((x) => JSON.stringify(x.payload ?? {}).includes(lb!.id) || JSON.stringify(x.payload ?? {}).includes(loser.id));
      for (const x of gone) await svc.from("events").delete().eq("id", x.id);
      rec.omitted = { bid_id: lb!.id, vendor: NAMES[vendors.indexOf(loser)], reveal_events_deleted: gone.length };
    } else if (sc.omit === "governance_note") {
      const { data: note, error: ne } = await svc.from("governance_notes").insert({ tender_id: id, author_user_id: admin.id, author_role: "admin", note_type: "general", text: "Evaluation panel conflict-of-interest declaration (deleted before export)" }).select("id").single();
      if (ne) throw ne;
      await svc.from("governance_notes").delete().eq("id", note.id);
      rec.omitted = { governance_note_id: note.id };
    }
    const e = await evidence(sc, id, rec, sc.regenerate ? "_v2" : "");
    {
      // A1: regenerating with unchanged records must return the same package and digest.
      const again = await ok("generate-tender-evidence", admin.jwt, { tender_id: id });
      rec.unchanged_regeneration = { same_package: again.package_id === e.packageId, same_digest: again.package_hash === e.pkg.package_hash, unchanged_flag: again.unchanged === true };
    }
    if (sc.regenerate) {
      // On-chain rules of the tender-bound anchor: duplicate hash and older version must revert.
      const tenderRef = ethers.keccak256(ethers.toUtf8Bytes(id));
      const v1 = rec["evidence_v1"] as { package_hash: string };
      const tries: Record<string, string> = {};
      for (const [label, ver, h] of [["re-anchor v1 hash as v3", 3, v1.package_hash], ["anchor new hash as v1 (older)", 1, ethers.id("x")], ["anchor v2 hash again as v2", 2, e.pkg.package_hash]] as const) {
        try { await anchor.anchorEvidence.staticCall(tenderRef, ver, h); tries[label] = "ACCEPTED"; } catch (err) { tries[label] = "reverted: " + String((err as Error).message).slice(0, 90); }
      }
      rec.anchor_rule_checks = tries;
    }
    rec.result = "completed";
  } catch (err) {
    rec.result = "error"; rec.error = String((err as Error).message).slice(0, 400);
  }
  console.log(JSON.stringify(rec));
  log.push(rec);
}
const ONLY = env("ONLY") ? env("ONLY").split(",") : null;
const todo = S.filter((sc) => !ONLY || ONLY.includes(sc.id) || (sc.group && ONLY.includes(sc.group)));
for (let k = 0; k < todo.length; k++) {
  const sc = todo[k];
  if (sc.group) {
    const g = todo.filter((x) => x.group === sc.group);
    await Promise.all(g.map((x) => runOne(x)));
    k += g.length - 1;
  } else await runOne(sc);
  Deno.writeTextFileSync(`${OUT}/scenario_results.json`, JSON.stringify(log, null, 2));
}
Deno.writeTextFileSync(`${OUT}/scenario_results.json`, JSON.stringify(log, null, 2));
provider.destroy();
