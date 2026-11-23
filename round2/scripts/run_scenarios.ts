// Bounded evaluation driver for paper 2 (local only: local Supabase + Anvil, contracts v2).
// Drives the real F-Procure edge functions for 10 synthetic tenders, then exports each
// evidence package ZIP plus a small metadata file for the standalone verifier.
import { createClient } from "npm:@supabase/supabase-js@2.87.1";
import { ethers } from "npm:ethers@6.16.0";
import {
  bidCommitment, commitDigest, type CommitDomain, PASSKEY_DELAY_MS, paymentRefHash,
  recordedRefundDigest, registrationChallenge, vendorIdFromUuid,
} from "/home/ubuntu/wt-e2e/supabase/functions/_lib/passkey.ts";
import { createTestPasskey, type TestPasskey } from "/home/ubuntu/wt-e2e/supabase/functions/_lib/passkey-test-utils.ts";

const env = (k: string) => Deno.env.get(k) ?? "";
const url = env("SB_URL"), anonKey = env("SB_ANON"), serviceKey = env("SB_SERVICE");
const rpcUrl = env("RPC") || "http://127.0.0.1:8545";
const procureAddress = env("PROCURE"), escrowAddress = env("ESCROW"), anchorAddress = env("ANCHOR");
const OUT = env("OUT") || "/home/ubuntu/paper2/eval/v2/packages";
Deno.mkdirSync(OUT, { recursive: true });
const CHAIN_ID = BigInt(env("CHAIN_ID") || "31337");
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
}
const S: Scenario[] = [
  { id: "S01", title: "Single bidder, recorded escrow released", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 48_500_00n }], escrow: "release" },
  { id: "S02", title: "Two bidders, recorded escrow released", currency: "EUR", settlement: "recorded", bids: [{ v: 0, amount: 1_650_000_00n }, { v: 1, amount: 1_720_000_00n }], escrow: "release" },
  { id: "S03", title: "Three bidders, no escrow step", currency: "GBP", settlement: "recorded", bids: [{ v: 0, amount: 125_000_00n }, { v: 1, amount: 98_000_00n }, { v: 2, amount: 110_500_00n }], escrow: "none" },
  { id: "S04", title: "Five bidders, recorded escrow released", currency: "KYD", settlement: "recorded", bids: [{ v: 0, amount: 310_000_00n }, { v: 1, amount: 295_250_00n }, { v: 2, amount: 301_000_00n }, { v: 3, amount: 287_900_00n }, { v: 4, amount: 322_400_00n }], escrow: "release" },
  { id: "S05", title: "Tie on lowest bid (lower vendor ID wins)", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 75_000_00n }, { v: 1, amount: 75_000_00n }, { v: 2, amount: 80_000_00n }], escrow: "none" },
  { id: "S06", title: "Lowest bidder never reveals (excluded)", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 50_000_00n, reveal: "none" }, { v: 1, amount: 61_000_00n }, { v: 2, amount: 64_500_00n }], escrow: "none" },
  { id: "S07", title: "Reveal with wrong amount rejected", currency: "EUR", settlement: "recorded", bids: [{ v: 0, amount: 40_000_00n, reveal: "wrong" }, { v: 1, amount: 42_000_00n }], escrow: "none" },
  { id: "S08", title: "FLR escrow funded by buyer and released", currency: "USD", settlement: "flr", bids: [{ v: 0, amount: 1_250_00n }, { v: 1, amount: 1_400_00n }], escrow: "release" },
  { id: "S09", title: "Recorded escrow refunded with winner's passkey approval", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 22_000_00n }, { v: 1, amount: 19_750_00n }], escrow: "refund" },
  { id: "S10", title: "Evidence regenerated after escrow (v1 then v2 anchored)", currency: "GBP", settlement: "recorded", bids: [{ v: 2, amount: 9_900_00n }, { v: 3, amount: 9_450_00n }], escrow: "release", regenerate: true },
  { id: "S11", title: "Losing reveal deleted from the database before package generation", currency: "USD", settlement: "recorded", bids: [{ v: 0, amount: 70_000_00n }, { v: 1, amount: 66_000_00n }, { v: 2, amount: 72_500_00n }], escrow: "none", omit: "reveal" },
  { id: "S12", title: "Governance note deleted before package generation (off-chain only)", currency: "EUR", settlement: "recorded", bids: [{ v: 3, amount: 15_000_00n }, { v: 4, amount: 14_200_00n }], escrow: "none", omit: "governance_note" },
];

const svc = createClient(url, serviceKey, noSession);
const provider = new ethers.JsonRpcProvider(rpcUrl, undefined, { cacheTimeout: -1, pollingInterval: 250 });
const relayer = new ethers.Wallet(devKey(0), provider);
const buyer = new ethers.Wallet(devKey(3), provider);
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
async function warpTo(ts: number) {
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
await provider.send("anvil_setBalance", [buyer.address, ethers.toQuantity(ethers.parseEther("1000000"))]);
const admin = await actor("admin", "admin");
const auditor = await actor("auditor", "auditor");
const NAMES = ["ALDER", "BIRCH", "CEDAR", "DOGWOOD", "ELM"];
const vendors: { user: Awaited<ReturnType<typeof actor>>; id: string; v32: string; key: TestPasskey; wallet: ethers.Wallet }[] = [];
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

for (const sc of S) {
  const rec: Record<string, unknown> = { scenario: sc.id, title: sc.title, currency: sc.currency, settlement: sc.settlement, bidders: sc.bids.length };
  try {
    const now = await chainNow();
    const commitDeadline = now + 600, revealDeadline = now + 1200;
    const { data: draft, error } = await svc.from("tenders").insert({ tender_id: `EVAL-${sc.id}-${run}`, title: `Paper 2 evaluation ${sc.id}: ${sc.title}`, status: "Open", created_by: admin.id, currency: sc.currency, settlement_mode: sc.settlement, commit_deadline: new Date(commitDeadline * 1000).toISOString(), reveal_deadline: new Date(revealDeadline * 1000).toISOString() }).select("id").single();
    if (error) throw error;
    const id = draft.id as string; rec.tender_uuid = id; rec.tender_ref = `EVAL-${sc.id}-${run}`;
    const pub = await ok("create-tender-onchain", admin.jwt, { tender_id: id });
    const contractId = String(pub.contract_tender_id); rec.contract_tender_id = contractId;
    const dom: CommitDomain = { chainId: CHAIN_ID, contract: procureAddress, tenderId: BigInt(contractId) };
    const nonce = (i: number) => `${sc.id}-${i}-${run}`;
    for (const [i, b] of sc.bids.entries()) {
      const v = vendors[b.v];
      const h = bidCommitment(dom, v.v32, b.amount, ethers.keccak256(ethers.toUtf8Bytes(nonce(i))));
      await ok("blockchain-commit", v.user.jwt, { tender_id: id, vendor_id: v.id, commit_hash: h, key_id: v.key.keyId, assertion: await v.key.sign(commitDigest(dom, v.v32, h)) });
    }
    await warpTo(commitDeadline + 1);
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
    await warpTo(revealDeadline + 1);
    await ok("close-reveal-phase", admin.jwt, { tender_id: id });
    await ok("evaluate-tender-onchain", admin.jwt, { tender_id: id });
    const row = await tenderRow(id);
    const chainT = await procure.getTender(contractId);
    // Expected: lowest correctly revealed bid, ties to the lower bytes32 vendor ID.
    const valid = sc.bids.filter((b) => (b.reveal ?? "ok") === "ok");
    valid.sort((a, b) => a.amount !== b.amount ? (a.amount < b.amount ? -1 : 1) : (BigInt(vendors[a.v].v32) < BigInt(vendors[b.v].v32) ? -1 : 1));
    const exp = valid[0];
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
        const digest = await escrow.payeeDigest(contractId, winner.v32, winner.wallet.address);
        const auth = await winner.key.sign(digest);
        const amountWei = await escrow.toWei(exp.amount, FTSO_PRICE, FTSO_DECIMALS);
        const tx = await (escrow.connect(buyer) as ethers.Contract).fundEscrow(contractId, winner.wallet.address, winner.key.keyId, auth, { value: amountWei });
        await tx.wait(1);
        await ok("fund-escrow", admin.jwt, { tender_id: id, funding_tx_hash: tx.hash });
        await ok("release-escrow", admin.jwt, { tender_id: id });
        rec.flr_amount_wei = amountWei.toString();
      }
      rec.escrow_status = (await tenderRow(id))?.escrow_status;
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
Deno.writeTextFileSync(`${OUT}/scenario_results.json`, JSON.stringify(log, null, 2));
provider.destroy();
