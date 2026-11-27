# Coston2 live run: contracts v2 (27 November 2026)

Twenty-two synthetic tenders (scenarios S01 to S19) were run against F-Procure's second contract version on **Coston2, Flare's public test network (chain ID 114)**, with real commit and reveal deadlines. All tenders, vendors and amounts are synthetic; Coston2 tokens have no monetary value.

## Deployment

| Contract | Address |
|---|---|
| FProcure | `0x1B131C70BBcAbE1f56c2906109a4Aa1b071F7A43` |
| FProcureEscrow | `0x4c9909C573fAb35E0a85Af67ab09b4193D8f0c9f` |
| EvidenceAnchor | `0x6DeB87c638bD372202021D00017Df9240f340543` |
| FtsoV2PriceSource | `0xf8aF109fCa717Ac2b5CBe802Dc64cFb3Fa41c6c5` |

- Deployed on 24 November 2026 (blocks 38218958 to 38218962) from F-Procure commit `b3c5b31`, by the research wallet `0x33d87b3AC5460BD9DAD7eF888DA21E01d0315c4e`, which is the contracts' owner and operator.
- Five test vendors registered P-256 passkeys on 24 November; the contract's 72-hour activation delay meant they became usable at 2026-11-27T00:39:44Z.
- The platform's backend functions (F-Procure commit `b3c5b31`) ran against a local Supabase stack and sent every transaction to Coston2.
- Explorer: <https://coston2-explorer.flare.network/address/0x1B131C70BBcAbE1f56c2906109a4Aa1b071F7A43>

## Scenarios

| Scenario | Title | Currency | Bidders | Contract tender | Winner | Escrow |
|---|---|---|---|---|---|---|
| S01 | Single bidder, recorded escrow released | USD | 1 | 2 | ALDER | released |
| S02 | Two bidders, recorded escrow released | EUR | 2 | 24 | ALDER | released |
| S03 | Three bidders, no escrow step | GBP | 3 | 4 | BIRCH | not used |
| S04 | Five bidders, recorded escrow released | KYD | 5 | 5 | DOGWOOD | released |
| S05 | Tie on lowest bid (lower vendor ID wins) | USD | 3 | 6 | BIRCH | not used |
| S06 | Lowest bidder never reveals (excluded) | USD | 3 | 7 | BIRCH | not used |
| S07 | Reveal with wrong amount rejected | EUR | 2 | 8 | BIRCH | not used |
| S08 | FLR escrow funded by buyer and released | USD | 2 | 25 | ALDER | released |
| S09 | Recorded escrow refunded with winner's passkey approval | USD | 2 | 10 | BIRCH | refunded |
| S10 | Evidence regenerated after escrow (v1 then v2 anchored) | GBP | 2 | 11 | DOGWOOD | released |
| S11 | Losing reveal deleted from the database before package generation | USD | 3 | 12 | BIRCH | not used |
| S12 | Governance note deleted before package generation (off-chain only) | EUR | 2 | 13 | ELM | not used |
| S13 | No bids submitted (no award) | USD | 0 | 14 | none (no valid bid) | not used |
| S14 | Bids committed but none revealed (no valid bid) | EUR | 2 | 15 | none (no valid bid) | not used |
| S15 | Commit signed with another vendor's passkey rejected | USD | 2 | 16 | CEDAR | not used |
| S16 | Second commit by the same vendor rejected | GBP | 2 | 17 | DOGWOOD | not used |
| S17a | Concurrent tender A (overlapping windows) | USD | 2 | 19 | BIRCH | released |
| S17b | Concurrent tender B (overlapping windows) | EUR | 3 | 20 | CEDAR | not used |
| S17c | Concurrent tender C (overlapping windows) | KYD | 2 | 18 | ELM | released |
| S18a | Short windows (5 min commit, 5 min reveal) | USD | 2 | 21 | DOGWOOD | released |
| S18b | Long windows (60 min commit, 60 min reveal) | GBP | 3 | 22 | CEDAR | released |
| S19 | Passkey revoked, then the vendor's bid is rejected | USD | 2 | 23 | BIRCH | not used |

S13 and S14 have no valid bid, so the tender closes without an award. S15 (commit signed with another vendor's passkey), S16 (second commit by the same vendor) and S19 (bid after passkey revocation) check that the platform and the contract reject the invalid action while the tender completes. S11 deletes a losing reveal and S12 a governance note from the database before the package is generated. S08 funds escrow in C2FLR, priced with a proof-checked FTSO v2 FLR/USD anchor feed. S10 regenerates the package after escrow, so it has two anchored versions.

## Results

- `results/scenario_results.json`: per-scenario outcome, on-chain award checks, escrow state, evidence package hash, anchor transaction and the platform's own verification checks.
- `results/receipts.json`: status, block and log count for all 200 transactions the platform sent; every one succeeded.
- `results/tamper_results.json` and `results/tamper_summary.txt`: the standalone verifier (`../verifier/`, F-Procure commit `a8aac0a`) on each unmodified package and on 15 tampered or mismatched variants of each, verified against Coston2.

Standalone verifier on Coston2 (all 13 steps against the public chain):

| Case | Packages | Result |
|---|---|---|
| Unmodified (T0) | 23 | 22 pass. S11 fails step 12 as designed: its losing reveal was deleted from the database, and the chain still records it. S13 has no bids, so step 13 (passkey assertions) is skipped. |
| Tampered or mismatched (T1 to T15) | 23 × 15 = 345 | All 345 rejected |

S12 passes although a governance note was deleted before export: the verifier cannot detect a missing off-chain record that was never anchored. For T5 (anchor transaction of another package) the other package is a neighbouring package from the same run; the matrix was run in eight batches on the public RPC with retries after HTTP 429 responses (`scripts/tamper_retry.py`), which does not change any verification step.

## Tenders not in the results

Three contract tenders on this deployment are not part of the evaluation. They were left incomplete by driver faults that were fixed before the reruns. Their transactions remain on-chain:

| Contract tender | Cause | Rerun as |
|---|---|---|
| 1 | Driver authentication tokens expired (15-minute local lifetime) before S01's reveal phase closed | S01, tender 2 |
| 3 | The evaluation machine was suspended mid-tender, so S02's reveal arrived after its deadline | S02, tender 24 |
| 9 | S08 tried to fund escrow from the contract admin wallet, which the escrow contract forbids | S08, tender 25, funded by a separate buyer wallet |

## Re-verifying a package

```bash
cd ../verifier && pip install -r requirements.txt
python verify_tep.py ../coston2-live/packages/S03.zip --rpc https://coston2-api.flare.network/ext/C/rpc --chain-id 114 \
  --tx <anchor_tx_hash from S03.anchor.json> --contract 0x6DeB87c638bD372202021D00017Df9240f340543 \
  --procure-contract 0x1B131C70BBcAbE1f56c2906109a4Aa1b071F7A43
```

## Scripts

`scripts/run.ts` (Deno) is the driver as run (`MODE=live`), `scripts/pk.ts` the software passkey used by the test vendors, and `scripts/tamper_matrix.py` the negative-case builder. They keep the evaluation machine's absolute paths, need an F-Procure checkout (proprietary, not included) and a local Supabase stack, and read every key from the environment. The password in `run.ts` is a local-only test value.
