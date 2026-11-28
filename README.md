# F-Procure Tender Evidence Package: reproducibility artefacts

Artefacts for the paper *From Tamper-Evident Execution to Portable Procurement Assurance: Tender Evidence Packages and Independent Verification in F-Procure* (P. Ola and V. Muñoz Albornoz). The bundle contains the package specification, the standalone verifier, every evaluated package with its anchor record, the scripts that produced them, and the raw results.

All tenders, vendors and amounts are synthetic. Rounds 1 and 2 were anchored on a **local Anvil chain (chain ID 31337)** using the second F-Procure contract version, so their on-chain steps can only be re-run against a re-created local environment. The Coston2 live run used the same contract version on **Coston2, Flare's public test network (chain ID 114)**, so anyone can re-verify its packages against the public chain. Other Coston2 references are in [coston2/REFERENCES.md](coston2/REFERENCES.md).

## Contents

| Path | What it is |
|---|---|
| [SPECIFICATION.md](SPECIFICATION.md) | Tender Evidence Package specification (schema 1.1.0, with the 1.0.0 differences) and the contract interfaces the verifier reads |
| [verifier/](verifier/) | Standalone 13-step verifier, hardened release (v1.2), with 37 offline unit tests |
| [coston2-live/](coston2-live/) | Coston2 live run, contracts v2: 22 scenarios (S01 to S19), 23 packages and anchor records, all 261 transaction receipts, scripts, results |
| [round2/](round2/) | Schema 1.1.0: 12 scenarios, 14 packages and anchor records, the verifier exactly as evaluated, scripts, results (210 negative cases) |
| [round1/](round1/) | Schema 1.0.0: 10 scenarios, 11 anchored packages plus 2 boundary-test packages, the ten-step verifier, scripts, results (88 negative cases) |
| [coston2/REFERENCES.md](coston2/REFERENCES.md) | Coston2 contract and transaction references |

## Quick start (no blockchain needed)

```bash
cd verifier
pip install -r requirements.txt
python -m unittest test_verify_tep          # 37 offline tests
python verify_tep.py ../round2/packages/S03.zip
```

Without `--rpc`, steps 1–8 and 13 run from the archive alone and steps 9–12 are reported as skipped. Skipped steps do not fail the overall result, so treat a skipped step as not verified: a full verification must confirm that steps 9–13 ran. Each package's SHA-256 should equal `package_hash` in its `.anchor.json`.

## Full verification (on-chain steps)

```bash
python verify_tep.py PACKAGE.zip --rpc <JSON-RPC URL> --chain-id <id> --tx <anchor tx> \
  --contract <anchor contract> --procure-contract <procurement contract>
```

Take both contract addresses from the operator's deployment record, not from the package. For the round-2 packages these are in each `.anchor.json`, and they exist only on the local chain used for the evaluation. For the Coston2 live run they are listed in [coston2-live/README.md](coston2-live/README.md).

## Re-running the evaluation

The scripts in `round*/scripts/` are kept exactly as run, including the absolute paths of the evaluation machine. They need an F-Procure checkout (proprietary, not included), a local Supabase stack and Anvil with the second contract version deployed:

| Round | F-Procure commit | Verifier |
|---|---|---|
| 1 | `7b87438` | `round1/verifier/verify_tep.py` (ten steps) |
| 2 | `60ca660` | `round2/verifier/verify_tep.py` (13 steps; F-Procure commit `5160598`) |

`run_scenarios.ts` (Deno) drives the platform's backend functions for each scenario and exports each package. `tamper_matrix.py` builds the negative cases and runs the standalone verifier. `app_side.py` exercises the platform's built-in verifier. The test wallets are derived from Anvil's public development mnemonic, and the passwords are local-only test values.

`verifier/` holds the hardened verifier (F-Procure commit `a8aac0a`). Since `661ab5b` it also rejects non-string tender IDs, refuses oversized archives before reading them, and fails the on-chain lifecycle check instead of scanning the chain from its first block when a package records no tender transaction. It accepts only stored or DEFLATE entries, adds archive size limits (256 MiB in total, 64 MiB per entry, checked before reading) and has stricter step-12 identity checks. Unreadable entries, incomplete manifests, missing passkey fields, unparseable JSON and a non-numeric chain ID now fail a step instead of crashing the verifier or, for unparseable bid records, skipping step 13. On the 14 round-2 packages it gives the same results as the evaluated verifier: 13 of 14 unmodified packages pass, and all 210 negative cases are rejected.

## What verification proves

It proves package integrity and correspondence with the ledger anchor. It also proves that every procurement-contract event for the tender is in the package, and that each bid's passkey assertion is valid. It does **not** prove that off-chain records (for example governance notes) are complete, or that records are accurate, authorised or compliant. Scenario S12 demonstrates this.
