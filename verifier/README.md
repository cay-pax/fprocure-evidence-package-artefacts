# Standalone evidence package verifier

`verify_tep.py` checks an F-Procure Tender Evidence Package without F-Procure or its database.
It needs the ZIP and, for the on-chain steps, a JSON-RPC endpoint for the chain the tender ran on.

```bash
pip install -r requirements.txt
python verify_tep.py package.zip --rpc <RPC URL> --chain-id <id> --tx <anchor tx hash> \
  --contract <anchor contract> --procure-contract <procurement contract>
```

Take both contract addresses from a source other than the package, such as the operator's published deployment record. `chain_context.json` names them, but a package supplier could name its own contracts, so the on-chain steps are skipped until you pass them.
Public Flare RPCs cap `eth_getLogs` ranges; `--log-span` (default 30 blocks) splits the search.

## What it proves and what it does not

- Steps 1 to 8 check structural completeness: the required files for the schema version are present, unaltered and the only files.
- Steps 9 to 11 check that the package digest is anchored for this tender and version.
- Step 12 checks that every commit, reveal and award the procurement contract emitted for the tender is in the package.
- Step 13 re-verifies each bid's passkey assertion against the public key in `passkeys.json`.

Malformed input fails a step and never stops the report: oversized archives (256 MiB total, 64 MiB per entry, checked before reading) fail step 2, unreadable entries step 6, manifest entries without a name and hash step 3, and unparseable or wrongly typed JSON step 8. In schema 1.1.0 every commitment must carry a passkey signature.
- It cannot detect an off-chain record (for example a governance note) removed before the package was generated, and it does not prove records are accurate, authorised or compliant.

`python -m unittest test_verify_tep` runs the offline tests.
