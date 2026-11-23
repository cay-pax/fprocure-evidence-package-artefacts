# Tender Evidence Package specification (schema 1.1.0)

A package is a ZIP archive of flat entries: twelve JSON artefacts and `manifest.json`.

| File | Content |
|---|---|
| tender.json | Tender record, status, deadlines, winning bid and escrow fields, creation and award transaction hashes, `contract_tender_id` |
| bids.json | Bids with commitment hash, passkey assertion, passkey identifier, commitment transaction hash, revealed amount and status |
| passkeys.json | Public keys of the vendors' bid-signing passkeys, with active/revoked times |
| events.json | Lifecycle events with transaction hashes |
| anomalies.json | Advisory anomaly flags |
| governance_notes.json | Governance notes and approvals recorded in the platform |
| erp_sync.json | ERP synchronisation logs |
| escrow.json | Escrow state and settlement references |
| onchain_references.json | Event type, transaction hash, network and time for each on-chain event |
| chain_context.json | `chain_id`, `chain_name`, `procure_contract`, `escrow_contract`, `anchor_contract` (hints only: verifiers take addresses from the deployment record) |
| audit_export.json | Record counts |
| verifier_instructions.json | Human-readable verification steps (format 1.1.0) |
| manifest.json | `schema_version`, `package_type` (`tender_evidence_package`), `tender_id`, `tender_ref`, `package_version`, `files[] = {name, sha256}` |

## Rules

- **Serialisation:** JSON with object keys sorted recursively, array order preserved, two-space indentation. This is implementation-specific, not RFC 8785.
- **Sorting:** record arrays are sorted by `created_at`, then `id`; manifest and archive entries are sorted by name.
- **Digests:** each file's SHA-256 is in the manifest (`0x`-prefixed hex). The **package digest** is the SHA-256 of the complete ZIP bytes and is the anchored value.
- **Archive:** every ZIP entry has the fixed timestamp 2024-01-01 00:00.
- **Timestamps:** no generation or export time is hashed.
- **Versioning:** regeneration with every file digest equal to the latest package returns that package unchanged; otherwise the package receives the next `package_version`.
- **Required files:** 1.1.0 requires all twelve artefacts. 1.0.0 lacks `chain_context.json`, hashes `manifest.generated_at` and `audit_export.exported_at` (so regeneration changes the digest), and early 1.0.0 packages lack `passkeys.json`.
- Bid salts and other secrets are never included.

## Anchor and procurement-contract interfaces read by the verifier

```solidity
// Tender-bound evidence anchor (second contract version)
event EvidenceAnchored(bytes32 indexed tenderRef, uint32 indexed version, bytes32 indexed packageHash, address submitter, uint256 timestamp);
mapping(bytes32 => mapping(uint32 => bytes32)) public anchors;
mapping(bytes32 => uint32) public latestVersion;
mapping(bytes32 => bool) public hashAnchored;
// tenderRef = keccak256(utf8(manifest.tender_id)); owner-only; versions strictly increase; each digest is anchored once

// Event-only evidence anchor (first contract version, Coston2)
event EvidenceAnchored(bytes32 indexed packageHash, address indexed submitter, uint256 timestamp);

// Procurement contract events read by step 12 (second contract version)
event TenderCreated(uint256 indexed tenderId, bytes32 indexed externalId, bytes3 currency, uint64 commitDeadline, uint64 revealDeadline); // externalId = keccak256(tender UUID)
event BidCommitted(uint256 indexed tenderId, bytes32 indexed vendorId, bytes32 commitHash, bytes32 keyId);
event BidRevealed(uint256 indexed tenderId, bytes32 indexed vendorId, uint256 amount);
event TenderAwarded(uint256 indexed tenderId, bytes32 indexed winner, uint256 amount);

// Passkey challenge checked by step 13
// commitDigest = keccak256(abi.encode(keccak256("FProcureCommit(uint256 chainId,address verifyingContract,uint256 tenderId,bytes32 vendorId,bytes32 commitHash)"),
//                                     chainId, procurementContract, tenderId, vendorId, commitHash))
```

Signatures are copied from the F-Procure contracts. `passkeys.json` entries carry `vendor_id`, `key_id`, `public_key_x`, `public_key_y`, `active_at` and `revoked_at`.
