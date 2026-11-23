"""Offline tests for verify_tep.py: structure, required files and passkey assertions."""
import base64, hashlib, io, json, unittest, zipfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import verify_tep as v

CHAIN, PROCURE, TID = 31337, "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707", 3
VENDOR, TENDER = "fd003b24-c9a7-4a40-9c6a-60a80c215818", "9f58489f-65b7-4ec4-9a3a-da789141dc8f"
COMMIT = "0x" + "ab" * 32


def stable(o):
    return json.dumps(o, sort_keys=True, indent=2)


def sign_bid(key, commit_hash, domain=(CHAIN, PROCURE, TID)):
    challenge = v.commit_digest(*domain, v.vendor_id(VENDOR), commit_hash)
    cd = json.dumps({"type": "webauthn.get", "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="), "origin": "https://fprocure.example"}, separators=(",", ":"))
    auth = bytes(32) + bytes([0x05]) + bytes(4)
    r, s = decode_dss_signature(key.sign(auth + hashlib.sha256(cd.encode()).digest(), ec.ECDSA(hashes.SHA256())))
    if s > v.P256_N // 2: s = v.P256_N - s
    return {"authenticatorData": "0x" + auth.hex(), "clientDataJSON": cd, "challengeIndex": cd.index('"challenge"'), "typeIndex": cd.index('"type"'), "r": hex(r), "s": hex(s)}


def package(mutate=None, offchain=False):
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_numbers()
    qx, qy = "0x%064x" % pub.x, "0x%064x" % pub.y
    key_id = v.k256(v.word(qx) + v.word(qy))
    domain = (0, "0x" + "00" * 20, int(TENDER.replace("-", ""), 16)) if offchain else (CHAIN, PROCURE, TID)
    sig = sign_bid(key, COMMIT, domain) | {"key_id": key_id}
    files = {n: [] for n in v.REQUIRED_FILES["1.1.0"]}
    files.update({
        "tender.json": {"id": TENDER, "contract_tender_id": None if offchain else TID},
        "bids.json": [{"id": "b1", "vendor_id": VENDOR, "commit_hash": COMMIT, "commit_signature": sig, "created_at": "2026-11-22T10:00:00Z"}],
        "passkeys.json": [{"id": "p1", "vendor_id": VENDOR, "key_id": key_id, "public_key_x": qx, "public_key_y": qy, "active_at": "2026-11-19T10:00:00Z", "revoked_at": None}],
        "chain_context.json": {"chain_id": CHAIN, "chain_name": "anvil", "procure_contract": PROCURE, "escrow_contract": None, "anchor_contract": None},
    })
    content = {n: stable(o) for n, o in files.items()}
    extra = {}
    manifest = {"schema_version": "1.1.0", "package_type": "tender_evidence_package", "tender_id": TENDER, "package_version": 1}
    if mutate: mutate(files, content, manifest, extra)
    content = {n: (c if isinstance(c, str) else stable(c)) for n, c in content.items()}
    manifest.setdefault("files", [{"name": n, "sha256": "0x" + hashlib.sha256(c.encode()).hexdigest()} for n, c in sorted(content.items())])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, c in {**content, **extra, "manifest.json": stable(manifest)}.items(): z.writestr(n, c)
    return buf.getvalue()


def status(zip_bytes, check):
    return next(r["status"] for r in v.verify(zip_bytes)[1] if r["check"] == check)


class VerifierTest(unittest.TestCase):
    def test_valid_package_passes_offline_steps(self):
        res = v.verify(package())[1]
        self.assertFalse([r for r in res if r["status"] == "failed"], res)
        self.assertEqual(status(package(), "passkey_assertions_valid"), "passed")

    def test_missing_required_file_fails(self):
        def drop(files, content, manifest, extra): del content["governance_notes.json"]
        self.assertEqual(status(package(drop), "required_files_listed"), "failed")

    def test_unlisted_file_fails(self):
        def add(files, content, manifest, extra): extra["note.txt"] = "x"
        self.assertEqual(status(package(add), "no_unlisted_files"), "failed")

    def test_legacy_1_0_0_without_passkeys_passes_structure(self):
        def legacy(files, content, manifest, extra):
            manifest["schema_version"] = "1.0.0"
            for n in ("passkeys.json", "chain_context.json"): del content[n]
        self.assertEqual(status(package(legacy), "required_files_listed"), "passed")

    def test_offchain_signature_verifies_against_tender_uuid(self):
        self.assertEqual(status(package(offchain=True), "passkey_assertions_valid"), "passed")

    def test_onchain_signature_fails_under_offchain_domain(self):
        def drop_tid(files, content, manifest, extra):
            content["tender.json"] = stable({"id": TENDER, "contract_tender_id": None})
        self.assertEqual(status(package(drop_tid), "passkey_assertions_valid"), "failed")

    def test_non_hex_offchain_tender_id_is_reported_not_raised(self):
        def bad_id(files, content, manifest, extra):
            content["tender.json"] = stable({"id": "z" * 32, "contract_tender_id": None})
        self.assertNotEqual(status(package(bad_id, offchain=True), "passkey_assertions_valid"), "passed")

    def test_unknown_schema_fails(self):
        def bump(files, content, manifest, extra): manifest["schema_version"] = "9.9.9"
        self.assertEqual(status(package(bump), "manifest_valid"), "failed")

    def test_altered_commitment_fails_passkey_check(self):
        def alter(files, content, manifest, extra):
            content["bids.json"] = [dict(files["bids.json"][0], commit_hash="0x" + "cd" * 32)]
        self.assertEqual(status(package(alter), "passkey_assertions_valid"), "failed")

    def test_forged_signature_fails(self):
        def forge(files, content, manifest, extra):
            b = files["bids.json"][0]; sig = dict(b["commit_signature"], r=hex(int(b["commit_signature"]["r"], 16) ^ 1))
            content["bids.json"] = [dict(b, commit_signature=sig)]
        self.assertEqual(status(package(forge), "passkey_assertions_valid"), "failed")

    def test_other_vendors_passkey_fails(self):
        def swap(files, content, manifest, extra):
            content["passkeys.json"] = [dict(files["passkeys.json"][0], vendor_id="00000000-0000-0000-0000-000000000001")]
        self.assertEqual(status(package(swap), "passkey_assertions_valid"), "failed")

    def test_wrong_chain_context_fails_identity(self):
        _, res = v.verify(package(), chain_id=114)
        self.assertEqual(next(r["status"] for r in res if r["check"] == "identity_consistent"), "failed")


if __name__ == "__main__":
    unittest.main()
