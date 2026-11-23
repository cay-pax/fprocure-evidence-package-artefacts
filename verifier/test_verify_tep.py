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

    def test_sim_tender_uses_offchain_domain(self):
        def sim_id(files, content, manifest, extra):
            content["tender.json"] = stable({"id": TENDER, "contract_tender_id": "SIM-" + TENDER})
        self.assertEqual(status(package(sim_id, offchain=True), "passkey_assertions_valid"), "passed")

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


    # Malformed and hostile archives fail a step; verify() never raises.

    def test_oversized_entry_is_refused_before_reading(self):
        orig = v.MAX_ENTRY
        v.MAX_ENTRY = 100
        try: res = v.verify(package())[1]
        finally: v.MAX_ENTRY = orig
        self.assertEqual(res[-1]["check"], "archive_readable")
        self.assertEqual(res[-1]["status"], "failed")
        self.assertIn("entry limit", res[-1]["detail"])

    def test_oversized_archive_is_refused_before_reading(self):
        orig = v.MAX_UNCOMPRESSED
        v.MAX_UNCOMPRESSED = 1000
        try: res = v.verify(package())[1]
        finally: v.MAX_UNCOMPRESSED = orig
        self.assertEqual([r["check"] for r in res], ["package_digest", "archive_readable"])
        self.assertEqual(res[-1]["status"], "failed")

    def test_bzip2_and_lzma_entries_are_refused_before_reading(self):
        for method in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            src = zipfile.ZipFile(io.BytesIO(package()))
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                for i in src.infolist():
                    z.writestr(i.filename, src.read(i), compress_type=method if i.filename == "bids.json" else zipfile.ZIP_DEFLATED)
            res = v.verify(buf.getvalue())[1]
            self.assertEqual([r["check"] for r in res], ["package_digest", "archive_readable"], method)
            self.assertEqual(res[-1]["status"], "failed")
            self.assertIn("bids.json", res[-1]["detail"])

    def test_deflate_package_is_accepted(self):
        src = zipfile.ZipFile(io.BytesIO(package()))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for i in src.infolist(): z.writestr(i.filename, src.read(i))
        self.assertEqual(status(buf.getvalue(), "archive_readable"), "passed")

    def test_non_numeric_chain_id_fails_passkey_step(self):
        def bad_chain(files, content, manifest, extra):
            content["chain_context.json"] = dict(files["chain_context.json"], chain_id="anvil")
        self.assertEqual(status(package(bad_chain), "passkey_assertions_valid"), "failed")

    def test_absent_chain_id_skips_passkey_step(self):
        def no_chain(files, content, manifest, extra):
            content["chain_context.json"] = dict(files["chain_context.json"], chain_id=None)
        self.assertEqual(status(package(no_chain), "passkey_assertions_valid"), "skipped")

    def test_bad_crc_fails_hash_step_not_raises(self):
        zb = package()
        self.assertEqual(zb.count(b'"b1"'), 1)
        res = v.verify(zb.replace(b'"b1"', b'"b2"'))[1]
        step = next(r for r in res if r["check"] == "file_hashes_match")
        self.assertEqual(step["status"], "failed")
        self.assertIn("unreadable: bids.json", step["detail"])

    def test_manifest_entry_without_sha256_fails_manifest_step(self):
        def no_hash(files, content, manifest, extra): manifest["files"] = [{"name": n} for n in sorted(content)]
        self.assertEqual(status(package(no_hash), "manifest_valid"), "failed")

    def test_manifest_entry_without_name_fails_manifest_step(self):
        def no_name(files, content, manifest, extra): manifest["files"] = [{"sha256": "0x00"}]
        self.assertEqual(status(package(no_name), "manifest_valid"), "failed")

    def test_manifest_listing_a_file_twice_fails(self):
        def twice(files, content, manifest, extra):
            c = content["bids.json"] if isinstance(content["bids.json"], str) else stable(content["bids.json"])
            h = "0x" + hashlib.sha256(c.encode()).hexdigest()
            manifest["files"] = [{"name": n, "sha256": "0x" + hashlib.sha256((x if isinstance(x, str) else stable(x)).encode()).hexdigest()} for n, x in sorted(content.items())] + [{"name": "bids.json", "sha256": h}]
        self.assertEqual(status(package(twice), "manifest_valid"), "failed")

    def test_invalid_json_bids_with_matching_hash_does_not_pass(self):
        def garble(files, content, manifest, extra): content["bids.json"] = "[{not json"
        zb = package(garble)
        self.assertEqual(status(zb, "file_hashes_match"), "passed")
        self.assertEqual(status(zb, "identity_consistent"), "failed")
        self.assertTrue(any(r["status"] == "failed" for r in v.verify(zb)[1]))

    def test_wrong_json_type_fails(self):
        def obj(files, content, manifest, extra): content["bids.json"] = stable({"id": "b1"})
        self.assertEqual(status(package(obj), "identity_consistent"), "failed")

    def test_unsigned_scenario_commitment_is_counted_not_failed(self):
        def add_unsigned(files, content, manifest, extra):
            b = dict(files["bids.json"][0], id="b2"); del b["commit_signature"]
            content["bids.json"] = [files["bids.json"][0], b]
        res = v.verify(package(add_unsigned))[1]
        step = next(r for r in res if r["check"] == "passkey_assertions_valid")
        self.assertEqual(step["status"], "passed")
        self.assertIn("1 unsigned commitments", step["detail"])

    def test_all_unsigned_is_skipped_not_passed(self):
        def unsign(files, content, manifest, extra):
            b = dict(files["bids.json"][0]); del b["commit_signature"]
            content["bids.json"] = [b]
        self.assertEqual(status(package(unsign), "passkey_assertions_valid"), "skipped")

    def test_no_bids_and_no_commits_is_skipped(self):
        def empty(files, content, manifest, extra): content["bids.json"] = []
        self.assertEqual(status(package(empty), "passkey_assertions_valid"), "skipped")

    def test_assertion_missing_fields_fails_not_raises(self):
        for field in ("r", "s", "typeIndex", "challengeIndex", "clientDataJSON", "authenticatorData"):
            def strip(files, content, manifest, extra, field=field):
                b = files["bids.json"][0]; sig = dict(b["commit_signature"]); del sig[field]
                content["bids.json"] = [dict(b, commit_signature=sig)]
            self.assertEqual(status(package(strip), "passkey_assertions_valid"), "failed", field)

    def test_passkey_missing_public_key_fails_not_raises(self):
        def strip(files, content, manifest, extra):
            p = dict(files["passkeys.json"][0]); del p["public_key_x"]
            content["passkeys.json"] = [p]
        self.assertEqual(status(package(strip), "passkey_assertions_valid"), "failed")

    def test_bid_missing_vendor_or_commit_fails_not_raises(self):
        for field in ("vendor_id", "commit_hash"):
            def strip(files, content, manifest, extra, field=field):
                b = dict(files["bids.json"][0]); del b[field]
                content["bids.json"] = [b]
            self.assertEqual(status(package(strip), "passkey_assertions_valid"), "failed", field)

    def test_non_object_bid_entry_fails(self):
        def junk(files, content, manifest, extra): content["bids.json"] = [files["bids.json"][0], "x"]
        zb = package(junk)
        self.assertEqual(status(zb, "identity_consistent"), "failed")

if __name__ == "__main__":
    unittest.main()
