"""Selective disclosure proof tests.

A court or external reviewer verifies only a few chunks without receiving
the whole image. The issuance endpoint anchors proofs in the sealed Merkle
root and the exact evidence package digest; selection is by chunk id or by
sector ranges aligned exactly with effective chunk boundaries. Verification
is stateless: only the leaf digest, the proof path (indices, sibling
digests and odd-node promotions) and the frozen root are recomputed.
Correction-superseded chunks, boundary-crossing/overlapping/duplicated
selections, a mismatched evidence package digest, unsealed manifests and
paths that never close to the root can never yield a proof or `valid`.
"""
from __future__ import annotations

import copy

import pytest

from app.disclosure import build_merkle_proof, verify_leaf_proof
from app.hashing import merkle_root, sha256_hex
from app.schemas import DisclosureProofStep
from tests.conftest import (
    N_CHUNKS,
    SECTOR_SIZE,
    build_payload,
    post_manifest,
    seal,
)


# ----------------------------------------------------------- sealed helper ----
def sealed(client, media_id="M-DISC", **kw):
    payload = build_payload(media_id=media_id, **kw)
    mid = post_manifest(client, payload).json()["manifest_id"]
    assert seal(client, mid).status_code == 200
    package = client.get(f"/manifests/{mid}/evidence-package").json()
    return mid, package, payload


def issue(client, mid, package, *, proof_id="DP-1", chunk_ids=None,
          sector_ranges=None, requested_by="court-01",
          reason="trial exhibit sectors 0..16", status_code=201):
    body = {"proof_id": proof_id,
            "evidence_package_digest": package["evidence_package_digest"],
            "chunk_ids": chunk_ids or [],
            "sector_ranges": sector_ranges or [],
            "requested_by": requested_by, "reason": reason}
    r = client.post(f"/manifests/{mid}/disclosure-proofs", json=body)
    assert r.status_code == status_code, r.text
    return r


def verify(client, leaf, *, root, leaf_count, leaf_digest=None, steps=None,
           proof_id="DP-1", chunk_id=None):
    body = {"proof_id": proof_id, "merkle_root": root,
            "chunk_id": chunk_id or leaf["chunk_id"],
            "leaf_index": leaf["leaf_index"], "leaf_count": leaf_count,
            "leaf_digest": leaf_digest or leaf["leaf_digest"],
            "proof_steps": steps if steps is not None else leaf["proof_steps"]}
    return client.post("/disclosure/verify", json=body).json()


# ============================================================ happy paths ====
def test_chunk_id_proof_recomputes_to_frozen_root(client):
    mid, package, payload = sealed(client)
    r = issue(client, mid, package, chunk_ids=["C01", "C03"])
    proof = r.json()
    assert proof["format"] == "split-image-selective-disclosure/v1"
    assert proof["manifest_id"] == mid
    assert proof["revision"] == 1
    assert proof["evidence_package_digest"] == \
        package["evidence_package_digest"]
    assert proof["merkle_root"] == package["computed"]["merkle_root"]
    assert proof["leaf_count"] == N_CHUNKS
    # full ordering disclosed (ids/spans only; other leaf digests stay private)
    assert [e["chunk_id"] for e in proof["ordered_leaves"]] == \
        ["C01", "C02", "C03", "C04"]
    assert [e["leaf_index"] for e in proof["ordered_leaves"]] == [0, 1, 2, 3]
    assert [lp["chunk_id"] for lp in proof["leaf_proofs"]] == ["C01", "C03"]
    first = proof["leaf_proofs"][0]
    assert first["selected_by"] == ["chunk_id"]
    assert "chunk_id C01" in first["selection_rationale"]
    assert proof["covered_sector_ranges"] == [
        {"start_sector": 0, "end_sector": 16},
        {"start_sector": 32, "end_sector": 48}]
    assert proof["covered_sectors"] == 32
    assert proof["total_sectors"] == 64
    assert proof["request"]["reason"].startswith("trial exhibit")
    # algorithm spec and leaf ordering pinned into the proof
    assert proof["merkle_spec"]["odd_node"] == \
        "promoted unchanged to the next level"
    assert "ordered_chunk_ids" in proof["leaf_ordering_rule"]
    assert proof["disclosure_digest"]

    for leaf in proof["leaf_proofs"]:
        out = verify(client, leaf, root=proof["merkle_root"],
                     leaf_count=proof["leaf_count"])
        assert out["valid"] is True, out
        assert out["recomputed_root"] == proof["merkle_root"]


def test_sector_range_aligned_with_chunk_boundaries(client):
    mid, package, payload = sealed(client)
    # sectors [16,48) cover exactly C02 and C03
    r = issue(client, mid, package, proof_id="DP-RANGE",
              sector_ranges=[{"start_sector": 16, "end_sector": 48}])
    proof = r.json()
    assert [lp["chunk_id"] for lp in proof["leaf_proofs"]] == ["C02", "C03"]
    assert all(lp["selected_by"] == ["sector_range"]
               for lp in proof["leaf_proofs"])
    assert "range [16,48)" in proof["leaf_proofs"][0]["selection_rationale"]
    assert proof["covered_sector_ranges"] == [
        {"start_sector": 16, "end_sector": 48}]
    for leaf in proof["leaf_proofs"]:
        assert verify(client, leaf, root=proof["merkle_root"],
                      leaf_count=proof["leaf_count"])["valid"] is True


def test_chunk_and_range_selectors_combine(client):
    mid, package, payload = sealed(client)
    proof = issue(client, mid, package, proof_id="DP-MIX",
                  chunk_ids=["C01"],
                  sector_ranges=[{"start_sector": 48, "end_sector": 64}]).json()
    assert [lp["chunk_id"] for lp in proof["leaf_proofs"]] == ["C01", "C04"]
    assert proof["covered_sectors"] == 32


def test_proof_listed_and_read_back_append_only(client):
    mid, package, payload = sealed(client)
    issue(client, mid, package, chunk_ids=["C01"])
    issue(client, mid, package, proof_id="DP-2", reason="second request",
          sector_ranges=[{"start_sector": 0, "end_sector": 64}])
    listing = client.get(f"/manifests/{mid}/disclosure-proofs").json()
    assert [s["proof_id"] for s in listing] == ["DP-1", "DP-2"]
    s1 = listing[0]
    assert s1["disclosed_chunk_ids"] == ["C01"]
    assert s1["requested_by"] == "court-01"
    assert s1["disclosure_digest"]
    # full read-back is byte-for-byte the frozen proof
    one = client.get(f"/manifests/{mid}/disclosure-proofs/DP-1").json()
    assert one["leaf_proofs"][0]["chunk_id"] == "C01"
    # unknown / other manifest -> 404
    assert client.get(f"/manifests/{mid}/disclosure-proofs/NOPE").status_code == 404


# ============================================================ refusal gates ==

def test_range_crossing_chunk_boundary_refused(client):
    mid, package, payload = sealed(client)
    r = issue(client, mid, package, proof_id="DP-X",
              sector_ranges=[{"start_sector": 8, "end_sector": 24}],
              status_code=422)
    detail = r.json()["detail"]
    assert detail["code"] == "DISCLOSURE_RANGE_NOT_ALIGNED"
    assert detail["valid_boundaries"] == [0, 16, 32, 48, 64]


def test_range_partially_inside_chunk_refused(client):
    mid, package, payload = sealed(client)
    # starts at a boundary but cuts C03 in half
    r = issue(client, mid, package, proof_id="DP-X",
              sector_ranges=[{"start_sector": 32, "end_sector": 40}],
              status_code=422)
    assert r.json()["detail"]["code"] == "DISCLOSURE_RANGE_NOT_ALIGNED"


def test_range_out_of_medium_refused(client):
    mid, package, payload = sealed(client)
    r = issue(client, mid, package, proof_id="DP-X",
              sector_ranges=[{"start_sector": 48, "end_sector": 80}],
              status_code=422)
    assert r.json()["detail"]["code"] == "DISCLOSURE_RANGE_OUT_OF_BOUNDS"


def test_unknown_chunk_refused(client):
    mid, package, payload = sealed(client)
    r = issue(client, mid, package, proof_id="DP-X", chunk_ids=["C99"],
              status_code=422)
    assert r.json()["detail"]["code"] == "DISCLOSURE_CHUNK_NOT_FOUND"


def test_duplicate_leaf_across_selectors_refused(client):
    mid, package, payload = sealed(client)
    r = issue(client, mid, package, proof_id="DP-X", chunk_ids=["C01", "C02"],
              sector_ranges=[{"start_sector": 0, "end_sector": 32}],
              status_code=422)
    detail = r.json()["detail"]
    assert detail["code"] == "DISCLOSURE_DUPLICATE_LEAF"
    assert set(detail["chunk_ids"]) == {"C01", "C02"}


def test_overlapping_ranges_refused_by_schema(client):
    mid, package, payload = sealed(client)
    r = issue(client, mid, package, proof_id="DP-X",
              sector_ranges=[{"start_sector": 0, "end_sector": 32},
                             {"start_sector": 16, "end_sector": 48}],
              status_code=422)
    assert "overlap" in r.text


def test_empty_selection_refused(client):
    mid, package, payload = sealed(client)
    r = issue(client, mid, package, proof_id="DP-X",
              chunk_ids=[], sector_ranges=[], status_code=422)
    assert r.status_code == 422


def test_evidence_package_digest_mismatch_refused(client):
    mid, package, payload = sealed(client)
    # build the request with a wrong digest (the helper pins the real one)
    body = {"proof_id": "DP-X",
            "evidence_package_digest": "f" * 64,
            "chunk_ids": ["C01"], "sector_ranges": [],
            "requested_by": "court-01", "reason": "x"}
    r = client.post(f"/manifests/{mid}/disclosure-proofs", json=body)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["code"] == "DISCLOSURE_EVIDENCE_PACKAGE_MISMATCH"
    assert detail["sealed_digest"] == package["evidence_package_digest"]
    # nothing was appended
    assert client.get(f"/manifests/{mid}/disclosure-proofs").json() == []


def test_manifest_must_be_sealed(client):
    payload = build_payload(media_id="M-DRAFT")
    mid = post_manifest(client, payload).json()["manifest_id"]
    body = {"proof_id": "DP-X",
            "evidence_package_digest": "f" * 64,
            "chunk_ids": ["C01"], "sector_ranges": [],
            "requested_by": "court-01", "reason": "x"}
    r = client.post(f"/manifests/{mid}/disclosure-proofs", json=body)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "DISCLOSURE_REQUIRES_SEALED"


def test_duplicate_proof_id_refused_and_never_overwritten(client):
    mid, package, payload = sealed(client)
    issue(client, mid, package, proof_id="DP-1", chunk_ids=["C01"])
    r = issue(client, mid, package, proof_id="DP-1", chunk_ids=["C02"],
              status_code=409)
    assert r.json()["detail"]["code"] == "DISCLOSURE_PROOF_DUPLICATE"
    one = client.get(f"/manifests/{mid}/disclosure-proofs/DP-1").json()
    assert [lp["chunk_id"] for lp in one["leaf_proofs"]] == ["C01"]


def test_unknown_manifest_404(client):
    body = {"proof_id": "DP-X", "evidence_package_digest": "f" * 64,
            "chunk_ids": ["C01"], "requested_by": "court-01", "reason": "x"}
    assert client.post("/manifests/MF-NOPE/disclosure-proofs",
                       json=body).status_code == 404


# ============================================== correction-superseded chunk ==
def test_superseded_chunk_is_not_disclosable(client):
    import base64
    import hashlib

    from tests.conftest import chunk_bytes

    p1 = build_payload(media_id="M-CORR-DISC")
    v1 = post_manifest(client, p1).json()
    assert seal(client, v1["manifest_id"]).status_code == 200

    p2 = build_payload(media_id="M-CORR-DISC", change_kind="correction",
                       parent=v1["manifest_id"])
    c02 = next(c for c in p2["chunks"] if c["chunk_id"] == "C02")
    data = b"erased-bad-sector-reimage".ljust(c02["length"], b"\x05")
    corrected = copy.deepcopy(c02)
    corrected.update({"chunk_id": "C02X",
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "content_b64": base64.b64encode(data).decode(),
                      "correction_of": "C02",
                      "note": "re-imaged after read error"})
    p2["chunks"].append(corrected)
    p2.setdefault("read_attempts", []).append({
        "attempt_id": "A-C02X", "session_id": corrected["session_id"],
        "chunk_id": "C02X", "start_sector": 16, "end_sector": 32,
        "round": 2, "result": "read",
        "actual_read_length": 16 * SECTOR_SIZE,
        "sha256": hashlib.sha256(data).hexdigest()})
    new_image = b"".join(data if i == 1 else chunk_bytes(i)
                         for i in range(N_CHUNKS))
    expected = hashlib.sha256(new_image).hexdigest()
    p2["expected_total_sha256"] = expected
    for rep in p2["replicas"]:
        rep["sha256"] = expected
    for ev in p2["custody_events"]:
        for key in ("digest_before", "digest_after", "expected_digest"):
            if ev.get(key):
                ev[key] = expected
    v2 = post_manifest(client, p2).json()
    assert seal(client, v2["manifest_id"]).status_code == 200
    pkg2 = client.get(
        f"/manifests/{v2['manifest_id']}/evidence-package").json()

    # the old C02 is still registered but no longer a leaf
    r = issue(client, v2["manifest_id"], pkg2, proof_id="DP-OLD",
              chunk_ids=["C02"], status_code=422)
    detail = r.json()["detail"]
    assert detail["code"] == "DISCLOSURE_CHUNK_SUPERSEDED"
    assert detail["effective_chunk_ids"] == ["C01", "C02X", "C03", "C04"]

    # the effective correction chunk IS disclosable at the same span
    proof = issue(client, v2["manifest_id"], pkg2, proof_id="DP-NEW",
                  chunk_ids=["C02X"]).json()
    leaf = proof["leaf_proofs"][0]
    assert leaf["start_sector"] == 16 and leaf["end_sector"] == 32
    out = verify(client, leaf, root=proof["merkle_root"],
                 leaf_count=proof["leaf_count"])
    assert out["valid"] is True


# ================================================ stateless verification ====
def test_verify_tampered_leaf_digest_invalid(client):
    mid, package, payload = sealed(client)
    proof = issue(client, mid, package, chunk_ids=["C01"]).json()
    leaf = proof["leaf_proofs"][0]
    out = verify(client, leaf, root=proof["merkle_root"],
                 leaf_count=proof["leaf_count"],
                 leaf_digest="f" * 64)
    assert out["valid"] is False
    # the first recombination already disagrees with the recorded step
    assert out["error_code"] == "DISCLOSURE_STEP_DIGEST_MISMATCH"
    assert out["recomputed_root"] is None


def test_verify_wrong_root_invalid(client):
    mid, package, payload = sealed(client)
    proof = issue(client, mid, package, chunk_ids=["C01"]).json()
    leaf = proof["leaf_proofs"][0]
    out = verify(client, leaf, root="e" * 64,
                 leaf_count=proof["leaf_count"])
    assert out["valid"] is False
    assert out["error_code"] == "DISCLOSURE_ROOT_MISMATCH"
    assert out["recomputed_root"] == proof["merkle_root"]


def test_verify_tampered_sibling_invalid(client):
    mid, package, payload = sealed(client)
    proof = issue(client, mid, package, chunk_ids=["C01"]).json()
    leaf = copy.deepcopy(proof["leaf_proofs"][0])
    leaf["proof_steps"][0]["sibling_digest"] = "f" * 64
    out = verify(client, leaf, root=proof["merkle_root"],
                 leaf_count=proof["leaf_count"])
    assert out["valid"] is False
    assert out["error_code"] == "DISCLOSURE_STEP_DIGEST_MISMATCH"


def test_verify_truncated_path_not_closed_invalid(client):
    mid, package, payload = sealed(client)
    proof = issue(client, mid, package, chunk_ids=["C01"]).json()
    leaf = copy.deepcopy(proof["leaf_proofs"][0])
    out = verify(client, leaf, root=proof["merkle_root"],
                 leaf_count=proof["leaf_count"],
                 steps=leaf["proof_steps"][:1])  # C01 needs two levels
    assert out["valid"] is False
    assert out["error_code"] == "DISCLOSURE_PATH_NOT_CLOSED"


def test_verify_extra_step_invalid(client):
    mid, package, payload = sealed(client)
    proof = issue(client, mid, package, chunk_ids=["C01"]).json()
    leaf = copy.deepcopy(proof["leaf_proofs"][0])
    leaf["proof_steps"].append(leaf["proof_steps"][-1])
    out = verify(client, leaf, root=proof["merkle_root"],
                 leaf_count=proof["leaf_count"])
    assert out["valid"] is False
    assert out["error_code"] == "DISCLOSURE_PATH_NOT_CLOSED"


def test_verify_wrong_sibling_side_invalid(client):
    mid, package, payload = sealed(client)
    proof = issue(client, mid, package, chunk_ids=["C02"]).json()
    leaf = copy.deepcopy(proof["leaf_proofs"][0])
    # index 1 is a right sibling; claim left instead
    leaf["proof_steps"][0]["position"] = "left"
    out = verify(client, leaf, root=proof["merkle_root"],
                 leaf_count=proof["leaf_count"])
    assert out["valid"] is False
    assert out["error_code"] == "DISCLOSURE_STEP_POSITION_MISMATCH"


def test_verify_leaf_index_out_of_range_invalid(client):
    mid, package, payload = sealed(client)
    proof = issue(client, mid, package, chunk_ids=["C01"]).json()
    leaf = proof["leaf_proofs"][0]
    out = verify(client, leaf, root=proof["merkle_root"], leaf_count=4,
                 steps=[])
    # index 0 < 4 with an empty path -> never closes
    assert out["valid"] is False
    body = {"proof_id": "DP-1", "merkle_root": proof["merkle_root"],
            "chunk_id": "C01", "leaf_index": 9, "leaf_count": 4,
            "leaf_digest": leaf["leaf_digest"], "proof_steps": []}
    out = client.post("/disclosure/verify", json=body).json()
    assert out["valid"] is False
    assert out["error_code"] == "DISCLOSURE_LEAF_INDEX_OUT_OF_RANGE"


def test_verify_endpoint_is_stateless_without_database(client):
    # Verifier needs no manifest at all: hand it a freshly computed path.
    from app.hashing import sha256_hex

    digests = [sha256_hex(f"leaf-{i}".encode()) for i in range(5)]
    root = merkle_root(digests)
    for idx in range(5):
        steps = build_merkle_proof(digests, idx)
        body = {"merkle_root": root, "chunk_id": f"X{idx}",
                "leaf_index": idx, "leaf_count": 5,
                "leaf_digest": digests[idx],
                "proof_steps": [s.model_dump() for s in steps]}
        out = client.post("/disclosure/verify", json=body).json()
        assert out["valid"] is True, out


# ===================================================== pure odd-leaf trees ====
def test_odd_leaf_promotion_steps_recompute_root():
    digests = [sha256_hex(bytes([i])) for i in range(3)]
    root = merkle_root(digests)
    # leaf 2 (the lone odd leaf) is promoted at level 0, then hashes right
    steps2 = build_merkle_proof(digests, 2)
    assert [s.position for s in steps2] == ["promoted", "right"]
    assert steps2[0].sibling_digest is None
    res = verify_leaf_proof(2, 3, digests[2], steps2, root)
    assert res.valid is True
    # leaf 0: hash with sibling at level 0, the odd node is on the right
    steps0 = build_merkle_proof(digests, 0)
    assert [s.position for s in steps0] == ["left", "left"]
    assert verify_leaf_proof(0, 3, digests[0], steps0, root).valid is True


def test_single_leaf_tree_proof_is_empty_path():
    digest = sha256_hex(b"only")
    assert build_merkle_proof([digest], 0) == []
    res = verify_leaf_proof(0, 1, digest, [], digest)
    assert res.valid is True
    assert verify_leaf_proof(0, 1, digest, [], "f" * 64).valid is False


def test_5_leaves_all_indices_roundtrip():
    digests = [sha256_hex(f"block-{i}".encode()) for i in range(5)]
    root = merkle_root(digests)
    for idx, digest in enumerate(digests):
        steps = build_merkle_proof(digests, idx)
        assert verify_leaf_proof(idx, 5, digest, steps, root).valid is True


def test_promotion_step_rejects_sibling_on_verify():
    digest = sha256_hex(b"x")
    step = DisclosureProofStep(level=0, position="promoted",
                               sibling_digest=None,
                               result_digest=digest)
    # a forged promotion that smuggles a sibling can never be built by the
    # schema, and a forged position at an even non-last index fails closure
    res = verify_leaf_proof(0, 2, digest, [step], digest)
    assert res.valid is False
    assert res.error_code == "DISCLOSURE_STEP_POSITION_MISMATCH"
