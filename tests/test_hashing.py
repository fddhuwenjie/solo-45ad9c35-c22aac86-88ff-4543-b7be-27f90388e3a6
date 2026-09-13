"""Unit tests for hashing primitives and geometric findings."""
from __future__ import annotations

import copy

from tests.conftest import (
    SECTOR_SIZE,
    build_payload,
    post_manifest,
    seal,
)
from app.hashing import (
    canonical_json,
    digest_canonical,
    linear_sha256,
    merkle_root,
    sha256_hex,
)


def test_merkle_known_vector_and_odd_promotion():
    a, b, c = sha256_hex(b"a"), sha256_hex(b"b"), sha256_hex(b"c")
    ab = sha256_hex(bytes.fromhex(a) + bytes.fromhex(b))
    assert merkle_root([a, b]) == ab
    # 3 leaves: (a,b) -> ab, lone c promoted; root = sha256(ab || c)
    assert merkle_root([a, b, c]) == sha256_hex(bytes.fromhex(ab) + bytes.fromhex(c))
    # 4 leaves
    abc_d = sha256_hex(bytes.fromhex(ab) + bytes.fromhex(ab))
    assert merkle_root([a, b, a, b]) == abc_d
    assert merkle_root([]) is None


def test_linear_hash_matches_concatenation():
    assert linear_sha256([b"ab", b"cd"]) == sha256_hex(b"abcd")


def test_canonical_json_is_key_order_independent():
    x = {"a": 1, "b": [1, 2, {"z": 9, "y": 8}]}
    y = {"b": [1, 2, {"y": 8, "z": 9}], "a": 1}
    assert canonical_json(x) == canonical_json(y)
    assert digest_canonical(x) == digest_canonical(y)


def test_out_of_range_chunk_locates_sector_interval(client):
    payload = build_payload(
        media_id="M-OOR",
        chunk_overrides={3: {"offset": (64 - 8) * SECTOR_SIZE,
                             "length": 16 * SECTOR_SIZE}})
    created = post_manifest(client, payload).json()
    f = next(x for x in created["report"]["findings"]
             if x["code"] == "CHUNK_OUT_OF_RANGE")
    assert f["start_sector"] == 56 and f["end_sector"] == 72
    assert seal(client, created["manifest_id"]).status_code == 409


def test_middle_gap_reports_exact_interval(client):
    # remove chunk C03 (sectors 32..47), keep C04 -> one internal gap
    payload = build_payload(media_id="M-MID")
    payload["chunks"] = [c for c in payload["chunks"] if c["chunk_id"] != "C03"]
    created = post_manifest(client, payload).json()
    gaps = [(g["start_sector"], g["end_sector"])
            for g in created["report"]["findings"]
            if g["code"] == "COVERAGE_GAP"]
    assert (32, 48) in gaps
    assert created["report"]["complete_coverage"] is False


def test_evidence_package_carries_payload_digest_chain(client):
    payload = build_payload(media_id="M-PKG")
    sid = post_manifest(client, payload).json()["manifest_id"]
    seal(client, sid)
    row = client.get(f"/manifests/{sid}").json()
    pkg = client.get(f"/manifests/{sid}/evidence-package").json()
    assert pkg["package"]["payload_digest"] == row["payload_digest"]
    assert pkg["package"]["status"] == "sealed"
    assert pkg["computed"]["coverage"]["complete"] is True
    # package itself is canonical JSON-able without changing digest
    rec = client.post("/evidence/recompute", json=copy.deepcopy(pkg)).json()
    assert rec["recomputed"]["payload_digest"] == row["payload_digest"]
    assert rec["valid"] is True
