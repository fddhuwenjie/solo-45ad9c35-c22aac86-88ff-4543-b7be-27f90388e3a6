"""Regression tests for the two hardened sealing gates.

1. Chunks without inline content are read from their registered stored_path:
   per-chunk SHA-256, length and the offset-order whole-image hash are all hard
   sealing requirements.
2. Replica/custody minimum continuity (acquired -> copies -> sealed+transferred
   terminal) is enforced by precheck, seal and evidence-package recompute.
"""
from __future__ import annotations

import copy

from tests.conftest import build_payload, post_manifest, seal, write_chunk_files


def _codes(resp_json, severity="error"):
    return [f["code"] for f in resp_json["report"]["findings"]
            if f["severity"] == severity]


def _assert_409_with(client, payload, code):
    created = post_manifest(client, payload).json()
    assert code in _codes(created), created["report"]["findings"]
    assert created["report"]["sealable"] is False
    r = seal(client, created["manifest_id"])
    assert r.status_code == 409
    blockers = {f["code"] for f in r.json()["detail"]["blocking_findings"]}
    assert code in blockers
    return created


# ============================================================ gate 1: files ==
def test_file_backed_chunks_verify_digests_and_image_hash_and_seal(
        client, evidence_root):
    payload = build_payload(media_id="M-FILE-OK")
    write_chunk_files(payload, evidence_root)  # every chunk stored on disk

    created = post_manifest(client, payload).json()
    report = created["report"]
    assert report["sealable"] is True, report["findings"]
    assert report["all_chunk_digests_verified"] is True
    sources = sorted({c["source"] for c in report["chunk_content"]})
    assert sources == ["file"]
    assert all(c["digest_verified"] for c in report["chunk_content"])
    assert report["reconstructed_sha256"]
    assert report["total_hash_verified"] is True

    sealed = seal(client, created["manifest_id"])
    assert sealed.status_code == 200, sealed.text

    pkg = client.get(
        f"/manifests/{created['manifest_id']}/evidence-package").json()
    rec = client.post("/evidence/recompute", json=pkg).json()
    assert rec["valid"] is True, rec
    assert rec["checks"]["chunk_content_ok"] is True
    assert all(c["digest_ok"] for c in rec["chunk_checks"])
    assert rec["recomputed"]["reconstructed_sha256"] == \
        report["reconstructed_sha256"]


def test_missing_chunk_file_is_hard_error_not_warning(client, evidence_root):
    payload = build_payload(media_id="M-FILE-MISSING")
    write_chunk_files(payload, evidence_root, omit={2})

    created = _assert_409_with(client, payload, "CHUNK_FILE_UNREADABLE")
    row = next(c for c in created["report"]["chunk_content"]
               if c["chunk_id"] == "C03")
    assert row["readable"] is False and row["source"] == "file"
    assert "IMAGE_HASH_NOT_RECOMPUTABLE" in _codes(created)
    assert created["report"]["all_chunk_digests_verified"] is False

    # precheck independently gives the same verdict
    pre = client.post(
        f"/manifests/{created['manifest_id']}/precheck").json()
    assert "CHUNK_FILE_UNREADABLE" in [f["code"] for f in pre["findings"]]
    assert pre["sealable"] is False


def test_chunk_file_digest_conflict_is_hard_error(client, evidence_root):
    payload = build_payload(media_id="M-FILE-CONFLICT")
    write_chunk_files(payload, evidence_root, corrupt={1})
    created = _assert_409_with(client, payload, "CHUNK_DIGEST_MISMATCH")
    finding = next(f for f in created["report"]["findings"]
                   if f["code"] == "CHUNK_DIGEST_MISMATCH")
    assert finding["chunk_ids"] == ["C02"]
    assert finding["detail"]["source"] == "file"


def test_truncated_chunk_file_is_length_and_image_hash_error(
        client, evidence_root):
    payload = build_payload(media_id="M-FILE-TRUNC")
    write_chunk_files(payload, evidence_root, truncate={0})
    created = _assert_409_with(client, payload,
                               "CHUNK_CONTENT_LENGTH_MISMATCH")
    assert "IMAGE_HASH_NOT_RECOMPUTABLE" in _codes(created)


def test_swapped_chunk_files_fail_total_hash_even_if_each_exists(
        client, evidence_root):
    # Every file is readable with matching individual digest, but C01/C02 files
    # are silently permuted on disk: coverage/Merkle of declared leaves pass,
    # the offset-rebuilt whole-image hash must catch the misassembly.
    payload = build_payload(media_id="M-FILE-SWAP")
    write_chunk_files(payload, evidence_root, swap={(0, 1)})
    # declared per-chunk digests stay attached to their ids, while bytes on disk
    # no longer match those digests after the permutation -> digest mismatch
    created = post_manifest(client, payload).json()
    codes = set(_codes(created))
    assert "CHUNK_DIGEST_MISMATCH" in codes
    assert "IMAGE_HASH_NOT_RECOMPUTABLE" in codes
    assert created["report"]["sealable"] is False
    assert seal(client, created["manifest_id"]).status_code == 409


def test_permuted_chunks_with_self_consistent_digests_fail_total_hash(
        client, evidence_root):
    # Stronger misassembly: the operator permutes both the files AND the
    # declared per-chunk digests, so every individual chunk digest verifies and
    # coverage is complete. Only the offset-order linear image hash catches it.
    payload = build_payload(media_id="M-FILE-REORDER")
    paths = write_chunk_files(payload, evidence_root, swap={(0, 1)})
    # make declarations consistent with the swapped files
    d1, d2 = payload["chunks"][0]["sha256"], payload["chunks"][1]["sha256"]
    payload["chunks"][0]["sha256"], payload["chunks"][1]["sha256"] = d2, d1
    created = post_manifest(client, payload).json()
    assert created["report"]["all_chunk_digests_verified"] is True
    assert "TOTAL_HASH_MISMATCH" in _codes(created)
    assert created["report"]["reconstructed_sha256"]
    assert created["report"]["total_hash_verified"] is False
    assert created["report"]["sealable"] is False
    r = seal(client, created["manifest_id"])
    assert r.status_code == 409
    assert {f["code"] for f in r.json()["detail"]["blocking_findings"]} \
        >= {"TOTAL_HASH_MISMATCH"}


def test_stored_path_outside_evidence_root_is_rejected(client, tmp_path,
                                                       evidence_root):
    outside = tmp_path / "outside.dd"
    outside.write_bytes(b"x")
    payload = build_payload(media_id="M-FILE-ESC")
    for c in payload["chunks"]:
        c.pop("content_b64", None)
    payload["chunks"][0]["stored_path"] = str(outside)
    # other chunks stay inline so only the escape matters geometrically
    created = post_manifest(client, payload).json()
    f = next(x for x in created["report"]["findings"]
             if x["code"] == "CHUNK_FILE_OUTSIDE_ROOT")
    assert f["chunk_ids"] == ["C01"]
    assert created["report"]["sealable"] is False
    assert seal(client, created["manifest_id"]).status_code == 409


def test_tampered_file_breaks_evidence_package_recompute(client, evidence_root):
    payload = build_payload(media_id="M-FILE-TAMPER")
    write_chunk_files(payload, evidence_root)
    sid = post_manifest(client, payload).json()["manifest_id"]
    assert seal(client, sid).status_code == 200
    pkg = client.get(f"/manifests/{sid}/evidence-package").json()

    # overwrite one stored file after sealing: recompute must fail hard
    target = evidence_root / "media" / "C02.dd"
    target.write_bytes(b"\x77" * target.stat().st_size)
    rec = client.post("/evidence/recompute", json=pkg).json()
    assert rec["valid"] is False
    assert rec["checks"]["chunk_content_ok"] is False
    bad = [c for c in rec["chunk_checks"] if not c["digest_ok"]]
    assert bad and bad[0]["chunk_id"] == "C02"


# ===================================================== gate 2: provenance ====
def test_zero_replicas_rejects_seal_and_package(client):
    payload = build_payload(media_id="M-NO-REP")
    payload["replicas"] = []
    payload["custody_events"] = []
    created = _assert_409_with(client, payload, "REPLICA_CHAIN_EMPTY")
    assert "CUSTODY_CHAIN_EMPTY" in _codes(created)
    assert created["report"]["replica_chain_proven"] is False

    pkg = client.get(
        f"/manifests/{created['manifest_id']}/evidence-package").json()
    rec = client.post("/evidence/recompute", json=pkg).json()
    assert rec["valid"] is False
    assert rec["checks"]["replica_custody_chain_ok"] is False


def test_no_acquired_replica_rejects_seal(client):
    payload = build_payload(media_id="M-NO-ACQ")
    payload["replicas"] = [r for r in payload["replicas"]
                           if r["role"] != "acquired"]
    payload["custody_events"] = [e for e in payload["custody_events"]
                                 if e["replica_id"] != "R-ACQ"]
    # remaining copies have an unknown parent
    created = post_manifest(client, payload).json()
    codes = set(_codes(created))
    assert "REPLICA_NO_ACQUISITION" in codes
    assert "REPLICA_PARENT_UNKNOWN" in codes
    assert created["report"]["sealable"] is False


def test_replica_without_custody_events_rejects_seal(client):
    payload = build_payload(media_id="M-NO-EVT")
    payload["custody_events"] = [e for e in payload["custody_events"]
                                 if e["replica_id"] != "R-CPY"]
    created = _assert_409_with(client, payload, "CUSTODY_EVENT_MISSING")
    codes = set(_codes(created))
    assert "CUSTODY_NO_EVENTS" in codes


def test_missing_transfer_on_terminal_rejects_seal(client):
    payload = build_payload(media_id="M-NO-XFR")
    # terminal archive sealed but never handed over
    payload["custody_events"] = [e for e in payload["custody_events"]
                                 if not (e["replica_id"] == "R-ARC"
                                         and e["event_type"] == "transferred")]
    created = _assert_409_with(client, payload,
                               "CUSTODY_TERMINAL_NOT_HANDED_OVER")
    f = next(x for x in created["report"]["findings"]
             if x["code"] == "CUSTODY_TERMINAL_NOT_HANDED_OVER")
    assert f["replica_ids"] == ["R-ARC"]
    assert f["detail"]["missing"] == ["transferred"]


def test_copy_without_copied_event_rejects_seal(client):
    payload = build_payload(media_id="M-NO-CPYEVT")
    payload["custody_events"] = [e for e in payload["custody_events"]
                                 if not (e["replica_id"] == "R-CPY"
                                         and e["event_type"] == "copied")]
    _assert_409_with(client, payload, "CUSTODY_EVENT_MISSING")


def test_handover_digest_break_rejects_and_carries_event(client):
    payload = build_payload(media_id="M-CHAIN-BREAK", custody_break=True)
    created = post_manifest(client, payload).json()
    f = next(x for x in created["report"]["findings"]
             if x["code"] == "CUSTODY_DIGEST_AFTER_BREAK")
    assert f["event_id"] == "E-R-ACQ-SEL"
    assert f["replica_ids"] == ["R-ACQ"]
    assert created["report"]["sealable"] is False
    assert seal(client, created["manifest_id"]).status_code == 409

    pkg = client.get(
        f"/manifests/{created['manifest_id']}/evidence-package").json()
    rec = client.post("/evidence/recompute", json=pkg).json()
    assert rec["valid"] is False
    assert rec["checks"]["replica_custody_chain_ok"] is False
    assert rec["chain"]["custody_ok"] is False


def test_copy_digest_divergence_breaks_chain_and_package(client):
    payload = build_payload(media_id="M-COPY-DIV")
    for r in payload["replicas"]:
        if r["replica_id"] == "R-CPY":
            r["sha256"] = "9" * 64
    for e in payload["custody_events"]:
        if e["replica_id"] == "R-CPY":
            for k in ("digest_before", "digest_after", "expected_digest"):
                if e.get(k):
                    e[k] = "9" * 64
    created = post_manifest(client, payload).json()
    assert "REPLICA_COPY_DIGEST_MISMATCH" in _codes(created)
    assert created["report"]["sealable"] is False
    pkg = client.get(
        f"/manifests/{created['manifest_id']}/evidence-package").json()
    rec = client.post("/evidence/recompute", json=pkg).json()
    assert rec["valid"] is False
    assert rec["chain"]["proven"] is False


def test_sealed_then_removed_transfer_event_cannot_revalidate_package(client):
    # package produced when valid; later submission claims the same digest but
    # drops the transfer event -> recompute over package raw fields must fail
    payload = build_payload(media_id="M-PKG-EDIT")
    sid = post_manifest(client, payload).json()["manifest_id"]
    seal(client, sid)
    pkg = client.get(f"/manifests/{sid}/evidence-package").json()

    tampered = copy.deepcopy(pkg)
    tampered["submission"]["custody_events"] = [
        e for e in tampered["submission"]["custody_events"]
        if e["event_type"] != "transferred"]
    rec = client.post("/evidence/recompute", json=tampered).json()
    assert rec["valid"] is False
    assert rec["checks"]["replica_custody_chain_ok"] is False
    assert rec["checks"]["payload_digest_ok"] is False  # raw submission changed


def test_full_chain_proven_path_recorded(client):
    payload = build_payload(media_id="M-CHAIN-OK")
    created = post_manifest(client, payload).json()
    assert created["report"]["sealable"] is True
    assert created["report"]["replica_chain_proven"] is True
    assert created["report"]["provenance_path"] == ["R-ACQ", "R-CPY", "R-ARC"]
    assert created["report"]["terminal_replica_ids"] == ["R-ARC"]
    assert seal(client, created["manifest_id"]).status_code == 200
