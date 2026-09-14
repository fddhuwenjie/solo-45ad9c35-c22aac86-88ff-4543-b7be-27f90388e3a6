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


# ===================================== counterexample 1: no real copy stage ==
def _acquired_only_payload(media_id, *, with_transfer=True):
    """Single acquired replica that itself carries acquired/sealed/transferred."""
    from tests.conftest import T0
    from datetime import timedelta

    payload = build_payload(media_id=media_id)
    digest = next(r for r in payload["replicas"]
                  if r["replica_id"] == "R-ACQ")["sha256"]
    payload["replicas"] = [r for r in payload["replicas"]
                           if r["replica_id"] == "R-ACQ"]
    keep = {"acquired", "verified", "sealed"}
    if with_transfer:
        keep.add("transferred")
    payload["custody_events"] = [e for e in payload["custody_events"]
                                 if e["replica_id"] == "R-ACQ"
                                 and e["event_type"] in keep]
    if with_transfer and not any(e["event_type"] == "transferred"
                                 for e in payload["custody_events"]):
        # build_payload never transfers R-ACQ; register it explicitly so the
        # counterexample is exactly "acquired replica with all three events"
        payload["custody_events"].append({
            "event_id": "E-R-ACQ-XFR", "event_type": "transferred",
            "replica_id": "R-ACQ",
            "at": (T0 + timedelta(days=1)).isoformat(),
            "actor": "qian.wu", "organization": "证据管理室",
            "counterpart": "司法鉴定中心-接收人 sun.li",
            "digest_before": digest, "digest_after": digest,
            "expected_digest": digest})
    return payload


def test_acquired_only_with_seal_and_transfer_is_not_proven(client):
    # The defect: a sole acquired replica registered acquired+sealed+
    # transferred events must still fail -- no copy/archive stage exists.
    payload = _acquired_only_payload("M-ACQ-ONLY")
    created = post_manifest(client, payload).json()
    codes = set(_codes(created))
    assert "REPLICA_CHAIN_NO_COPY_STAGE" in codes
    assert "REPLICA_CHAIN_UNPROVEN" in codes
    f = next(x for x in created["report"]["findings"]
             if x["code"] == "REPLICA_CHAIN_NO_COPY_STAGE")
    assert f["replica_ids"] == ["R-ACQ"]
    assert created["report"]["replica_chain_proven"] is False
    assert created["report"]["provenance_path"] == []
    assert created["report"]["sealable"] is False

    r = seal(client, created["manifest_id"])
    assert r.status_code == 409
    blocker_codes = {x["code"]
                     for x in r.json()["detail"]["blocking_findings"]}
    assert {"REPLICA_CHAIN_NO_COPY_STAGE", "REPLICA_CHAIN_UNPROVEN"} \
        <= blocker_codes


def test_acquired_only_chain_fails_precheck_and_package_recompute(client):
    payload = _acquired_only_payload("M-ACQ-ONLY-PC")
    sid = post_manifest(client, payload).json()["manifest_id"]

    pre = client.post(f"/manifests/{sid}/precheck").json()
    assert pre["sealable"] is False
    assert "REPLICA_CHAIN_NO_COPY_STAGE" in [f["code"] for f in pre["findings"]]
    assert seal(client, sid).status_code == 409

    # evidence package exists for a draft too; recompute must not say valid
    pkg = client.get(f"/manifests/{sid}/evidence-package").json()
    rec = client.post("/evidence/recompute", json=pkg).json()
    assert rec["valid"] is False
    assert rec["checks"]["replica_custody_chain_ok"] is False
    assert rec["chain"]["proven"] is False


def test_acquired_with_copy_but_terminal_not_transferred_still_unproven(client):
    # acquired + one copy replica proves the replication stage, but without
    # sealed+transferred on the copy terminal it still cannot be proven
    payload = build_payload(media_id="M-COPY-NO-XFR")
    payload["replicas"] = [r for r in payload["replicas"]
                           if r["replica_id"] in ("R-ACQ", "R-CPY")]
    payload["custody_events"] = [
        e for e in payload["custody_events"]
        if e["replica_id"] in ("R-ACQ", "R-CPY")]
    # keep the copy's copied+sealed but drop nothing else: copy is a terminal
    # lacking transferred
    created = post_manifest(client, payload).json()
    codes = set(_codes(created))
    assert "REPLICA_CHAIN_NO_COPY_STAGE" not in codes  # copy stage present
    assert "CUSTODY_TERMINAL_NOT_HANDED_OVER" in codes
    assert created["report"]["replica_chain_proven"] is False
    assert seal(client, created["manifest_id"]).status_code == 409


def test_tampering_package_to_drop_copy_replica_invalidates_recompute(client):
    payload = build_payload(media_id="M-PKG-DROPCOPY")
    sid = post_manifest(client, payload).json()["manifest_id"]
    assert seal(client, sid).status_code == 200
    pkg = client.get(f"/manifests/{sid}/evidence-package").json()

    edited = copy.deepcopy(pkg)
    sub = edited["submission"]
    sub["replicas"] = [r for r in sub["replicas"]
                       if r["replica_id"] == "R-ACQ"]
    sub["custody_events"] = [e for e in sub["custody_events"]
                             if e["replica_id"] == "R-ACQ"]
    rec = client.post("/evidence/recompute", json=edited).json()
    assert rec["valid"] is False
    assert rec["checks"]["replica_custody_chain_ok"] is False


# ===================== counterexample 2: superseded old chunk still verified ==
def _sealed_correction_base(client, media_id):
    p1 = build_payload(media_id=media_id)
    v1 = post_manifest(client, p1).json()
    assert seal(client, v1["manifest_id"]).status_code == 200
    return v1


def _correction_payload(parent_id, media_id, *, make_old_unreadable=False,
                        truncate_old=False, corrupt_old_digest_decl=False):
    """Build a v2 correction: C02X supersedes C02 at the same range.

    By default the superseded C02 still carries valid inline content.
    Flags simulate defects of the registered old chunk.
    """
    import base64
    import hashlib

    from tests.conftest import chunk_bytes

    p2 = build_payload(media_id=media_id, change_kind="correction",
                       parent=parent_id)
    c02 = next(c for c in p2["chunks"] if c["chunk_id"] == "C02")
    data = b"erased-bad-sector-reimage".ljust(c02["length"], b"\x05")
    corrected = copy.deepcopy(c02)
    corrected.update({"chunk_id": "C02X",
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "content_b64": base64.b64encode(data).decode(),
                      "correction_of": "C02",
                      "note": "re-imaged after read error on sector 16"})
    p2["chunks"].append(corrected)
    new_image = b"".join(data if i == 1 else chunk_bytes(i)
                         for i in range(4))
    expected = hashlib.sha256(new_image).hexdigest()
    p2["expected_total_sha256"] = expected
    for rep in p2["replicas"]:
        rep["sha256"] = expected
    for ev in p2["custody_events"]:
        for key in ("digest_before", "digest_after", "expected_digest"):
            if ev.get(key):
                ev[key] = expected

    old = next(c for c in p2["chunks"] if c["chunk_id"] == "C02")
    if make_old_unreadable:
        old["stored_path"] = "media/MISSING-C02.dd"
        old.pop("content_b64", None)
    elif truncate_old:
        old["content_b64"] = base64.b64encode(
            chunk_bytes(1)[: old["length"] // 2]).decode()
    elif corrupt_old_digest_decl:
        # bytes stay valid inline content, but declared digest is wrong
        old["sha256"] = "f" * 64
    return p2


def test_superseded_old_chunk_unreadable_blocks_seal(client, evidence_root):
    v1 = _sealed_correction_base(client, "M-CORR-MISSING")
    p2 = _correction_payload(v1["manifest_id"], "M-CORR-MISSING",
                             make_old_unreadable=True)
    created = post_manifest(client, p2).json()
    codes = set(_codes(created))
    # hard error, never a *_SUPERSEDED warning
    assert "CHUNK_FILE_UNREADABLE" in codes
    assert not any(c.endswith("_SUPERSEDED") for c in codes)
    f = next(x for x in created["report"]["findings"]
             if x["code"] == "CHUNK_FILE_UNREADABLE")
    assert f["chunk_ids"] == ["C02"]
    assert f["detail"]["effective"] is False
    # correction chunk itself still reconstructs the image, but the manifest
    # cannot be sealed while the registered old chunk is unverifiable
    assert created["report"]["all_chunk_digests_verified"] is False
    assert created["report"]["sealable"] is False
    r = seal(client, created["manifest_id"])
    assert r.status_code == 409
    assert "CHUNK_FILE_UNREADABLE" in {x["code"]
                                       for x in r.json()["detail"]["blocking_findings"]}

    pkg = client.get(
        f"/manifests/{created['manifest_id']}/evidence-package").json()
    rec = client.post("/evidence/recompute", json=pkg).json()
    assert rec["valid"] is False
    assert rec["checks"]["chunk_content_ok"] is False
    bad = [c for c in rec["chunk_checks"] if c["chunk_id"] == "C02"]
    assert bad and bad[0]["readable"] is False and bad[0]["effective"] is False


def test_superseded_old_chunk_truncated_blocks_seal(client):
    v1 = _sealed_correction_base(client, "M-CORR-TRUNC")
    p2 = _correction_payload(v1["manifest_id"], "M-CORR-TRUNC",
                             truncate_old=True)
    created = post_manifest(client, p2).json()
    codes = set(_codes(created))
    assert "CHUNK_CONTENT_LENGTH_MISMATCH" in codes
    f = next(x for x in created["report"]["findings"]
             if x["code"] == "CHUNK_CONTENT_LENGTH_MISMATCH"
             and x["chunk_ids"] == ["C02"])
    assert f["detail"]["effective"] is False
    assert created["report"]["sealable"] is False
    assert seal(client, created["manifest_id"]).status_code == 409

    pkg = client.get(
        f"/manifests/{created['manifest_id']}/evidence-package").json()
    rec = client.post("/evidence/recompute", json=pkg).json()
    assert rec["valid"] is False
    assert rec["checks"]["chunk_content_ok"] is False
    old_check = next(c for c in rec["chunk_checks"] if c["chunk_id"] == "C02")
    assert old_check["length_ok"] is False and old_check["effective"] is False


def test_superseded_old_chunk_digest_conflict_blocks_seal(client):
    v1 = _sealed_correction_base(client, "M-CORR-DIG")
    p2 = _correction_payload(v1["manifest_id"], "M-CORR-DIG",
                             corrupt_old_digest_decl=True)
    created = post_manifest(client, p2).json()
    f = next(x for x in created["report"]["findings"]
             if x["code"] == "CHUNK_DIGEST_MISMATCH"
             and x["chunk_ids"] == ["C02"])
    assert f["detail"]["effective"] is False
    assert created["report"]["sealable"] is False
    r = seal(client, created["manifest_id"])
    assert r.status_code == 409
    assert "CHUNK_DIGEST_MISMATCH" in {x["code"]
                                      for x in r.json()["detail"]["blocking_findings"]}

    pkg = client.get(
        f"/manifests/{created['manifest_id']}/evidence-package").json()
    rec = client.post("/evidence/recompute", json=pkg).json()
    assert rec["valid"] is False
    old_check = next(c for c in rec["chunk_checks"] if c["chunk_id"] == "C02")
    assert old_check["digest_ok"] is False


def test_correction_with_old_chunk_file_on_disk_verifies_and_seals(
        client, evidence_root):
    # positive counterpart: old C02 registered as a readable file with its
    # original digest, C02X inline -> both verify, seal allowed (regression
    # guard so the hard rule does not over-block legitimate corrections)
    import base64

    from tests.conftest import chunk_bytes

    v1 = _sealed_correction_base(client, "M-CORR-OK2")
    p2 = build_payload(media_id="M-CORR-OK2", change_kind="correction",
                       parent=v1["manifest_id"])
    c02 = next(c for c in p2["chunks"] if c["chunk_id"] == "C02")
    # place the OLD content on disk and point the superseded chunk at it
    old_path = evidence_root / "media" / "C02.dd"
    old_path.parent.mkdir(parents=True, exist_ok=True)
    old_path.write_bytes(chunk_bytes(1))
    c02.pop("content_b64", None)
    c02["stored_path"] = "media/C02.dd"

    import hashlib
    data = b"erased-bad-sector-reimage".ljust(c02["length"], b"\x05")
    corrected = copy.deepcopy(c02)
    corrected.update({"chunk_id": "C02X", "index": 1,
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "content_b64": base64.b64encode(data).decode(),
                      "correction_of": "C02",
                      "stored_path": None,
                      "note": "re-imaged after read error"})
    p2["chunks"].append(corrected)
    new_image = b"".join(data if i == 1 else chunk_bytes(i)
                         for i in range(4))
    expected = hashlib.sha256(new_image).hexdigest()
    p2["expected_total_sha256"] = expected
    for rep in p2["replicas"]:
        rep["sha256"] = expected
    for ev in p2["custody_events"]:
        for key in ("digest_before", "digest_after", "expected_digest"):
            if ev.get(key):
                ev[key] = expected

    created = post_manifest(client, p2).json()
    assert created["report"]["sealable"] is True, created["report"]["findings"]
    applied = [f for f in created["report"]["findings"]
               if f["code"] == "CHUNK_CORRECTION_APPLIED"]
    assert len(applied) == 1
    rows = {c["chunk_id"]: c for c in created["report"]["chunk_content"]}
    assert rows["C02"]["digest_verified"] and rows["C02"]["source"] == "file"
    assert rows["C02X"]["digest_verified"] and rows["C02X"]["source"] == "inline"
    assert seal(client, created["manifest_id"]).status_code == 200
