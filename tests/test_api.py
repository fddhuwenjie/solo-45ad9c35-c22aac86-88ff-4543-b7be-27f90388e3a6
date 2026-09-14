"""End-to-end tests for the split-image evidence verification API."""
from __future__ import annotations

import copy

from tests.conftest import (
    N_CHUNKS,
    SECTOR_SIZE,
    TOTAL_SECTORS,
    build_payload,
    post_manifest,
    seal,
)


# ------------------------------------------------------------------ happy ----
def test_happy_path_full_across_two_sessions_seals(client):
    payload = build_payload()
    r = post_manifest(client, payload)
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["status"] == "draft"
    report = created["report"]
    assert report["sealable"] is True
    assert report["complete_coverage"] is True
    assert report["total_hash_verified"] is True
    assert [f["code"] for f in report["findings"] if f["severity"] == "error"] == []
    # order rebuilt from offsets across both power-loss-split sessions
    assert report["ordered_chunk_ids"] == [f"C{i:02d}" for i in range(1, N_CHUNKS + 1)]
    assert report["covered_sectors"] == TOTAL_SECTORS
    assert report["gaps"] == []
    assert report["overlaps"] == []

    sid = created["manifest_id"]
    r2 = seal(client, sid)
    assert r2.status_code == 200, r2.text
    sealed = r2.json()
    assert sealed["status"] == "sealed"
    assert sealed["merkle_root"] == report["merkle_root"]
    assert sealed["evidence_package_digest"]

    # sealed manifest is read-only: re-seal rejected
    assert seal(client, sid).status_code == 409

    # media registry frozen at first manifest
    media = client.get(f"/media/{payload['media']['media_id']}").json()
    assert media["sector_size"] == SECTOR_SIZE
    assert media["first_manifest_id"] == sid


def test_evidence_package_is_deterministic_and_recomputable(client):
    payload = build_payload()
    sid = post_manifest(client, payload).json()["manifest_id"]
    seal(client, sid)

    pkg1 = client.get(f"/manifests/{sid}/evidence-package").json()
    pkg2 = client.get(f"/manifests/{sid}/evidence-package").json()
    assert pkg1 == pkg2  # deterministic (no volatile fields)

    rec = client.post("/evidence/recompute", json=pkg1).json()
    assert rec["valid"] is True, rec
    assert rec["checks"]["payload_digest_ok"] is True
    assert rec["checks"]["merkle_root_ok"] is True
    assert rec["checks"]["coverage_ok"] is True
    assert rec["checks"]["total_hash_ok"] is True
    assert rec["checks"]["evidence_package_digest_ok"] is True
    assert rec["recomputed"]["merkle_root"] == pkg1["computed"]["merkle_root"]

    # tampering with a chunk digest invalidates package + payload digests
    tampered = copy.deepcopy(pkg1)
    tampered["submission"]["chunks"][0]["sha256"] = "f" * 64
    rec2 = client.post("/evidence/recompute", json=tampered).json()
    assert rec2["valid"] is False
    assert rec2["checks"]["payload_digest_ok"] is False
    assert rec2["checks"]["merkle_root_ok"] is False
    assert rec2["checks"]["evidence_package_digest_ok"] is False


# ------------------------------------------------- segmented resume revisions
def test_partial_then_resume_revision(client):
    # v1: only first two chunks after power loss -> gap, cannot seal
    p1 = build_payload(chunk_seq=[0, 1], sessions_row=[
        {"session_id": "S1", "started_at": "2026-09-10T09:00:00+00:00",
         "ended_at": "2026-09-10T09:40:00+00:00", "operator": "zhao.lei",
         "tool": "dd-guigazi", "interruption": "power-loss"}])
    p1["sessions"] = p1["sessions"][:1]
    p1["chunks"] = [c for c in p1["chunks"] if c["session_id"] == "S1"]
    p1["replicas"] = []
    p1["custody_events"] = []
    p1["expected_total_sha256"] = None
    r1 = post_manifest(client, p1)
    assert r1.status_code == 201, r1.text
    v1 = r1.json()
    assert v1["report"]["sealable"] is False
    gap_codes = [f["code"] for f in v1["report"]["findings"]]
    assert "COVERAGE_GAP" in gap_codes
    assert seal(client, v1["manifest_id"]).status_code == 409

    # cannot register another initial manifest for the same medium
    again = post_manifest(client, p1)
    assert again.status_code == 422
    assert again.json()["detail"]["code"] == "REVISION_REQUIRED"

    # v2: cumulative resumption with new session and remaining chunks
    p2 = build_payload(change_kind="resume", parent=v1["manifest_id"])
    r2 = post_manifest(client, p2)
    assert r2.status_code == 201, r2.text
    v2 = r2.json()
    assert v2["revision"] == 2
    assert v2["parent_manifest_id"] == v1["manifest_id"]
    assert v2["report"]["sealable"] is True
    assert seal(client, v2["manifest_id"]).status_code == 200

    # old revision frozen/superseded, remains readable
    old = client.get(f"/manifests/{v1['manifest_id']}").json()
    assert old["status"] == "superseded"
    assert old["superseded_by"] == v2["manifest_id"]
    assert seal(client, v1["manifest_id"]).status_code == 409

    # revision comparison shows added sessions/chunks/replicas/events, same roots
    diff = client.get("/diffs", params={"left": v1["manifest_id"],
                                        "right": v2["manifest_id"]}).json()
    assert diff["sessions_added"] == ["S2"]
    assert diff["chunks_added"] == ["C03", "C04"]
    assert set(diff["replicas_added"]) == {"R-ACQ", "R-ARC", "R-CPY"}
    assert diff["events_removed"] == []


def test_resume_from_draft_supersedes_it_and_linear_branching_guard(client):
    p = build_payload(media_id="M-LIN")
    v1 = post_manifest(client, p).json()  # left as draft
    child = build_payload(media_id="M-LIN", change_kind="resume",
                          parent=v1["manifest_id"])
    r = post_manifest(client, child)
    assert r.status_code == 201, r.text
    v2 = r.json()
    # v1 is now frozen superseded; a further branch from it is rejected
    child2 = build_payload(media_id="M-LIN", change_kind="resume",
                           parent=v1["manifest_id"])
    r2 = post_manifest(client, child2)
    assert r2.status_code == 409
    assert r2.json()["detail"]["code"] == "PARENT_SUPERSEDED"
    assert r2.json()["detail"]["superseded_by"] == v2["manifest_id"]


# ------------------------------------------------------------ corrections ----
def test_chunk_correction_replaces_bad_segment_in_new_revision(client):
    import base64
    import hashlib

    from tests.conftest import chunk_bytes

    p1 = build_payload()
    v1 = post_manifest(client, p1).json()
    seal(client, v1["manifest_id"])

    # v2: original C02 kept alongside corrected C02X at exactly the same range
    p2 = build_payload(change_kind="correction", parent=v1["manifest_id"])
    c02 = next(c for c in p2["chunks"] if c["chunk_id"] == "C02")
    data = b"erased-bad-sector-reimage".ljust(c02["length"], b"\x05")
    corrected = copy.deepcopy(c02)
    corrected.update({"chunk_id": "C02X",
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "content_b64": base64.b64encode(data).decode(),
                      "correction_of": "C02",
                      "note": "re-imaged after read error on sector 16"})
    p2["chunks"].append(corrected)
    # the re-imaged range is genuinely read again in the correction round
    p2.setdefault("read_attempts", []).append({
        "attempt_id": "A-C02X", "session_id": corrected["session_id"],
        "chunk_id": "C02X",
        "start_sector": 16, "end_sector": 32, "round": 2, "result": "read",
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

    r2 = post_manifest(client, p2)
    assert r2.status_code == 201, r2.text
    v2 = r2.json()
    applied = [f for f in v2["report"]["findings"]
               if f["code"] == "CHUNK_CORRECTION_APPLIED"]
    assert len(applied) == 1
    assert set(applied[0]["chunk_ids"]) == {"C02", "C02X"}
    assert v2["report"]["ordered_chunk_ids"][1] == "C02X"
    assert v2["report"]["total_hash_verified"] is True
    assert v2["report"]["sealable"] is True
    assert seal(client, v2["manifest_id"]).status_code == 200

    diff = client.get("/diffs", params={"left": v1["manifest_id"],
                                        "right": v2["manifest_id"]}).json()
    assert diff["chunks_added"] == ["C02X"]
    assert diff["chunk_digests_changed"] == []  # C02 id retained unchanged
    assert diff["merkle_root_left"] != diff["merkle_root_right"]


def test_same_range_digest_conflict_without_correction_rejects_seal(client):
    p = build_payload()
    bad = copy.deepcopy(p["chunks"][1])
    bad.update({"chunk_id": "C02B", "sha256": "d" * 64, "content_b64": None})
    p["chunks"].append(bad)
    created = post_manifest(client, p).json()
    codes_ = [f["code"] for f in created["report"]["findings"]]
    assert "CHUNK_DIGEST_CONFLICT" in codes_
    assert created["report"]["sealable"] is False
    r = seal(client, created["manifest_id"])
    assert r.status_code == 409
    blockers = r.json()["detail"]["blocking_findings"]
    assert any(b["code"] == "CHUNK_DIGEST_CONFLICT" for b in blockers)
    assert blockers[0]["media_id"] == "MEDIA-001"


# ----------------------------------------------------------- target swap ------
def test_target_swap_derives_revision_and_media_geometry_guard(client):
    p1 = build_payload(media_id="MEDIA-SWAP")
    v1 = post_manifest(client, p1).json()
    seal(client, v1["manifest_id"])

    # swap with unchanged geometry is allowed
    p2 = build_payload(media_id="MEDIA-SWAP", change_kind="target-swap",
                       parent=v1["manifest_id"])
    p2["media"]["geometry"]["media_sn"] = "WD-XYZ12345"
    r2 = post_manifest(client, p2)
    assert r2.status_code == 201, r2.text
    v2_id = r2.json()["manifest_id"]
    assert seal(client, v2_id).status_code == 200

    # source parameters changed mid-case: different sector geometry rejected
    p3 = build_payload(media_id="MEDIA-SWAP", change_kind="target-swap",
                       parent=v2_id)
    p3["media"]["geometry"]["total_sectors"] = 128
    p3["media"]["geometry"]["capacity_bytes"] = SECTOR_SIZE * 128
    v3 = post_manifest(client, p3).json()
    assert v3["report"]["sealable"] is False
    changed = [f for f in v3["report"]["findings"]
               if f["code"] == "MEDIA_PARAMETERS_CHANGED"]
    assert len(changed) == 1
    assert changed[0]["detail"]["registered"]["total_sectors"] == 64
    assert seal(client, v3["manifest_id"]).status_code == 409


# --------------------------------------------------------- failure matrix ----
def _assert_seal_blocked(client, payload, expected_code):
    r = post_manifest(client, payload)
    assert r.status_code == 201, r.text
    report = r.json()["report"]
    assert expected_code in [f["code"] for f in report["findings"]]
    assert report["sealable"] is False
    rs = seal(client, r.json()["manifest_id"])
    assert rs.status_code == 409
    assert any(f["code"] == expected_code
               for f in rs.json()["detail"]["blocking_findings"])
    return report


def test_coverage_gap_is_reported_with_sector_interval(client):
    payload = build_payload(media_id="M-GAP",
                            chunk_seq=[0, 1, 2])  # 48/64 sectors
    # three chunks in default sessions split (2,2) -> second session mapping
    report = _assert_seal_blocked(client, payload, "COVERAGE_GAP")
    gap = next(f for f in report["findings"] if f["code"] == "COVERAGE_GAP")
    assert (gap["start_sector"], gap["end_sector"]) == (48, 64)
    assert report["complete_coverage"] is False


def test_overlap_reports_interval_and_chunks(client):
    overlap = {"chunk_id": "CX", "session_id": "S1", "index": 9,
               "offset": SECTOR_SIZE * 20, "length": SECTOR_SIZE * 4,
               "sha256": "a" * 64, "content_b64": None}
    payload = build_payload(media_id="M-OVL", extra_chunks=[overlap])
    report = _assert_seal_blocked(client, payload, "CHUNK_OVERLAP")
    ovl = next(f for f in report["findings"] if f["code"] == "CHUNK_OVERLAP")
    assert set(ovl["chunk_ids"]) == {"C02", "CX"}
    assert ovl["start_sector"] == 20 and ovl["end_sector"] == 24
    assert report["overlaps"][0]["chunk_ids"] == ["C02", "CX"]


def test_misaligned_chunk_rejected(client):
    payload = build_payload(media_id="M-ALN",
                            chunk_overrides={1: {"offset": SECTOR_SIZE * 16 + 3}})
    _assert_seal_blocked(client, payload, "CHUNK_MISALIGNED")


def test_write_blocker_failure_blocks_seal(client):
    payload = build_payload(media_id="M-WB",
                            write_blocker_row=None)
    _assert_seal_blocked(client, payload, "WRITE_BLOCKER_MISSING")

    payload2 = build_payload(media_id="M-WB2",
                             write_blocker_row={
                                 "blocker_id": "WB-09", "mode": "read-only",
                                 "checked_by": "zhao.lei",
                                 "checked_at": "2026-09-10T09:00:00+00:00",
                                 "passed": False})
    _assert_seal_blocked(client, payload2, "WRITE_BLOCKER_FAILED")

    payload3 = build_payload(
        media_id="M-WB3",
        write_blocker_row={
            "blocker_id": "WB-09", "mode": "read-only", "checked_by": "zhao.lei",
            "checked_at": "2026-09-10T09:00:00+00:00", "passed": True,
            "self_test_digest": "1" * 64,
            "expected_self_test_digest": "2" * 64})
    _assert_seal_blocked(client, payload3,
                         "WRITE_BLOCKER_SELF_TEST_MISMATCH")


def test_chunk_digest_mismatch_against_content(client):
    payload = build_payload(
        media_id="M-DIG",
        chunk_overrides={0: {"sha256": "b" * 64}})  # content disagrees
    _assert_seal_blocked(client, payload, "CHUNK_DIGEST_MISMATCH")


def test_total_scene_hash_mismatch(client):
    payload = build_payload(media_id="M-TOT")
    payload["expected_total_sha256"] = "c" * 64
    report = _assert_seal_blocked(client, payload, "TOTAL_HASH_MISMATCH")
    assert report["total_hash_verified"] is False


def test_replica_copy_digest_break_blocks_seal(client):
    payload = build_payload(media_id="M-REP")
    for rep in payload["replicas"]:
        if rep["replica_id"] == "R-CPY":
            rep["sha256"] = "9" * 64  # copy differs from acquisition
    _assert_seal_blocked(client, payload, "REPLICA_COPY_DIGEST_MISMATCH")


def test_custody_handover_digest_break_blocks_seal(client):
    payload = build_payload(media_id="M-CUS", custody_break=True)
    report = _assert_seal_blocked(client, payload, "CUSTODY_DIGEST_AFTER_BREAK")
    ev = next(f for f in report["findings"]
              if f["code"] == "CUSTODY_DIGEST_AFTER_BREAK")
    assert ev["event_id"] == "E-R-ACQ-SEL"
    assert "R-ACQ" in ev["replica_ids"]


def test_index_order_mismatch(client):
    payload = build_payload(media_id="M-IDX",
                            chunk_overrides={0: {"index": 5}, 3: {"index": 0}})
    _assert_seal_blocked(client, payload, "INDEX_ORDER_MISMATCH")


# --------------------------------------------------------- warnings / precheck
def test_identical_duplicate_chunk_is_warning_and_deduplicated(client):
    dup = copy.deepcopy(build_payload(media_id="M-DUP")["chunks"][0])
    dup["chunk_id"] = "C01-COPY"
    payload = build_payload(media_id="M-DUP", extra_chunks=[dup])
    created = post_manifest(client, payload).json()
    warnings_ = [f["code"] for f in created["report"]["findings"]
                 if f["severity"] == "warning"]
    assert "CHUNK_DUPLICATE_RANGE" in warnings_
    assert created["report"]["sealable"] is True
    assert "C01-COPY" not in created["report"]["ordered_chunk_ids"]


def test_precheck_endpoint_returns_findings_without_sealing(client):
    payload = build_payload(media_id="M-PC",
                            chunk_overrides={2: {"sha256": "b" * 64}})
    sid = post_manifest(client, payload).json()["manifest_id"]
    r = client.post(f"/manifests/{sid}/precheck")
    assert r.status_code == 200
    assert "CHUNK_DIGEST_MISMATCH" in [f["code"] for f in r.json()["findings"]]
    assert client.get(f"/manifests/{sid}").json()["status"] == "draft"

    listed = client.get("/manifests", params={"media_id": "M-PC"}).json()
    assert len(listed) == 1 and listed[0]["status"] == "draft"
    findings = client.get(f"/manifests/{sid}/findings").json()
    assert any(f["code"] == "CHUNK_DIGEST_MISMATCH" for f in findings)


def test_without_inline_content_or_files_is_hard_rejected(client):
    """Weak path 1: no content_b64 and no readable stored_path must error,
    never warn: every effective chunk digest and the image hash must recompute."""
    payload = build_payload(media_id="M-NOINLINE", with_content=False,
                            expected_total=False, replicas="full")
    created = post_manifest(client, payload).json()
    report = created["report"]
    assert report["merkle_root"]  # declared-digest Merkle still computed
    assert report["reconstructed_sha256"] is None
    assert report["all_chunk_digests_verified"] is False
    emitted = {f["code"] for f in report["findings"]
               if f["severity"] == "error"}
    assert "CHUNK_CONTENT_UNAVAILABLE" in emitted
    assert "IMAGE_HASH_NOT_RECOMPUTABLE" in emitted
    assert report["sealable"] is False
    r = seal(client, created["manifest_id"])
    assert r.status_code == 409
    blocker_codes = {f["code"] for f in r.json()["detail"]["blocking_findings"]}
    assert "CHUNK_CONTENT_UNAVAILABLE" in blocker_codes
    assert "IMAGE_HASH_NOT_RECOMPUTABLE" in blocker_codes


def test_unknown_parent_and_cross_media_parent_rejected(client):
    p = build_payload(change_kind="resume", parent="MF-NOPE")
    assert post_manifest(client, p).status_code == 404

    p1 = build_payload(media_id="MEDIA-AAA")
    v1 = post_manifest(client, p1).json()
    seal(client, v1["manifest_id"])
    p2 = build_payload(media_id="MEDIA-BBB", change_kind="resume",
                       parent=v1["manifest_id"])
    assert post_manifest(client, p2).status_code == 422
