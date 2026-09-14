"""Post-seal integrity inspection tests.

A sealed image's copies are patrolled with a seed-deterministic sample plan
(head/tail sectors, chunk seams, random sectors). The service regenerates
the plan from the frozen seed, compares each submitted reading against the
sealed evidence package and keeps an append-only history: re-tests never
overwrite a failed result and the first-change time of a divergent interval
survives later passes.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.conftest import (
    SECTOR_SIZE,
    TOTAL_SECTORS,
    build_payload,
    chunk_bytes,
    post_manifest,
    seal,
    total_image_bytes,
    write_chunk_files,
)

T_READ = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)

# With the default 4x16-sector layout the mandatory set is exactly 8 sectors,
# so ratio 8/64 yields a seed-independent plan: head/tail + seam pairs.
MANDATORY_PLAN = [[0, 1], [15, 17], [31, 33], [47, 49], [63, 64]]


def interval_digest(s0: int, s1: int) -> str:
    data = total_image_bytes()
    return hashlib.sha256(data[s0 * SECTOR_SIZE:s1 * SECTOR_SIZE]).hexdigest()


def make_readings(plan_intervals, *, read_at=T_READ, corrupt=(), error_for=(),
                  skip=()):
    corrupt = set(corrupt)
    error_for = set(error_for)
    skip = set(skip)
    readings = []
    for i, iv in enumerate(plan_intervals):
        s0, s1 = iv["start_sector"], iv["end_sector"]
        if (s0, s1) in skip:
            continue
        rd = {"start_sector": s0, "end_sector": s1,
              "read_at": (read_at + timedelta(seconds=5 * i)).isoformat()}
        if (s0, s1) in error_for:
            rd["error"] = "medium-error: UNC"
        elif (s0, s1) in corrupt:
            rd["sha256"] = "0" * 64
        else:
            rd["sha256"] = interval_digest(s0, s1)
        readings.append(rd)
    return readings


def sealed_manifest(client, media_id="M-INSP", **kw):
    payload = build_payload(media_id=media_id, **kw)
    created = post_manifest(client, payload)
    assert created.status_code == 201, created.text
    mid = created.json()["manifest_id"]
    assert seal(client, mid).status_code == 200
    return mid


def get_plan(client, mid, seed="seed-1", ratio=0.125):
    r = client.get(f"/manifests/{mid}/inspection-plan",
                   params={"seed": seed, "sample_ratio": ratio})
    assert r.status_code == 200, r.text
    return r.json()


def submit(client, mid, plan, *, inspection_id="I-1", replica_id="R-ARC",
           seed="seed-1", ratio=0.125, readings=None, device_id="READER-01"):
    body = {
        "inspection_id": inspection_id,
        "replica_id": replica_id,
        "seed": seed,
        "sample_ratio": ratio,
        "device": {"device_id": device_id, "model": "Tableau TD3",
                   "serial": "TD3-7788", "interface": "SATA"},
        "readings": (readings if readings is not None
                     else make_readings(plan["planned_intervals"])),
    }
    return client.post(f"/manifests/{mid}/inspections", json=body)


# ------------------------------------------------------------- sample plan --
def test_plan_is_deterministic_and_covers_head_tail_and_seams(client):
    mid = sealed_manifest(client, "M-PLAN")
    p1 = get_plan(client, mid, seed="alpha", ratio=0.5)
    p2 = get_plan(client, mid, seed="alpha", ratio=0.5)
    assert p1 == p2  # same seed -> identical plan (no cherry-picking)

    sampled = {s for iv in p1["planned_intervals"]
               for s in range(iv["start_sector"], iv["end_sector"])}
    # head/tail and both sectors straddling every chunk seam (16/32/48)
    assert {0, 63, 15, 16, 31, 32, 47, 48} <= sampled
    assert p1["chunk_boundaries"] == [16, 32, 48]
    assert p1["planned_sectors"] >= round(TOTAL_SECTORS * 0.5)
    assert p1["total_sectors"] == TOTAL_SECTORS

    p3 = get_plan(client, mid, seed="beta", ratio=0.5)
    assert p1["planned_intervals"] != p3["planned_intervals"]

    # the plan is bound to the sealed evidence package
    pkg = client.get(f"/manifests/{mid}/evidence-package").json()
    assert p1["evidence_package_digest"] == pkg["evidence_package_digest"]
    assert p1["image_sha256"] == pkg["computed"]["reconstructed_sha256"]
    assert p1["merkle_root"] == pkg["computed"]["merkle_root"]


def test_plan_requires_sealed_manifest(client):
    payload = build_payload(media_id="M-DRAFT")
    mid = post_manifest(client, payload).json()["manifest_id"]
    r = client.get(f"/manifests/{mid}/inspection-plan",
                   params={"seed": "s", "sample_ratio": 0.5})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "INSPECTION_REQUIRES_SEALED"
    assert client.get("/manifests/MF-NOPE/inspection-plan",
                      params={"seed": "s", "sample_ratio": 0.5}).status_code == 404


# ------------------------------------------------------------------ verdict --
def test_passed_inspection_full_match(client):
    mid = sealed_manifest(client, "M-PASS")
    plan = get_plan(client, mid)
    assert [[i["start_sector"], i["end_sector"]]
            for i in plan["planned_intervals"]] == MANDATORY_PLAN

    r = submit(client, mid, plan)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["result"] == "passed"
    assert rep["coverage_rate"] == 1.0
    assert rep["verified_rate"] == 1.0
    assert rep["planned_sectors"] == 8
    assert rep["verified_sectors"] == 8
    assert rep["findings"] == []
    assert rep["divergent_intervals"] == []
    assert rep["first_change_at"] is None
    # frozen context echoed back and bound to the evidence package
    assert rep["seed"] == "seed-1"
    assert rep["replica_id"] == "R-ARC"
    assert rep["device"]["device_id"] == "READER-01"
    assert rep["chunk_boundaries"] == [16, 32, 48]
    pkg = client.get(f"/manifests/{mid}/evidence-package").json()
    assert rep["evidence_package_digest"] == pkg["evidence_package_digest"]
    assert all(iv["status"] == "match" for iv in rep["intervals"])
    # seam interval [15,17) spans chunks C01/C02 and still matched
    seam = next(iv for iv in rep["intervals"] if iv["start_sector"] == 15)
    assert seam["end_sector"] == 17 and seam["chunk_ids"] == ["C01", "C02"]

    # stored record is retrievable and identical
    stored = client.get(f"/manifests/{mid}/inspections/I-1").json()
    assert stored == rep
    listed = client.get(f"/manifests/{mid}/inspections").json()
    assert [x["inspection_id"] for x in listed] == ["I-1"]
    assert listed[0]["result"] == "passed"


def test_digest_conflict_marks_failed_and_locates_replica_and_sectors(client):
    mid = sealed_manifest(client, "M-FAIL")
    plan = get_plan(client, mid)
    readings = make_readings(plan["planned_intervals"],
                             corrupt={(15, 17)})
    r = submit(client, mid, plan, readings=readings)
    assert r.status_code == 201
    rep = r.json()
    assert rep["result"] == "failed"
    conflict = [f for f in rep["findings"]
                if f["code"] == "INSPECTION_DIGEST_CONFLICT"]
    assert len(conflict) == 1
    assert conflict[0]["replica_ids"] == ["R-ARC"]
    assert (conflict[0]["start_sector"], conflict[0]["end_sector"]) == (15, 17)
    assert conflict[0]["detail"]["expected"] == interval_digest(15, 17)
    assert conflict[0]["detail"]["actual"] == "0" * 64

    assert rep["verified_sectors"] == 6  # 8 planned - 2 divergent
    div = rep["divergent_intervals"]
    assert len(div) == 1
    assert (div[0]["start_sector"], div[0]["end_sector"]) == (15, 17)
    assert div[0]["replica_id"] == "R-ARC"
    # first change observed at the reading's own read_at
    assert div[0]["first_change_at"] == div[0]["read_at"]
    assert div[0]["first_inspection_id"] == "I-1"
    assert rep["first_change_at"] == div[0]["read_at"]


def test_missing_interval_is_inconclusive(client):
    mid = sealed_manifest(client, "M-MISS")
    plan = get_plan(client, mid)
    readings = make_readings(plan["planned_intervals"], skip={(31, 33)})
    rep = submit(client, mid, plan, readings=readings).json()
    assert rep["result"] == "inconclusive"
    miss = [f for f in rep["findings"]
            if f["code"] == "INSPECTION_INTERVAL_MISSING"]
    assert len(miss) == 1
    assert (miss[0]["start_sector"], miss[0]["end_sector"]) == (31, 33)
    assert miss[0]["replica_ids"] == ["R-ARC"]
    assert rep["coverage_rate"] == 0.75  # 6 of 8 planned sectors submitted
    assert rep["verified_sectors"] == 6


def test_duplicate_and_out_of_plan_readings_are_inconclusive(client):
    mid = sealed_manifest(client, "M-SHAPE")
    plan = get_plan(client, mid)
    readings = make_readings(plan["planned_intervals"])
    readings.append(dict(readings[0]))  # duplicate of [0,1)
    readings.append({"start_sector": 40, "end_sector": 41,
                     "read_at": T_READ.isoformat(),
                     "sha256": interval_digest(40, 41)})  # not in the plan
    readings.append({"start_sector": 63, "end_sector": 65,
                     "read_at": T_READ.isoformat(),
                     "sha256": "a" * 64})  # beyond the medium geometry
    rep = submit(client, mid, plan, readings=readings).json()
    assert rep["result"] == "inconclusive"
    codes = [f["code"] for f in rep["findings"]]
    assert codes.count("INSPECTION_READING_DUPLICATE") == 1
    assert codes.count("INSPECTION_READING_OUT_OF_BOUNDS") == 2
    oob = [f for f in rep["findings"]
           if f["code"] == "INSPECTION_READING_OUT_OF_BOUNDS"]
    assert any(f["end_sector"] == 65 for f in oob)
    assert any(f["start_sector"] == 40 for f in oob)


def test_duplicate_interval_contributes_zero_coverage(client):
    """Submitting the same in-plan reading twice keeps the duplicate warning
    and the first reading's comparison, but that interval contributes zero
    sectors both to the run's covered/verified counts and to the historical
    cumulative coverage."""
    mid = sealed_manifest(client, "M-DUPCOV")
    plan = get_plan(client, mid)
    intervals = plan["planned_intervals"]
    head = intervals[0]
    assert (head["start_sector"], head["end_sector"]) == (0, 1)

    readings = make_readings(intervals)
    readings.append(dict(readings[0]))  # [0,1) submitted twice
    rep = submit(client, mid, plan, inspection_id="I-D1",
                 readings=readings).json()

    assert rep["result"] == "inconclusive"
    dup = [f for f in rep["findings"]
           if f["code"] == "INSPECTION_READING_DUPLICATE"]
    assert len(dup) == 1
    assert (dup[0]["start_sector"], dup[0]["end_sector"]) == (0, 1)
    # the first reading was still compared and matched; only the duplicate
    # reading itself is rejected
    head_result = next(iv for iv in rep["intervals"]
                       if iv["start_sector"] == 0 and iv["end_sector"] == 1)
    assert head_result["status"] == "match"

    # the duplicated interval's one sector contributes nothing
    assert rep["planned_sectors"] == 8
    assert rep["covered_sectors"] == 7
    assert rep["verified_sectors"] == 7
    assert rep["coverage_rate"] == 0.875
    assert rep["verified_rate"] == 0.875

    history = client.get(f"/manifests/{mid}/inspection-report").json()
    assert history["inspection_count"] == 1
    # 7 genuinely-read sectors of 64 total -- not 8
    assert history["cumulative_coverage_rate"] == 7 / TOTAL_SECTORS

    # a later, non-duplicated run over the same plan restores the duplicated
    # sector's coverage; append-only keeps the first record untouched
    rep2 = submit(client, mid, plan, inspection_id="I-D2",
                  readings=make_readings(intervals,
                                         read_at=T_READ + timedelta(days=1)),
                  device_id="READER-02").json()
    assert rep2["result"] == "passed"
    assert rep2["covered_sectors"] == 8
    history2 = client.get(f"/manifests/{mid}/inspection-report").json()
    assert history2["cumulative_coverage_rate"] == 8 / TOTAL_SECTORS
    assert history2["results"] == {"inconclusive": 1, "passed": 1}
    stored1 = client.get(f"/manifests/{mid}/inspections/I-D1").json()
    assert stored1 == rep
    assert stored1["covered_sectors"] == 7


def test_read_failure_is_inconclusive_not_overwritten_by_retest(client):
    mid = sealed_manifest(client, "M-READERR")
    plan = get_plan(client, mid)
    readings = make_readings(plan["planned_intervals"],
                             error_for={(47, 49)})
    rep = submit(client, mid, plan, readings=readings).json()
    assert rep["result"] == "inconclusive"
    fail = [f for f in rep["findings"] if f["code"] == "INSPECTION_READ_FAILED"]
    assert len(fail) == 1
    assert (fail[0]["start_sector"], fail[0]["end_sector"]) == (47, 49)
    assert fail[0]["replica_ids"] == ["R-ARC"]
    assert fail[0]["detail"]["tool_error"] == "medium-error: UNC"

    # re-test with a new id passes, but the append-only history keeps both
    rep2 = submit(client, mid, plan, inspection_id="I-2").json()
    assert rep2["result"] == "passed"
    listed = client.get(f"/manifests/{mid}/inspections").json()
    assert [x["result"] for x in listed] == ["inconclusive", "passed"]
    history = client.get(f"/manifests/{mid}/inspection-report").json()
    assert history["results"] == {"inconclusive": 1, "passed": 1}
    assert history["latest_result"] == "passed"


def test_unknown_replica_breaks_chain_and_fails(client):
    mid = sealed_manifest(client, "M-REPLICA")
    plan = get_plan(client, mid)
    rep = submit(client, mid, plan, replica_id="R-GHOST").json()
    assert rep["result"] == "failed"
    codes = [f["code"] for f in rep["findings"]]
    assert "INSPECTION_REPLICA_UNKNOWN" in codes
    f = next(f for f in rep["findings"]
             if f["code"] == "INSPECTION_REPLICA_UNKNOWN")
    assert f["replica_ids"] == ["R-GHOST"]


def test_inspection_on_draft_manifest_rejected(client):
    payload = build_payload(media_id="M-NOTSEALED")
    mid = post_manifest(client, payload).json()["manifest_id"]
    r = submit(client, mid, {"planned_intervals": []})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "INSPECTION_REQUIRES_SEALED"


def test_reading_must_carry_exactly_one_of_digest_or_error(client):
    mid = sealed_manifest(client, "M-READING-SCHEMA")
    plan = get_plan(client, mid)
    readings = make_readings(plan["planned_intervals"])
    both = dict(readings[0])
    both["error"] = "medium-error"  # digest AND error -> 422
    r = submit(client, mid, plan, readings=[both])
    assert r.status_code == 422
    neither = {k: v for k, v in readings[0].items() if k != "sha256"}
    r2 = submit(client, mid, plan, readings=[neither])
    assert r2.status_code == 422


# ------------------------------------------------------- append-only history --
def test_duplicate_inspection_id_never_overwrites(client):
    mid = sealed_manifest(client, "M-APPEND")
    plan = get_plan(client, mid)
    bad = make_readings(plan["planned_intervals"], corrupt={(0, 1)})
    rep1 = submit(client, mid, plan, readings=bad).json()
    assert rep1["result"] == "failed"

    # same id with a now-passing reading set must not overwrite the failure
    r = submit(client, mid, plan)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "INSPECTION_DUPLICATE"
    stored = client.get(f"/manifests/{mid}/inspections/I-1").json()
    assert stored["result"] == "failed"
    assert stored["divergent_intervals"][0]["start_sector"] == 0


def test_first_change_time_survives_later_passing_retest(client):
    mid = sealed_manifest(client, "M-FIRSTCHANGE")
    plan = get_plan(client, mid)
    t1 = T_READ
    bad = make_readings(plan["planned_intervals"], read_at=t1,
                        corrupt={(15, 17)})
    rep1 = submit(client, mid, plan, inspection_id="I-1",
                  readings=bad).json()
    assert rep1["result"] == "failed"
    first_seen = rep1["divergent_intervals"][0]["first_change_at"]

    # later re-test passes: the divergence stays on record with its time
    ok2 = make_readings(plan["planned_intervals"],
                        read_at=t1 + timedelta(days=7))
    rep2 = submit(client, mid, plan, inspection_id="I-2",
                  readings=ok2).json()
    assert rep2["result"] == "passed"

    history = client.get(f"/manifests/{mid}/inspection-report").json()
    assert history["ever_failed"] is True
    assert history["results"] == {"failed": 1, "passed": 1}
    assert len(history["divergent_intervals"]) == 1
    div = history["divergent_intervals"][0]
    assert (div["start_sector"], div["end_sector"]) == (15, 17)
    assert div["first_change_at"] == first_seen
    assert div["first_inspection_id"] == "I-1"
    assert history["first_change_at"] == first_seen

    # a still later failure of the same interval keeps the ORIGINAL time
    bad3 = make_readings(plan["planned_intervals"],
                         read_at=t1 + timedelta(days=30),
                         corrupt={(15, 17)})
    rep3 = submit(client, mid, plan, inspection_id="I-3",
                  readings=bad3).json()
    assert rep3["result"] == "failed"
    assert rep3["divergent_intervals"][0]["first_change_at"] == first_seen
    assert rep3["divergent_intervals"][0]["first_inspection_id"] == "I-1"
    history2 = client.get(f"/manifests/{mid}/inspection-report").json()
    assert history2["first_change_at"] == first_seen
    assert len(history2["divergent_intervals"]) == 1


def test_history_report_cumulative_coverage_and_binding(client):
    mid = sealed_manifest(client, "M-HIST")
    p1 = get_plan(client, mid, seed="s1", ratio=0.25)
    p2 = get_plan(client, mid, seed="s2", ratio=0.25)
    r1 = submit(client, mid, p1, inspection_id="I-1", seed="s1", ratio=0.25)
    r2 = submit(client, mid, p2, inspection_id="I-2", seed="s2", ratio=0.25)
    assert r1.json()["result"] == r2.json()["result"] == "passed"

    history = client.get(f"/manifests/{mid}/inspection-report").json()
    assert history["inspection_count"] == 2
    assert history["results"] == {"passed": 2}
    assert history["ever_failed"] is False
    assert history["latest_result"] == "passed"
    union = {s for p in (p1, p2) for iv in p["planned_intervals"]
             for s in range(iv["start_sector"], iv["end_sector"])}
    assert history["cumulative_coverage_rate"] == \
        len(union) / TOTAL_SECTORS
    assert history["cumulative_coverage_rate"] >= 0.25
    pkg = client.get(f"/manifests/{mid}/evidence-package").json()
    assert history["evidence_package_digest"] == pkg["evidence_package_digest"]
    assert history["image_sha256"] == pkg["computed"]["reconstructed_sha256"]
    assert history["merkle_root"] == pkg["computed"]["merkle_root"]
    assert history["divergent_intervals"] == []
    assert history["first_change_at"] is None
    assert [i["inspection_id"] for i in history["inspections"]] == ["I-1", "I-2"]


# ------------------------------------------------- sealed bytes unavailable --
def test_unreadable_sealed_chunk_makes_interval_unverifiable(
        client, evidence_root):
    payload = build_payload(media_id="M-GONE", with_content=True)
    write_chunk_files(payload, evidence_root)  # strips inline content
    mid = post_manifest(client, payload).json()["manifest_id"]
    assert seal(client, mid).status_code == 200

    # whole-disk plan (ratio 1.0 -> one interval [0,64)); then a sealed chunk
    # file silently disappears from the evidence store
    plan = get_plan(client, mid, seed="s", ratio=1.0)
    assert plan["planned_intervals"] == [
        {"start_sector": 0, "end_sector": TOTAL_SECTORS}]
    (evidence_root / "media" / "C02.dd").unlink()

    readings = [{"start_sector": 0, "end_sector": TOTAL_SECTORS,
                 "read_at": T_READ.isoformat(),
                 "sha256": hashlib.sha256(total_image_bytes()).hexdigest()}]
    rep = submit(client, mid, plan, seed="s", ratio=1.0,
                 readings=readings).json()
    assert rep["result"] == "inconclusive"
    codes = [f["code"] for f in rep["findings"]]
    assert "INSPECTION_EXPECTED_UNRECOMPUTABLE" in codes
    iv = rep["intervals"][0]
    assert iv["status"] == "unverifiable"


# ------------------------------------------------------- unit: chain broken --
def test_replica_digest_mismatch_breaks_chain_unit():
    """A replica registered in the manifest whose digest no longer matches
    the sealed image digest breaks the replica chain -> failed."""
    from app.content import FilesystemContentResolver
    from app.inspection import evaluate_inspection
    from app.schemas import InspectionCreate, ManifestCreate
    from app.verifier import evaluate

    payload = ManifestCreate.model_validate(build_payload(media_id="M-UNIT"))
    report = evaluate(payload)
    assert report.sealable is True
    # the sealed image digest stays, but the archive replica's recorded
    # digest no longer matches it (chain broken after sealing)
    payload.replicas[-1].sha256 = "f" * 64

    plan = [[0, 1], [15, 17], [31, 33], [47, 49], [63, 64]]
    readings = [{"start_sector": a, "end_sector": b,
                 "read_at": T_READ.isoformat(),
                 "sha256": interval_digest(a, b)} for a, b in plan]
    insp = InspectionCreate.model_validate({
        "inspection_id": "I-U1", "replica_id": "R-ARC", "seed": "seed-1",
        "sample_ratio": 0.125, "device": {"device_id": "READER-01"},
        "readings": readings})
    row = {"manifest_id": "MF-UNIT", "media_id": "M-UNIT"}
    rep = evaluate_inspection(
        insp, manifest_row=row, sealed_payload=payload, sealed_report=report,
        resolver=FilesystemContentResolver(()), prior_reports=[],
        evidence_package_digest="d" * 64, created_at=T_READ.isoformat())
    assert rep.result == "failed"
    codes = [f.code for f in rep.findings]
    assert "INSPECTION_REPLICA_DIGEST_MISMATCH" in codes
    f = next(f for f in rep.findings
             if f.code == "INSPECTION_REPLICA_DIGEST_MISMATCH")
    assert f.replica_ids == ["R-ARC"]
    assert f.detail["sealed_image"] == report.reconstructed_sha256


def test_sample_plan_generator_properties():
    from app.inspection import generate_sample_plan

    # determinism
    a = generate_sample_plan(64, [16, 32, 48], 0.5, "seed")
    assert a == generate_sample_plan(64, [16, 32, 48], 0.5, "seed")
    # mandatory coverage: head, tail, seam neighbours
    sampled = {s for s0, s1 in a for s in range(s0, s1)}
    assert {0, 63, 15, 16, 31, 32, 47, 48} <= sampled
    # ratio target respected (32 of 64) and intervals are merged runs
    assert sum(s1 - s0 for s0, s1 in a) == 32
    for (s0, s1), (n0, _) in zip(a, a[1:]):
        assert s1 < n0  # non-adjacent, sorted
    # ratio below the mandatory set still covers all mandatory sectors
    b = generate_sample_plan(64, [16, 32, 48], 0.01, "seed")
    assert sum(s1 - s0 for s0, s1 in b) == 8
    # full ratio covers everything as one interval
    assert generate_sample_plan(64, [16, 32, 48], 1.0, "seed") == [[0, 64]]
    # empty medium -> empty plan
    assert generate_sample_plan(0, [], 0.5, "seed") == []


# -------------------------------- frozen baseline: reference file rewritten --
def _sealed_file_manifest(client, evidence_root, media_id):
    """Seal a manifest whose chunks are file-backed under a temp evidence root."""
    payload = build_payload(media_id=media_id, with_content=True)
    paths = write_chunk_files(payload, evidence_root)  # strips inline content
    mid = post_manifest(client, payload).json()["manifest_id"]
    assert seal(client, mid).status_code == 200
    return mid, paths


def test_rewritten_source_file_does_not_implicate_unchanged_copy(
        client, evidence_root):
    """Sealing freezes the per-chunk baseline. If the registered reference file
    is rewritten *after* sealing, an inspection of an unchanged copy that
    submits the original correct digests must be inconclusive (frozen baseline
    no longer restorable) -- never a digest conflict against the new bytes."""
    mid, paths = _sealed_file_manifest(client, evidence_root, "M-REBASE")
    plan = get_plan(client, mid)

    # the source file backing C02 (sectors 16..31) is silently overwritten
    # in place with same-length but different bytes after sealing
    target = Path(paths[1])
    target.write_bytes(b"\x99" * (SECTOR_SIZE * 16))

    # the replica itself is untouched: readings are the ORIGINAL correct
    # digests, computed from the sealed image bytes
    readings = make_readings(plan["planned_intervals"])
    rep = submit(client, mid, plan, readings=readings).json()

    assert rep["result"] == "inconclusive"
    codes_ = [f["code"] for f in rep["findings"]]
    # no replica digest conflict: the copy is not the thing that changed
    assert "INSPECTION_DIGEST_CONFLICT" not in codes_
    assert "INSPECTION_EXPECTED_UNRECOMPUTABLE" in codes_
    unv = [f for f in rep["findings"]
           if f["code"] == "INSPECTION_EXPECTED_UNRECOMPUTABLE"]
    # exactly the two seam intervals straddling rewritten chunk C02
    assert sorted((f["start_sector"], f["end_sector"]) for f in unv) == \
        [(15, 17), (31, 33)]
    assert all(f["replica_ids"] == ["R-ARC"] for f in unv)

    statuses = {(iv["start_sector"], iv["end_sector"]): iv["status"]
                for iv in rep["intervals"]}
    assert statuses[(15, 17)] == "unverifiable"
    assert statuses[(31, 33)] == "unverifiable"
    # intervals wholly inside untouched chunks still verify from the baseline
    for key in ((0, 1), (47, 49), (63, 64)):
        assert statuses[key] == "match"
    # the read genuinely returned bytes, so it is covered but not verified
    assert rep["planned_sectors"] == 8
    assert rep["covered_sectors"] == 8
    assert rep["verified_sectors"] == 4
    assert rep["coverage_rate"] == 1.0
    assert rep["verified_rate"] == 0.5
    assert rep["divergent_intervals"] == []
    assert rep["first_change_at"] is None

    # history must not invent a divergence either; binding is unchanged
    history = client.get(f"/manifests/{mid}/inspection-report").json()
    assert history["divergent_intervals"] == []
    assert history["ever_failed"] is False
    pkg = client.get(f"/manifests/{mid}/evidence-package").json()
    assert rep["evidence_package_digest"] == pkg["evidence_package_digest"]
    assert history["evidence_package_digest"] == pkg["evidence_package_digest"]


def test_truncated_source_file_makes_touching_intervals_inconclusive(
        client, evidence_root):
    """A truncated reference file equally destroys the frozen baseline for the
    intervals touching it; correct copy digests never become conflicts."""
    mid, paths = _sealed_file_manifest(client, evidence_root, "M-RETRUNC")
    plan = get_plan(client, mid)
    Path(paths[1]).write_bytes(chunk_bytes(1)[: SECTOR_SIZE * 8])  # C02 half gone

    rep = submit(client, mid, plan,
                 readings=make_readings(plan["planned_intervals"]),
                 inspection_id="I-T1").json()
    assert rep["result"] == "inconclusive"
    codes_ = [f["code"] for f in rep["findings"]]
    assert "INSPECTION_DIGEST_CONFLICT" not in codes_
    unv = sorted((f["start_sector"], f["end_sector"])
                 for f in rep["findings"]
                 if f["code"] == "INSPECTION_EXPECTED_UNRECOMPUTABLE")
    assert unv == [(15, 17), (31, 33)]


def test_corrupt_copy_against_intact_baseline_still_fails(client, evidence_root):
    """Guard the other direction: while the frozen baseline is intact, a copy
    that really returns different bytes is still proven failed."""
    mid, _ = _sealed_file_manifest(client, evidence_root, "M-REOK")
    plan = get_plan(client, mid)
    readings = make_readings(plan["planned_intervals"], corrupt={(15, 17)})
    rep = submit(client, mid, plan, readings=readings,
                 inspection_id="I-C1").json()
    assert rep["result"] == "failed"
    codes_ = [f["code"] for f in rep["findings"]]
    assert "INSPECTION_DIGEST_CONFLICT" in codes_
    assert "INSPECTION_EXPECTED_UNRECOMPUTABLE" not in codes_


# -------------------- cumulative coverage only merges real successful reads --
def test_history_coverage_excludes_missing_failed_duplicate_oob(client):
    mid = sealed_manifest(client, "M-COVCAL")
    plan = get_plan(client, mid, seed="cov-seed", ratio=0.25)
    intervals = plan["planned_intervals"]
    assert len(intervals) >= 4

    # I-1: one interval duplicated, one skipped (missing), one read error,
    # one out-of-plan reading and one beyond geometry; the rest read fine.
    dup_iv, skip_iv, err_iv = intervals[0], intervals[1], intervals[2]
    good = make_readings(intervals[3:])
    dup_reading = make_readings([dup_iv])
    readings = list(dup_reading)
    readings.append(dict(dup_reading[0]))  # duplicate of the same interval
    readings.append(make_readings([err_iv], error_for={
        (err_iv["start_sector"], err_iv["end_sector"])})[0])
    readings += good

    planned_sectors_set = {s for iv in intervals
                           for s in range(iv["start_sector"], iv["end_sector"])}
    sampled_sectors = {s for iv in intervals
                       for s in range(iv["start_sector"], iv["end_sector"])}
    sampled_sectors -= set(range(skip_iv["start_sector"], skip_iv["end_sector"]))
    sampled_sectors -= set(range(err_iv["start_sector"], err_iv["end_sector"]))
    # the duplicated interval contributes zero coverage in this run, even
    # though its first reading carried a correct digest
    sampled_sectors -= set(range(dup_iv["start_sector"], dup_iv["end_sector"]))

    free = next(s for s in range(TOTAL_SECTORS - 1)
                if s not in planned_sectors_set and s + 1 not in planned_sectors_set)
    readings.append({"start_sector": free, "end_sector": free + 1,
                     "read_at": T_READ.isoformat(),
                     "sha256": interval_digest(free, free + 1)})
    readings.append({"start_sector": 63, "end_sector": 65,
                     "read_at": T_READ.isoformat(), "sha256": "b" * 64})

    r1 = submit(client, mid, plan, inspection_id="I-1", seed="cov-seed",
                ratio=0.25, readings=readings)
    assert r1.status_code == 201, r1.text
    rep1 = r1.json()
    assert rep1["result"] == "inconclusive"
    fcodes = [f["code"] for f in rep1["findings"]]
    assert "INSPECTION_INTERVAL_MISSING" in fcodes
    assert "INSPECTION_READ_FAILED" in fcodes
    assert "INSPECTION_READING_DUPLICATE" in fcodes
    assert fcodes.count("INSPECTION_READING_OUT_OF_BOUNDS") == 2
    expected_covered = len(sampled_sectors)
    assert rep1["planned_sectors"] == len(planned_sectors_set)
    assert rep1["covered_sectors"] == expected_covered
    assert rep1["verified_sectors"] == expected_covered
    dup_result = next(iv for iv in rep1["intervals"]
                      if iv["start_sector"] == dup_iv["start_sector"])
    assert dup_result["status"] == "match"  # first reading still compared
    width = lambda iv: iv["end_sector"] - iv["start_sector"]
    assert rep1["covered_sectors"] == \
        len(planned_sectors_set) - width(skip_iv) - width(err_iv) - width(dup_iv)

    history = client.get(f"/manifests/{mid}/inspection-report").json()
    # missing/read-failed/duplicated intervals are not covered; oob readings
    # contribute nothing
    assert history["cumulative_coverage_rate"] == \
        expected_covered / TOTAL_SECTORS
    assert history["cumulative_coverage_rate"] < \
        len(planned_sectors_set) / TOTAL_SECTORS

    # I-2: now genuinely read the three intervals I-1 did not count
    # (skipped, read-failed and duplicated), plus an out-of-plan reading that
    # must still be ignored; the other plan intervals stay missing in this run
    # (they were already covered by I-1).
    fill = make_readings([dup_iv, skip_iv, err_iv],
                         read_at=T_READ + timedelta(days=1))
    fill.append({"start_sector": free, "end_sector": free + 1,
                 "read_at": (T_READ + timedelta(days=1)).isoformat(),
                 "sha256": interval_digest(free, free + 1)})
    rep2 = submit(client, mid, plan, inspection_id="I-2", seed="cov-seed",
                  ratio=0.25, readings=fill).json()
    assert rep2["result"] == "inconclusive"  # remaining intervals missing + oob
    assert rep2["covered_sectors"] == \
        (dup_iv["end_sector"] - dup_iv["start_sector"]) + \
        (skip_iv["end_sector"] - skip_iv["start_sector"]) + \
        (err_iv["end_sector"] - err_iv["start_sector"])

    history2 = client.get(f"/manifests/{mid}/inspection-report").json()
    assert history2["cumulative_coverage_rate"] == \
        len(planned_sectors_set) / TOTAL_SECTORS

    # I-3: repeat I-2's genuine reads; union coverage must not grow and the
    # history stays append-only
    rep3 = submit(client, mid, plan, inspection_id="I-3", seed="cov-seed",
                  ratio=0.25,
                  readings=make_readings([skip_iv, err_iv],
                                         read_at=T_READ + timedelta(days=2)),
                  device_id="READER-02").json()
    assert rep3["result"] == "inconclusive"
    history3 = client.get(f"/manifests/{mid}/inspection-report").json()
    assert history3["inspection_count"] == 3
    assert history3["cumulative_coverage_rate"] == \
        len(planned_sectors_set) / TOTAL_SECTORS
    assert [i["inspection_id"] for i in history3["inspections"]] == \
        ["I-1", "I-2", "I-3"]
    # bound evidence package survives all of this
    pkg = client.get(f"/manifests/{mid}/evidence-package").json()
    assert history3["evidence_package_digest"] == \
        pkg["evidence_package_digest"]
    # saved inspection records were not rewritten by later runs
    stored1 = client.get(f"/manifests/{mid}/inspections/I-1").json()
    assert stored1 == rep1

