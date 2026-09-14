"""Multi-replica joint inspection tests.

A sealed image is kept as several copies (working / off-site / archive).
A joint inspection task freezes the sealed manifest, the evidence package
digest, the participating replicas, one unified seed, one sampling ratio and
a completion window; every replica is then read against the SAME seed-derived
plan intervals (submitted as ordinary per-replica inspection records) and
each record is bound to the task. The service compares the frozen baseline
against every replica interval by interval, distinguishing all-match,
single-replica deviation, multi-replica joint deviation, missing reads and
an unrecomputable baseline (where inter-replica agreement can never be
rejudged as a pass). Tasks and bindings are append-only: a later passing
re-test never erases an earlier difference.
"""
from __future__ import annotations

from datetime import timedelta, timezone
from pathlib import Path

from tests.conftest import (
    SECTOR_SIZE,
    TOTAL_SECTORS,
    build_payload,
    post_manifest,
    seal,
    write_chunk_files,
)
from tests.test_inspection import (
    MANDATORY_PLAN,
    T_READ,
    get_plan,
    interval_digest,
    make_readings,
    sealed_manifest,
    submit,
)

REPLICAS = ["R-ACQ", "R-CPY", "R-ARC"]
WINDOW = ("2026-10-01T00:00:00+00:00", "2026-10-02T00:00:00+00:00")
WIDE_WINDOW = ("2026-09-30T00:00:00+00:00", "2026-11-15T00:00:00+00:00")


def create_joint(client, mid, *, joint_id="J-1", replicas=REPLICAS,
                 seed="seed-1", ratio=0.125, window=WINDOW):
    body = {"joint_id": joint_id, "replica_ids": list(replicas), "seed": seed,
            "sample_ratio": ratio, "window_start": window[0],
            "window_end": window[1]}
    return client.post(f"/manifests/{mid}/joint-inspections", json=body)


def bind(client, mid, joint_id, inspection_id):
    return client.post(
        f"/manifests/{mid}/joint-inspections/{joint_id}/submissions",
        json={"inspection_id": inspection_id})


def get_joint(client, mid, joint_id="J-1"):
    r = client.get(f"/manifests/{mid}/joint-inspections/{joint_id}")
    assert r.status_code == 200, r.text
    return r.json()


def inspect_and_bind(client, mid, plan, *, joint_id="J-1", replica_id,
                     inspection_id, seed="seed-1", ratio=0.125, readings=None):
    """Submit one per-replica inspection and bind it to the joint task."""
    r = submit(client, mid, plan, inspection_id=inspection_id,
               replica_id=replica_id, seed=seed, ratio=ratio, readings=readings)
    assert r.status_code == 201, r.text
    rb = bind(client, mid, joint_id, inspection_id)
    assert rb.status_code == 201, rb.text
    return r.json(), rb.json()


def bind_all_passing(client, mid, plan, *, joint_id="J-1", replicas=REPLICAS):
    last = None
    for rid in replicas:
        _, last = inspect_and_bind(client, mid, plan, joint_id=joint_id,
                                   replica_id=rid, inspection_id=f"I-{rid}")
    return last


def interval_status(rep, s0):
    return next(iv for iv in rep["intervals"] if iv["start_sector"] == s0)


# ------------------------------------------------------------- task creation --
def test_joint_task_creation_freezes_context(client):
    mid = sealed_manifest(client, "M-JCREATE")
    plan = get_plan(client, mid)  # seed-1, ratio 0.125
    r = create_joint(client, mid)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["joint_id"] == "J-1"
    assert rep["manifest_id"] == mid
    assert rep["media_id"] == "M-JCREATE"
    assert rep["seed"] == "seed-1"
    assert rep["sample_ratio"] == 0.125
    assert rep["replica_ids"] == REPLICAS
    assert rep["window_start"].replace("Z", "+00:00") == WINDOW[0]
    assert rep["window_end"].replace("Z", "+00:00") == WINDOW[1]
    # the frozen unified plan is exactly the seed-derived single plan
    assert rep["planned_intervals"] == plan["planned_intervals"]
    assert [[i["start_sector"], i["end_sector"]]
            for i in rep["planned_intervals"]] == MANDATORY_PLAN
    assert rep["planned_sectors"] == 8
    assert rep["total_sectors"] == TOTAL_SECTORS
    assert rep["chunk_boundaries"] == [16, 32, 48]
    # frozen binding to the sealed evidence package
    pkg = client.get(f"/manifests/{mid}/evidence-package").json()
    assert rep["evidence_package_digest"] == pkg["evidence_package_digest"]
    assert rep["image_sha256"] == pkg["computed"]["reconstructed_sha256"]
    assert rep["merkle_root"] == pkg["computed"]["merkle_root"]
    # nobody submitted yet: every replica absent -> inconclusive
    assert rep["result"] == "inconclusive"
    absent = [f for f in rep["findings"] if f["code"] == "JOINT_REPLICA_ABSENT"]
    assert {f["replica_ids"][0] for f in absent} == set(REPLICAS)
    assert all(iv["status"] == "missing-read" for iv in rep["intervals"])
    assert all(iv["missing_replica_ids"] == REPLICAS for iv in rep["intervals"])
    cov = {rc["replica_id"]: rc for rc in rep["replica_coverage"]}
    assert all(cov[rid]["status"] == "absent" for rid in REPLICAS)
    assert rep["bindings"] == []
    assert rep["divergent_intervals"] == []
    assert rep["ever_failed"] is False


def test_joint_task_creation_validation(client):
    mid = sealed_manifest(client, "M-JVAL")
    # unknown manifest -> 404
    assert create_joint(client, "MF-NOPE").status_code == 404
    # unsealed manifest -> 409
    draft = post_manifest(client, build_payload(media_id="M-JDRAFT")) \
        .json()["manifest_id"]
    r = create_joint(client, draft)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "INSPECTION_REQUIRES_SEALED"
    # participating replica not registered in the sealed manifest -> 422
    r = create_joint(client, mid, replicas=["R-ACQ", "R-GHOST"])
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "JOINT_REPLICA_UNKNOWN"
    assert r.json()["detail"]["unknown_replica_ids"] == ["R-GHOST"]
    # duplicate / empty participants -> 422
    assert create_joint(client, mid, replicas=["R-ACQ", "R-ACQ"]) \
        .status_code == 422
    assert create_joint(client, mid, replicas=[]).status_code == 422
    # empty completion window -> 422
    assert create_joint(client, mid, window=(WINDOW[1], WINDOW[0])) \
        .status_code == 422


def test_joint_task_is_append_only(client):
    mid = sealed_manifest(client, "M-JAPPEND")
    assert create_joint(client, mid).status_code == 201
    first = get_joint(client, mid)
    r = create_joint(client, mid)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "JOINT_INSPECTION_DUPLICATE"
    # same id with different parameters is rejected too, task unchanged
    assert create_joint(client, mid, seed="other", ratio=0.5).status_code == 409
    assert get_joint(client, mid) == first


def test_joint_endpoints_404_and_empty_list(client):
    mid = sealed_manifest(client, "M-J404")
    assert client.get(f"/manifests/{mid}/joint-inspections").json() == []
    assert client.get(f"/manifests/{mid}/joint-inspections/J-NOPE") \
        .status_code == 404
    assert bind(client, mid, "J-NOPE", "I-1").status_code == 404
    assert create_joint(client, mid).status_code == 201
    # binding an inspection record that does not exist -> 404
    r = bind(client, mid, "J-1", "I-NOPE")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "JOINT_INSPECTION_UNKNOWN"
    assert client.get("/manifests/MF-NOPE/joint-inspections").status_code == 404


# ------------------------------------------------------------------ verdicts --
def test_joint_all_replicas_match_passes(client):
    mid = sealed_manifest(client, "M-JPASS")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    rep = bind_all_passing(client, mid, plan)
    assert rep["result"] == "passed"
    assert rep["findings"] == []
    assert all(iv["status"] == "all-match" for iv in rep["intervals"])
    for iv in rep["intervals"]:
        assert {c["replica_id"] for c in iv["cells"]} == set(REPLICAS)
        assert all(c["status"] == "match" for c in iv["cells"])
        # every cell is bound to the replica's own inspection record
        assert all(c["inspection_id"] == f"I-{c['replica_id']}"
                   for c in iv["cells"])
    cov = {rc["replica_id"]: rc for rc in rep["replica_coverage"]}
    for rid in REPLICAS:
        assert cov[rid]["status"] == "complete"
        assert cov[rid]["coverage_rate"] == 1.0
        assert cov[rid]["verified_rate"] == 1.0
        assert cov[rid]["result"] == "passed"
        assert cov[rid]["inspection_id"] == f"I-{rid}"
    assert rep["divergent_intervals"] == []
    assert rep["first_change_at"] is None
    assert rep["ever_failed"] is False
    assert [b["inspection_id"] for b in rep["bindings"]] == \
        [f"I-{rid}" for rid in REPLICAS]
    # the report is recomputable from the stored rows and stays identical
    assert get_joint(client, mid) == rep
    listed = client.get(f"/manifests/{mid}/joint-inspections").json()
    assert [s["joint_id"] for s in listed] == ["J-1"]
    assert listed[0]["result"] == "passed"
    assert listed[0]["submitted_replica_ids"] == sorted(REPLICAS)
    assert listed[0]["binding_count"] == 3


def test_single_replica_deviation_fails_and_localizes(client):
    mid = sealed_manifest(client, "M-J1DEV")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    for rid in ("R-ACQ", "R-CPY"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}")
    _, rep = inspect_and_bind(
        client, mid, plan, replica_id="R-ARC", inspection_id="I-R-ARC",
        readings=make_readings(plan["planned_intervals"],
                               corrupt={(15, 17)}))
    assert rep["result"] == "failed"
    iv = interval_status(rep, 15)
    assert iv["status"] == "single-replica-deviation"
    assert iv["deviating_replica_ids"] == ["R-ARC"]
    assert iv["expected_sha256"] == interval_digest(15, 17)
    cells = {c["replica_id"]: c for c in iv["cells"]}
    assert cells["R-ACQ"]["status"] == "match"
    assert cells["R-CPY"]["status"] == "match"
    assert cells["R-ARC"]["status"] == "digest-conflict"
    assert cells["R-ARC"]["actual_sha256"] == "0" * 64
    conflicts = [f for f in rep["findings"]
                 if f["code"] == "JOINT_DIGEST_CONFLICT"]
    assert len(conflicts) == 1
    assert conflicts[0]["replica_ids"] == ["R-ARC"]
    assert (conflicts[0]["start_sector"], conflicts[0]["end_sector"]) == (15, 17)
    assert conflicts[0]["detail"]["classification"] == \
        "single-replica-deviation"
    # the remaining intervals are unaffected
    assert all(i["status"] == "all-match" for i in rep["intervals"]
               if i["start_sector"] != 15)
    # divergence history binds the original inspection record and first-seen
    # time
    assert len(rep["divergent_intervals"]) == 1
    div = rep["divergent_intervals"][0]
    assert div["replica_id"] == "R-ARC"
    assert (div["start_sector"], div["end_sector"]) == (15, 17)
    assert div["first_inspection_id"] == "I-R-ARC"
    assert div["first_change_at"] == div["read_at"]
    assert rep["first_change_at"] == div["read_at"]
    assert rep["ever_failed"] is True


def test_multi_replica_shared_deviation_fails(client):
    """Two replicas returning the SAME wrong digest: a common upstream
    corruption (e.g. both copied from the same rotting intermediate)."""
    mid = sealed_manifest(client, "M-JMDEV")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    inspect_and_bind(client, mid, plan, replica_id="R-ACQ",
                     inspection_id="I-R-ACQ")
    for rid in ("R-CPY", "R-ARC"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}",
                         readings=make_readings(plan["planned_intervals"],
                                                corrupt={(15, 17)}))
    rep = get_joint(client, mid)
    assert rep["result"] == "failed"
    iv = interval_status(rep, 15)
    assert iv["status"] == "multi-replica-deviation"
    assert iv["deviating_replica_ids"] == ["R-CPY", "R-ARC"]
    assert iv["shared_deviation"] is True
    conflict = next(f for f in rep["findings"]
                    if f["code"] == "JOINT_DIGEST_CONFLICT")
    assert conflict["detail"]["shared_deviation"] is True
    assert set(conflict["detail"]["actual_by_replica"]) == {"R-CPY", "R-ARC"}
    # each divergence is bound to the inspection record that saw it
    divs = {(d["replica_id"], d["first_inspection_id"])
            for d in rep["divergent_intervals"]}
    assert divs == {("R-CPY", "I-R-CPY"), ("R-ARC", "I-R-ARC")}


def test_multi_replica_independent_deviation_fails(client):
    """Two replicas diverging with DIFFERENT wrong digests: independent
    media rot, not a shared upstream cause."""
    mid = sealed_manifest(client, "M-JIDEV")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    inspect_and_bind(client, mid, plan, replica_id="R-ACQ",
                     inspection_id="I-R-ACQ")
    inspect_and_bind(client, mid, plan, replica_id="R-CPY",
                     inspection_id="I-R-CPY",
                     readings=make_readings(plan["planned_intervals"],
                                            corrupt={(15, 17)}))  # "0"*64
    arc_readings = make_readings(plan["planned_intervals"])
    for rd in arc_readings:
        if (rd["start_sector"], rd["end_sector"]) == (15, 17):
            rd["sha256"] = "1" * 64  # a different wrong digest
    _, rep = inspect_and_bind(client, mid, plan, replica_id="R-ARC",
                              inspection_id="I-R-ARC", readings=arc_readings)
    assert rep["result"] == "failed"
    iv = interval_status(rep, 15)
    assert iv["status"] == "multi-replica-deviation"
    assert iv["shared_deviation"] is False


# ------------------------------------------------- inconclusive conditions --
def test_absent_replica_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JABSENT")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    for rid in ("R-ACQ", "R-CPY"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}")
    rep = get_joint(client, mid)
    assert rep["result"] == "inconclusive"
    absent = [f for f in rep["findings"] if f["code"] == "JOINT_REPLICA_ABSENT"]
    assert len(absent) == 1
    assert absent[0]["replica_ids"] == ["R-ARC"]
    cov = {rc["replica_id"]: rc for rc in rep["replica_coverage"]}
    assert cov["R-ARC"]["status"] == "absent"
    assert cov["R-ARC"]["bound_inspection_ids"] == []
    assert all(iv["status"] == "missing-read" for iv in rep["intervals"])
    assert all("R-ARC" in iv["missing_replica_ids"]
               for iv in rep["intervals"])


def test_out_of_window_reading_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JWINDOW")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    for rid in ("R-ACQ", "R-CPY"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}")
    # R-ARC's patrol ran after the frozen completion window closed; the
    # per-replica record itself is fine, but it cannot count for this task
    late = make_readings(plan["planned_intervals"],
                         read_at=T_READ + timedelta(days=3))
    _, rep = inspect_and_bind(client, mid, plan, replica_id="R-ARC",
                              inspection_id="I-R-ARC-LATE", readings=late)
    assert rep["result"] == "inconclusive"
    oob = [f for f in rep["findings"]
           if f["code"] == "JOINT_READING_OUT_OF_WINDOW"]
    assert len(oob) == len(plan["planned_intervals"])
    assert all(f["replica_ids"] == ["R-ARC"] for f in oob)
    for iv in rep["intervals"]:
        assert iv["status"] == "missing-read"
        cell = next(c for c in iv["cells"] if c["replica_id"] == "R-ARC")
        assert cell["status"] == "out-of-window"
        assert cell["inspection_id"] == "I-R-ARC-LATE"


def test_incomplete_plan_intervals_stay_inconclusive(client):
    mid = sealed_manifest(client, "M-JINCOMP")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    for rid in ("R-ACQ", "R-CPY"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}")
    # R-ARC skipped one planned interval: the joint plan was not fully executed
    _, rep = inspect_and_bind(
        client, mid, plan, replica_id="R-ARC", inspection_id="I-R-ARC-PART",
        readings=make_readings(plan["planned_intervals"], skip={(31, 33)}))
    assert rep["result"] == "inconclusive"
    miss = [f for f in rep["findings"]
            if f["code"] == "JOINT_INTERVAL_MISSING"]
    assert len(miss) == 1
    assert (miss[0]["start_sector"], miss[0]["end_sector"]) == (31, 33)
    assert miss[0]["replica_ids"] == ["R-ARC"]
    assert miss[0]["detail"]["inspection_id"] == "I-R-ARC-PART"
    iv = interval_status(rep, 31)
    assert iv["status"] == "missing-read"
    assert iv["missing_replica_ids"] == ["R-ARC"]
    assert all(i["status"] == "all-match" for i in rep["intervals"]
               if i["start_sector"] != 31)


def test_read_failure_counts_as_missing_read(client):
    mid = sealed_manifest(client, "M-JREADERR")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    for rid in ("R-ACQ", "R-CPY"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}")
    _, rep = inspect_and_bind(
        client, mid, plan, replica_id="R-ARC", inspection_id="I-R-ARC-ERR",
        readings=make_readings(plan["planned_intervals"],
                               error_for={(47, 49)}))
    assert rep["result"] == "inconclusive"
    fail = [f for f in rep["findings"] if f["code"] == "JOINT_READ_FAILED"]
    assert len(fail) == 1
    assert (fail[0]["start_sector"], fail[0]["end_sector"]) == (47, 49)
    iv = interval_status(rep, 47)
    assert iv["status"] == "missing-read"
    cell = next(c for c in iv["cells"] if c["replica_id"] == "R-ARC")
    assert cell["status"] == "read-failed"


def test_duplicate_inspection_reference_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JDUP")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    inspect_and_bind(client, mid, plan, replica_id="R-ACQ",
                     inspection_id="I-R-ACQ")
    # binding the SAME record again is recorded (append-only) but keeps the
    # task inconclusive: one replica's readings must not be replayed as
    # evidence twice
    rep = bind(client, mid, "J-1", "I-R-ACQ").json()
    assert rep["result"] == "inconclusive"
    reused = [f for f in rep["findings"]
              if f["code"] == "JOINT_INSPECTION_RECORD_REUSED"]
    assert len(reused) == 1
    assert reused[0]["detail"]["inspection_id"] == "I-R-ACQ"
    assert reused[0]["detail"]["references"] == 2
    assert [b["inspection_id"] for b in rep["bindings"]] == ["I-R-ACQ"] * 2


def test_plan_mismatch_binding_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JMISM")
    plan = get_plan(client, mid)  # seed-1, ratio 0.125
    assert create_joint(client, mid).status_code == 201
    for rid in ("R-ACQ", "R-CPY"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}")
    # R-ARC was patrolled with a DIFFERENT sampling ratio: a valid run on its
    # own, but not the frozen unified plan of this joint task
    other_plan = get_plan(client, mid, seed="seed-1", ratio=0.25)
    r = submit(client, mid, other_plan, inspection_id="I-R-ARC-OTHER",
               replica_id="R-ARC", seed="seed-1", ratio=0.25)
    assert r.status_code == 201 and r.json()["result"] == "passed"
    rep = bind(client, mid, "J-1", "I-R-ARC-OTHER").json()
    assert rep["result"] == "inconclusive"
    mism = [f for f in rep["findings"] if f["code"] == "JOINT_PLAN_MISMATCH"]
    assert len(mism) == 1
    assert mism[0]["replica_ids"] == ["R-ARC"]
    assert mism[0]["detail"]["inspection_id"] == "I-R-ARC-OTHER"


def test_non_participant_binding_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JOUTSIDE")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    # an inspection of a medium the sealed manifest never registered
    r = submit(client, mid, plan, inspection_id="I-GHOST", replica_id="R-GHOST")
    assert r.status_code == 201 and r.json()["result"] == "failed"
    rep = bind(client, mid, "J-1", "I-GHOST").json()
    assert rep["result"] == "inconclusive"
    outs = [f for f in rep["findings"]
            if f["code"] == "JOINT_REPLICA_NOT_PARTICIPANT"]
    assert len(outs) == 1
    assert outs[0]["replica_ids"] == ["R-GHOST"]
    assert outs[0]["detail"]["inspection_ids"] == ["I-GHOST"]


def test_malformed_bound_inspection_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JSHAPE")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    for rid in ("R-ACQ", "R-CPY"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}")
    # R-ARC's run contains an out-of-plan reading: malformed as evidence,
    # the joint task cannot conclude from it
    readings = make_readings(plan["planned_intervals"])
    readings.append({"start_sector": 40, "end_sector": 41,
                     "read_at": T_READ.isoformat(),
                     "sha256": interval_digest(40, 41)})
    _, rep = inspect_and_bind(client, mid, plan, replica_id="R-ARC",
                              inspection_id="I-R-ARC-SHAPE", readings=readings)
    assert rep["result"] == "inconclusive"
    codes = [f["code"] for f in rep["findings"]]
    assert "JOINT_INSPECTION_SHAPE_VIOLATION" in codes


# ------------------------------------- baseline unrecomputable: no rejudging --
def _sealed_file_manifest(client, evidence_root, media_id):
    """Seal a manifest whose chunks are file-backed under a temp root."""
    payload = build_payload(media_id=media_id, with_content=True)
    paths = write_chunk_files(payload, evidence_root)  # strips inline content
    mid = post_manifest(client, payload).json()["manifest_id"]
    assert seal(client, mid).status_code == 200
    return mid, paths


def test_baseline_unrecomputable_agreement_cannot_pass(client, evidence_root):
    """The reference file backing a chunk is rewritten AFTER sealing. Every
    replica still returns the original correct digests -- they fully agree
    with each other -- but the frozen baseline can no longer be recomputed,
    so the affected intervals can NOT be rejudged as passed."""
    mid, paths = _sealed_file_manifest(client, evidence_root, "M-JREBASE")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    Path(paths[1]).write_bytes(b"\x99" * (SECTOR_SIZE * 16))  # C02 rewritten

    rep = bind_all_passing(client, mid, plan)
    assert rep["result"] == "inconclusive"  # never passed on agreement alone
    codes = [f["code"] for f in rep["findings"]]
    assert "JOINT_BASELINE_UNRECOMPUTABLE" in codes
    assert "JOINT_DIGEST_CONFLICT" not in codes
    statuses = {(iv["start_sector"], iv["end_sector"]): iv["status"]
                for iv in rep["intervals"]}
    # exactly the two seam intervals straddling the rewritten chunk
    assert statuses[(15, 17)] == "baseline-unrecomputable"
    assert statuses[(31, 33)] == "baseline-unrecomputable"
    for key in ((0, 1), (47, 49), (63, 64)):
        assert statuses[key] == "all-match"
    # inter-replica agreement is not evidence of divergence either
    assert rep["divergent_intervals"] == []
    assert rep["ever_failed"] is False


def test_baseline_unrecomputable_shared_wrong_digest_stays_inconclusive(
        client, evidence_root):
    """All replicas returning the SAME wrong-looking digest while the
    baseline is gone still cannot convict: agreement among replicas is no
    substitute for the frozen baseline, in either direction."""
    mid, paths = _sealed_file_manifest(client, evidence_root, "M-JREBASE2")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    Path(paths[1]).write_bytes(b"\x99" * (SECTOR_SIZE * 16))

    last = None
    for rid in REPLICAS:
        _, last = inspect_and_bind(
            client, mid, plan, replica_id=rid, inspection_id=f"I-{rid}",
            readings=make_readings(plan["planned_intervals"],
                                   corrupt={(15, 17)}))
    rep = last
    assert rep["result"] == "inconclusive"  # neither failed nor passed
    codes = [f["code"] for f in rep["findings"]]
    assert "JOINT_DIGEST_CONFLICT" not in codes
    assert "JOINT_BASELINE_UNRECOMPUTABLE" in codes
    assert interval_status(rep, 15)["status"] == "baseline-unrecomputable"
    assert rep["divergent_intervals"] == []


# --------------------------------------- append-only re-tests and history --
def test_retest_never_erases_first_difference(client):
    mid = sealed_manifest(client, "M-JRETEST")
    plan = get_plan(client, mid)
    assert create_joint(client, mid, window=WIDE_WINDOW).status_code == 201
    t1 = T_READ
    for rid in ("R-ACQ", "R-CPY"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}-1",
                         readings=make_readings(plan["planned_intervals"],
                                                read_at=t1))
    # R-ARC provably diverges on [15,17)
    _, rep = inspect_and_bind(
        client, mid, plan, replica_id="R-ARC", inspection_id="I-R-ARC-1",
        readings=make_readings(plan["planned_intervals"], read_at=t1,
                               corrupt={(15, 17)}))
    assert rep["result"] == "failed"
    first_seen = rep["divergent_intervals"][0]["first_change_at"]
    assert rep["divergent_intervals"][0]["first_inspection_id"] == "I-R-ARC-1"

    # a later re-test passes: the current verdict recovers, but the earlier
    # difference and its first-appearance time stay on record
    _, rep2 = inspect_and_bind(
        client, mid, plan, replica_id="R-ARC", inspection_id="I-R-ARC-2",
        readings=make_readings(plan["planned_intervals"],
                               read_at=t1 + timedelta(days=7)))
    assert rep2["result"] == "passed"
    assert rep2["ever_failed"] is True
    assert len(rep2["divergent_intervals"]) == 1
    div = rep2["divergent_intervals"][0]
    assert div["first_change_at"] == first_seen
    assert div["first_inspection_id"] == "I-R-ARC-1"
    assert rep2["first_change_at"] == first_seen
    cov = {rc["replica_id"]: rc for rc in rep2["replica_coverage"]}
    assert cov["R-ARC"]["bound_inspection_ids"] == ["I-R-ARC-1", "I-R-ARC-2"]
    assert cov["R-ARC"]["inspection_id"] == "I-R-ARC-2"
    assert [b["inspection_id"] for b in rep2["bindings"]] == \
        ["I-R-ACQ-1", "I-R-CPY-1", "I-R-ARC-1", "I-R-ARC-2"]

    # a still later failure of the same interval keeps the ORIGINAL time
    _, rep3 = inspect_and_bind(
        client, mid, plan, replica_id="R-ARC", inspection_id="I-R-ARC-3",
        readings=make_readings(plan["planned_intervals"],
                               read_at=t1 + timedelta(days=30),
                               corrupt={(15, 17)}))
    assert rep3["result"] == "failed"
    assert rep3["divergent_intervals"][0]["first_change_at"] == first_seen
    assert rep3["divergent_intervals"][0]["first_inspection_id"] == "I-R-ARC-1"
    # every binding is still on record (append-only)
    assert len(rep3["bindings"]) == 5


def test_per_replica_coverage_partial_and_cumulative(client):
    mid = sealed_manifest(client, "M-JCOV")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    ivs = plan["planned_intervals"]
    # R-ACQ first skips two intervals, then a re-test reads exactly those
    inspect_and_bind(client, mid, plan, replica_id="R-ACQ",
                     inspection_id="I-R-ACQ-1",
                     readings=make_readings(ivs, skip={(31, 33), (47, 49)}))
    inspect_and_bind(client, mid, plan, replica_id="R-ACQ",
                     inspection_id="I-R-ACQ-2",
                     readings=make_readings(
                         ivs, skip={(0, 1), (15, 17), (63, 64)}))
    for rid in ("R-CPY", "R-ARC"):
        inspect_and_bind(client, mid, plan, replica_id=rid,
                         inspection_id=f"I-{rid}")
    rep = get_joint(client, mid)
    assert rep["result"] == "inconclusive"  # latest R-ACQ run missed intervals
    assert "JOINT_INTERVAL_MISSING" in [f["code"] for f in rep["findings"]]
    cov = {rc["replica_id"]: rc for rc in rep["replica_coverage"]}
    acq = cov["R-ACQ"]
    assert acq["status"] == "partial"
    assert acq["inspection_id"] == "I-R-ACQ-2"
    assert acq["bound_inspection_ids"] == ["I-R-ACQ-1", "I-R-ACQ-2"]
    assert acq["planned_sectors"] == 8
    assert acq["covered_sectors"] == 4          # latest binding read 4 sectors
    assert acq["coverage_rate"] == 0.5
    assert acq["cumulative_covered_sectors"] == 8   # union across bindings
    assert acq["cumulative_coverage_rate"] == 1.0
    assert cov["R-CPY"]["status"] == "complete"
    assert cov["R-CPY"]["cumulative_coverage_rate"] == 1.0


# --------------- conflict + insufficient evidence stays inconclusive -------
# A proven digest deviation cannot finalize the task as failed while the
# joint patrol itself is evidence-incomplete: absent replica, out-of-window
# reading, incomplete plan intervals or a reused inspection record. The
# conflict findings and the divergence history are preserved either way.
def test_conflict_with_absent_replica_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JCABS")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    inspect_and_bind(client, mid, plan, replica_id="R-ACQ",
                     inspection_id="I-R-ACQ",
                     readings=make_readings(plan["planned_intervals"],
                                            corrupt={(15, 17)}))
    inspect_and_bind(client, mid, plan, replica_id="R-CPY",
                     inspection_id="I-R-CPY")
    # R-ARC never binds: the joint comparison is incomplete
    rep = get_joint(client, mid)
    assert rep["result"] == "inconclusive"
    codes = [f["code"] for f in rep["findings"]]
    assert "JOINT_REPLICA_ABSENT" in codes
    # the proven conflict stays on record
    assert "JOINT_DIGEST_CONFLICT" in codes
    conflict = next(f for f in rep["findings"]
                    if f["code"] == "JOINT_DIGEST_CONFLICT")
    assert conflict["replica_ids"] == ["R-ACQ"]
    assert (conflict["start_sector"], conflict["end_sector"]) == (15, 17)
    assert interval_status(rep, 15)["status"] == "single-replica-deviation"
    assert len(rep["divergent_intervals"]) == 1
    assert rep["divergent_intervals"][0]["replica_id"] == "R-ACQ"
    assert rep["divergent_intervals"][0]["first_inspection_id"] == "I-R-ACQ"
    assert rep["ever_failed"] is True


def test_conflict_with_out_of_window_reading_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JCWIN")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    inspect_and_bind(client, mid, plan, replica_id="R-ACQ",
                     inspection_id="I-R-ACQ",
                     readings=make_readings(plan["planned_intervals"],
                                            corrupt={(15, 17)}))
    inspect_and_bind(client, mid, plan, replica_id="R-CPY",
                     inspection_id="I-R-CPY")
    # R-ARC read after the frozen completion window closed
    late = make_readings(plan["planned_intervals"],
                         read_at=T_READ + timedelta(days=3))
    inspect_and_bind(client, mid, plan, replica_id="R-ARC",
                     inspection_id="I-R-ARC-LATE", readings=late)
    rep = get_joint(client, mid)
    assert rep["result"] == "inconclusive"
    codes = [f["code"] for f in rep["findings"]]
    assert "JOINT_READING_OUT_OF_WINDOW" in codes
    assert "JOINT_DIGEST_CONFLICT" in codes
    assert interval_status(rep, 15)["status"] == "single-replica-deviation"
    assert len(rep["divergent_intervals"]) == 1
    assert rep["divergent_intervals"][0]["replica_id"] == "R-ACQ"
    assert rep["ever_failed"] is True


def test_conflict_with_incomplete_plan_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JCPLAN")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    inspect_and_bind(client, mid, plan, replica_id="R-ACQ",
                     inspection_id="I-R-ACQ",
                     readings=make_readings(plan["planned_intervals"],
                                            corrupt={(15, 17)}))
    inspect_and_bind(client, mid, plan, replica_id="R-CPY",
                     inspection_id="I-R-CPY")
    # R-ARC skipped one planned interval
    inspect_and_bind(client, mid, plan, replica_id="R-ARC",
                     inspection_id="I-R-ARC-PART",
                     readings=make_readings(plan["planned_intervals"],
                                            skip={(31, 33)}))
    rep = get_joint(client, mid)
    assert rep["result"] == "inconclusive"
    codes = [f["code"] for f in rep["findings"]]
    assert "JOINT_INTERVAL_MISSING" in codes
    assert "JOINT_DIGEST_CONFLICT" in codes
    assert interval_status(rep, 15)["status"] == "single-replica-deviation"
    assert interval_status(rep, 31)["status"] == "missing-read"
    assert len(rep["divergent_intervals"]) == 1
    assert rep["divergent_intervals"][0]["replica_id"] == "R-ACQ"
    assert rep["ever_failed"] is True


def test_conflict_with_duplicate_record_reference_stays_inconclusive(client):
    mid = sealed_manifest(client, "M-JCDUP")
    plan = get_plan(client, mid)
    assert create_joint(client, mid).status_code == 201
    inspect_and_bind(client, mid, plan, replica_id="R-ACQ",
                     inspection_id="I-R-ACQ",
                     readings=make_readings(plan["planned_intervals"],
                                            corrupt={(15, 17)}))
    inspect_and_bind(client, mid, plan, replica_id="R-CPY",
                     inspection_id="I-R-CPY")
    inspect_and_bind(client, mid, plan, replica_id="R-ARC",
                     inspection_id="I-R-ARC")
    # replaying R-ARC's record taints the run even though a deviation was
    # proven on R-ACQ
    rep = bind(client, mid, "J-1", "I-R-ARC").json()
    assert rep["result"] == "inconclusive"
    codes = [f["code"] for f in rep["findings"]]
    assert "JOINT_INSPECTION_RECORD_REUSED" in codes
    assert "JOINT_DIGEST_CONFLICT" in codes
    assert interval_status(rep, 15)["status"] == "single-replica-deviation"
    assert len(rep["divergent_intervals"]) == 1
    assert rep["divergent_intervals"][0]["replica_id"] == "R-ACQ"
    assert rep["ever_failed"] is True


# ------------------------------------------------------- unit: evaluation ----
def _stored_report(iid, rid, *, result="passed", findings=None, pkg="d" * 64):
    from app.schemas import InspectionReport
    plan_ivs = [{"start_sector": a, "end_sector": b} for a, b in MANDATORY_PLAN]
    intervals = [{"start_sector": a, "end_sector": b, "status": "match",
                  "expected_sha256": "e" * 64, "actual_sha256": "e" * 64,
                  "read_at": T_READ.isoformat()} for a, b in MANDATORY_PLAN]
    return InspectionReport.model_validate({
        "inspection_id": iid, "manifest_id": "MF-U", "media_id": "M-U",
        "replica_id": rid, "result": result, "seed": "seed-1",
        "sample_ratio": 0.125, "device": {"device_id": "D-1"},
        "chunk_boundaries": [16, 32, 48], "planned_intervals": plan_ivs,
        "planned_sectors": 8, "covered_sectors": 8, "verified_sectors": 8,
        "total_sectors": 64, "intervals": intervals,
        "findings": findings or [], "evidence_package_digest": pkg,
        "created_at": T_READ.isoformat()})


def _evaluate(reports, pkg="d" * 64):
    from app.joint import JointTaskContext, evaluate_joint_inspection
    task = JointTaskContext(
        joint_id="J-U", manifest_id="MF-U", media_id="M-U",
        replica_ids=["R-ACQ", "R-CPY"], seed="seed-1", sample_ratio=0.125,
        window_start="2026-10-01T00:00:00+00:00",
        window_end="2026-10-02T00:00:00+00:00",
        plan=[list(p) for p in MANDATORY_PLAN], chunk_boundaries=[16, 32, 48],
        evidence_package_digest=pkg, created_at=T_READ.isoformat())
    bindings = [{"inspection_id": r.inspection_id,
                 "replica_id": r.replica_id,
                 "bound_at": T_READ.isoformat()} for r in reports]
    inspections = {r.inspection_id: r for r in reports}
    return evaluate_joint_inspection(
        task, bindings=bindings, inspections=inspections, total_sectors=64,
        image_sha256="a" * 64, merkle_root="b" * 64)


def test_chain_broken_bound_inspection_fails_joint_unit():
    """A bound inspection that proves the replica chain is broken fails the
    joint task even when every sampled interval matched."""
    broken = _stored_report(
        "I-1", "R-ACQ", result="failed",
        findings=[{"code": "INSPECTION_REPLICA_DIGEST_MISMATCH",
                   "severity": "error", "message": "chain broken"}])
    rep = _evaluate([broken, _stored_report("I-2", "R-CPY")])
    assert rep.result == "failed"
    codes = [f.code for f in rep.findings]
    assert "JOINT_REPLICA_CHAIN_BROKEN" in codes
    assert rep.ever_failed is True


def test_evidence_package_mismatch_stays_inconclusive_unit():
    """A bound inspection evaluated against a different evidence package
    than the one frozen into the task cannot be used."""
    foreign = _stored_report("I-1", "R-ACQ", pkg="f" * 64)
    rep = _evaluate([foreign, _stored_report("I-2", "R-CPY")])
    assert rep.result == "inconclusive"
    codes = [f.code for f in rep.findings]
    assert "JOINT_EVIDENCE_PACKAGE_MISMATCH" in codes


def test_chain_broken_still_fails_despite_absent_replica_unit():
    """Only digest deviation is demoted by insufficient joint evidence; a
    proven broken replica chain remains a hard failure even when a
    participant never submitted."""
    broken = _stored_report(
        "I-1", "R-ACQ", result="failed",
        findings=[{"code": "INSPECTION_REPLICA_DIGEST_MISMATCH",
                   "severity": "error", "message": "chain broken"}])
    # R-CPY never binds -> absent (insufficient evidence) + chain broken
    rep = _evaluate([broken])
    assert rep.result == "failed"
    codes = [f.code for f in rep.findings]
    assert "JOINT_REPLICA_CHAIN_BROKEN" in codes
    assert "JOINT_REPLICA_ABSENT" in codes
