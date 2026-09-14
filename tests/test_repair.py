"""Replica interval repair execution gate tests.

A repair execution may only complete — registering the repaired medium as a
new derived replica together with its handover events — when every planned
interval was written, the recomputed whole-disk SHA-256 and Merkle root of
the target equal the sealed image roots, AND the handover is documented:
at least one custody event, with every event digest equal to the verified
derived-replica digest. An empty custody_events list or any digest that
disagrees with the verified replica keeps the execution failed and registers
nothing; failure records stay append-only.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tests.conftest import codes, post_manifest, build_payload, seal  # noqa: F401
from tests.test_inspection import (
    T_READ,
    get_plan,
    interval_digest,
    make_readings,
    sealed_manifest,
)
from tests.test_joint_inspection import (
    REPLICAS,
    create_joint,
    inspect_and_bind,
)

T_EXEC = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
TARGET = "R-ARC"
DONORS = ["R-ACQ", "R-CPY"]


def joint_with_deviation(client, mid, *, target=TARGET, corrupt={(15, 17)},
                         joint_id="J-1"):
    """Open a joint task where ``target`` provably deviates on ``corrupt``
    intervals and every other replica matches the sealed baseline."""
    plan = get_plan(client, mid)
    assert create_joint(client, mid, joint_id=joint_id).status_code == 201
    for rid in REPLICAS:
        readings = make_readings(plan["planned_intervals"],
                                 corrupt=corrupt if rid == target else ())
        inspect_and_bind(client, mid, plan, joint_id=joint_id, replica_id=rid,
                         inspection_id=f"I-{rid}", readings=readings)
    return plan


def create_repair_plan(client, mid, *, plan_id="RP-1", joint_id="J-1",
                       target=TARGET, donors=DONORS, intervals=None):
    body = {"plan_id": plan_id, "joint_id": joint_id,
            "target_replica_id": target, "donor_priority": list(donors)}
    if intervals is not None:
        body["intervals"] = [{"start_sector": a, "end_sector": b}
                             for a, b in intervals]
    return client.post(f"/manifests/{mid}/repair-plans", json=body)


def get_repair_plan(client, mid, plan_id="RP-1"):
    r = client.get(f"/manifests/{mid}/repair-plans/{plan_id}")
    assert r.status_code == 200, r.text
    return r.json()


def exec_entries(plan_json, **per_interval):
    """Passing execution entries from a plan report; ``per_interval`` maps
    start_sector -> field overrides."""
    entries = []
    for i, iv in enumerate(plan_json["repair_intervals"]):
        e = {"start_sector": iv["start_sector"],
             "end_sector": iv["end_sector"],
             "donor_replica_id": iv["donor_replica_id"],
             "read_sha256": iv["expected_sha256"],
             "write_sha256": iv["expected_sha256"],
             "read_at": (T_EXEC + timedelta(seconds=10 * i)).isoformat(),
             "written_at": (T_EXEC + timedelta(seconds=10 * i + 5)).isoformat()}
        e.update(per_interval.get(iv["start_sector"], {}))
        entries.append(e)
    return entries


def repair_custody(replica_id, digest, **digest_overrides):
    """Two handover events whose digests all equal ``digest``; each
    digest_overrides entry (event_index__field=value) breaks one field."""
    base = T_EXEC + timedelta(hours=1)
    events = [
        {"event_id": f"E-{replica_id}-CPY", "event_type": "copied",
         "replica_id": replica_id, "at": base.isoformat(),
         "actor": "qian.wu", "organization": "证据管理室",
         "digest_before": digest, "digest_after": digest,
         "expected_digest": digest},
        {"event_id": f"E-{replica_id}-VRF", "event_type": "verified",
         "replica_id": replica_id,
         "at": (base + timedelta(minutes=30)).isoformat(),
         "actor": "qian.wu", "digest_before": digest,
         "digest_after": digest, "expected_digest": digest},
    ]
    for key, value in digest_overrides.items():
        index, field = key.split("__")
        events[int(index)][field] = value
    return events


def execute(client, mid, plan_id="RP-1", *, execution_id="EX-1",
            derived="R-ARC-FIX1", entries=None, final="sealed",
            custody="default", device_id="WRITER-01"):
    plan_json = get_repair_plan(client, mid, plan_id)
    if entries is None:
        entries = exec_entries(plan_json)
    body = {"execution_id": execution_id,
            "device": {"device_id": device_id, "model": "Tableau TD3"},
            "entries": entries,
            "derived_replica": {"replica_id": derived,
                                "storage_location": "修复盘柜 R-11",
                                "custodian": "qian.wu"}}
    if final == "sealed":
        body["final_sha256"] = plan_json["image_sha256"]
        body["final_merkle_root"] = plan_json["merkle_root"]
    elif final is not None:
        body["final_sha256"], body["final_merkle_root"] = final
    if custody == "default":
        body["custody_events"] = repair_custody(derived,
                                                plan_json["image_sha256"])
    elif custody != "omit":
        body["custody_events"] = custody
    return client.post(
        f"/manifests/{mid}/repair-plans/{plan_id}/executions", json=body)


def repair_replicas(client, mid):
    r = client.get(f"/manifests/{mid}/repair-replicas")
    assert r.status_code == 200, r.text
    return r.json()


def executable_plan(client, media_id):
    """Sealed manifest + joint deviation + executable repair plan."""
    mid = sealed_manifest(client, media_id)
    joint_with_deviation(client, mid)
    r = create_repair_plan(client, mid)
    assert r.status_code == 201, r.text
    assert r.json()["executable"] is True
    return mid


# ---------------------------------------------------------- completion gate --
def test_completed_execution_registers_derived_replica_and_events(client):
    """Control: a fully consistent execution completes and registers the
    derived replica together with its handover events."""
    mid = executable_plan(client, "M-RGATE-OK")
    r = execute(client, mid)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["result"] == "completed"
    assert rep["findings"] == []
    assert rep["final_verified"] is True
    derived = rep["derived_replica"]
    assert derived["replica_id"] == "R-ARC-FIX1"
    assert derived["parent_replica_id"] == "R-ARC"
    assert derived["sha256"] == rep["expected_image_sha256"]
    assert derived["merkle_root"] == rep["expected_merkle_root"]
    assert [e["event_type"] for e in derived["custody_events"]] == \
        ["copied", "verified"]
    assert all(e["replica_id"] == "R-ARC-FIX1"
               for e in derived["custody_events"])
    # registered and listable; the sealed manifest itself is untouched
    replicas = repair_replicas(client, mid)
    assert [r_["replica_id"] for r_ in replicas] == ["R-ARC-FIX1"]
    assert len(replicas[0]["custody_events"]) == 2
    payload = client.get(f"/manifests/{mid}").json()["payload"]
    assert [r_["replica_id"] for r_ in payload["replicas"]] == REPLICAS


def test_empty_custody_events_stay_failed(client):
    """Regression: an explicit empty custody_events list must not complete
    and must not register the derived replica."""
    mid = executable_plan(client, "M-RGATE-EMPTY")
    r = execute(client, mid, custody=[])
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["result"] == "failed"
    assert rep["final_verified"] is True  # roots verified; handover missing
    assert "REPAIR_CUSTODY_EVENTS_MISSING" in codes(rep)
    miss = next(f for f in rep["findings"]
                if f["code"] == "REPAIR_CUSTODY_EVENTS_MISSING")
    assert miss["replica_ids"] == ["R-ARC-FIX1"]
    assert rep["derived_replica"] is None
    assert repair_replicas(client, mid) == []
    # the failed record is stored and stays on record
    stored = client.get(
        f"/manifests/{mid}/repair-plans/RP-1/executions/EX-1").json()
    assert stored["result"] == "failed"
    assert stored["derived_replica"] is None


def test_omitted_custody_events_stay_failed(client):
    """Regression: omitting custody_events entirely (schema default: empty
    list) is the same as an empty list — no completion, no registration."""
    mid = executable_plan(client, "M-RGATE-OMIT")
    r = execute(client, mid, custody="omit")
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["result"] == "failed"
    assert "REPAIR_CUSTODY_EVENTS_MISSING" in codes(rep)
    assert rep["derived_replica"] is None
    assert repair_replicas(client, mid) == []


def test_custody_digest_mismatch_stays_failed(client):
    """Regression: any event digest that disagrees with the verified
    derived-replica digest keeps the execution failed; nothing registers."""
    mid = executable_plan(client, "M-RGATE-MISM")
    plan_json = get_repair_plan(client, mid)
    good = plan_json["image_sha256"]
    wrong = "0" * 64
    assert wrong != good

    # (a) every digest field wrong on every event
    r = execute(client, mid, execution_id="EX-1",
                custody=repair_custody("R-ARC-FIX1", wrong))
    rep = r.json()
    assert rep["result"] == "failed"
    assert "REPAIR_CUSTODY_DIGEST_MISMATCH" in codes(rep)
    mism = next(f for f in rep["findings"]
                if f["code"] == "REPAIR_CUSTODY_DIGEST_MISMATCH")
    assert mism["replica_ids"] == ["R-ARC-FIX1"]
    assert mism["detail"]["event_ids"] == ["E-R-ARC-FIX1-CPY",
                                           "E-R-ARC-FIX1-VRF"]
    assert mism["detail"]["derived_sha256"] == good
    assert mism["detail"]["derived_merkle_root"] == plan_json["merkle_root"]
    assert rep["derived_replica"] is None

    # (b) only digest_before wrong on the second event
    r = execute(client, mid, execution_id="EX-2",
                custody=repair_custody("R-ARC-FIX1", good,
                                       **{"1__digest_before": wrong}))
    rep = r.json()
    assert rep["result"] == "failed"
    mism = next(f for f in rep["findings"]
                if f["code"] == "REPAIR_CUSTODY_DIGEST_MISMATCH")
    assert mism["detail"]["event_ids"] == ["E-R-ARC-FIX1-VRF"]
    assert rep["derived_replica"] is None

    # (c) only expected_digest wrong on the first event
    r = execute(client, mid, execution_id="EX-3",
                custody=repair_custody("R-ARC-FIX1", good,
                                       **{"0__expected_digest": wrong}))
    rep = r.json()
    assert rep["result"] == "failed"
    mism = next(f for f in rep["findings"]
                if f["code"] == "REPAIR_CUSTODY_DIGEST_MISMATCH")
    assert mism["detail"]["event_ids"] == ["E-R-ARC-FIX1-CPY"]
    assert rep["derived_replica"] is None

    # (d) only digest_after wrong on both events
    r = execute(client, mid, execution_id="EX-4",
                custody=repair_custody("R-ARC-FIX1", good,
                                       **{"0__digest_after": wrong,
                                          "1__digest_after": wrong}))
    rep = r.json()
    assert rep["result"] == "failed"
    mism = next(f for f in rep["findings"]
                if f["code"] == "REPAIR_CUSTODY_DIGEST_MISMATCH")
    assert mism["detail"]["event_ids"] == ["E-R-ARC-FIX1-CPY",
                                           "E-R-ARC-FIX1-VRF"]
    assert rep["derived_replica"] is None

    # nothing was ever registered; every failure stayed on record
    assert repair_replicas(client, mid) == []
    listed = client.get(
        f"/manifests/{mid}/repair-plans/RP-1/executions").json()
    assert [(e["execution_id"], e["result"]) for e in listed] == [
        ("EX-1", "failed"), ("EX-2", "failed"),
        ("EX-3", "failed"), ("EX-4", "failed")]


def test_consistent_custody_after_failures_completes(client):
    """Failure records are append-only: after an empty and a mismatching
    handover fail, a corrected execution under a new id completes and
    registers; the earlier failures are never rewritten."""
    mid = executable_plan(client, "M-RGATE-RETRY")
    plan_json = get_repair_plan(client, mid)

    r1 = execute(client, mid, execution_id="EX-1", custody=[])
    assert r1.json()["result"] == "failed"
    r2 = execute(client, mid, execution_id="EX-2",
                 custody=repair_custody("R-ARC-FIX1", "0" * 64))
    assert r2.json()["result"] == "failed"
    assert repair_replicas(client, mid) == []

    r3 = execute(client, mid, execution_id="EX-3")
    rep = r3.json()
    assert rep["result"] == "completed"
    assert rep["derived_replica"]["replica_id"] == "R-ARC-FIX1"
    assert len(rep["derived_replica"]["custody_events"]) == 2
    assert repair_replicas(client, mid)[0]["replica_id"] == "R-ARC-FIX1"

    # all three records listed in order; the failures kept their findings
    listed = client.get(
        f"/manifests/{mid}/repair-plans/RP-1/executions").json()
    assert [(e["execution_id"], e["result"]) for e in listed] == [
        ("EX-1", "failed"), ("EX-2", "failed"), ("EX-3", "completed")]
    first = client.get(
        f"/manifests/{mid}/repair-plans/RP-1/executions/EX-1").json()
    assert "REPAIR_CUSTODY_EVENTS_MISSING" in codes(first)
    second = client.get(
        f"/manifests/{mid}/repair-plans/RP-1/executions/EX-2").json()
    assert "REPAIR_CUSTODY_DIGEST_MISMATCH" in codes(second)
    assert plan_json["repair_package_digest"] == \
        rep["repair_package_digest"]
