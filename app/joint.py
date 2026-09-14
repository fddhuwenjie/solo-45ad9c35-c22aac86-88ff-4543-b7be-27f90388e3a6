"""Multi-replica joint inspection of a sealed image.

A sealed master image usually survives as several copies on different media
(working disk, off-site disk, archive disk). Patrolling each copy with an
independent sample plan makes the reports hard to compare: the runs cover
different sectors, so when one digest changes it is impossible to tell a
single rotting medium from a common upstream corruption.

A joint inspection task freezes the sealed manifest, the evidence package
digest, the participating replicas, one unified seed, one sampling ratio and
a completion window. Every participating replica is then patrolled against
the SAME seed-derived plan intervals — submitted as ordinary per-replica
inspection records — and each record is bound to the task. The evaluation
compares, interval by interval, the frozen sealed baseline against every
replica and classifies:

* ``all-match`` — every replica agrees with the sealed baseline;
* ``single-replica-deviation`` — exactly one replica provably diverges;
* ``multi-replica-deviation`` — two or more replicas diverge from the
  baseline (``shared_deviation`` records whether they returned the *same*
  wrong digest: identical deviations point at a common upstream corruption
  rather than independent media rot);
* ``missing-read`` — a replica is absent, skipped the interval, reported a
  read failure or read it outside the frozen completion window;
* ``baseline-unrecomputable`` — the sealed baseline could not be recomputed
  for the interval. Replicas agreeing with each other can NOT turn this
  into a pass: with the baseline gone there is nothing left to agree
  against, so the interval stays inconclusive.

The task stays ``inconclusive`` while a participating replica is absent, a
reading falls outside the completion window, the submitted plan intervals
are incomplete, or an inspection record is referenced more than once. A
bound inspection that proves a broken replica chain fails the task.

Tasks and bindings are append-only: a re-test binds a new inspection record
and never rewrites an earlier one, so a later pass can never erase the
first-appearance time of a divergence.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from .inspection import as_utc
from .schemas import (
    DivergentInterval,
    Finding,
    InspectionReport,
    JointBinding,
    JointInspectionReport,
    JointIntervalResult,
    JointReplicaCell,
    JointReplicaCoverage,
    SectorInterval,
    Severity,
)

# Finding codes inside a bound per-replica inspection that prove the replica
# chain is broken; the joint task inherits the failure.
CHAIN_BROKEN_CODES = {
    "INSPECTION_REPLICA_UNKNOWN",
    "INSPECTION_REPLICA_DIGEST_MISMATCH",
}
# Finding codes marking a malformed per-replica run (duplicated or
# out-of-plan readings); the joint task cannot conclude from it either.
SHAPE_VIOLATION_CODES = {
    "INSPECTION_READING_DUPLICATE",
    "INSPECTION_READING_OUT_OF_BOUNDS",
}
# Stored interval statuses meaning the replica genuinely returned bytes.
READ_STATUSES = {"match", "digest-conflict", "unverifiable"}
# Cell statuses meaning the interval has no usable reading from a replica.
MISSING_CELL_STATUSES = {"absent", "missing", "read-failed", "out-of-window"}


@dataclass
class JointTaskContext:
    """The frozen joint-inspection task parameters (stored append-only)."""

    joint_id: str
    manifest_id: str
    media_id: str
    replica_ids: list[str]
    seed: str
    sample_ratio: float
    window_start: Any
    window_end: Any
    plan: list[list[int]]
    chunk_boundaries: list[int]
    evidence_package_digest: Optional[str]
    created_at: Any


def _as_dt(value: Any) -> Optional[datetime]:
    """Normalize a stored datetime (str or datetime) to tz-aware UTC."""
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return as_utc(value)


def evaluate_joint_inspection(
        task: JointTaskContext, *,
        bindings: list[dict[str, Any]],
        inspections: dict[str, InspectionReport],
        total_sectors: int,
        image_sha256: Optional[str],
        merkle_root: Optional[str]) -> JointInspectionReport:
    """Evaluate a joint task against its append-only bindings.

    ``bindings`` are the stored binding rows in insertion order
    (``inspection_id`` / ``replica_id`` / ``bound_at``); ``inspections``
    maps each referenced inspection_id to its stored per-replica report.
    The evaluation is a pure function of the stored records: per-interval
    expected digests are taken from the immutable per-replica reports (each
    frozen against the sealed baseline at its own submission time), never
    recomputed here, so the joint report cannot drift with the evidence
    store.
    """
    media_id = task.media_id
    findings: list[Finding] = []

    def error(code: str, message: str, **kw: Any) -> None:
        findings.append(Finding(code=code, severity=Severity.error,
                                message=message, media_id=media_id, **kw))

    plan_pairs = [(int(p[0]), int(p[1])) for p in task.plan]
    plan_set = set(plan_pairs)
    planned_sectors = sum(b - a for a, b in plan_pairs)
    window_start = _as_dt(task.window_start)
    window_end = _as_dt(task.window_end)

    has_inconclusive = False
    has_chain_broken = False
    has_deviation = False
    # inspection ids already named by a specific finding (the catch-all
    # inconclusive finding only fires when nothing more specific did)
    flagged: set[str] = set()

    # -------------------------------------- binding classification ---------
    # Bindings are append-only; a duplicate reference is recorded and keeps
    # the task inconclusive instead of being rejected, so the attempt itself
    # stays on record.
    usage: dict[str, int] = {}
    for b in bindings:
        usage[b["inspection_id"]] = usage.get(b["inspection_id"], 0) + 1
    for iid in sorted(iid for iid, n in usage.items() if n > 1):
        flagged.add(iid)
        error("JOINT_INSPECTION_RECORD_REUSED",
              f"inspection record {iid} is referenced {usage[iid]} times by "
              f"joint task {task.joint_id}; each record may be bound at most "
              f"once, otherwise one replica's readings could be replayed as "
              f"another's",
              replica_ids=sorted({b["replica_id"] for b in bindings
                                  if b["inspection_id"] == iid}),
              detail={"inspection_id": iid, "references": usage[iid]})
        has_inconclusive = True

    outsiders: dict[str, list[str]] = {}
    for b in bindings:
        if b["replica_id"] not in task.replica_ids:
            outsiders.setdefault(b["replica_id"], []).append(b["inspection_id"])
    for rid in sorted(outsiders):
        flagged.update(outsiders[rid])
        error("JOINT_REPLICA_NOT_PARTICIPANT",
              f"replica {rid} is not a participant of joint task "
              f"{task.joint_id}; its bound records cannot stand in for any "
              f"participant",
              replica_ids=[rid],
              detail={"inspection_ids": outsiders[rid]})
        has_inconclusive = True

    # Latest binding per participant replica drives the current per-interval
    # status; earlier bindings stay on record and feed the divergence history.
    latest_by_replica: dict[str, dict[str, Any]] = {}
    for b in bindings:
        latest_by_replica[b["replica_id"]] = b

    valid_latest: dict[str, InspectionReport] = {}
    for rid in task.replica_ids:
        b = latest_by_replica.get(rid)
        if b is None:
            error("JOINT_REPLICA_ABSENT",
                  f"participating replica {rid} has not bound any inspection "
                  f"record to joint task {task.joint_id}",
                  replica_ids=[rid])
            has_inconclusive = True
            continue
        insp = inspections.get(b["inspection_id"])
        if insp is None:
            flagged.add(b["inspection_id"])
            error("JOINT_INSPECTION_UNKNOWN",
                  f"bound inspection record {b['inspection_id']} of replica "
                  f"{rid} is not stored for this manifest",
                  replica_ids=[rid],
                  detail={"inspection_id": b["inspection_id"]})
            has_inconclusive = True
            continue
        iid = insp.inspection_id
        insp_plan = [(iv.start_sector, iv.end_sector)
                     for iv in insp.planned_intervals]
        if (insp.seed != task.seed or insp.sample_ratio != task.sample_ratio
                or insp_plan != plan_pairs):
            flagged.add(iid)
            error("JOINT_PLAN_MISMATCH",
                  f"inspection {iid} of replica {rid} was derived from a "
                  f"different seed/ratio/plan than the frozen joint plan; "
                  f"every replica must be read against the same planned "
                  f"intervals",
                  replica_ids=[rid],
                  detail={"inspection_id": iid, "seed": insp.seed,
                          "sample_ratio": insp.sample_ratio})
            has_inconclusive = True
            continue
        if (insp.evidence_package_digest and task.evidence_package_digest
                and insp.evidence_package_digest
                != task.evidence_package_digest):
            flagged.add(iid)
            error("JOINT_EVIDENCE_PACKAGE_MISMATCH",
                  f"inspection {iid} of replica {rid} was evaluated against "
                  f"a different evidence package than the one frozen into "
                  f"joint task {task.joint_id}",
                  replica_ids=[rid],
                  detail={"inspection_id": iid,
                          "inspection_package": insp.evidence_package_digest,
                          "joint_package": task.evidence_package_digest})
            has_inconclusive = True
            continue
        codes = {f.code for f in insp.findings}
        if codes & CHAIN_BROKEN_CODES:
            flagged.add(iid)
            error("JOINT_REPLICA_CHAIN_BROKEN",
                  f"inspection {iid} proves the replica chain of {rid} is "
                  f"broken ({', '.join(sorted(codes & CHAIN_BROKEN_CODES))})",
                  replica_ids=[rid], detail={"inspection_id": iid})
            has_chain_broken = True
        if codes & SHAPE_VIOLATION_CODES:
            flagged.add(iid)
            error("JOINT_INSPECTION_SHAPE_VIOLATION",
                  f"inspection {iid} of replica {rid} contains duplicated "
                  f"or out-of-plan readings; the joint task cannot conclude "
                  f"from a malformed run",
                  replica_ids=[rid], detail={"inspection_id": iid})
            has_inconclusive = True
        valid_latest[rid] = insp

    # ------------------------- per-interval cross-replica comparison -------
    interval_maps = {rid: {(iv.start_sector, iv.end_sector): iv
                           for iv in insp.intervals}
                     for rid, insp in valid_latest.items()}
    interval_results: list[JointIntervalResult] = []
    for s0, s1 in plan_pairs:
        cells: list[JointReplicaCell] = []
        for rid in task.replica_ids:
            insp = valid_latest.get(rid)
            if insp is None:
                cells.append(JointReplicaCell(replica_id=rid, status="absent"))
                continue
            iid = insp.inspection_id
            stored = interval_maps[rid].get((s0, s1))
            if stored is None:
                flagged.add(iid)
                error("JOINT_INTERVAL_MISSING",
                      f"inspection {iid} of replica {rid} has no result for "
                      f"planned interval [{s0},{s1}); the joint plan was not "
                      f"fully executed",
                      replica_ids=[rid], start_sector=s0, end_sector=s1,
                      detail={"inspection_id": iid})
                has_inconclusive = True
                cells.append(JointReplicaCell(replica_id=rid,
                                              inspection_id=iid,
                                              status="missing"))
                continue
            read_at = _as_dt(stored.read_at)
            if (stored.status in READ_STATUSES and read_at is not None
                    and window_start is not None and window_end is not None
                    and not window_start <= read_at <= window_end):
                flagged.add(iid)
                error("JOINT_READING_OUT_OF_WINDOW",
                      f"replica {rid} read sectors [{s0},{s1}) at "
                      f"{read_at.isoformat()}, outside the frozen completion "
                      f"window {window_start.isoformat()} .. "
                      f"{window_end.isoformat()}",
                      replica_ids=[rid], start_sector=s0, end_sector=s1,
                      detail={"inspection_id": iid,
                              "read_at": read_at.isoformat()})
                has_inconclusive = True
                cells.append(JointReplicaCell(
                    replica_id=rid, inspection_id=iid, status="out-of-window",
                    expected_sha256=stored.expected_sha256,
                    actual_sha256=stored.actual_sha256,
                    read_at=stored.read_at))
                continue
            if stored.status == "missing":
                flagged.add(iid)
                error("JOINT_INTERVAL_MISSING",
                      f"inspection {iid} of replica {rid} has no reading for "
                      f"planned interval [{s0},{s1}); the joint plan was not "
                      f"fully executed",
                      replica_ids=[rid], start_sector=s0, end_sector=s1,
                      detail={"inspection_id": iid})
                has_inconclusive = True
            elif stored.status == "read-failed":
                flagged.add(iid)
                error("JOINT_READ_FAILED",
                      f"replica {rid} could not read sectors [{s0},{s1}): "
                      f"{stored.error}",
                      replica_ids=[rid], start_sector=s0, end_sector=s1,
                      detail={"inspection_id": iid,
                              "tool_error": stored.error})
                has_inconclusive = True
            elif stored.status == "unverifiable":
                flagged.add(iid)
                error("JOINT_BASELINE_UNRECOMPUTABLE",
                      f"the sealed baseline for sectors [{s0},{s1}) could "
                      f"not be recomputed when replica {rid} was inspected; "
                      f"replicas agreeing with each other cannot turn this "
                      f"interval into a pass",
                      replica_ids=[rid], start_sector=s0, end_sector=s1,
                      detail={"inspection_id": iid})
                has_inconclusive = True
            cells.append(JointReplicaCell(
                replica_id=rid, inspection_id=iid, status=stored.status,
                expected_sha256=stored.expected_sha256,
                actual_sha256=stored.actual_sha256, read_at=stored.read_at))

        conflicts = [c for c in cells if c.status == "digest-conflict"]
        unverifiable = [c for c in cells if c.status == "unverifiable"]
        missing = [c for c in cells if c.status in MISSING_CELL_STATUSES]
        expected = next((c.expected_sha256 for c in cells
                         if c.expected_sha256), None)
        shared: Optional[bool] = None
        if len(conflicts) >= 2:
            status = "multi-replica-deviation"
            shared = len({c.actual_sha256 for c in conflicts}) == 1
            has_deviation = True
        elif len(conflicts) == 1:
            status = "single-replica-deviation"
            has_deviation = True
        elif unverifiable:
            status = "baseline-unrecomputable"
        elif missing:
            status = "missing-read"
        else:
            status = "all-match"
        if conflicts:
            names = ", ".join(c.replica_id for c in conflicts)
            error("JOINT_DIGEST_CONFLICT",
                  f"sectors [{s0},{s1}) provably diverge from the sealed "
                  f"baseline on {len(conflicts)} replica(s): {names}",
                  replica_ids=[c.replica_id for c in conflicts],
                  start_sector=s0, end_sector=s1,
                  detail={"classification": status,
                          "expected_sha256": expected,
                          "actual_by_replica": {c.replica_id: c.actual_sha256
                                                for c in conflicts},
                          "shared_deviation": shared})
        interval_results.append(JointIntervalResult(
            start_sector=s0, end_sector=s1, status=status,
            expected_sha256=expected,
            deviating_replica_ids=[c.replica_id for c in conflicts],
            missing_replica_ids=[c.replica_id for c in missing],
            shared_deviation=shared, cells=cells))

    # A bound inspection that came out inconclusive for a reason no specific
    # joint finding covered still keeps the task from concluding.
    for rid, insp in valid_latest.items():
        if insp.result == "inconclusive" and insp.inspection_id not in flagged:
            error("JOINT_INSPECTION_INCONCLUSIVE",
                  f"bound inspection {insp.inspection_id} of replica {rid} "
                  f"is inconclusive; the joint task cannot conclude either",
                  replica_ids=[rid],
                  detail={"inspection_id": insp.inspection_id})
            has_inconclusive = True

    if has_deviation or has_chain_broken:
        result = "failed"
    elif has_inconclusive or any(iv.status != "all-match"
                                 for iv in interval_results):
        result = "inconclusive"
    else:
        result = "passed"

    # ----------------------------- per-replica coverage --------------------
    coverage: list[JointReplicaCoverage] = []
    for rid in task.replica_ids:
        bound_ids = [b["inspection_id"] for b in bindings
                     if b["replica_id"] == rid]
        # Cumulative genuinely-read sectors across every binding of this
        # replica (in-plan, non-duplicated readings that returned bytes) --
        # the same accounting the single-replica history uses.
        cumulative: set[int] = set()
        for iid in bound_ids:
            bi = inspections.get(iid)
            if bi is None:
                continue
            duplicated = {(f.start_sector, f.end_sector) for f in bi.findings
                          if f.code == "INSPECTION_READING_DUPLICATE"}
            status_by_interval = {(iv.start_sector, iv.end_sector): iv.status
                                  for iv in bi.intervals}
            for iv in bi.planned_intervals:
                key = (iv.start_sector, iv.end_sector)
                if key not in plan_set or key in duplicated:
                    continue
                if status_by_interval.get(key) in READ_STATUSES:
                    cumulative.update(range(iv.start_sector, iv.end_sector))
        cumulative_rate = (len(cumulative) / planned_sectors
                           if planned_sectors else 1.0)
        insp = valid_latest.get(rid)
        if insp is None:
            coverage.append(JointReplicaCoverage(
                replica_id=rid,
                status="absent" if not bound_ids else "partial",
                bound_inspection_ids=bound_ids,
                planned_sectors=planned_sectors,
                cumulative_covered_sectors=len(cumulative),
                cumulative_coverage_rate=cumulative_rate))
            continue
        coverage.append(JointReplicaCoverage(
            replica_id=rid,
            status=("complete" if insp.planned_sectors > 0
                    and insp.covered_sectors == insp.planned_sectors
                    else "partial"),
            inspection_id=insp.inspection_id,
            bound_inspection_ids=bound_ids,
            result=insp.result,
            planned_sectors=planned_sectors,
            covered_sectors=insp.covered_sectors,
            verified_sectors=insp.verified_sectors,
            coverage_rate=insp.coverage_rate,
            verified_rate=insp.verified_rate,
            cumulative_covered_sectors=len(cumulative),
            cumulative_coverage_rate=cumulative_rate))

    # ------------- append-only divergence history across ALL bindings ------
    # A re-test binds a new record; it never rewrites an earlier one, so the
    # first-appearance time of every divergence survives later passes.
    divergent: dict[tuple[str, int, int], dict[str, Any]] = {}
    for b in bindings:
        insp = inspections.get(b["inspection_id"])
        if insp is None:
            continue
        for d in insp.divergent_intervals:
            key = (d.replica_id, d.start_sector, d.end_sector)
            when = as_utc(d.first_change_at or d.read_at)
            entry = divergent.get(key)
            if entry is None:
                divergent[key] = {
                    "first_change_at": when,
                    "first_inspection_id": (d.first_inspection_id
                                            or insp.inspection_id),
                    "latest": d}
            else:
                if when is not None and (entry["first_change_at"] is None
                                         or when < entry["first_change_at"]):
                    entry["first_change_at"] = when
                    entry["first_inspection_id"] = (d.first_inspection_id
                                                    or insp.inspection_id)
                entry["latest"] = d

    divergent_intervals: list[DivergentInterval] = []
    for (replica_id, s0, s1), entry in sorted(
            divergent.items(), key=lambda kv: (kv[0][1], kv[0][2], kv[0][0])):
        latest = entry["latest"]
        divergent_intervals.append(DivergentInterval(
            start_sector=s0, end_sector=s1, replica_id=replica_id,
            expected_sha256=latest.expected_sha256,
            actual_sha256=latest.actual_sha256, read_at=latest.read_at,
            first_change_at=entry["first_change_at"],
            first_inspection_id=entry["first_inspection_id"]))
    first_change_at = min((d.first_change_at for d in divergent_intervals
                           if d.first_change_at is not None), default=None)

    ever_failed = (result == "failed"
                   or any(i.result == "failed" for i in inspections.values())
                   or bool(divergent_intervals))

    return JointInspectionReport(
        joint_id=task.joint_id,
        manifest_id=task.manifest_id,
        media_id=media_id,
        result=result,
        seed=task.seed,
        sample_ratio=task.sample_ratio,
        replica_ids=list(task.replica_ids),
        window_start=window_start,
        window_end=window_end,
        chunk_boundaries=list(task.chunk_boundaries),
        planned_intervals=[SectorInterval(start_sector=a, end_sector=b)
                           for a, b in plan_pairs],
        planned_sectors=planned_sectors,
        total_sectors=total_sectors,
        sample_coverage=(planned_sectors / total_sectors
                         if total_sectors else 1.0),
        intervals=interval_results,
        replica_coverage=coverage,
        divergent_intervals=divergent_intervals,
        first_change_at=first_change_at,
        ever_failed=ever_failed,
        findings=findings,
        bindings=[JointBinding(inspection_id=b["inspection_id"],
                               replica_id=b["replica_id"],
                               bound_at=_as_dt(b["bound_at"]))
                  for b in bindings],
        evidence_package_digest=task.evidence_package_digest,
        image_sha256=image_sha256,
        merkle_root=merkle_root,
        created_at=_as_dt(task.created_at))
