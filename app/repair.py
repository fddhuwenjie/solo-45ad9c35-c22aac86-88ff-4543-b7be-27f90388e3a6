"""Replica interval repair orchestration.

A joint inspection localizes the sectors where one replica deviates from the
sealed baseline, but the archivist still has to choose where the replacement
bytes come from. Picking a donor by hand is dangerous: a replica that
co-deviates on the same interval (a shared upstream corruption) used as a
donor propagates the error into every newly written copy.

A repair plan freezes the sealed manifest, the joint inspection task, the
target replica and the donor priority order, then derives, per frozen joint
plan interval, the donor that may be read: only a replica whose own bound
inspection read the SAME interval, matched the sealed baseline and whose
inspection evidence is complete (no shape violation, no reused record, no
plan/package mismatch, intact replica chain). Adjacent intervals served by
the same donor are merged, and the donors are scheduled in priority order so
the operator swaps media as few times as possible.

The plan stays non-executable — pointing out the exact gap — when the sealed
baseline cannot be recomputed for an interval, every donor lacks a reading,
the readable donors return conflicting digests, every readable donor
co-deviates with the target, the source chain is broken, or a requested
target interval falls outside the geometry / the frozen joint plan.

An execution records, per planned interval, the donor read digest, the target
write digest and any device error. When every interval is written and the
recomputed whole-disk SHA-256 and Merkle root of the repaired target equal
the sealed image roots, the repaired medium is registered as a new derived
replica of the sealed manifest together with its handover events; otherwise
the failed execution is stored and nothing is registered.

Plans, executions and failure records are append-only: ids are never reused
and a stored record is never updated. The JSON repair package binds the
original inspection records and the donor-selection rationale, and carries a
self digest so any party can recompute it.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from .hashing import canonical_bytes, sha256_hex
from .schemas import (
    Finding,
    JointInspectionReport,
    JointIntervalResult,
    RepairDerivedReplica,
    RepairDonorRejection,
    RepairExecutionCreate,
    RepairExecutionEntryResult,
    RepairExecutionReport,
    RepairIntervalPlan,
    RepairMediaStep,
    RepairPlanReport,
    RepairSegment,
    RepairSourceBinding,
    SectorInterval,
    Severity,
)

# Cell statuses meaning the replica genuinely returned bytes for the interval.
READ_STATUSES = {"match", "digest-conflict", "unverifiable"}
# Cell statuses meaning the interval has no usable reading from a replica.
MISSING_CELL_STATUSES = {"absent", "missing", "read-failed", "out-of-window"}
# Joint finding codes that taint every inspection record bound by the named
# replicas: a donor whose evidence is malformed, replayed or not comparable
# with the frozen joint plan cannot serve as a repair source.
TAINT_FINDING_CODES = {
    "JOINT_INSPECTION_SHAPE_VIOLATION",
    "JOINT_INSPECTION_RECORD_REUSED",
    "JOINT_PLAN_MISMATCH",
    "JOINT_EVIDENCE_PACKAGE_MISMATCH",
    "JOINT_INSPECTION_UNKNOWN",
    "JOINT_INSPECTION_INCONCLUSIVE",
}


def _replica_set(findings: list[Finding], code: str) -> set[str]:
    out: set[str] = set()
    for f in findings:
        if f.code == code:
            out.update(f.replica_ids)
    return out


def _tainted_replicas(findings: list[Finding]) -> set[str]:
    out: set[str] = set()
    for f in findings:
        if f.code in TAINT_FINDING_CODES:
            out.update(f.replica_ids)
    return out


def _evaluate_interval(
        key: tuple[int, int],
        joint_interval: JointIntervalResult, *,
        joint_id: str,
        target_replica_id: str,
        donor_priority: list[str],
        chain_broken: set[str],
        tainted: set[str],
        latest_insp: dict[str, Optional[str]],
        emit: Callable[..., None]) -> RepairIntervalPlan:
    """Pick the donor for one frozen joint plan interval, or name the gap."""
    s0, s1 = key
    cells = {c.replica_id: c for c in joint_interval.cells}
    target_cell = cells.get(target_replica_id)
    expected = joint_interval.expected_sha256
    target_insp = (target_cell.inspection_id
                   if target_cell and target_cell.inspection_id
                   else latest_insp.get(target_replica_id))

    def blocked(gap_code: str, rationale: str,
                rejections: Optional[list[RepairDonorRejection]] = None
                ) -> RepairIntervalPlan:
        return RepairIntervalPlan(
            start_sector=s0, end_sector=s1, status="blocked",
            expected_sha256=expected, target_inspection_id=target_insp,
            target_actual_sha256=(target_cell.actual_sha256
                                  if target_cell else None),
            rationale=rationale, rejected_donors=rejections or [],
            gap_code=gap_code)

    # The frozen baseline digest is the only arbiter; without it no donor
    # reading can be verified, whatever the replicas claim.
    if expected is None:
        emit("REPAIR_BASELINE_UNRECOMPUTABLE",
             f"the sealed baseline digest for sectors [{s0},{s1}) could not "
             f"be recomputed in joint task {joint_id}; no donor reading can "
             f"be verified against the frozen baseline",
             replica_ids=[target_replica_id], start_sector=s0, end_sector=s1)
        return blocked("REPAIR_BASELINE_UNRECOMPUTABLE",
                       "the frozen baseline is unrecomputable for this "
                       "interval; agreement among replicas cannot substitute "
                       "for it")
    # Repairing sectors the target provably holds correctly is not a repair.
    if target_cell is None or target_cell.status != "digest-conflict":
        status = target_cell.status if target_cell else "absent"
        emit("REPAIR_TARGET_NOT_DEVIATING",
             f"target replica {target_replica_id} does not provably deviate "
             f"from the sealed baseline on sectors [{s0},{s1}) (cell status "
             f"{status}); there is no proven damage to repair",
             replica_ids=[target_replica_id], start_sector=s0, end_sector=s1,
             detail={"target_status": status})
        return blocked("REPAIR_TARGET_NOT_DEVIATING",
                       f"the target does not provably deviate here (status "
                       f"{status}); overwriting baseline-consistent sectors "
                       f"is not a repair")

    eligible: list[tuple[int, str, Any]] = []
    rejections: list[RepairDonorRejection] = []
    for rank, rid in enumerate(donor_priority, start=1):
        cell = cells.get(rid)
        insp_id = (cell.inspection_id if cell and cell.inspection_id
                   else latest_insp.get(rid))
        if rid in chain_broken:
            rejections.append(RepairDonorRejection(
                replica_id=rid, inspection_id=insp_id,
                reason="source-chain-broken",
                detail="the bound inspection proves the replica chain is "
                       "broken"))
            continue
        if rid in tainted:
            rejections.append(RepairDonorRejection(
                replica_id=rid, inspection_id=insp_id,
                reason="evidence-incomplete",
                detail="the bound inspection record is malformed, reused or "
                       "not comparable with the frozen joint plan"))
            continue
        if cell is None or cell.status in MISSING_CELL_STATUSES:
            status = cell.status if cell else "absent"
            rejections.append(RepairDonorRejection(
                replica_id=rid, inspection_id=insp_id, reason="read-missing",
                detail=f"no usable reading for this interval (cell status "
                       f"{status})"))
            continue
        if cell.status == "unverifiable":
            rejections.append(RepairDonorRejection(
                replica_id=rid, inspection_id=insp_id,
                reason="baseline-unverifiable",
                detail="the donor's own baseline could not be recomputed "
                       "when it was inspected"))
            continue
        if cell.status == "digest-conflict":
            rejections.append(RepairDonorRejection(
                replica_id=rid, inspection_id=insp_id, reason="co-deviating",
                detail="the donor itself deviates from the sealed baseline "
                       "on this interval; using it would propagate the "
                       "error into the repaired copy"))
            continue
        eligible.append((rank, rid, cell))

    if eligible:
        digests = {c.actual_sha256 for _, _, c in eligible}
        if len(digests) > 1:
            emit("REPAIR_DONOR_DIGEST_CONFLICT",
                 f"the baseline-matching donors for sectors [{s0},{s1}) "
                 f"carry different digests; the donor evidence contradicts "
                 f"itself",
                 replica_ids=[rid for _, rid, _ in eligible],
                 start_sector=s0, end_sector=s1,
                 detail={"digests": sorted(d for d in digests if d)})
            return blocked("REPAIR_DONOR_DIGEST_CONFLICT",
                           "baseline-matching donors disagree with each "
                           "other; no single source can be trusted",
                           rejections)
        rank, rid, cell = eligible[0]
        for _, rid2, cell2 in eligible[1:]:
            rejections.append(RepairDonorRejection(
                replica_id=rid2, inspection_id=cell2.inspection_id,
                reason="lower-priority",
                detail="also matched the sealed baseline; not needed"))
        read_at = cell.read_at.isoformat() if cell.read_at else "unknown time"
        rationale = (f"donor {rid} (priority {rank}/{len(donor_priority)}) "
                     f"read sectors [{s0},{s1}) in inspection "
                     f"{cell.inspection_id} at {read_at} and the reading "
                     f"matched the sealed baseline digest; it is the "
                     f"highest-priority replica with complete, "
                     f"baseline-consistent evidence for this interval")
        return RepairIntervalPlan(
            start_sector=s0, end_sector=s1, status="ready",
            expected_sha256=expected, target_inspection_id=target_insp,
            target_actual_sha256=target_cell.actual_sha256,
            donor_replica_id=rid, donor_inspection_id=cell.inspection_id,
            donor_priority_rank=rank, rationale=rationale,
            rejected_donors=rejections)

    # ---------------- no eligible donor: name the exact gap ----------------
    reasons = {r.reason for r in rejections}
    byte_digests: list[str] = []
    for rid in donor_priority:
        if rid in chain_broken or rid in tainted:
            continue
        cell = cells.get(rid)
        if (cell is not None and cell.status in READ_STATUSES
                and cell.actual_sha256):
            byte_digests.append(cell.actual_sha256)
    if reasons == {"source-chain-broken"}:
        gap = "REPAIR_SOURCE_CHAIN_BROKEN"
        message = (f"every donor for sectors [{s0},{s1}) is on a broken "
                   f"replica chain; no trustworthy source remains")
    elif not byte_digests:
        if "evidence-incomplete" in reasons:
            gap = "REPAIR_DONOR_EVIDENCE_INCOMPLETE"
            message = (f"donor evidence for sectors [{s0},{s1}) is "
                       f"incomplete (malformed, reused or non-comparable "
                       f"inspection records); no donor reading can be "
                       f"trusted")
        else:
            gap = "REPAIR_DONOR_READ_MISSING"
            message = (f"no donor holds a usable reading for sectors "
                       f"[{s0},{s1}); every candidate is absent, skipped "
                       f"the interval, failed to read or read it outside "
                       f"the completion window")
    elif len(set(byte_digests)) > 1:
        gap = "REPAIR_DONOR_DIGEST_CONFLICT"
        message = (f"the readable donors return conflicting digests for "
                   f"sectors [{s0},{s1}) and none matches the sealed "
                   f"baseline; there is no way to pick a source")
    else:
        gap = "REPAIR_DONOR_NO_BASELINE_MATCH"
        message = (f"every readable donor deviates from the sealed baseline "
                   f"on sectors [{s0},{s1}) with the same wrong digest; the "
                   f"deviation is shared with the target and must not be "
                   f"copied into the repair")
    emit(gap, message, replica_ids=list(donor_priority),
         start_sector=s0, end_sector=s1,
         detail={"rejected_donors": [r.model_dump(mode="json")
                                     for r in rejections]})
    return blocked(gap, message, rejections)


def _merge_segments(ready: list[RepairIntervalPlan],
                    donor_priority: list[str]) -> list[RepairSegment]:
    """Merge adjacent intervals served by the same donor and lay out the
    media-swap order: each donor's medium is mounted once, in donor-priority
    order, and its segments are read in sector order."""
    rank = {rid: i for i, rid in enumerate(donor_priority)}
    by_donor: dict[str, list[RepairIntervalPlan]] = {}
    for iv in ready:
        assert iv.donor_replica_id is not None
        by_donor.setdefault(iv.donor_replica_id, []).append(iv)
    segments: list[RepairSegment] = []
    for rid in sorted(by_donor, key=lambda r: rank.get(r, len(rank))):
        for iv in sorted(by_donor[rid], key=lambda i: i.start_sector):
            if (segments and segments[-1].donor_replica_id == rid
                    and segments[-1].end_sector == iv.start_sector):
                segments[-1].end_sector = iv.end_sector
                segments[-1].intervals.append(SectorInterval(
                    start_sector=iv.start_sector, end_sector=iv.end_sector))
            else:
                segments.append(RepairSegment(
                    start_sector=iv.start_sector, end_sector=iv.end_sector,
                    donor_replica_id=rid,
                    intervals=[SectorInterval(start_sector=iv.start_sector,
                                              end_sector=iv.end_sector)]))
    return segments


def _media_schedule(segments: list[RepairSegment],
                    donor_priority: list[str],
                    latest_insp: dict[str, Optional[str]]
                    ) -> list[RepairMediaStep]:
    rank = {rid: i for i, rid in enumerate(donor_priority)}
    by_donor: dict[str, list[RepairSegment]] = {}
    for seg in segments:
        by_donor.setdefault(seg.donor_replica_id, []).append(seg)
    steps: list[RepairMediaStep] = []
    for mount, rid in enumerate(
            sorted(by_donor, key=lambda r: rank.get(r, len(rank))), start=1):
        segs = by_donor[rid]
        steps.append(RepairMediaStep(
            mount_order=mount, donor_replica_id=rid,
            donor_inspection_id=latest_insp.get(rid), segments=segs,
            sectors=sum(s.end_sector - s.start_sector for s in segs)))
    return steps


def evaluate_repair_plan(*, plan_id: str,
                         joint_report: JointInspectionReport,
                         target_replica_id: str,
                         donor_priority: list[str],
                         requested_intervals: Optional[list[SectorInterval]],
                         total_sectors: int,
                         evidence_package_digest: Optional[str],
                         image_sha256: Optional[str],
                         merkle_root: Optional[str],
                         created_at: Any) -> RepairPlanReport:
    """Derive a frozen repair plan from a joint inspection evaluation.

    The evaluation is a pure function of the stored joint report (itself a
    pure function of the append-only inspection records); the resulting plan
    is stored and never re-derived, so later joint bindings cannot rewrite
    the donor decisions an execution is verified against.
    """
    media_id = joint_report.media_id
    findings: list[Finding] = []

    def error(code: str, message: str, **kw: Any) -> None:
        findings.append(Finding(code=code, severity=Severity.error,
                                message=message, media_id=media_id, **kw))

    planned_set = {(iv.start_sector, iv.end_sector)
                   for iv in joint_report.planned_intervals}
    interval_by_key = {(iv.start_sector, iv.end_sector): iv
                       for iv in joint_report.intervals}
    chain_broken = _replica_set(joint_report.findings,
                                "JOINT_REPLICA_CHAIN_BROKEN")
    tainted = _tainted_replicas(joint_report.findings)
    latest_insp = {rc.replica_id: rc.inspection_id
                   for rc in joint_report.replica_coverage}

    # ----------------------------- repair interval set ---------------------
    repair_keys: list[tuple[int, int]] = []
    if requested_intervals is None:
        for iv in joint_report.intervals:
            cell = next((c for c in iv.cells
                         if c.replica_id == target_replica_id), None)
            if cell is not None and cell.status == "digest-conflict":
                repair_keys.append((iv.start_sector, iv.end_sector))
    else:
        seen: set[tuple[int, int]] = set()
        for req in requested_intervals:
            key = (req.start_sector, req.end_sector)
            if key in seen:
                continue
            seen.add(key)
            if req.start_sector < 0 or req.end_sector > total_sectors:
                error("REPAIR_TARGET_INTERVAL_OUT_OF_BOUNDS",
                      f"requested repair interval [{key[0]},{key[1]}) "
                      f"exceeds the medium geometry ({total_sectors} "
                      f"sectors)",
                      replica_ids=[target_replica_id],
                      start_sector=key[0], end_sector=key[1],
                      detail={"total_sectors": total_sectors})
                continue
            if key not in planned_set:
                error("REPAIR_TARGET_INTERVAL_OUT_OF_BOUNDS",
                      f"requested repair interval [{key[0]},{key[1]}) is "
                      f"not one of the frozen joint plan intervals; donor "
                      f"evidence only exists per planned interval",
                      replica_ids=[target_replica_id],
                      start_sector=key[0], end_sector=key[1])
                continue
            repair_keys.append(key)
    repair_keys = sorted(set(repair_keys))

    interval_plans: list[RepairIntervalPlan] = []
    if target_replica_id in chain_broken:
        # A deviation reported by a broken chain is no basis for writes.
        error("REPAIR_SOURCE_CHAIN_BROKEN",
              f"the inspection bound for target replica {target_replica_id} "
              f"proves its replica chain is broken; a repair cannot "
              f"re-derive trust from a broken source chain",
              replica_ids=[target_replica_id])
    else:
        if requested_intervals is None and not repair_keys:
            error("REPAIR_NO_DEVIATION",
                  f"target replica {target_replica_id} shows no proven "
                  f"digest deviation in joint task {joint_report.joint_id}; "
                  f"there is nothing to repair",
                  replica_ids=[target_replica_id])
        for key in repair_keys:
            interval_plans.append(_evaluate_interval(
                key, interval_by_key[key], joint_id=joint_report.joint_id,
                target_replica_id=target_replica_id,
                donor_priority=donor_priority, chain_broken=chain_broken,
                tainted=tainted, latest_insp=latest_insp, emit=error))

    ready = [i for i in interval_plans if i.status == "ready"]
    segments = _merge_segments(ready, donor_priority)
    schedule = _media_schedule(segments, donor_priority, latest_insp)
    executable = (not any(f.severity == Severity.error for f in findings)
                    and bool(ready))
    source_inspections = [RepairSourceBinding(
        replica_id=target_replica_id, role="target",
        inspection_id=latest_insp.get(target_replica_id))]
    source_inspections += [
        RepairSourceBinding(replica_id=rid, role="donor",
                            inspection_id=latest_insp.get(rid))
        for rid in donor_priority]

    report = RepairPlanReport(
        plan_id=plan_id, manifest_id=joint_report.manifest_id,
        media_id=media_id, joint_id=joint_report.joint_id,
        target_replica_id=target_replica_id,
        donor_priority=list(donor_priority),
        executable=executable,
        repair_intervals=interval_plans,
        repair_sectors=sum(i.end_sector - i.start_sector for i in ready),
        segments=segments, media_schedule=schedule,
        source_inspections=source_inspections,
        findings=findings,
        evidence_package_digest=evidence_package_digest,
        image_sha256=image_sha256, merkle_root=merkle_root,
        created_at=created_at)
    # Self digest over the package with the digest field removed, mirroring
    # the evidence-package convention: re-serializing the stored plan and
    # recomputing yields the same value.
    body = report.model_dump(mode="json")
    body.pop("repair_package_digest", None)
    report.repair_package_digest = sha256_hex(canonical_bytes(body))
    return report


def evaluate_repair_execution(*, plan: RepairPlanReport,
                              payload: RepairExecutionCreate,
                              existing_replica_ids: set[str],
                              created_at: Any) -> RepairExecutionReport:
    """Verify one repair execution against its frozen plan.

    Every planned interval must be recorded exactly once; the donor read
    digest must equal the baseline digest frozen into the plan (the donor
    medium may have degraded since the joint inspection), the write digest
    must equal the read digest, and finally the recomputed whole-disk
    SHA-256 and Merkle root of the repaired target must equal the sealed
    image roots. The handover must also be documented: at least one custody
    event, and every event digest equal to the verified derived-replica
    digest. Only then is the new derived replica with its handover events
    registered; any failure is stored and nothing is registered.
    """
    media_id = plan.media_id
    findings: list[Finding] = []

    def error(code: str, message: str, **kw: Any) -> None:
        findings.append(Finding(code=code, severity=Severity.error,
                                message=message, media_id=media_id, **kw))

    ready = {(i.start_sector, i.end_sector): i
             for i in plan.repair_intervals if i.status == "ready"}
    results: list[RepairExecutionEntryResult] = []
    seen: set[tuple[int, int]] = set()
    written_intervals = 0
    written_sectors = 0

    for entry in payload.entries:
        key = (entry.start_sector, entry.end_sector)
        iv = ready.get(key)
        base: dict[str, Any] = dict(
            start_sector=entry.start_sector, end_sector=entry.end_sector,
            donor_replica_id=(iv.donor_replica_id if iv
                              else entry.donor_replica_id),
            expected_sha256=iv.expected_sha256 if iv else None,
            read_sha256=entry.read_sha256, read_error=entry.read_error,
            write_sha256=entry.write_sha256, write_error=entry.write_error,
            read_at=entry.read_at, written_at=entry.written_at)
        if key in seen:
            error("REPAIR_EXEC_INTERVAL_DUPLICATE",
                  f"interval [{key[0]},{key[1]}) was executed more than "
                  f"once; a repeated write record is not additional "
                  f"evidence",
                  replica_ids=[plan.target_replica_id],
                  start_sector=key[0], end_sector=key[1])
            results.append(RepairExecutionEntryResult(
                status="duplicate", **base))
            continue
        seen.add(key)
        if iv is None:
            error("REPAIR_EXEC_INTERVAL_OUT_OF_PLAN",
                  f"executed interval [{key[0]},{key[1]}) is not one of "
                  f"the frozen repair plan intervals",
                  replica_ids=[plan.target_replica_id],
                  start_sector=key[0], end_sector=key[1])
            results.append(RepairExecutionEntryResult(
                status="out-of-plan", **base))
            continue
        if (entry.donor_replica_id is not None
                and entry.donor_replica_id != iv.donor_replica_id):
            error("REPAIR_EXEC_DONOR_MISMATCH",
                  f"sectors [{key[0]},{key[1]}) were read from "
                  f"{entry.donor_replica_id} but the frozen plan assigns "
                  f"donor {iv.donor_replica_id}",
                  replica_ids=[entry.donor_replica_id, iv.donor_replica_id],
                  start_sector=key[0], end_sector=key[1])
            results.append(RepairExecutionEntryResult(
                status="donor-mismatch", **base))
            continue
        if entry.read_error:
            error("REPAIR_EXEC_DEVICE_ERROR",
                  f"donor {iv.donor_replica_id} could not be read for "
                  f"sectors [{key[0]},{key[1]}): {entry.read_error}",
                  replica_ids=[iv.donor_replica_id],
                  start_sector=key[0], end_sector=key[1],
                  detail={"side": "read", "tool_error": entry.read_error})
            results.append(RepairExecutionEntryResult(
                status="read-failed", **base))
            continue
        if entry.read_sha256 != iv.expected_sha256:
            error("REPAIR_EXEC_READ_DIGEST_MISMATCH",
                  f"bytes read from donor {iv.donor_replica_id} for "
                  f"sectors [{key[0]},{key[1]}) no longer match the "
                  f"baseline digest frozen in the repair plan; the donor "
                  f"medium may have degraded since the joint inspection",
                  replica_ids=[iv.donor_replica_id],
                  start_sector=key[0], end_sector=key[1],
                  detail={"expected": iv.expected_sha256,
                          "actual": entry.read_sha256})
            results.append(RepairExecutionEntryResult(
                status="read-mismatch", **base))
            continue
        if entry.write_error:
            error("REPAIR_EXEC_DEVICE_ERROR",
                  f"target {plan.target_replica_id} could not be written "
                  f"for sectors [{key[0]},{key[1]}): {entry.write_error}",
                  replica_ids=[plan.target_replica_id],
                  start_sector=key[0], end_sector=key[1],
                  detail={"side": "write", "tool_error": entry.write_error})
            results.append(RepairExecutionEntryResult(
                status="write-failed", **base))
            continue
        if entry.write_sha256 != entry.read_sha256:
            error("REPAIR_EXEC_WRITE_DIGEST_MISMATCH",
                  f"bytes written to target {plan.target_replica_id} for "
                  f"sectors [{key[0]},{key[1]}) differ from the verified "
                  f"donor bytes",
                  replica_ids=[plan.target_replica_id],
                  start_sector=key[0], end_sector=key[1],
                  detail={"read": entry.read_sha256,
                          "written": entry.write_sha256})
            results.append(RepairExecutionEntryResult(
                status="write-mismatch", **base))
            continue
        written_intervals += 1
        written_sectors += key[1] - key[0]
        results.append(RepairExecutionEntryResult(status="written", **base))

    for key in sorted(ready):
        if key in seen:
            continue
        iv = ready[key]
        error("REPAIR_EXEC_INTERVAL_MISSING",
              f"planned repair interval [{key[0]},{key[1]}) has no "
              f"execution record",
              replica_ids=[plan.target_replica_id],
              start_sector=key[0], end_sector=key[1])
        results.append(RepairExecutionEntryResult(
            start_sector=key[0], end_sector=key[1], status="missing",
            donor_replica_id=iv.donor_replica_id,
            expected_sha256=iv.expected_sha256))

    def has_errors() -> bool:
        return any(f.severity == Severity.error for f in findings)

    final_verified = False
    if not has_errors():
        if not payload.final_sha256 or not payload.final_merkle_root:
            error("REPAIR_EXEC_FINAL_MISSING",
                  "the execution records no recomputed whole-disk SHA-256 "
                  "and Merkle root of the repaired target; completion "
                  "cannot be verified",
                  replica_ids=[plan.target_replica_id])
        elif (payload.final_sha256 != plan.image_sha256
                or payload.final_merkle_root != plan.merkle_root):
            error("REPAIR_EXEC_FINAL_DIGEST_MISMATCH",
                  "the recomputed whole-disk SHA-256 / Merkle root of the "
                  "repaired target differs from the sealed image roots; "
                  "the repair did not reproduce the sealed image",
                  replica_ids=[plan.target_replica_id],
                  detail={"expected_sha256": plan.image_sha256,
                          "actual_sha256": payload.final_sha256,
                          "expected_merkle_root": plan.merkle_root,
                          "actual_merkle_root": payload.final_merkle_root})
        else:
            final_verified = True

    derived: Optional[RepairDerivedReplica] = None
    if not has_errors():
        rid = payload.derived_replica.replica_id
        if rid in existing_replica_ids:
            error("REPAIR_DERIVED_REPLICA_DUPLICATE",
                  f"replica {rid} is already registered for this manifest; "
                  f"a repaired medium must be registered under a new "
                  f"replica id",
                  replica_ids=[rid])
        # A completing execution registers the repaired medium TOGETHER WITH
        # its handover events: at least one event must be on record, and
        # every event digest must equal the verified whole-disk SHA-256 of
        # the derived replica (whose Merkle root was verified against the
        # sealed image above). An empty handover or a digest that disagrees
        # with the verified replica keeps the execution failed and registers
        # nothing.
        if not payload.custody_events:
            error("REPAIR_CUSTODY_EVENTS_MISSING",
                  "a completing execution must register at least one "
                  "handover event for the derived replica; an empty "
                  "custody_events list cannot document the handover",
                  replica_ids=[rid])
        else:
            mismatched = [
                e.event_id for e in payload.custody_events
                if any(d != payload.final_sha256
                       for d in (e.digest_before, e.digest_after,
                                 e.expected_digest) if d)]
            if mismatched:
                error("REPAIR_CUSTODY_DIGEST_MISMATCH",
                      "every handover event digest must equal the verified "
                      "whole-disk SHA-256 of the derived replica (registered "
                      "with the sealed Merkle root); the listed events "
                      "declare a different digest",
                      replica_ids=[rid],
                      detail={"event_ids": mismatched,
                              "derived_sha256": payload.final_sha256,
                              "derived_merkle_root": payload.final_merkle_root})
        if not has_errors():
            derived = RepairDerivedReplica(
                replica_id=rid, manifest_id=plan.manifest_id,
                plan_id=plan.plan_id, execution_id=payload.execution_id,
                parent_replica_id=plan.target_replica_id,
                sha256=payload.final_sha256 or "",
                merkle_root=payload.final_merkle_root,
                storage_location=payload.derived_replica.storage_location,
                custodian=payload.derived_replica.custodian,
                custody_events=list(payload.custody_events),
                registered_at=created_at)

    return RepairExecutionReport(
        execution_id=payload.execution_id, plan_id=plan.plan_id,
        manifest_id=plan.manifest_id, media_id=media_id,
        target_replica_id=plan.target_replica_id,
        result="failed" if has_errors() else "completed",
        device=payload.device, entries=results,
        planned_intervals=[SectorInterval(start_sector=a, end_sector=b)
                           for a, b in sorted(ready)],
        written_intervals=written_intervals, written_sectors=written_sectors,
        final_sha256=payload.final_sha256,
        final_merkle_root=payload.final_merkle_root,
        expected_image_sha256=plan.image_sha256,
        expected_merkle_root=plan.merkle_root,
        final_verified=final_verified,
        derived_replica=derived,
        findings=findings,
        evidence_package_digest=plan.evidence_package_digest,
        repair_package_digest=plan.repair_package_digest,
        created_at=created_at)
