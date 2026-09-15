"""FastAPI application: manifest intake, precheck, sealing, diffs, evidence."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query

from .chains import analyze_replica_custody
from .content import ContentResolver, FilesystemContentResolver
from .db import (
    configure,
    get_db,
    get_disclosure_proof_by_id,
    get_inspection,
    get_inspection_by_id,
    get_joint_inspection,
    get_joint_inspection_by_id,
    get_manifest,
    get_media,
    get_repair_execution,
    get_repair_execution_by_id,
    get_repair_plan,
    get_repair_plan_by_id,
    get_transfer_proposal,
    get_transfer_proposal_by_id,
    insert_disclosure_proof,
    insert_inspection,
    insert_joint_binding,
    insert_joint_inspection,
    insert_manifest,
    insert_repair_execution,
    insert_repair_plan,
    insert_transfer_proposal,
    insert_transfer_receipt,
    list_disclosure_proofs,
    list_inspections,
    list_joint_bindings,
    list_joint_inspections,
    list_manifests,
    list_repair_derived_replicas,
    list_repair_executions,
    list_repair_plans,
    list_transfer_proposals,
    list_transfer_receipts,
    list_transfer_receipts_for_proposal,
    mark_sealed,
    save_precheck,
    transfer_receipt_id_exists,
    utcnow_iso,
)
from .disclosure import (
    DisclosureError,
    build_disclosure_proof,
    evaluate_verification,
)
from .evidence import (
    build_evidence_package,
    diff_manifests,
    package_digest,
    payload_from_row,
    report_from_json,
)
from .hashing import canonical_json, digest_canonical, merkle_root
from .inspection import (
    as_utc,
    chunk_sector_ranges,
    evaluate_inspection,
    generate_sample_plan,
    internal_seams,
)
from .joint import JointTaskContext, evaluate_joint_inspection
from .recovery import analyze_recovery
from .repair import evaluate_repair_execution, evaluate_repair_plan
from .schemas import (
    CustodyChainReport,
    CustodyTransferPackage,
    CustodyTransferProposal,
    CustodyTransferProposalCreate,
    CustodyTransferReceiptCreate,
    CustodyTransferReceiptReport,
    CustodyTransferSummary,
    DiffReport,
    DisclosureProof,
    DisclosureProofCreate,
    DisclosureProofSummary,
    DisclosureVerifyRequest,
    DisclosureVerifyResult,
    EvaluationReport,
    Finding,
    InspectionCreate,
    InspectionHistoryReport,
    InspectionReport,
    InspectionSummary,
    JointInspectionBindingCreate,
    JointInspectionCreate,
    JointInspectionReport,
    JointInspectionSummary,
    ManifestCreate,
    ManifestCreated,
    MediaRecord,
    RecoveryState,
    RepairDerivedReplica,
    RepairExecutionCreate,
    RepairExecutionReport,
    RepairExecutionSummary,
    RepairPlanCreate,
    RepairPlanReport,
    RepairPlanSummary,
    SealRejected,
    SealResult,
    Severity,
)
from .transfer import (
    build_chains,
    build_transfer_package,
    chain_views,
    evaluate_receipt,
    genesis_heads,
    proposal_digest,
    transfer_status,
)
from .verifier import evaluate


def _evidence_roots() -> list[str]:
    raw = os.environ.get("EVIDENCE_ROOTS", "data/evidence")
    return [p for p in raw.split(os.pathsep) if p]


_content_resolver: ContentResolver = FilesystemContentResolver(_evidence_roots())


def set_content_resolver(resolver: Optional[ContentResolver]) -> None:
    """Override the chunk-content resolver (used by tests / deployments)."""
    global _content_resolver
    _content_resolver = (resolver if resolver is not None
                         else FilesystemContentResolver(_evidence_roots()))


def get_content_resolver() -> ContentResolver:
    return _content_resolver


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure(app.state.db_path)
    set_content_resolver(FilesystemContentResolver(_evidence_roots()))
    yield


app = FastAPI(
    title="Split-Image Forensic Evidence Verification API",
    version="1.5.0",
    description=(
        "Verify segmented disk acquisitions: sector coverage by offset, "
        "chunk-order reconstruction, SHA-256/Merkle roots, write-protector "
        "checks, bad-sector retry/fill provenance and replica/chain-of-custody "
        "digest continuity. Resumes, target swaps and corrections can only "
        "create new revisions; sealed manifests stay read-only. Post-seal "
        "integrity inspections patrol handed-over replicas with a "
        "seed-deterministic sample plan (head/tail, chunk seams, random "
        "sectors) and append-only tamper-evident history. Multi-replica "
        "joint inspections freeze the participating replicas, one unified "
        "seed/ratio and a completion window, then compare every replica "
        "against the sealed baseline interval by interval to tell a single "
        "rotting medium from a common multi-copy divergence. Repair plans "
        "freeze the joint task, the target replica and the donor priority, "
        "draw replacement bytes only from replicas that matched the sealed "
        "baseline on the same interval with complete evidence, and register "
        "the repaired medium as a derived replica only after its recomputed "
        "whole-disk SHA-256 and Merkle root match the sealed image. "
        "Selective disclosure proofs bind individually delivered chunks to "
        "the sealed Merkle root (leaf index, sibling digests and odd-node "
        "promotions), selected by chunk id or by ranges aligned exactly with "
        "effective chunk boundaries, with an append-only issuance record and "
        "a stateless recomputation endpoint. Post-seal custody transfers "
        "continue the frozen custody chain: a proposal cites the sealed "
        "manifest, the evidence package digest, the replica and the live "
        "chain head (parties, location, validity window), and the receiver's "
        "receipt binds the in-window passing inspections; an effective "
        "receipt mints the next hash-linked chain head while every rejected "
        "attempt stays on the append-only record with its rejection basis."
    ),
    lifespan=lifespan,
)
app.state.db_path = "data/evidence.db"


def _new_manifest_id() -> str:
    return f"MF-{uuid.uuid4().hex[:12].upper()}"


def _attach_lineage_findings(conn: sqlite3.Connection, payload: ManifestCreate,
                             report: EvaluationReport) -> None:
    """Cross-revision rules that need prior manifests.

    Source geometry is fixed when a medium is first registered; a revision that
    changes sector size / sector count / capacity is a mid-acquisition source
    parameter change and can never be sealed.
    """
    media_row = get_media(conn, payload.media.media_id)
    if media_row is None:
        return
    g = payload.media.geometry
    old = {"sector_size": media_row["sector_size"],
           "total_sectors": media_row["total_sectors"],
           "capacity_bytes": media_row["capacity_bytes"]}
    new = {"sector_size": g.sector_size,
           "total_sectors": g.total_sectors,
           "capacity_bytes": g.capacity_bytes}
    if old != new:
        report.error(
            "MEDIA_PARAMETERS_CHANGED",
            f"medium {payload.media.media_id} geometry differs from the first "
            f"registered manifest {media_row['first_manifest_id']}",
            start_sector=0, end_sector=g.total_sectors,
            detail={"first_manifest_id": media_row["first_manifest_id"],
                    "registered": old, "submitted": new})
    has_errors = any(f.severity == Severity.error for f in report.findings)
    report.sealable = report.sealable and not has_errors


def _evaluate_with_lineage(conn: sqlite3.Connection,
                           payload: ManifestCreate,
                           resolver: Optional[ContentResolver] = None
                           ) -> EvaluationReport:
    report = evaluate(payload, resolver=resolver or _content_resolver)
    _attach_lineage_findings(conn, payload, report)
    return report


def _summary(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "manifest_id": row["manifest_id"],
        "revision": row["revision"],
        "media_id": row["media_id"],
        "status": row["status"],
        "change_kind": row["change_kind"],
        "parent_manifest_id": row["parent_manifest_id"],
        "superseded_by": row["superseded_by"],
        "created_at": row["created_at"],
        "sealed_at": row["sealed_at"],
    }


def _validate_lineage(conn: sqlite3.Connection, payload: ManifestCreate) -> None:
    media_id = payload.media.media_id
    existing = list_manifests(conn, media_id)
    # Manual acceptance of unrecovered sectors must be justified on record and
    # can only be introduced by a derived revision, never by the initial one.
    if payload.recovery_exceptions and payload.change_kind == "initial":
        raise HTTPException(
            status_code=422,
            detail={"code": "EXCEPTION_REVISION_REQUIRED",
                    "message": "manual acceptance of unrecovered sectors "
                               "requires a documented reason and a derived "
                               "revision (resume/target-swap/correction); it "
                               "cannot be registered on the initial manifest",
                    "exception_ids": [e.exception_id
                                      for e in payload.recovery_exceptions]})
    if payload.change_kind == "initial":
        if existing:
            raise HTTPException(
                status_code=422,
                detail={"code": "REVISION_REQUIRED",
                        "message": "medium already has manifests; resume, target-swap "
                                   "or correction must create a derived revision",
                        "latest_manifest_id": existing[-1]["manifest_id"]})
    else:
        if not payload.parent_manifest_id:
            raise HTTPException(
                status_code=422,
                detail={"code": "PARENT_REQUIRED",
                        "message": f"change_kind={payload.change_kind} requires "
                                   f"parent_manifest_id"})
        parent = get_manifest(conn, payload.parent_manifest_id)
        if parent is None:
            raise HTTPException(status_code=404,
                                detail=f"parent manifest "
                                       f"{payload.parent_manifest_id} not found")
        if parent["media_id"] != media_id:
            raise HTTPException(
                status_code=422,
                detail={"code": "PARENT_MEDIA_MISMATCH",
                        "message": "parent manifest belongs to another medium",
                        "parent_media_id": parent["media_id"]})
        if parent["status"] == "superseded":
            raise HTTPException(
                status_code=409,
                detail={"code": "PARENT_SUPERSEDED",
                        "message": "cannot derive from an already superseded "
                                   "manifest; branch from its current successor",
                        "superseded_by": parent["superseded_by"]})
        # A draft parent is allowed (a power-loss partial image can never seal);
        # inserting the revision supersedes it and freezes it read-only.


@app.post("/manifests", response_model=ManifestCreated, status_code=201)
def create_manifest(payload: ManifestCreate,
                    conn: sqlite3.Connection = Depends(get_db)):
    """Register a manifest revision (pre-flight evaluation runs automatically)."""
    _validate_lineage(conn, payload)
    report = _evaluate_with_lineage(conn, payload)
    manifest_id = _new_manifest_id()
    row = insert_manifest(conn, manifest_id, payload)
    save_precheck(conn, manifest_id, json.dumps(report.model_dump(mode="json")))
    row = get_manifest(conn, manifest_id)
    result = _summary(row)
    result["report"] = report.model_dump(mode="json")
    return result


@app.get("/manifests", response_model=list[dict])
def get_manifests(media_id: str = Query(..., min_length=1),
                  conn: sqlite3.Connection = Depends(get_db)):
    return [_summary(r) for r in list_manifests(conn, media_id)]


@app.get("/manifests/{manifest_id}")
def read_manifest(manifest_id: str, conn: sqlite3.Connection = Depends(get_db)):
    row = get_manifest(conn, manifest_id)
    if row is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    return {**_summary(row),
            "payload": json.loads(row["payload_json"]),
            "payload_digest": row["payload_digest"]}


@app.post("/manifests/{manifest_id}/precheck", response_model=EvaluationReport)
def precheck_manifest(manifest_id: str, conn: sqlite3.Connection = Depends(get_db)):
    """Re-run every verification rule without sealing. Works on any revision."""
    row = get_manifest(conn, manifest_id)
    if row is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    payload = payload_from_row(row)
    report = _evaluate_with_lineage(conn, payload)
    save_precheck(conn, manifest_id, json.dumps(report.model_dump(mode="json")))
    return report


@app.post("/manifests/{manifest_id}/seal",
          response_model=SealResult,
          responses={409: {"model": SealRejected}})
def seal_manifest(manifest_id: str, conn: sqlite3.Connection = Depends(get_db)):
    """Seal a draft revision. Any error finding rejects sealing; the manifest
    stays a draft and the blocking findings (medium, intervals, events) are
    returned so the operator can produce a corrected derived revision."""
    row = get_manifest(conn, manifest_id)
    if row is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    if row["status"] == "sealed":
        raise HTTPException(409, detail={"code": "ALREADY_SEALED",
                                         "message": "manifest is already sealed; "
                                                    "sealed manifests are read-only"})
    if row["status"] == "superseded":
        raise HTTPException(409, detail={"code": "SUPERSEDED",
                                         "message": "manifest was superseded by a "
                                                    "newer revision and is read-only"})
    payload = payload_from_row(row)
    report = _evaluate_with_lineage(conn, payload)
    if not report.sealable:
        blockers = [f for f in report.findings if f.severity == Severity.error]
        raise HTTPException(409, detail={
            "detail": "manifest is not sealable",
            "manifest_id": manifest_id,
            "sealable": False,
            "blocking_findings": [f.model_dump(mode="json") for f in blockers],
        })

    sealed_at = datetime.now(timezone.utc).isoformat()
    report_json = json.dumps(report.model_dump(mode="json"))

    # Build the complete evidence package BEFORE changing any state: package
    # serialization/assembly can fail, and a failed seal attempt must never
    # leave the revision marked sealed. The package records status/sealed_at
    # of the successful sealing it is part of.
    package = build_evidence_package(
        row, report,
        status_override="sealed", sealed_at_override=sealed_at)

    # Everything above succeeded -- only now commit the sealed state.
    mark_sealed(conn, manifest_id, sealed_at, report_json,
                report.merkle_root, report.reconstructed_sha256)
    return SealResult(
        manifest_id=manifest_id,
        status="sealed",
        sealed_at=sealed_at,
        merkle_root=report.merkle_root or "",
        reconstructed_sha256=report.reconstructed_sha256,
        evidence_package_digest=package["evidence_package_digest"],
        evidence_package=package)


@app.get("/manifests/{manifest_id}/findings",
         response_model=list[Finding])
def manifest_findings(manifest_id: str, conn: sqlite3.Connection = Depends(get_db)):
    row = get_manifest(conn, manifest_id)
    if row is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    report = report_from_json(row["seal_report_json"] or row["precheck_json"])
    return report.findings if report else []


@app.get("/manifests/{manifest_id}/recovery",
         response_model=RecoveryState)
def manifest_recovery(manifest_id: str,
                      conn: sqlite3.Connection = Depends(get_db)):
    """Read-attempt log, final read/fill/unrecovered segments, exception
    decisions and recovery rate from the same evaluation used by precheck,
    diffs, the evidence package and recompute."""
    row = get_manifest(conn, manifest_id)
    if row is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    report = report_from_json(row["seal_report_json"] or row["precheck_json"])
    if report is None:
        report = _evaluate_with_lineage(conn, payload_from_row(row))
    return report.recovery


@app.get("/manifests/{manifest_id}/evidence-package")
def evidence_package(manifest_id: str, conn: sqlite3.Connection = Depends(get_db)):
    """Deterministic, reproducible JSON evidence package (see /evidence/recompute)."""
    row = get_manifest(conn, manifest_id)
    if row is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    report = report_from_json(row["seal_report_json"] or row["precheck_json"])
    if report is None:
        report = _evaluate_with_lineage(conn, payload_from_row(row))
    return build_evidence_package(row, report)


# ------------------------------------- post-seal integrity inspection ----
def _sealed_context(conn: sqlite3.Connection, manifest_id: str,
                    code: str = "INSPECTION_REQUIRES_SEALED"):
    """Load a sealed manifest plus its sealed report and bound package digest.

    Inspections patrol the copies of a *sealed* image; a draft or superseded
    manifest has no frozen evidence to compare against.
    """
    row = get_manifest(conn, manifest_id)
    if row is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    if row["status"] != "sealed":
        raise HTTPException(409, detail={
            "code": code,
            "message": "this post-seal operation references the sealed "
                       f"manifest; manifest {manifest_id} is "
                       f"'{row['status']}'",
            "status": row["status"]})
    sealed_report = report_from_json(row["seal_report_json"])
    sealed_payload = payload_from_row(row)
    if sealed_report is None:
        sealed_report = _evaluate_with_lineage(conn, sealed_payload)
    package = build_evidence_package(row, sealed_report)
    return row, sealed_payload, sealed_report, \
        package["evidence_package_digest"]


def _stored_inspection_report(row: sqlite3.Row) -> InspectionReport:
    return InspectionReport.model_validate(json.loads(row["report_json"]))


def _inspection_summary(report: InspectionReport) -> InspectionSummary:
    return InspectionSummary(
        inspection_id=report.inspection_id, replica_id=report.replica_id,
        result=report.result, seed=report.seed,
        sample_ratio=report.sample_ratio, device_id=report.device.device_id,
        planned_sectors=report.planned_sectors,
        verified_sectors=report.verified_sectors,
        coverage_rate=report.coverage_rate, created_at=report.created_at)


@app.get("/manifests/{manifest_id}/inspection-plan")
def inspection_plan(manifest_id: str,
                    seed: str = Query(..., min_length=1),
                    sample_ratio: float = Query(..., gt=0.0, le=1.0),
                    conn: sqlite3.Connection = Depends(get_db)):
    """Preview the deterministic sample plan for a seed and sampling ratio.

    The plan always covers the first/last sector and both sectors straddling
    every chunk seam, filled to the ratio with seeded random sectors. The
    patrol tool reads exactly these intervals off the replica and submits the
    digests via POST /manifests/{id}/inspections; because the seed is frozen
    into the inspection record, anyone can re-derive the plan and prove the
    sampled ranges were not cherry-picked afterwards.
    """
    row, sealed_payload, sealed_report, package_digest_ = \
        _sealed_context(conn, manifest_id)
    geom = sealed_payload.media.geometry
    ranges = chunk_sector_ranges(sealed_payload,
                                 sealed_report.ordered_chunk_ids,
                                 geom.sector_size)
    seams = internal_seams(ranges)
    plan = generate_sample_plan(geom.total_sectors, seams, sample_ratio, seed)
    return {
        "manifest_id": manifest_id,
        "media_id": row["media_id"],
        "seed": seed,
        "sample_ratio": sample_ratio,
        "chunk_boundaries": seams,
        "planned_intervals": [{"start_sector": a, "end_sector": b}
                              for a, b in plan],
        "planned_sectors": sum(b - a for a, b in plan),
        "total_sectors": geom.total_sectors,
        "evidence_package_digest": package_digest_,
        "image_sha256": sealed_report.reconstructed_sha256,
        "merkle_root": sealed_report.merkle_root,
    }


@app.post("/manifests/{manifest_id}/inspections",
          response_model=InspectionReport, status_code=201)
def create_inspection(manifest_id: str, payload: InspectionCreate,
                      conn: sqlite3.Connection = Depends(get_db)):
    """Submit one post-seal integrity inspection (append-only).

    The service regenerates the sample plan from the frozen seed, compares
    every submitted reading against the sealed evidence package and stores
    the report. Missing intervals, duplicates, out-of-plan readings, read
    failures or an unrecomputable expectation mark the run ``inconclusive``;
    a digest conflict or a broken replica chain marks it ``failed`` — in
    both cases the finding carries the replica and the sector interval. An
    existing inspection_id is never overwritten (409).
    """
    row, sealed_payload, sealed_report, package_digest_ = \
        _sealed_context(conn, manifest_id)
    if get_inspection_by_id(conn, payload.inspection_id) is not None:
        raise HTTPException(409, detail={
            "code": "INSPECTION_DUPLICATE",
            "message": f"inspection {payload.inspection_id} already exists; "
                       "inspection records are append-only and a re-test "
                       "must use a new inspection_id",
            "inspection_id": payload.inspection_id})
    priors = [_stored_inspection_report(r)
              for r in list_inspections(conn, manifest_id)]
    report = evaluate_inspection(
        payload, manifest_row=row, sealed_payload=sealed_payload,
        sealed_report=sealed_report, resolver=_content_resolver,
        prior_reports=priors, evidence_package_digest=package_digest_,
        created_at=utcnow_iso())
    plan = [[i.start_sector, i.end_sector] for i in report.planned_intervals]
    insert_inspection(conn, report, plan)
    return report


@app.get("/manifests/{manifest_id}/inspections",
         response_model=list[InspectionSummary])
def list_manifest_inspections(manifest_id: str,
                              conn: sqlite3.Connection = Depends(get_db)):
    if get_manifest(conn, manifest_id) is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    return [_inspection_summary(_stored_inspection_report(r))
            for r in list_inspections(conn, manifest_id)]


@app.get("/manifests/{manifest_id}/inspections/{inspection_id}",
         response_model=InspectionReport)
def read_inspection(manifest_id: str, inspection_id: str,
                    conn: sqlite3.Connection = Depends(get_db)):
    row = get_inspection(conn, manifest_id, inspection_id)
    if row is None:
        raise HTTPException(404, f"inspection {inspection_id} not found for "
                                 f"manifest {manifest_id}")
    return _stored_inspection_report(row)


@app.get("/manifests/{manifest_id}/inspection-report",
         response_model=InspectionHistoryReport)
def inspection_history(manifest_id: str,
                       conn: sqlite3.Connection = Depends(get_db)):
    """Append-only patrol history of a sealed manifest.

    Aggregates every inspection ever submitted: cumulative sample coverage,
    all divergent intervals with their first-change time (never erased by
    later passing re-tests) and the bound evidence package.
    """
    row, sealed_payload, sealed_report, package_digest_ = \
        _sealed_context(conn, manifest_id)
    reports = [_stored_inspection_report(r)
               for r in list_inspections(conn, manifest_id)]
    geom = sealed_payload.media.geometry
    total_sectors = int(geom.total_sectors)

    results: dict[str, int] = {}
    sampled: set[int] = set()
    divergent: dict[tuple[str, int, int], dict[str, Any]] = {}
    # Only intervals the tool genuinely read off a replica count toward
    # cumulative coverage: an in-plan, non-duplicate reading that returned
    # bytes -- matching, conflicting, or with an unrecomputable frozen
    # baseline. Planned-but-missing intervals and reported read failures are
    # not "covered"; out-of-plan readings never reach the per-interval
    # results, and per-run duplicated readings are excluded explicitly below.
    # Union across inspections de-duplicates repeats.
    read_statuses = {"match", "digest-conflict", "unverifiable"}
    for rep in reports:
        results[rep.result] = results.get(rep.result, 0) + 1
        # An interval submitted more than once within this run contributes
        # zero coverage even though its first reading still has a per-interval
        # result: duplicated readings are not additional evidence.
        duplicated = {(f.start_sector, f.end_sector)
                      for f in rep.findings
                      if f.code == "INSPECTION_READING_DUPLICATE"}
        status_by_interval = {(iv.start_sector, iv.end_sector): iv.status
                              for iv in rep.intervals}
        for iv in rep.planned_intervals:
            key = (iv.start_sector, iv.end_sector)
            if key in duplicated:
                continue
            if status_by_interval.get(key) in read_statuses:
                sampled.update(range(iv.start_sector, iv.end_sector))
        for d in rep.divergent_intervals:
            key = (d.replica_id, d.start_sector, d.end_sector)
            when = as_utc(d.first_change_at or d.read_at)
            entry = divergent.get(key)
            if entry is None:
                divergent[key] = {
                    "first_change_at": when,
                    "first_inspection_id": (d.first_inspection_id
                                            or rep.inspection_id),
                    "latest": d}
            else:
                if when is not None and (entry["first_change_at"] is None
                                         or when < entry["first_change_at"]):
                    entry["first_change_at"] = when
                    entry["first_inspection_id"] = (d.first_inspection_id
                                                    or rep.inspection_id)
                entry["latest"] = d

    divergent_intervals = []
    for (replica_id, s0, s1), entry in sorted(divergent.items(),
                                              key=lambda kv: kv[0][1:]):
        latest = entry["latest"]
        divergent_intervals.append({
            "start_sector": s0, "end_sector": s1, "replica_id": replica_id,
            "expected_sha256": latest.expected_sha256,
            "actual_sha256": latest.actual_sha256,
            "read_at": latest.read_at,
            "first_change_at": entry["first_change_at"],
            "first_inspection_id": entry["first_inspection_id"]})
    first_change_at = min((d["first_change_at"] for d in divergent_intervals
                           if d["first_change_at"] is not None), default=None)
    return InspectionHistoryReport(
        manifest_id=manifest_id,
        media_id=row["media_id"],
        evidence_package_digest=package_digest_,
        image_sha256=sealed_report.reconstructed_sha256,
        merkle_root=sealed_report.merkle_root,
        total_sectors=total_sectors,
        inspection_count=len(reports),
        results=results,
        latest_result=reports[-1].result if reports else None,
        ever_failed=any(r.result == "failed" for r in reports),
        cumulative_coverage_rate=(len(sampled) / total_sectors
                                  if total_sectors else 1.0),
        divergent_intervals=divergent_intervals,
        first_change_at=first_change_at,
        inspections=[_inspection_summary(r) for r in reports])


# ------------------------ multi-replica joint inspection (append-only) ----
def _joint_report(conn: sqlite3.Connection,
                  task_row: sqlite3.Row) -> JointInspectionReport:
    """Evaluate a stored joint task against its append-only bindings.

    The report is a pure function of the stored task row, the stored binding
    rows and the immutable per-replica inspection records, so re-reading it
    never rewrites history.
    """
    manifest_id = task_row["manifest_id"]
    mrow = get_manifest(conn, manifest_id)
    sealed_report = report_from_json(mrow["seal_report_json"])
    sealed_payload = payload_from_row(mrow)
    bindings = [dict(b) for b in list_joint_bindings(conn, task_row["joint_id"])]
    inspections: dict[str, InspectionReport] = {}
    for b in bindings:
        iid = b["inspection_id"]
        if iid not in inspections:
            irow = get_inspection(conn, manifest_id, iid)
            if irow is not None:
                inspections[iid] = _stored_inspection_report(irow)
    geom = sealed_payload.media.geometry
    task = JointTaskContext(
        joint_id=task_row["joint_id"], manifest_id=manifest_id,
        media_id=task_row["media_id"],
        replica_ids=json.loads(task_row["replica_ids_json"]),
        seed=task_row["seed"], sample_ratio=task_row["sample_ratio"],
        window_start=task_row["window_start"],
        window_end=task_row["window_end"],
        plan=json.loads(task_row["plan_json"]),
        chunk_boundaries=json.loads(task_row["chunk_boundaries_json"]),
        evidence_package_digest=task_row["evidence_package_digest"],
        created_at=task_row["created_at"])
    return evaluate_joint_inspection(
        task, bindings=bindings, inspections=inspections,
        total_sectors=int(geom.total_sectors),
        image_sha256=(sealed_report.reconstructed_sha256 if sealed_report
                      else mrow["reconstructed_sha256"]),
        merkle_root=(sealed_report.merkle_root if sealed_report
                     else mrow["merkle_root"]))


def _joint_summary(report: JointInspectionReport) -> JointInspectionSummary:
    participants = set(report.replica_ids)
    return JointInspectionSummary(
        joint_id=report.joint_id, result=report.result, seed=report.seed,
        sample_ratio=report.sample_ratio, replica_ids=report.replica_ids,
        submitted_replica_ids=sorted({b.replica_id for b in report.bindings
                                      if b.replica_id in participants}),
        binding_count=len(report.bindings),
        window_start=report.window_start, window_end=report.window_end,
        created_at=report.created_at)


@app.post("/manifests/{manifest_id}/joint-inspections",
          response_model=JointInspectionReport, status_code=201)
def create_joint_inspection(manifest_id: str, payload: JointInspectionCreate,
                            conn: sqlite3.Connection = Depends(get_db)):
    """Open a multi-replica joint patrol task on a sealed manifest.

    Freezes the sealed manifest, the evidence package digest, the
    participating replicas, the unified seed, the sampling ratio and the
    completion window, and derives the single sample plan every replica is
    read against. Each replica then submits an ordinary inspection record
    (same seed/ratio) and binds it via
    ``POST .../joint-inspections/{joint_id}/submissions``. Tasks are
    append-only: an existing joint_id is never rewritten (409).
    """
    row, sealed_payload, sealed_report, package_digest_ = \
        _sealed_context(conn, manifest_id)
    if get_joint_inspection_by_id(conn, payload.joint_id) is not None:
        raise HTTPException(409, detail={
            "code": "JOINT_INSPECTION_DUPLICATE",
            "message": f"joint inspection {payload.joint_id} already exists; "
                       "joint tasks are append-only and a re-test binds new "
                       "inspection records instead of rewriting the task",
            "joint_id": payload.joint_id})
    registered = {r.replica_id for r in sealed_payload.replicas}
    unknown = [rid for rid in payload.replica_ids if rid not in registered]
    if unknown:
        raise HTTPException(422, detail={
            "code": "JOINT_REPLICA_UNKNOWN",
            "message": "participating replicas must be registered in the "
                       "sealed manifest",
            "unknown_replica_ids": unknown})
    geom = sealed_payload.media.geometry
    ranges = chunk_sector_ranges(sealed_payload,
                                 sealed_report.ordered_chunk_ids,
                                 geom.sector_size)
    seams = internal_seams(ranges)
    plan = generate_sample_plan(geom.total_sectors, seams,
                                payload.sample_ratio, payload.seed)
    insert_joint_inspection(
        conn, joint_id=payload.joint_id, manifest_id=manifest_id,
        media_id=row["media_id"], replica_ids=payload.replica_ids,
        seed=payload.seed, sample_ratio=payload.sample_ratio,
        window_start=payload.window_start.isoformat(),
        window_end=payload.window_end.isoformat(), plan=plan,
        chunk_boundaries=seams, evidence_package_digest=package_digest_,
        created_at=utcnow_iso())
    task_row = get_joint_inspection(conn, manifest_id, payload.joint_id)
    return _joint_report(conn, task_row)


@app.get("/manifests/{manifest_id}/joint-inspections",
         response_model=list[JointInspectionSummary])
def list_manifest_joint_inspections(manifest_id: str,
                                    conn: sqlite3.Connection = Depends(get_db)):
    if get_manifest(conn, manifest_id) is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    return [_joint_summary(_joint_report(conn, task_row))
            for task_row in list_joint_inspections(conn, manifest_id)]


@app.get("/manifests/{manifest_id}/joint-inspections/{joint_id}",
         response_model=JointInspectionReport)
def read_joint_inspection(manifest_id: str, joint_id: str,
                          conn: sqlite3.Connection = Depends(get_db)):
    """Full joint report: per-interval cross-replica verdicts, per-replica
    coverage, the append-only divergence history with first-appearance
    times, and the bindings to the original inspection records."""
    task_row = get_joint_inspection(conn, manifest_id, joint_id)
    if task_row is None:
        raise HTTPException(404, f"joint inspection {joint_id} not found for "
                                 f"manifest {manifest_id}")
    return _joint_report(conn, task_row)


@app.post("/manifests/{manifest_id}/joint-inspections/{joint_id}/submissions",
          response_model=JointInspectionReport, status_code=201)
def bind_joint_submission(manifest_id: str, joint_id: str,
                          payload: JointInspectionBindingCreate,
                          conn: sqlite3.Connection = Depends(get_db)):
    """Bind a submitted per-replica inspection record to the joint task
    (append-only).

    The replica is taken from the inspection record itself. Bindings are
    never rejected for semantic mismatches — a plan/window/duplicate
    violation is recorded and the joint evaluation stays ``inconclusive``,
    so the attempt remains auditable. A re-test binds a NEW inspection
    record; earlier bindings and their divergences are never erased.
    """
    task_row = get_joint_inspection(conn, manifest_id, joint_id)
    if task_row is None:
        raise HTTPException(404, f"joint inspection {joint_id} not found for "
                                 f"manifest {manifest_id}")
    insp_row = get_inspection(conn, manifest_id, payload.inspection_id)
    if insp_row is None:
        raise HTTPException(404, detail={
            "code": "JOINT_INSPECTION_UNKNOWN",
            "message": f"inspection {payload.inspection_id} not found for "
                       f"manifest {manifest_id}; submit the per-replica "
                       f"inspection first",
            "inspection_id": payload.inspection_id})
    insp = _stored_inspection_report(insp_row)
    insert_joint_binding(conn, joint_id, payload.inspection_id,
                         insp.replica_id, utcnow_iso())
    return _joint_report(conn, task_row)


# ------------------------ replica interval repair (append-only) ----
def _stored_repair_plan(row: sqlite3.Row) -> RepairPlanReport:
    return RepairPlanReport.model_validate(json.loads(row["plan_json"]))


def _stored_repair_execution(row: sqlite3.Row) -> RepairExecutionReport:
    return RepairExecutionReport.model_validate(json.loads(row["report_json"]))


def _repair_plan_summary(report: RepairPlanReport) -> RepairPlanSummary:
    donors = sorted({i.donor_replica_id for i in report.repair_intervals
                     if i.donor_replica_id})
    return RepairPlanSummary(
        plan_id=report.plan_id, joint_id=report.joint_id,
        target_replica_id=report.target_replica_id,
        executable=report.executable,
        interval_count=len(report.repair_intervals),
        repair_sectors=report.repair_sectors, donor_replica_ids=donors,
        created_at=report.created_at)


def _repair_execution_summary(report: RepairExecutionReport
                              ) -> RepairExecutionSummary:
    return RepairExecutionSummary(
        execution_id=report.execution_id, plan_id=report.plan_id,
        result=report.result, written_intervals=report.written_intervals,
        written_sectors=report.written_sectors,
        derived_replica_id=(report.derived_replica.replica_id
                            if report.derived_replica else None),
        created_at=report.created_at)


@app.post("/manifests/{manifest_id}/repair-plans",
          response_model=RepairPlanReport, status_code=201)
def create_repair_plan(manifest_id: str, payload: RepairPlanCreate,
                       conn: sqlite3.Connection = Depends(get_db)):
    """Open a replica interval repair plan (append-only).

    Freezes the sealed manifest, the joint inspection task, the target
    replica and the donor priority order, then derives per frozen joint
    plan interval the donor that may be read: only a replica whose own
    bound inspection matched the sealed baseline on the SAME interval with
    complete evidence. Adjacent intervals served by the same donor are
    merged and donors are scheduled in priority order (one media mount per
    donor). An unrecomputable baseline, missing donor reads, conflicting
    donor digests, a broken source chain or an out-of-bounds target
    interval leave the plan non-executable and name the gap. An existing
    plan_id is never rewritten (409).
    """
    row, sealed_payload, sealed_report, package_digest_ = \
        _sealed_context(conn, manifest_id)
    if get_repair_plan_by_id(conn, payload.plan_id) is not None:
        raise HTTPException(409, detail={
            "code": "REPAIR_PLAN_DUPLICATE",
            "message": f"repair plan {payload.plan_id} already exists; "
                       "repair plans are append-only and a changed scope "
                       "must use a new plan_id",
            "plan_id": payload.plan_id})
    task_row = get_joint_inspection(conn, manifest_id, payload.joint_id)
    if task_row is None:
        raise HTTPException(404, detail={
            "code": "REPAIR_JOINT_UNKNOWN",
            "message": f"joint inspection {payload.joint_id} not found for "
                       f"manifest {manifest_id}; a repair plan must freeze "
                       "an existing joint task",
            "joint_id": payload.joint_id})
    joint_report = _joint_report(conn, task_row)
    participants = set(joint_report.replica_ids)
    if payload.target_replica_id not in participants:
        raise HTTPException(422, detail={
            "code": "REPAIR_TARGET_NOT_PARTICIPANT",
            "message": "the repair target must be a participating replica "
                       "of the frozen joint task",
            "target_replica_id": payload.target_replica_id,
            "joint_replica_ids": joint_report.replica_ids})
    unknown = [d for d in payload.donor_priority if d not in participants]
    if unknown:
        raise HTTPException(422, detail={
            "code": "REPAIR_DONOR_NOT_PARTICIPANT",
            "message": "donor candidates must be participating replicas of "
                       "the frozen joint task",
            "unknown_donor_ids": unknown,
            "joint_replica_ids": joint_report.replica_ids})
    geom = sealed_payload.media.geometry
    report = evaluate_repair_plan(
        plan_id=payload.plan_id, joint_report=joint_report,
        target_replica_id=payload.target_replica_id,
        donor_priority=payload.donor_priority,
        requested_intervals=payload.intervals,
        total_sectors=int(geom.total_sectors),
        evidence_package_digest=package_digest_,
        image_sha256=joint_report.image_sha256,
        merkle_root=joint_report.merkle_root,
        created_at=utcnow_iso())
    insert_repair_plan(conn, report)
    return report


@app.get("/manifests/{manifest_id}/repair-plans",
         response_model=list[RepairPlanSummary])
def list_manifest_repair_plans(manifest_id: str,
                               conn: sqlite3.Connection = Depends(get_db)):
    if get_manifest(conn, manifest_id) is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    return [_repair_plan_summary(_stored_repair_plan(r))
            for r in list_repair_plans(conn, manifest_id)]


@app.get("/manifests/{manifest_id}/repair-plans/{plan_id}",
         response_model=RepairPlanReport)
def read_repair_plan(manifest_id: str, plan_id: str,
                     conn: sqlite3.Connection = Depends(get_db)):
    """The frozen JSON repair package: per-interval donor decisions with
    the selection rationale, merged segments, the media-swap schedule, the
    bound original inspection records and the self digest."""
    row = get_repair_plan(conn, manifest_id, plan_id)
    if row is None:
        raise HTTPException(404, f"repair plan {plan_id} not found for "
                                 f"manifest {manifest_id}")
    return _stored_repair_plan(row)


@app.post("/manifests/{manifest_id}/repair-plans/{plan_id}/executions",
          response_model=RepairExecutionReport, status_code=201)
def create_repair_execution(manifest_id: str, plan_id: str,
                            payload: RepairExecutionCreate,
                            conn: sqlite3.Connection = Depends(get_db)):
    """Submit one repair execution against a frozen plan (append-only).

    Every planned interval must be recorded exactly once: the donor read
    digest must equal the baseline digest frozen into the plan, the write
    digest must equal the read digest, and device errors are stored per
    interval. When every interval is written, the recomputed whole-disk
    SHA-256 and Merkle root of the repaired target must equal the sealed
    image roots, and the handover must be documented by at least one
    custody event carrying digest_before, digest_after and expected_digest,
    each equal to the verified derived-replica digest — only then is the
    new derived replica with its handover events registered. A failed
    execution is stored and registers nothing;
    an existing execution_id is never overwritten (409).
    """
    plan_row = get_repair_plan(conn, manifest_id, plan_id)
    if plan_row is None:
        raise HTTPException(404, f"repair plan {plan_id} not found for "
                                 f"manifest {manifest_id}")
    plan = _stored_repair_plan(plan_row)
    if not plan.executable:
        raise HTTPException(409, detail={
            "code": "REPAIR_PLAN_NOT_EXECUTABLE",
            "message": "the repair plan has blocking gaps and is not "
                       "executable; open a new plan that resolves them",
            "plan_id": plan_id,
            "gaps": [f.model_dump(mode="json") for f in plan.findings
                     if f.severity == Severity.error]})
    if get_repair_execution_by_id(conn, payload.execution_id) is not None:
        raise HTTPException(409, detail={
            "code": "REPAIR_EXECUTION_DUPLICATE",
            "message": f"repair execution {payload.execution_id} already "
                       "exists; execution records are append-only and a "
                       "re-run must use a new execution_id",
            "execution_id": payload.execution_id})
    derived_id = payload.derived_replica.replica_id
    foreign = [e.event_id for e in payload.custody_events
               if e.replica_id != derived_id]
    if foreign:
        raise HTTPException(422, detail={
            "code": "REPAIR_CUSTODY_REPLICA_MISMATCH",
            "message": "every handover event must reference the derived "
                       f"replica {derived_id} being registered",
            "event_ids": foreign})
    event_ids = [e.event_id for e in payload.custody_events]
    if len(set(event_ids)) != len(event_ids):
        raise HTTPException(422, detail={
            "code": "REPAIR_CUSTODY_EVENT_DUPLICATE",
            "message": "handover event ids must be unique within one "
                       "execution",
            "event_ids": sorted(i for i in set(event_ids)
                                if event_ids.count(i) > 1)})
    row, sealed_payload, sealed_report, package_digest_ = \
        _sealed_context(conn, manifest_id)
    existing = {r.replica_id for r in sealed_payload.replicas}
    existing |= {r["replica_id"]
                 for r in list_repair_derived_replicas(conn, manifest_id)}
    report = evaluate_repair_execution(
        plan=plan, payload=payload, existing_replica_ids=existing,
        created_at=utcnow_iso())
    insert_repair_execution(conn, report)
    return report


@app.get("/manifests/{manifest_id}/repair-plans/{plan_id}/executions",
         response_model=list[RepairExecutionSummary])
def list_plan_executions(manifest_id: str, plan_id: str,
                         conn: sqlite3.Connection = Depends(get_db)):
    if get_repair_plan(conn, manifest_id, plan_id) is None:
        raise HTTPException(404, f"repair plan {plan_id} not found for "
                                 f"manifest {manifest_id}")
    return [_repair_execution_summary(_stored_repair_execution(r))
            for r in list_repair_executions(conn, plan_id)]


@app.get("/manifests/{manifest_id}/repair-plans/{plan_id}/executions/{execution_id}",
         response_model=RepairExecutionReport)
def read_repair_execution(manifest_id: str, plan_id: str, execution_id: str,
                          conn: sqlite3.Connection = Depends(get_db)):
    row = get_repair_execution(conn, manifest_id, plan_id, execution_id)
    if row is None:
        raise HTTPException(404, f"repair execution {execution_id} not found "
                                 f"for plan {plan_id} of manifest "
                                 f"{manifest_id}")
    return _stored_repair_execution(row)


@app.get("/manifests/{manifest_id}/repair-replicas",
         response_model=list[RepairDerivedReplica])
def list_manifest_repair_replicas(manifest_id: str,
                                  conn: sqlite3.Connection = Depends(get_db)):
    """Derived replicas registered by completed repair executions, with
    their handover events (append-only; the sealed manifest itself is
    never modified)."""
    if get_manifest(conn, manifest_id) is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    return [RepairDerivedReplica.model_validate(json.loads(r["record_json"]))
            for r in list_repair_derived_replicas(conn, manifest_id)]


# ----------------------------- selective disclosure proofs (append-only) ----
def _disclosure_summary_row(row: sqlite3.Row) -> DisclosureProofSummary:
    proof = DisclosureProof.model_validate(json.loads(row["proof_json"]))
    return DisclosureProofSummary(
        proof_id=proof.proof_id, manifest_id=proof.manifest_id,
        media_id=proof.media_id, revision=proof.revision,
        evidence_package_digest=proof.evidence_package_digest,
        requested_by=row["requested_by"], reason=row["reason"],
        leaf_count=proof.leaf_count,
        disclosed_chunk_ids=[lp.chunk_id for lp in proof.leaf_proofs],
        covered_sector_ranges=proof.covered_sector_ranges,
        covered_sectors=proof.covered_sectors,
        total_sectors=proof.total_sectors,
        disclosure_digest=proof.disclosure_digest,
        created_at=proof.created_at)


@app.post("/manifests/{manifest_id}/disclosure-proofs",
          response_model=DisclosureProof, status_code=201)
def create_disclosure_proof(manifest_id: str,
                            payload: DisclosureProofCreate,
                            conn: sqlite3.Connection = Depends(get_db)):
    """Issue selective Merkle inclusion proofs for chunks of a sealed image.

    The request must cite the sealed manifest and the exact
    ``evidence_package_digest`` of the sealed package, and select effective
    leaves by ``chunk_id`` and/or by sector ranges that line up EXACTLY with
    valid chunk boundaries. For every disclosed leaf the proof freezes its
    leaf index, the left/right sibling digests on each level and every
    odd-node promotion step, plus the pinned manifest revision, the Merkle
    algorithm specification and the adopted leaf ordering. The request
    scope, covered ranges and per-leaf selection rationale are written to
    an append-only record; an existing proof_id is never overwritten (409).
    Correction-superseded chunks, boundary-crossing or out-of-medium ranges,
    duplicate leaves and a mismatched evidence package digest refuse the
    request — no proof is issued on any such error.
    """
    row = get_manifest(conn, manifest_id)
    if row is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    if row["status"] != "sealed":
        raise HTTPException(409, detail={
            "code": "DISCLOSURE_REQUIRES_SEALED",
            "message": "selective disclosure proofs are anchored in the "
                       "frozen Merkle root of a sealed manifest; manifest "
                       f"{manifest_id} is '{row['status']}'",
            "status": row["status"]})
    if get_disclosure_proof_by_id(conn, payload.proof_id) is not None:
        raise HTTPException(409, detail={
            "code": "DISCLOSURE_PROOF_DUPLICATE",
            "message": f"disclosure proof {payload.proof_id} already exists; "
                       "proof records are append-only and a re-request must "
                       "use a new proof_id",
            "proof_id": payload.proof_id})
    sealed_payload = payload_from_row(row)
    sealed_report = report_from_json(row["seal_report_json"])
    if sealed_report is None:
        raise HTTPException(500, detail={
            "code": "DISCLOSURE_SEALED_REPORT_MISSING",
            "message": "sealed manifest has no stored seal report"})
    package = build_evidence_package(row, sealed_report)
    if package["evidence_package_digest"] != payload.evidence_package_digest:
        raise HTTPException(422, detail={
            "code": "DISCLOSURE_EVIDENCE_PACKAGE_MISMATCH",
            "message": "the cited evidence_package_digest does not match the "
                       "digest of the sealed evidence package; a proof can "
                       "only be anchored to the package frozen at sealing time",
            "submitted_digest": payload.evidence_package_digest,
            "sealed_digest": package["evidence_package_digest"]})
    try:
        proof = build_disclosure_proof(
            request=payload, manifest_row=row,
            sealed_payload=sealed_payload,
            ordered_chunk_ids=sealed_report.ordered_chunk_ids,
            frozen_root=sealed_report.merkle_root,
            evidence_package_digest=payload.evidence_package_digest,
            created_at=utcnow_iso())
    except DisclosureError as exc:
        raise HTTPException(exc.status_code, detail=exc.detail)
    insert_disclosure_proof(conn, proof, payload)
    return proof


@app.get("/manifests/{manifest_id}/disclosure-proofs",
         response_model=list[DisclosureProofSummary])
def list_manifest_disclosure_proofs(manifest_id: str,
                                    conn: sqlite3.Connection = Depends(get_db)):
    if get_manifest(conn, manifest_id) is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    return [_disclosure_summary_row(r)
            for r in list_disclosure_proofs(conn, manifest_id)]


@app.get("/manifests/{manifest_id}/disclosure-proofs/{proof_id}",
         response_model=DisclosureProof)
def read_disclosure_proof(manifest_id: str, proof_id: str,
                          conn: sqlite3.Connection = Depends(get_db)):
    row = get_disclosure_proof_by_id(conn, proof_id)
    if row is None or row["manifest_id"] != manifest_id:
        raise HTTPException(404, f"disclosure proof {proof_id} not found for "
                                 f"manifest {manifest_id}")
    return DisclosureProof.model_validate(json.loads(row["proof_json"]))


@app.post("/disclosure/verify", response_model=DisclosureVerifyResult)
def verify_disclosure_proof(payload: DisclosureVerifyRequest):
    """Recompute one leaf inclusion proof purely from the leaf digest, the
    proof path and the caller-supplied frozen Merkle root.

    No manifest, evidence package, database or chunk bytes are consulted;
    mismatched root, a path that never closes to a single node, a wrong
    sibling side for the leaf position or a wrong promotion step all return
    ``valid=false`` with an explicit error code.
    """
    return evaluate_verification(payload)


# --------------------- post-seal custody transfer continuation (append-only)
def _stored_transfer_proposal(row: sqlite3.Row) -> CustodyTransferProposal:
    return CustodyTransferProposal.model_validate(json.loads(row["record_json"]))


def _stored_transfer_receipt(row: sqlite3.Row) -> CustodyTransferReceiptReport:
    return CustodyTransferReceiptReport.model_validate(
        json.loads(row["report_json"]))


def _transfer_chain_state(conn: sqlite3.Connection, manifest_id: str):
    """Sealed context plus the live post-seal custody chain state.

    The genesis heads are derived from the sealed manifest's frozen custody
    events; the effective receipt records (append-only, in insertion order)
    extend them. Returns everything the transfer endpoints need: the sealed
    context, the per-replica chains and the stored receipt reports.
    """
    row, sealed_payload, sealed_report, package_digest_ = _sealed_context(
        conn, manifest_id, code="TRANSFER_REQUIRES_SEALED")
    genesis = genesis_heads(
        sealed_payload, manifest_id=manifest_id,
        evidence_package_digest=package_digest_,
        image_sha256=sealed_report.reconstructed_sha256,
        created_at=row["sealed_at"])
    receipts = [_stored_transfer_receipt(r)
                for r in list_transfer_receipts(conn, manifest_id)]
    chains = build_chains(genesis, receipts)
    return row, sealed_payload, sealed_report, package_digest_, receipts, chains


def _transfer_summary(proposal: CustodyTransferProposal,
                      receipts: list[CustodyTransferReceiptReport]
                      ) -> CustodyTransferSummary:
    new_head_id = next((r.new_head.head_id for r in receipts
                        if r.effective and r.new_head is not None), None)
    return CustodyTransferSummary(
        proposal_id=proposal.proposal_id, replica_id=proposal.replica_id,
        from_party=proposal.from_party, to_party=proposal.to_party,
        location=proposal.location, window_start=proposal.window_start,
        window_end=proposal.window_end, status=transfer_status(receipts),
        receipt_count=len(receipts), new_head_id=new_head_id,
        created_at=proposal.created_at)


@app.post("/manifests/{manifest_id}/custody-transfers",
          response_model=CustodyTransferProposal, status_code=201)
def create_transfer_proposal(manifest_id: str,
                             payload: CustodyTransferProposalCreate,
                             conn: sqlite3.Connection = Depends(get_db)):
    """Open a post-seal custody transfer proposal (append-only).

    The proposal cites the sealed manifest, the exact
    ``evidence_package_digest``, the replica and the CURRENT custody chain
    head it extends, and freezes the handing-over party, the receiving
    party, the location and the validity window. The receiver answers with a
    receipt via ``POST .../custody-transfers/{proposal_id}/receipts``. A
    proposal anchored to a head that another effective transfer already
    consumed is refused (the chain never forks); an existing proposal_id is
    never rewritten (409).
    """
    row, sealed_payload, sealed_report, package_digest_, receipts, chains = \
        _transfer_chain_state(conn, manifest_id)
    if get_transfer_proposal_by_id(conn, payload.proposal_id) is not None:
        raise HTTPException(409, detail={
            "code": "TRANSFER_PROPOSAL_DUPLICATE",
            "message": f"transfer proposal {payload.proposal_id} already "
                       "exists; proposals are append-only and a changed "
                       "offer must use a new proposal_id",
            "proposal_id": payload.proposal_id})
    if payload.evidence_package_digest != package_digest_:
        raise HTTPException(422, detail={
            "code": "TRANSFER_EVIDENCE_PACKAGE_MISMATCH",
            "message": "the cited evidence_package_digest does not match the "
                       "digest of the sealed evidence package; a transfer "
                       "can only continue the chain of the sealed image",
            "submitted_digest": payload.evidence_package_digest,
            "sealed_digest": package_digest_})
    if payload.replica_id not in chains:
        raise HTTPException(422, detail={
            "code": "TRANSFER_REPLICA_UNKNOWN",
            "message": f"replica {payload.replica_id} is not registered in "
                       "the sealed manifest; only sealed replicas carry a "
                       "custody chain that can be continued",
            "replica_id": payload.replica_id})
    heads = chains[payload.replica_id]
    known_head_ids = {h.head_id for h in heads}
    if payload.predecessor_head_id not in known_head_ids:
        raise HTTPException(422, detail={
            "code": "TRANSFER_HEAD_UNKNOWN",
            "message": f"chain head {payload.predecessor_head_id} is not on "
                       f"the custody chain of replica {payload.replica_id}; "
                       "query GET /manifests/{id}/custody-chain for the "
                       "live head",
            "replica_id": payload.replica_id,
            "predecessor_head_id": payload.predecessor_head_id})
    tip = heads[-1]
    if payload.predecessor_head_id != tip.head_id:
        raise HTTPException(409, detail={
            "code": "TRANSFER_HEAD_OCCUPIED",
            "message": f"chain head {payload.predecessor_head_id} of replica "
                       f"{payload.replica_id} was already consumed by an "
                       f"effective transfer; the live head is {tip.head_id} "
                       "and the custody chain does not fork",
            "replica_id": payload.replica_id,
            "predecessor_head_id": payload.predecessor_head_id,
            "live_head_id": tip.head_id})
    record = CustodyTransferProposal(
        proposal_id=payload.proposal_id, manifest_id=manifest_id,
        media_id=row["media_id"], replica_id=payload.replica_id,
        evidence_package_digest=payload.evidence_package_digest,
        predecessor_head_id=tip.head_id,
        predecessor_head_digest=tip.head_digest,
        from_party=payload.from_party, to_party=payload.to_party,
        location=payload.location, window_start=payload.window_start,
        window_end=payload.window_end, note=payload.note,
        created_at=utcnow_iso())
    record.proposal_digest = proposal_digest(record)
    insert_transfer_proposal(conn, record)
    return record


@app.get("/manifests/{manifest_id}/custody-transfers",
         response_model=list[CustodyTransferSummary])
def list_manifest_transfer_proposals(
        manifest_id: str, conn: sqlite3.Connection = Depends(get_db)):
    """List every transfer proposal of the manifest with its rolled-up
    receipt status (pending / completed / rejected)."""
    if get_manifest(conn, manifest_id) is None:
        raise HTTPException(404, f"manifest {manifest_id} not found")
    out: list[CustodyTransferSummary] = []
    for prow in list_transfer_proposals(conn, manifest_id):
        proposal = _stored_transfer_proposal(prow)
        receipts = [_stored_transfer_receipt(r)
                    for r in list_transfer_receipts_for_proposal(
                        conn, proposal.proposal_id)]
        out.append(_transfer_summary(proposal, receipts))
    return out


@app.get("/manifests/{manifest_id}/custody-transfers/{proposal_id}",
         response_model=CustodyTransferPackage)
def read_transfer_proposal(manifest_id: str, proposal_id: str,
                           conn: sqlite3.Connection = Depends(get_db)):
    """The full JSON transfer package: the frozen proposal, every receipt
    attempt with its rejection basis, the resolved inspection references and
    the minted chain head of an effective transfer, self-digested so any
    party can recompute it."""
    prow = get_transfer_proposal(conn, manifest_id, proposal_id)
    if prow is None:
        raise HTTPException(404, f"transfer proposal {proposal_id} not found "
                                 f"for manifest {manifest_id}")
    proposal = _stored_transfer_proposal(prow)
    receipts = [_stored_transfer_receipt(r)
                for r in list_transfer_receipts_for_proposal(conn, proposal_id)]
    return build_transfer_package(proposal, media_id=prow["media_id"],
                                  receipts=receipts)


@app.post("/manifests/{manifest_id}/custody-transfers/{proposal_id}/receipts",
          response_model=CustodyTransferReceiptReport, status_code=201)
def create_transfer_receipt(manifest_id: str, proposal_id: str,
                            payload: CustodyTransferReceiptCreate,
                            conn: sqlite3.Connection = Depends(get_db)):
    """Submit the receiver's receipt for a transfer proposal (append-only).

    The receipt binds the inspection records of the transferred replica
    completed inside the proposal's validity window. The service checks both
    party identities against the proposal, the uniqueness of the predecessor
    head (a parallel transfer that consumed the head first wins), the
    attribution and conclusion of every bound inspection, digest continuity
    and time ordering. An effective receipt mints the next chain head with a
    hash link to its predecessor. An expired window, a duplicate receipt, an
    occupied head, a failed/inconclusive inspection or a package digest
    mismatch leave the transfer without effect — the attempt is appended to
    the record all the same, with the rejection basis in its findings.
    """
    row, sealed_payload, sealed_report, package_digest_, receipts, chains = \
        _transfer_chain_state(conn, manifest_id)
    prow = get_transfer_proposal(conn, manifest_id, proposal_id)
    if prow is None:
        raise HTTPException(404, detail={
            "code": "TRANSFER_PROPOSAL_UNKNOWN",
            "message": f"transfer proposal {proposal_id} not found for "
                       f"manifest {manifest_id}; open the proposal first",
            "proposal_id": proposal_id})
    proposal = _stored_transfer_proposal(prow)
    inspections = {r.inspection_id: r for r in
                   (_stored_inspection_report(i)
                    for i in list_inspections(conn, manifest_id))}
    report = evaluate_receipt(
        payload, proposal=proposal, media_id=row["media_id"],
        current_tip=chains[proposal.replica_id][-1],
        sealed_package_digest=package_digest_,
        image_sha256=sealed_report.reconstructed_sha256,
        inspections=inspections,
        receipt_id_seen=transfer_receipt_id_exists(conn, payload.receipt_id),
        proposal_fulfilled=any(r.effective and r.proposal_id == proposal_id
                               for r in receipts),
        created_at=utcnow_iso())
    insert_transfer_receipt(conn, report)
    return report


@app.get("/manifests/{manifest_id}/custody-chain",
         response_model=CustodyChainReport)
def read_custody_chain(manifest_id: str,
                       conn: sqlite3.Connection = Depends(get_db)):
    """Current post-seal custody chain state of a sealed manifest.

    Per replica: the genesis head derived from the sealed custody events,
    every head minted by an effective transfer in hash-linked order, and the
    live tip a new transfer proposal must cite. The sealed manifest's own
    custody_events keep being read by the original logic; this chain only
    continues them.
    """
    row, sealed_payload, sealed_report, package_digest_, receipts, chains = \
        _transfer_chain_state(conn, manifest_id)
    genesis = {rid: heads[0] for rid, heads in chains.items()}
    return CustodyChainReport(
        manifest_id=manifest_id, media_id=row["media_id"],
        evidence_package_digest=package_digest_,
        image_sha256=sealed_report.reconstructed_sha256,
        merkle_root=sealed_report.merkle_root,
        replicas=chain_views(genesis, receipts))


@app.get("/media/{media_id}", response_model=MediaRecord)
def read_media(media_id: str, conn: sqlite3.Connection = Depends(get_db)):
    row = get_media(conn, media_id)
    if row is None:
        raise HTTPException(404, f"media {media_id} not found")
    return MediaRecord(
        media_id=row["media_id"], evidence_label=row["evidence_label"],
        sector_size=row["sector_size"], total_sectors=row["total_sectors"],
        capacity_bytes=row["capacity_bytes"], media_sn=row["media_sn"],
        first_manifest_id=row["first_manifest_id"],
        first_registered_at=row["first_registered_at"])


@app.get("/diffs", response_model=DiffReport)
def compare_revisions(left: str = Query(..., description="manifest id (base)"),
                      right: str = Query(..., description="manifest id (revision)"),
                      conn: sqlite3.Connection = Depends(get_db)):
    left_row, right_row = get_manifest(conn, left), get_manifest(conn, right)
    if left_row is None:
        raise HTTPException(404, f"manifest {left} not found")
    if right_row is None:
        raise HTTPException(404, f"manifest {right} not found")
    if left_row["media_id"] != right_row["media_id"]:
        raise HTTPException(422, "manifests belong to different media")
    left_report = (report_from_json(left_row["seal_report_json"]
                                    or left_row["precheck_json"])
                   or _evaluate_with_lineage(conn, payload_from_row(left_row)))
    right_report = (report_from_json(right_row["seal_report_json"]
                                     or right_row["precheck_json"])
                    or _evaluate_with_lineage(conn, payload_from_row(right_row)))
    return diff_manifests(left_row, right_row, left_report, right_report)


@app.post("/evidence/recompute")
def recompute_evidence(body: dict[str, Any]):
    """Recompute every digest inside an evidence package from its raw fields.

    Hard gate (valid=false unless all pass): payload digest, per-chunk content
    digest/length (inline content_b64 re-decoded, otherwise the registered
    stored_path is re-read under the configured evidence roots), Merkle root,
    full-coverage without overlap, linear whole-image hash against the scene
    total hash when present, and the replica/custody minimum chain.
    """
    declared_digest = body.get("evidence_package_digest")
    package_digest_ok = None
    if declared_digest:
        package_digest_ok = package_digest(body) == declared_digest

    pkg = body.get("package") or {}
    submission = body.get("submission") or {}
    computed = body.get("computed") if isinstance(body.get("computed"), dict) else {}
    payload_digest_recomputed = digest_canonical(submission)
    payload_digest_ok = payload_digest_recomputed == pkg.get("payload_digest")

    # Validate the raw submission against the same Pydantic contract; a malformed
    # package can never be valid.
    schema_ok = True
    schema_errors: list[Any] = []
    try:
        payload = ManifestCreate.model_validate(submission)
    except Exception as exc:  # ValidationError / ValueError
        schema_ok = False
        schema_errors = [str(exc)]
        payload = None

    media = submission.get("media") or {}
    geom = media.get("geometry") or {}
    sector_size = int(geom.get("sector_size") or 0) or 1
    total_sectors = int(geom.get("total_sectors") or 0)

    chunks = submission.get("chunks") or []
    chunks_by_id = {c.get("chunk_id"): c for c in chunks
                    if c.get("chunk_id") is not None}

    # Follow the reconstructed order stored in the package: corrections may have
    # superseded raw chunks that are still present in the submission.
    ordered_ids = (computed.get("ordered_chunk_ids") or [])
    ordered = [chunks_by_id[cid] for cid in ordered_ids if cid in chunks_by_id]
    if not ordered:
        ordered = sorted(chunks, key=lambda c: (int(c.get("offset", 0)),
                                                c.get("chunk_id", "")))

    intervals = sorted(
        ((int(c["offset"]) // sector_size,
          (int(c["offset"]) + int(c["length"])) // sector_size) for c in ordered))
    merged: list[list[int]] = []
    overlap_detected = False
    for s0, s1 in intervals:
        if merged and s0 < merged[-1][1]:
            overlap_detected = True
            merged[-1][1] = max(merged[-1][1], s1)
        else:
            merged.append([s0, s1])
    coverage_ok = (not overlap_detected and bool(merged)
                   and merged[0][0] == 0 and merged[-1][1] == total_sectors)

    merkle_recomputed = merkle_root([c["sha256"] for c in ordered])
    merkle_ok = bool(ordered) and merkle_recomputed == computed.get("merkle_root")

    # ---- hard per-chunk verification against actual bytes -----------------
    # Effective chunks are streamed once into both leaf and image hashers;
    # every *other registered* chunk (e.g. an old chunk superseded via
    # correction_of) is also hard-verified, but excluded from the image hash.
    chunk_checks: list[dict[str, Any]] = []
    chunk_content_ok = bool(ordered)
    linear = None
    total_hash_ok = None
    if payload is not None and ordered:
        by_id = {c.chunk_id: c for c in payload.chunks}
        effective_models = [by_id[cid] for cid in ordered_ids if cid in by_id]
        effective_id_set = {m.chunk_id for m in effective_models}
        effective_verified = 0
        all_verified = True
        image_hasher = hashlib.sha256()

        def _verify(model, feeds_image: bool) -> None:
            nonlocal effective_verified, all_verified
            result = (_content_resolver.inspect(model, image_hasher)
                      if feeds_image else _content_resolver.inspect(model))
            length_ok = result.readable and result.length == model.length
            digest_ok = result.readable and result.sha256 == model.sha256
            row_ok = length_ok and digest_ok
            if row_ok and feeds_image:
                effective_verified += 1
            if not row_ok:
                all_verified = False
            chunk_checks.append({
                "chunk_id": model.chunk_id, "source": result.source,
                "readable": result.readable,
                "stored_path": result.registered_path,
                "effective": feeds_image,
                "length_ok": length_ok,
                "digest_ok": digest_ok,
                "actual_sha256": result.sha256,
                "error_code": result.error_code,
            })

        for model in effective_models:
            _verify(model, True)
        for model in payload.chunks:
            if model.chunk_id not in effective_id_set:
                _verify(model, False)

        chunk_content_ok = all_verified and bool(payload.chunks)
        if effective_verified == len(effective_models) and effective_models:
            linear = image_hasher.hexdigest()
            expected = submission.get("expected_total_sha256")
            if expected:
                total_hash_ok = linear == expected
        else:
            chunk_content_ok = False

    # ---- bad-sector retry / fill provenance from the same raw records -----
    # The attempt log, exception decisions and recovery rate stored in the
    # package must be exactly what the raw submission recomputes to, and every
    # fill declaration / successful-read digest must re-verify against bytes.
    recovery_ok: Optional[bool] = None
    recovery_detail: dict[str, Any] = {}
    recovery_findings: list[dict[str, Any]] = []
    recorded_recovery = computed.get("recovery") if isinstance(
        computed.get("recovery"), dict) else None
    if payload is not None:
        def _norm(d):
            return json.loads(canonical_json(d)) if d is not None else None

        eff_for_recovery: list[Any] = []
        if ordered_ids:
            by_id_rc = {c.chunk_id: c for c in payload.chunks}
            eff_for_recovery = [by_id_rc[cid] for cid in ordered_ids
                                if cid in by_id_rc]
        else:
            eff_for_recovery = sorted(payload.chunks,
                                      key=lambda c: (c.offset, c.chunk_id))
        content_rows_map = {
            chk["chunk_id"]: type("_R", (), {
                "sha256": chk.get("actual_sha256"),
                "digest_verified": chk.get("digest_ok")})()
            for chk in chunk_checks}

        def _recovery_collect(severity, code, message, **kw):
            recovery_findings.append({"severity": severity, "code": code,
                                      "message": message, **kw})

        recovery_state = analyze_recovery(
            payload, eff_for_recovery, _content_resolver,
            content_rows=content_rows_map, emit=_recovery_collect)
        recomputed_recovery = recovery_state.model_dump(mode="json")

        error_codes = {f["code"] for f in recovery_findings
                       if f["severity"] == "error"}

        def _segment_ok(s) -> bool:
            if s.kind == "unrecovered":
                return s.exception_id is not None
            return s.kind in ("read", "fill") and s.content_ok

        recomputation_clean = (not error_codes
                               and recovery_state.freeze_ok
                               and all(_segment_ok(s)
                                       for s in recovery_state.segments))
        recovery_detail = {
            "provenance_mode": recovery_state.provenance_mode,
            "recovery_rate": recovery_state.recovery_rate,
            "fill_rate": recovery_state.fill_rate,
            "read_sectors": recovery_state.read_sectors,
            "filled_sectors": recovery_state.filled_sectors,
            "unattested_sectors": recovery_state.unattested_sectors,
            "unrecovered_sectors": recovery_state.unrecovered_sectors,
            "accepted_sectors": recovery_state.accepted_sectors,
            "recovered_sectors": recovery_state.recovered_sectors,
            "freeze_ok": recovery_state.freeze_ok,
            "error_codes": sorted(error_codes),
        }
        # Precheck, diffs, evidence package and recompute use the exact same
        # attempt records, exception decisions and recovery rate: the stored
        # recovery block must equal the recomputed state field-for-field.
        if recorded_recovery is not None:
            recovery_ok = (_norm(recorded_recovery)
                           == _norm(recomputed_recovery)
                           and recomputation_clean)
        else:
            # package produced before attempts existed: clean legacy analysis
            recovery_ok = (recovery_state.provenance_mode
                           == "legacy-content-only" and recomputation_clean)

    # ---- replica/custody minimum chain over recorded digests --------------
    chain_ok = False
    chain_detail: dict[str, Any] = {}
    if payload is not None:
        session_ids = {s.session_id for s in payload.sessions}
        state = analyze_replica_custody(
            payload.replicas, payload.custody_events, session_ids,
            image_digest=linear,
            expected_total_sha256=payload.expected_total_sha256 or None,
            merkle_root=merkle_recomputed if merkle_ok else None)
        chain_ok = state.proven
        chain_detail = {"replica_ok": state.replica_ok,
                        "custody_ok": state.custody_ok,
                        "proven": state.proven,
                        "provenance_path": state.chain_path,
                        "terminal_replica_ids": state.terminal_replica_ids}

        # recorded whole-image hash inside the package must match recomputation
        recorded_linear = computed.get("reconstructed_sha256")
        if recorded_linear is not None and linear is not None:
            if recorded_linear != linear:
                chunk_content_ok = False

    recorded_chain_proven = computed.get("replica_chain_proven")
    recorded_chain_ok = (recorded_chain_proven is True) if \
        "replica_chain_proven" in computed else True

    checks = {
        "schema_ok": schema_ok,
        "payload_digest_ok": payload_digest_ok,
        "chunk_content_ok": chunk_content_ok,
        "merkle_root_ok": merkle_ok,
        "coverage_ok": coverage_ok,
        "overlap_detected": overlap_detected,
        "total_hash_ok": total_hash_ok,
        "recovery_provenance_ok": recovery_ok,
        "replica_custody_chain_ok": chain_ok and recorded_chain_ok,
        "evidence_package_digest_ok": package_digest_ok,
    }
    # overlap_detected is an informational negative indicator, not a pass flag.
    pass_flags = {k: v for k, v in checks.items()
                  if k != "overlap_detected" and v is not None}
    valid = all(pass_flags.values())
    return {
        "format": pkg.get("format"),
        "manifest_id": pkg.get("manifest_id"),
        "valid": valid,
        "checks": checks,
        "chain": chain_detail,
        "recovery": recovery_detail,
        "recovery_findings": recovery_findings,
        "schema_errors": schema_errors,
        "chunk_checks": [{k: v for k, v in c.items()
                          if k != "actual_sha256"} for c in chunk_checks],
        "recomputed": {
            "payload_digest": payload_digest_recomputed,
            "merkle_root": merkle_recomputed,
            "reconstructed_sha256": linear,
            "covered_intervals": [{"start_sector": a, "end_sector": b}
                                  for a, b in merged],
            "evidence_package_digest": package_digest(body),
        },
    }


@app.get("/health")
def health():
    return {"status": "ok"}
