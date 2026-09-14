"""Pydantic models: submission payloads, findings and verification reports."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HEX64 = r"^[0-9a-f]{64}$"
HEX64_OR_EMPTY = r"^(?:[0-9a-f]{64})?$"
HEX64_OR_BLANK = r"^(?:[0-9a-f]{64})?$"


class ForensicModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Byte offsets/lengths are always on-disk byte positions; the verifier
    # translates them to sectors using the declared sector size.
    @field_validator("*", mode="before")
    @classmethod
    def _empty_string_to_none(cls, value: Any, info: Any) -> Any:
        return None if value == "" else value


# ---------------------------------------------------------------- inputs ----
class SectorGeometry(ForensicModel):
    sector_size: int = Field(ge=1, description="Bytes per sector, e.g. 512")
    total_sectors: int = Field(ge=0, description="Sector count of the source medium")
    capacity_bytes: int = Field(ge=0, description="Declared raw capacity in bytes")
    media_sn: Optional[str] = Field(None, description="Source medium serial number")
    model: Optional[str] = Field(None, description="Source medium model/part number")
    firmware: Optional[str] = Field(None)


class MediaIdentity(ForensicModel):
    media_id: str = Field(min_length=1, description="Case-unique source medium identifier")
    evidence_label: Optional[str] = None
    interface: Optional[str] = Field(None, description="e.g. SATA / USB / NVMe")
    geometry: SectorGeometry


class WriteBlockerCheck(ForensicModel):
    blocker_id: str = Field(min_length=1)
    blocker_model: Optional[str] = None
    firmware: Optional[str] = None
    mode: Literal["read-only", "write-blocked", "unknown"] = "read-only"
    checked_by: str = Field(min_length=1)
    checked_at: datetime
    passed: bool
    self_test_digest: Optional[str] = Field(None, pattern=HEX64_OR_EMPTY,
                                            description="Optional firmware/self-test SHA-256")
    expected_self_test_digest: Optional[str] = Field(None, pattern=HEX64_OR_EMPTY)
    note: Optional[str] = None


class AcquisitionSession(ForensicModel):
    session_id: str = Field(min_length=1)
    started_at: datetime
    ended_at: Optional[datetime] = None
    operator: str = Field(min_length=1)
    tool: Optional[str] = Field(None, description="Imaging tool and version")
    interruption: Literal["none", "power-loss", "target-swap", "error-correction",
                         "manual-pause"] = "none"
    note: Optional[str] = None


# --------------------------------------------------------- read attempts ----
# Read attempts are submitted in acquisition order per session. A tool that
# reads a range partially MUST split it into separate attempts for the sectors
# it actually got and for the sectors it failed on; an attempt that claims a
# range wider than its actual_read_length is rejected. Fill/sparse-hole
# declarations are first-class provenance, never silently counted as reads.
ReadResult = Literal["read", "error", "fill"]
FillMethod = Literal["zero-pad", "pattern-pad", "sparse-hole"]


class ReadAttemptInput(ForensicModel):
    attempt_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    chunk_id: str = Field(min_length=1,
                          description="Final chunk this attempt is bound to")
    start_sector: int = Field(ge=0, description="Source medium sector (inclusive)")
    end_sector: int = Field(ge=0, description="Source medium sector (exclusive)")
    round: int = Field(ge=1, description="Retry round; non-decreasing per session")
    result: ReadResult
    tool_error_code: Optional[str] = Field(
        None, min_length=1,
        description="Tool-reported error (e.g. ECC/UNC/medium-error); required "
                    "for result=error")
    # Bytes actually transferred from the source. Must equal the sector span
    # * sector_size for result=read and must be 0 for result=error/fill.
    actual_read_length: int = Field(ge=0)
    fill_method: Optional[FillMethod] = None
    fill_value: Optional[int] = Field(None, ge=0, le=255)
    sparse_hole: bool = False
    sha256: Optional[str] = Field(
        None, pattern=HEX64_OR_EMPTY,
        description="Optional tool-reported digest of the successfully read bytes")
    note: Optional[str] = None

    @model_validator(mode="after")
    def _check_shape(self) -> "ReadAttemptInput":
        if self.end_sector <= self.start_sector:
            raise ValueError("end_sector must be greater than start_sector")
        if self.result == "read":
            if self.fill_method is not None or self.fill_value is not None \
                    or self.sparse_hole:
                raise ValueError("a successful read must not carry fill "
                                 "declarations")
            if self.tool_error_code:
                raise ValueError("a successful read must not carry a tool error "
                                 "code")
        elif self.result == "error":
            if not self.tool_error_code:
                raise ValueError("result=error requires tool_error_code")
            if self.fill_method is not None or self.fill_value is not None \
                    or self.sparse_hole:
                raise ValueError("a failed attempt must not carry fill "
                                 "declarations; declare the zero-fill/sparse "
                                 "hole as a separate fill attempt")
        elif self.result == "fill":
            if not self.fill_method:
                raise ValueError("result=fill requires fill_method")
            if self.fill_method == "zero-pad" and self.fill_value not in (None, 0):
                raise ValueError("zero-pad fill requires fill_value 0/omitted")
            if self.fill_method in ("pattern-pad",) and self.fill_value is None:
                raise ValueError("pattern-pad fill requires an explicit "
                                 "fill_value")
            if self.fill_method == "sparse-hole":
                if self.fill_value is not None:
                    raise ValueError("a sparse hole declares no byte value")
                self.sparse_hole = True
            if self.tool_error_code:
                raise ValueError("a fill declaration must not carry a tool "
                                 "error code")
        return self


class RecoveryExceptionInput(ForensicModel):
    """Manual acceptance of sectors that could not be recovered."""

    exception_id: str = Field(min_length=1)
    start_sector: int = Field(ge=0)
    end_sector: int = Field(ge=0)
    reason: str = Field(min_length=1,
                        description="Documented reason for accepting the gap")
    accepted_by: str = Field(min_length=1)
    accepted_at: datetime
    note: Optional[str] = None

    @model_validator(mode="after")
    def _check_shape(self) -> "RecoveryExceptionInput":
        if self.end_sector <= self.start_sector:
            raise ValueError("end_sector must be greater than start_sector")
        return self


class FreezePolicyInput(ForensicModel):
    """Frozen tolerance for unrecovered source sectors at sealing time."""

    max_unrecovered_sectors: Optional[int] = Field(
        None, ge=0,
        description="Absolute cap on unrecovered-but-unaccepted sectors")
    max_unrecovered_ratio: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Ratio cap on unrecovered-but-unaccepted sectors")

    @model_validator(mode="after")
    def _check_present(self) -> "FreezePolicyInput":
        if (self.max_unrecovered_sectors is None
                and self.max_unrecovered_ratio is None):
            raise ValueError("freeze policy must set an absolute or ratio "
                             "threshold")
        return self


class ChunkInput(ForensicModel):
    chunk_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    index: int = Field(ge=0, description="Chunk position declared by the acquisition tool")
    offset: int = Field(ge=0, description="Byte offset from the start of the medium")
    length: int = Field(ge=0, description="Chunk length in bytes (0 is rejected)")
    sha256: str = Field(pattern=HEX64)
    # Optional inline content; when present the server recomputes sha256 and the
    # end-to-end linear hash. Absent for real multi-GB acquisitions.
    content_b64: Optional[str] = None
    # Error correction: this chunk replaces an earlier chunk covering same range.
    correction_of: Optional[str] = None
    stored_path: Optional[str] = None
    file_size: Optional[int] = Field(None, ge=0)
    note: Optional[str] = None


class ReplicaInput(ForensicModel):
    replica_id: str = Field(min_length=1)
    role: Literal["acquired", "copy", "archive"]
    session_id: Optional[str] = Field(
        None, description="Required for role=acquired: producing acquisition session")
    parent_replica_id: Optional[str] = Field(
        None, description="Required for role=copy/archive: source replica")
    sha256: str = Field(pattern=HEX64, description="Whole-image digest of this replica")
    merkle_root: Optional[str] = Field(None, pattern=HEX64_OR_EMPTY)
    storage_location: Optional[str] = None
    custodian: Optional[str] = None
    created_at: datetime


class CustodyEvent(ForensicModel):
    event_id: str = Field(min_length=1)
    event_type: Literal["acquired", "copied", "verified", "sealed", "transferred"]
    replica_id: str
    at: datetime
    actor: str = Field(min_length=1)
    organization: Optional[str] = None
    digest_before: Optional[str] = Field(None, pattern=HEX64_OR_BLANK)
    digest_after: Optional[str] = Field(None, pattern=HEX64_OR_BLANK)
    expected_digest: Optional[str] = Field(None, pattern=HEX64_OR_BLANK)
    counterpart: Optional[str] = Field(None, description="Receiving party / destination")
    note: Optional[str] = None


class ManifestCreate(ForensicModel):
    change_kind: Literal["initial", "resume", "target-swap", "correction"] = "initial"
    parent_manifest_id: Optional[str] = None
    media: MediaIdentity
    write_blocker: Optional[WriteBlockerCheck] = None
    sessions: list[AcquisitionSession] = Field(default_factory=list)
    chunks: list[ChunkInput] = Field(default_factory=list)
    read_attempts: list[ReadAttemptInput] = Field(
        default_factory=list,
        description="Per-session, in-order read attempts (retries, errors and "
                    "fills) bound to final chunks")
    recovery_exceptions: list[RecoveryExceptionInput] = Field(
        default_factory=list,
        description="Manually accepted unrecovered ranges (derived revisions "
                    "only; each must carry a reason)")
    freeze_policy: Optional[FreezePolicyInput] = Field(
        None,
        description="Frozen tolerance for unrecovered sectors; defaults to "
                    "zero tolerance (every sector must be read or accepted)")
    replicas: list[ReplicaInput] = Field(default_factory=list)
    custody_events: list[CustodyEvent] = Field(default_factory=list)
    expected_total_sha256: Optional[str] = Field(
        None, pattern=HEX64_OR_EMPTY,
        description="Single total hash left at the scene; verified when content is inline")


# --------------------------------------------------------------- findings ----
class Severity(str, Enum):
    error = "error"
    warning = "warning"


class Finding(ForensicModel):
    code: str
    severity: Severity
    message: str
    media_id: Optional[str] = None
    chunk_ids: list[str] = Field(default_factory=list)
    session_id: Optional[str] = None
    replica_ids: list[str] = Field(default_factory=list)
    event_id: Optional[str] = None
    start_sector: Optional[int] = None
    end_sector: Optional[int] = None
    detail: Optional[dict[str, Any]] = None


class SectorInterval(ForensicModel):
    start_sector: int
    end_sector: int  # exclusive


class ChunkContentVerification(ForensicModel):
    chunk_id: str
    source: Literal["inline", "file", "none"]
    readable: bool
    stored_path: Optional[str] = None
    length: Optional[int] = None
    sha256: Optional[str] = None
    declared_sha256: Optional[str] = None
    digest_verified: bool = False


class ReadAttemptRecord(ForensicModel):
    """One submitted attempt, in submission order, with provenance context."""

    attempt_id: str
    session_id: str
    chunk_id: str
    start_sector: int
    end_sector: int
    round: int
    result: str
    tool_error_code: Optional[str] = None
    actual_read_length: int
    fill_method: Optional[str] = None
    fill_value: Optional[int] = None
    sparse_hole: bool = False
    sha256: Optional[str] = None
    note: Optional[str] = None
    # Whether the bound chunk is one of the effective chunks participating in
    # image reconstruction (as opposed to a corrected/deduplicated old chunk).
    effective: bool = True


class FinalSegment(ForensicModel):
    """One atomic source sector range in the reconstructed image."""

    start_sector: int
    end_sector: int  # exclusive
    chunk_id: str
    session_id: Optional[str] = None
    # read        -> bytes really read from the source
    # fill        -> declared zero/pattern padding or sparse hole
    # unrecovered -> never read; sealable only when covered by an accepted
    #                exception (exception_id then set)
    # unattested  -> no read-attempt record at all; a matching digest can
    #                never substitute for proof of a source-medium read
    kind: Literal["read", "fill", "unrecovered", "unattested"]
    winning_attempt_id: Optional[str] = None
    exception_id: Optional[str] = None
    fill_method: Optional[str] = None
    fill_value: Optional[int] = None
    sparse_hole: bool = False
    tool_error_code: Optional[str] = None
    attempts: list[str] = Field(default_factory=list)
    sha256: Optional[str] = None  # read: digest of the real bytes at this range
    content_ok: bool = True       # recompute-time flag (digest/fill/hole check)


class RecoveryState(ForensicModel):
    provenance_mode: Literal["attempts", "legacy-content-only"] = "legacy-content-only"
    attempts: list[ReadAttemptRecord] = Field(default_factory=list)
    segments: list[FinalSegment] = Field(default_factory=list)
    total_sectors: int = 0
    read_sectors: int = 0
    filled_sectors: int = 0
    unattested_sectors: int = 0
    unrecovered_sectors: int = 0
    accepted_sectors: int = 0
    # Actual source-read recovery: accepted exceptions document that sectors
    # are NOT source data; they never count as recovered.
    recovered_sectors: int = 0
    recovery_rate: float = 0.0           # read_sectors / total (source reads only)
    fill_rate: float = 0.0               # filled / total
    unrecovered_rate: float = 0.0        # unaccepted unrecovered / total
    freeze_policy: Optional[dict[str, Any]] = None
    freeze_ok: bool = True
    exceptions: list[dict[str, Any]] = Field(default_factory=list)


class Overlap(ForensicModel):
    start_sector: int
    end_sector: int  # exclusive
    chunk_ids: list[str] = Field(default_factory=list)
    reason: str


class EvaluationReport(ForensicModel):
    media_id: str
    findings: list[Finding] = Field(default_factory=list)
    ordered_chunk_ids: list[str] = Field(default_factory=list)
    covered_intervals: list[SectorInterval] = Field(default_factory=list)
    gaps: list[SectorInterval] = Field(default_factory=list)
    overlaps: list[Overlap] = Field(default_factory=list)
    chunk_content: list[ChunkContentVerification] = Field(default_factory=list)
    covered_sectors: int = 0
    total_sectors: int = 0
    complete_coverage: bool = False
    all_chunk_digests_verified: bool = False
    replica_chain_proven: bool = False
    terminal_replica_ids: list[str] = Field(default_factory=list)
    provenance_path: list[str] = Field(default_factory=list)
    merkle_root: Optional[str] = None
    reconstructed_sha256: Optional[str] = None
    expected_total_sha256: Optional[str] = None
    total_hash_verified: Optional[bool] = None
    recovery: RecoveryState = Field(default_factory=RecoveryState)
    sealable: bool = False

    def error(self, code: str, message: str, **kw: Any) -> None:
        self.findings.append(Finding(code=code, severity=Severity.error,
                                     message=message, media_id=self.media_id, **kw))

    def warn(self, code: str, message: str, **kw: Any) -> None:
        self.findings.append(Finding(code=code, severity=Severity.warning,
                                     message=message, media_id=self.media_id, **kw))


# --------------------------------------------------------------- API rows ----
class ManifestSummary(ForensicModel):
    manifest_id: str
    revision: int
    media_id: str
    status: str
    change_kind: str
    parent_manifest_id: Optional[str] = None
    superseded_by: Optional[str] = None
    created_at: datetime
    sealed_at: Optional[datetime] = None


class ManifestCreated(ManifestSummary):
    report: EvaluationReport


class SealResult(ForensicModel):
    manifest_id: str
    status: Literal["sealed"]
    sealed_at: datetime
    merkle_root: str
    reconstructed_sha256: Optional[str] = None
    evidence_package_digest: str
    evidence_package: Optional[dict[str, Any]] = Field(
        None,
        description="Complete reproducible evidence package; returned only "
                    "when sealing succeeds")


class SealRejected(ForensicModel):
    detail: str = "manifest is not sealable"
    manifest_id: str
    sealable: bool
    blocking_findings: list[Finding]


class MediaRecord(ForensicModel):
    media_id: str
    evidence_label: Optional[str] = None
    sector_size: int
    total_sectors: int
    capacity_bytes: int
    media_sn: Optional[str] = None
    first_manifest_id: str
    first_registered_at: datetime


# ------------------------------------------- post-seal integrity inspection ----
# After a sealed image is handed over, the copy's medium can silently rot.
# Re-hashing the whole disk on every patrol cannot localize damage when a read
# aborts, and an ad-hoc spot check cannot prove the sampled ranges were not
# cherry-picked afterwards. An inspection therefore freezes the replica, the
# random seed, the sampling ratio, the chunk boundaries, the read timestamps
# and the device identity; the service deterministically regenerates the
# sample set (first/last sector, chunk seams, random sectors) from the seed
# and compares each submitted reading against the sealed evidence package.


class InspectionDevice(ForensicModel):
    """Identity of the inspection reader/medium, frozen into the record."""

    device_id: str = Field(min_length=1,
                           description="Unique identifier of the inspection "
                                       "device / copy medium being read")
    model: Optional[str] = None
    serial: Optional[str] = None
    interface: Optional[str] = None
    firmware: Optional[str] = None


class InspectionReading(ForensicModel):
    """One sampled interval actually read off the inspected replica.

    Exactly one of ``sha256`` (digest of the bytes really read) or ``error``
    (tool-reported read failure) must be present.
    """

    start_sector: int = Field(ge=0)
    end_sector: int = Field(ge=0, description="exclusive")
    read_at: datetime = Field(description="Moment this interval was read")
    sha256: Optional[str] = Field(
        None, pattern=HEX64_OR_EMPTY,
        description="SHA-256 of the bytes actually read over the interval")
    error: Optional[str] = Field(
        None, min_length=1,
        description="Tool-reported read error (e.g. medium-error); the "
                    "interval could not be read")

    @model_validator(mode="after")
    def _check_shape(self) -> "InspectionReading":
        if self.end_sector <= self.start_sector:
            raise ValueError("end_sector must be greater than start_sector")
        if (self.sha256 is None) == (self.error is None):
            raise ValueError("a reading must carry exactly one of sha256 "
                             "(bytes read) or error (read failed)")
        return self


class InspectionCreate(ForensicModel):
    """Post-seal integrity inspection of one replica of a sealed manifest."""

    inspection_id: str = Field(min_length=1,
                               description="Unique id; records are append-only "
                                           "and an existing id is never "
                                           "overwritten by a re-test")
    replica_id: str = Field(min_length=1,
                            description="Replica (from the sealed manifest) "
                                        "whose medium was sampled")
    seed: str = Field(min_length=1,
                      description="Random seed; the service deterministically "
                                  "regenerates the sample plan from it")
    sample_ratio: float = Field(
        gt=0.0, le=1.0,
        description="Fraction of sectors to sample; head/tail and chunk-seam "
                    "sectors are always included on top")
    device: InspectionDevice
    readings: list[InspectionReading] = Field(
        default_factory=list,
        description="One reading per planned sample interval: actual digest "
                    "or read error")
    note: Optional[str] = None


class InspectionIntervalResult(ForensicModel):
    """Per planned-interval outcome of one inspection."""

    start_sector: int
    end_sector: int  # exclusive
    status: Literal["match", "digest-conflict", "read-failed", "missing",
                    "unverifiable"]
    expected_sha256: Optional[str] = None
    actual_sha256: Optional[str] = None
    read_at: Optional[datetime] = None
    error: Optional[str] = None
    chunk_ids: list[str] = Field(default_factory=list)


class DivergentInterval(ForensicModel):
    """A sampled interval whose actual bytes provably differ from the sealed
    evidence, with the first time the divergence was observed (append-only
    history: later passing re-tests never erase it)."""

    start_sector: int
    end_sector: int  # exclusive
    replica_id: str
    expected_sha256: Optional[str] = None
    actual_sha256: Optional[str] = None
    read_at: Optional[datetime] = None
    first_change_at: Optional[datetime] = None
    first_inspection_id: Optional[str] = None


class InspectionReport(ForensicModel):
    """Full JSON report of one inspection run, bound to the sealed evidence
    package it was evaluated against."""

    inspection_id: str
    manifest_id: str
    media_id: str
    replica_id: str
    result: Literal["passed", "failed", "inconclusive"]
    seed: str
    sample_ratio: float
    device: InspectionDevice
    chunk_boundaries: list[int] = Field(
        default_factory=list,
        description="Frozen internal chunk-seam sectors of the sealed image")
    planned_intervals: list[SectorInterval] = Field(default_factory=list)
    planned_sectors: int = 0
    covered_sectors: int = 0
    verified_sectors: int = 0
    total_sectors: int = 0
    sample_coverage: float = 0.0    # planned / total
    coverage_rate: float = 0.0      # genuinely read / planned (no read failure)
    verified_rate: float = 0.0      # digest-matched / planned
    intervals: list[InspectionIntervalResult] = Field(default_factory=list)
    divergent_intervals: list[DivergentInterval] = Field(default_factory=list)
    first_change_at: Optional[datetime] = None
    findings: list[Finding] = Field(default_factory=list)
    evidence_package_digest: Optional[str] = None
    image_sha256: Optional[str] = None
    merkle_root: Optional[str] = None
    created_at: datetime


class InspectionSummary(ForensicModel):
    inspection_id: str
    replica_id: str
    result: str
    seed: str
    sample_ratio: float
    device_id: str
    planned_sectors: int
    verified_sectors: int
    coverage_rate: float
    created_at: datetime


class InspectionHistoryReport(ForensicModel):
    """Append-only patrol history of one sealed manifest: cumulative coverage,
    every divergence ever observed with its first-change time, and the bound
    evidence package. Re-tests add rows; they never overwrite a failure."""

    manifest_id: str
    media_id: str
    evidence_package_digest: Optional[str] = None
    image_sha256: Optional[str] = None
    merkle_root: Optional[str] = None
    total_sectors: int = 0
    inspection_count: int = 0
    results: dict[str, int] = Field(default_factory=dict)
    latest_result: Optional[str] = None
    ever_failed: bool = False
    cumulative_coverage_rate: float = 0.0
    divergent_intervals: list[DivergentInterval] = Field(default_factory=list)
    first_change_at: Optional[datetime] = None
    inspections: list[InspectionSummary] = Field(default_factory=list)


# ------------------------------------- multi-replica joint inspection ----
# A sealed master image usually survives as several copies on different media
# (working disk, off-site disk, archive disk). Patrolling each copy with an
# independent sample plan makes the reports hard to compare: the runs cover
# different sectors, so one changed digest cannot be told apart from a common
# upstream corruption. A joint inspection task freezes the sealed manifest,
# the evidence package digest, the participating replicas, one unified seed,
# one sampling ratio and a completion window; every replica is then read
# against the SAME seed-derived plan intervals (submitted as ordinary
# per-replica inspection records) and each record is bound to the task.


class JointInspectionCreate(ForensicModel):
    """Open a multi-replica joint patrol task on a sealed manifest."""

    joint_id: str = Field(min_length=1,
                          description="Unique id; joint tasks are append-only "
                                      "and an existing id is never rewritten")
    replica_ids: list[str] = Field(
        min_length=1,
        description="Participating replicas from the sealed manifest; every "
                    "one of them must bind an inspection record")
    seed: str = Field(min_length=1,
                      description="Unified random seed; all replicas are read "
                                  "against the same seed-derived plan")
    sample_ratio: float = Field(gt=0.0, le=1.0,
                                description="Unified sampling ratio")
    window_start: datetime = Field(
        description="Start of the frozen completion window (inclusive); "
                    "readings must be taken inside the window")
    window_end: datetime = Field(
        description="End of the frozen completion window (inclusive)")
    note: Optional[str] = None

    @model_validator(mode="after")
    def _check_shape(self) -> "JointInspectionCreate":
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        if any(not rid or not rid.strip() for rid in self.replica_ids):
            raise ValueError("replica_ids must not contain empty identifiers")
        if len(set(self.replica_ids)) != len(self.replica_ids):
            raise ValueError("replica_ids must not contain duplicates")
        return self


class JointInspectionBindingCreate(ForensicModel):
    """Bind one submitted per-replica inspection record to a joint task."""

    inspection_id: str = Field(min_length=1,
                               description="Existing inspection record of this "
                                           "manifest to bind; bindings are "
                                           "append-only, a re-test binds a "
                                           "new record")


class JointBinding(ForensicModel):
    """One append-only binding between a joint task and an inspection record."""

    inspection_id: str
    replica_id: str
    bound_at: datetime


class JointReplicaCell(ForensicModel):
    """One replica's outcome for one planned interval inside a joint task."""

    replica_id: str
    inspection_id: Optional[str] = None
    status: Literal["match", "digest-conflict", "read-failed", "missing",
                    "unverifiable", "absent", "out-of-window"]
    expected_sha256: Optional[str] = None
    actual_sha256: Optional[str] = None
    read_at: Optional[datetime] = None


class JointIntervalResult(ForensicModel):
    """Cross-replica verdict for one planned interval of a joint task."""

    start_sector: int
    end_sector: int  # exclusive
    # all-match                -> every replica agrees with the sealed baseline
    # single-replica-deviation -> exactly one replica provably diverges
    # multi-replica-deviation  -> two or more replicas diverge from baseline
    # missing-read             -> a replica is absent / skipped / unread / late
    # baseline-unrecomputable  -> the frozen baseline cannot be recomputed;
    #                             replicas agreeing with each other can NOT
    #                             turn this into a pass
    status: Literal["all-match", "single-replica-deviation",
                    "multi-replica-deviation", "missing-read",
                    "baseline-unrecomputable"]
    expected_sha256: Optional[str] = None
    deviating_replica_ids: list[str] = Field(default_factory=list)
    missing_replica_ids: list[str] = Field(default_factory=list)
    # For multi-replica deviations: True when the diverging replicas returned
    # the *same* wrong digest (points at a common upstream corruption rather
    # than independent media rot).
    shared_deviation: Optional[bool] = None
    cells: list[JointReplicaCell] = Field(default_factory=list)


class JointReplicaCoverage(ForensicModel):
    """Per-replica coverage inside a joint task, bound to the original
    inspection record(s)."""

    replica_id: str
    status: Literal["complete", "partial", "absent"]
    inspection_id: Optional[str] = Field(
        None, description="Latest bound inspection record used for the "
                          "current per-interval status")
    bound_inspection_ids: list[str] = Field(
        default_factory=list,
        description="Every inspection record ever bound for this replica "
                    "(append-only; re-tests add, never rewrite)")
    result: Optional[str] = None
    planned_sectors: int = 0
    covered_sectors: int = 0
    verified_sectors: int = 0
    coverage_rate: float = 0.0
    verified_rate: float = 0.0
    cumulative_covered_sectors: int = 0
    cumulative_coverage_rate: float = 0.0


class JointInspectionReport(ForensicModel):
    """Full JSON report of a multi-replica joint inspection task, bound to
    the sealed evidence package and the original inspection records."""

    joint_id: str
    manifest_id: str
    media_id: str
    result: Literal["passed", "failed", "inconclusive"]
    seed: str
    sample_ratio: float
    replica_ids: list[str]
    window_start: datetime
    window_end: datetime
    chunk_boundaries: list[int] = Field(default_factory=list)
    planned_intervals: list[SectorInterval] = Field(default_factory=list)
    planned_sectors: int = 0
    total_sectors: int = 0
    sample_coverage: float = 0.0
    intervals: list[JointIntervalResult] = Field(default_factory=list)
    replica_coverage: list[JointReplicaCoverage] = Field(default_factory=list)
    # Append-only divergence history across ALL bindings ever made: a later
    # passing re-test never erases an earlier difference or its first-seen
    # time, and every entry names the inspection record that first saw it.
    divergent_intervals: list[DivergentInterval] = Field(default_factory=list)
    first_change_at: Optional[datetime] = None
    ever_failed: bool = False
    findings: list[Finding] = Field(default_factory=list)
    bindings: list[JointBinding] = Field(default_factory=list)
    evidence_package_digest: Optional[str] = None
    image_sha256: Optional[str] = None
    merkle_root: Optional[str] = None
    created_at: datetime


class JointInspectionSummary(ForensicModel):
    joint_id: str
    result: str
    seed: str
    sample_ratio: float
    replica_ids: list[str]
    submitted_replica_ids: list[str]
    binding_count: int
    window_start: datetime
    window_end: datetime
    created_at: datetime


# ------------------------------------------- replica interval repair ----
# A joint inspection localizes the sectors where one replica deviates from
# the sealed baseline, but the archivist still has to choose where the
# replacement bytes come from — and a co-deviating replica used as a donor
# propagates the error into every newly written copy. A repair plan freezes
# the sealed manifest, the joint inspection task, the target replica and the
# donor priority order, then allows data only from replicas whose own bound
# inspection read the SAME interval, matched the sealed baseline and whose
# inspection evidence is complete. Adjacent intervals served by the same
# donor are merged and the donors are scheduled in priority order so the
# operator swaps media as few times as possible. Plans, executions and
# failure records are append-only.


class RepairPlanCreate(ForensicModel):
    """Open a replica interval repair plan on a sealed manifest."""

    plan_id: str = Field(min_length=1,
                         description="Unique id; repair plans are append-only "
                                     "and an existing id is never rewritten")
    joint_id: str = Field(min_length=1,
                          description="Joint inspection task whose frozen "
                                      "cross-replica evidence the plan is "
                                      "derived from")
    target_replica_id: str = Field(min_length=1,
                                   description="Deviating replica to repair")
    donor_priority: list[str] = Field(
        min_length=1,
        description="Donor candidates in priority order; only a replica that "
                    "matched the sealed baseline on the same interval with "
                    "complete inspection evidence may serve")
    intervals: Optional[list[SectorInterval]] = Field(
        None,
        description="Explicit intervals to repair (each must be one of the "
                    "frozen joint plan intervals); defaults to every interval "
                    "where the target provably deviates")
    note: Optional[str] = None

    @model_validator(mode="after")
    def _check_shape(self) -> "RepairPlanCreate":
        if any(not d or not d.strip() for d in self.donor_priority):
            raise ValueError("donor_priority must not contain empty identifiers")
        if len(set(self.donor_priority)) != len(self.donor_priority):
            raise ValueError("donor_priority must not contain duplicates")
        if self.target_replica_id in self.donor_priority:
            raise ValueError("the target replica cannot be its own donor")
        for iv in self.intervals or []:
            if iv.start_sector < 0:
                raise ValueError("interval start_sector must be >= 0")
            if iv.end_sector <= iv.start_sector:
                raise ValueError("interval end_sector must be greater than "
                                 "start_sector")
        return self


class RepairDonorRejection(ForensicModel):
    """Why one donor candidate could not serve one interval."""

    replica_id: str
    inspection_id: Optional[str] = None
    reason: Literal["co-deviating", "read-missing", "baseline-unverifiable",
                    "source-chain-broken", "evidence-incomplete",
                    "lower-priority"]
    detail: Optional[str] = None


class RepairIntervalPlan(ForensicModel):
    """Per-interval repair decision frozen into the plan."""

    start_sector: int
    end_sector: int  # exclusive
    status: Literal["ready", "blocked"]
    expected_sha256: Optional[str] = Field(
        None, description="Sealed baseline digest the donor bytes must hash to")
    target_inspection_id: Optional[str] = None
    target_actual_sha256: Optional[str] = Field(
        None, description="Deviating digest observed on the target replica")
    donor_replica_id: Optional[str] = None
    donor_inspection_id: Optional[str] = None
    donor_priority_rank: Optional[int] = Field(
        None, description="1-based rank of the chosen donor in donor_priority")
    rationale: Optional[str] = Field(
        None, description="Human-readable donor selection rationale")
    rejected_donors: list[RepairDonorRejection] = Field(default_factory=list)
    gap_code: Optional[str] = Field(
        None, description="Blocking gap code when status=blocked")


class RepairSourceBinding(ForensicModel):
    """Binding from the repair package to an original inspection record."""

    replica_id: str
    role: Literal["target", "donor"]
    inspection_id: Optional[str] = None


class RepairSegment(ForensicModel):
    """Adjacent intervals served by the same donor, merged for one read pass."""

    start_sector: int
    end_sector: int  # exclusive
    donor_replica_id: str
    intervals: list[SectorInterval] = Field(default_factory=list)


class RepairMediaStep(ForensicModel):
    """One media mount in the frozen swap order (donor priority order)."""

    mount_order: int
    donor_replica_id: str
    donor_inspection_id: Optional[str] = None
    segments: list[RepairSegment] = Field(default_factory=list)
    sectors: int = 0


class RepairPlanReport(ForensicModel):
    """Full JSON repair package: binds the original inspection records and
    the donor selection rationale, and carries a self digest."""

    plan_id: str
    manifest_id: str
    media_id: str
    joint_id: str
    target_replica_id: str
    donor_priority: list[str]
    executable: bool
    repair_intervals: list[RepairIntervalPlan] = Field(default_factory=list)
    repair_sectors: int = 0
    segments: list[RepairSegment] = Field(default_factory=list)
    media_schedule: list[RepairMediaStep] = Field(default_factory=list)
    source_inspections: list[RepairSourceBinding] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence_package_digest: Optional[str] = None
    image_sha256: Optional[str] = None
    merkle_root: Optional[str] = None
    repair_package_digest: Optional[str] = None
    created_at: datetime


class RepairPlanSummary(ForensicModel):
    plan_id: str
    joint_id: str
    target_replica_id: str
    executable: bool
    interval_count: int
    repair_sectors: int
    donor_replica_ids: list[str]
    created_at: datetime


class RepairExecutionEntry(ForensicModel):
    """Per-interval execution record: what was read from the donor and what
    was written to the target, or the device error that prevented it."""

    start_sector: int = Field(ge=0)
    end_sector: int = Field(ge=0, description="exclusive")
    donor_replica_id: Optional[str] = Field(
        None, description="Self-declared donor medium; checked against the "
                          "frozen plan")
    read_sha256: Optional[str] = Field(
        None, pattern=HEX64_OR_EMPTY,
        description="SHA-256 of the bytes read from the donor")
    read_error: Optional[str] = Field(
        None, min_length=1,
        description="Tool-reported device error while reading the donor")
    write_sha256: Optional[str] = Field(
        None, pattern=HEX64_OR_EMPTY,
        description="SHA-256 of the bytes written to the target")
    write_error: Optional[str] = Field(
        None, min_length=1,
        description="Tool-reported device error while writing the target")
    read_at: Optional[datetime] = None
    written_at: Optional[datetime] = None

    @model_validator(mode="after")
    def _check_shape(self) -> "RepairExecutionEntry":
        if self.end_sector <= self.start_sector:
            raise ValueError("end_sector must be greater than start_sector")
        if (self.read_sha256 is None) == (self.read_error is None):
            raise ValueError("an entry must carry exactly one of read_sha256 "
                             "(bytes read) or read_error (read failed)")
        if self.read_sha256 is not None:
            if (self.write_sha256 is None) == (self.write_error is None):
                raise ValueError("a successful read must be followed by "
                                 "exactly one of write_sha256 / write_error")
        elif self.write_sha256 is not None:
            raise ValueError("nothing was read from the donor; no bytes can "
                             "have been written")
        return self


class DerivedReplicaInput(ForensicModel):
    """Registration block for the repaired medium (registered only when the
    execution completes and the final roots verify)."""

    replica_id: str = Field(min_length=1)
    storage_location: Optional[str] = None
    custodian: Optional[str] = None
    note: Optional[str] = None


class RepairExecutionCreate(ForensicModel):
    """Submit one repair execution against a frozen, executable plan."""

    execution_id: str = Field(min_length=1,
                              description="Unique id; execution records are "
                                          "append-only and an existing id is "
                                          "never overwritten")
    device: InspectionDevice
    entries: list[RepairExecutionEntry] = Field(
        default_factory=list,
        description="One record per planned repair interval")
    final_sha256: Optional[str] = Field(
        None, pattern=HEX64_OR_EMPTY,
        description="Recomputed whole-disk SHA-256 of the repaired target")
    final_merkle_root: Optional[str] = Field(
        None, pattern=HEX64_OR_EMPTY,
        description="Recomputed Merkle root of the repaired target")
    derived_replica: DerivedReplicaInput = Field(
        description="Replica registration requested when the execution "
                    "completes and the final roots verify")
    custody_events: list[CustodyEvent] = Field(
        default_factory=list,
        description="Handover events registered together with the derived "
                    "replica; every event must reference its replica_id")
    note: Optional[str] = None


class RepairExecutionEntryResult(ForensicModel):
    """Verified per-interval outcome of one execution."""

    start_sector: int
    end_sector: int  # exclusive
    donor_replica_id: Optional[str] = None
    expected_sha256: Optional[str] = None
    status: Literal["written", "read-failed", "read-mismatch", "write-failed",
                    "write-mismatch", "donor-mismatch", "missing",
                    "out-of-plan", "duplicate"]
    read_sha256: Optional[str] = None
    read_error: Optional[str] = None
    write_sha256: Optional[str] = None
    write_error: Optional[str] = None
    read_at: Optional[datetime] = None
    written_at: Optional[datetime] = None


class RepairDerivedReplica(ForensicModel):
    """The repaired medium, registered as a new derived replica of the sealed
    manifest together with its handover events."""

    replica_id: str
    manifest_id: str
    plan_id: str
    execution_id: str
    parent_replica_id: str
    sha256: str
    merkle_root: Optional[str] = None
    storage_location: Optional[str] = None
    custodian: Optional[str] = None
    custody_events: list[CustodyEvent] = Field(default_factory=list)
    registered_at: datetime


class RepairExecutionReport(ForensicModel):
    """Full JSON report of one repair execution, bound to the frozen plan."""

    execution_id: str
    plan_id: str
    manifest_id: str
    media_id: str
    target_replica_id: str
    result: Literal["completed", "failed"]
    device: InspectionDevice
    entries: list[RepairExecutionEntryResult] = Field(default_factory=list)
    planned_intervals: list[SectorInterval] = Field(default_factory=list)
    written_intervals: int = 0
    written_sectors: int = 0
    final_sha256: Optional[str] = None
    final_merkle_root: Optional[str] = None
    expected_image_sha256: Optional[str] = None
    expected_merkle_root: Optional[str] = None
    final_verified: bool = False
    derived_replica: Optional[RepairDerivedReplica] = None
    findings: list[Finding] = Field(default_factory=list)
    evidence_package_digest: Optional[str] = None
    repair_package_digest: Optional[str] = None
    created_at: datetime


class RepairExecutionSummary(ForensicModel):
    execution_id: str
    plan_id: str
    result: str
    written_intervals: int
    written_sectors: int
    derived_replica_id: Optional[str] = None
    created_at: datetime


class FieldChange(ForensicModel):
    field: str
    left: Any = None
    right: Any = None


class DiffReport(ForensicModel):
    left_manifest_id: str
    right_manifest_id: str
    left_change_kind: str
    right_change_kind: str
    media_field_changes: list[FieldChange] = Field(default_factory=list)
    sessions_added: list[str] = Field(default_factory=list)
    sessions_removed: list[str] = Field(default_factory=list)
    chunks_added: list[str] = Field(default_factory=list)
    chunks_removed: list[str] = Field(default_factory=list)
    chunk_digests_changed: list[str] = Field(default_factory=list)
    replicas_added: list[str] = Field(default_factory=list)
    replicas_removed: list[str] = Field(default_factory=list)
    events_added: list[str] = Field(default_factory=list)
    events_removed: list[str] = Field(default_factory=list)
    merkle_root_left: Optional[str] = None
    merkle_root_right: Optional[str] = None
    reconstructed_sha256_left: Optional[str] = None
    reconstructed_sha256_right: Optional[str] = None
    # ---- bad-sector retry / fill provenance (same attempt records as precheck,
    # evidence package and recompute) --------------------------------------
    attempts_added: list[str] = Field(default_factory=list)
    attempts_removed: list[str] = Field(default_factory=list)
    attempt_results_changed: list[str] = Field(
        default_factory=list,
        description="attempt ids present in both revisions whose interval, "
                    "round, result, actual_read_length or fill declaration "
                    "changed")
    exceptions_added: list[str] = Field(default_factory=list)
    exceptions_removed: list[str] = Field(default_factory=list)
    recovery_rate_left: float = 0.0
    recovery_rate_right: float = 0.0
    unrecovered_sectors_left: int = 0
    unrecovered_sectors_right: int = 0
    accepted_sectors_left: int = 0
    accepted_sectors_right: int = 0
