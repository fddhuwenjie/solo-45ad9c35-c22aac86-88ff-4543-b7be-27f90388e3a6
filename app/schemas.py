"""Pydantic models: submission payloads, findings and verification reports."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    covered_sectors: int = 0
    total_sectors: int = 0
    complete_coverage: bool = False
    merkle_root: Optional[str] = None
    reconstructed_sha256: Optional[str] = None
    expected_total_sha256: Optional[str] = None
    total_hash_verified: Optional[bool] = None
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
