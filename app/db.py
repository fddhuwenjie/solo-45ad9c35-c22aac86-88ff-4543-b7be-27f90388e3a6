"""SQLite storage for media, manifest revisions and their child records."""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from fastapi import Depends

from .hashing import canonical_json
from .schemas import ManifestCreate

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS media (
    media_id             TEXT PRIMARY KEY,
    evidence_label       TEXT,
    sector_size          INTEGER NOT NULL,
    total_sectors        INTEGER NOT NULL,
    capacity_bytes       INTEGER NOT NULL,
    media_sn             TEXT,
    first_manifest_id    TEXT NOT NULL,
    first_registered_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manifests (
    manifest_id          TEXT PRIMARY KEY,
    media_id             TEXT NOT NULL REFERENCES media(media_id),
    revision             INTEGER NOT NULL,
    change_kind          TEXT NOT NULL,
    parent_manifest_id   TEXT REFERENCES manifests(manifest_id),
    superseded_by        TEXT REFERENCES manifests(manifest_id),
    status               TEXT NOT NULL CHECK (status IN ('draft','sealed','superseded')),
    payload_json         TEXT NOT NULL,
    payload_digest       TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    sealed_at            TEXT,
    precheck_json        TEXT,
    seal_report_json     TEXT,
    merkle_root          TEXT,
    reconstructed_sha256 TEXT,
    UNIQUE (media_id, revision)
);

CREATE TABLE IF NOT EXISTS write_blocker_checks (
    manifest_id  TEXT NOT NULL REFERENCES manifests(manifest_id),
    blocker_id   TEXT NOT NULL,
    passed       INTEGER NOT NULL,
    record_json  TEXT NOT NULL,
    PRIMARY KEY (manifest_id, blocker_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id),
    session_id  TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (manifest_id, session_id)
);

CREATE TABLE IF NOT EXISTS chunks (
    manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id),
    chunk_id    TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    idx         INTEGER NOT NULL,
    offset      INTEGER NOT NULL,
    length      INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    PRIMARY KEY (manifest_id, chunk_id)
);

CREATE TABLE IF NOT EXISTS replicas (
    manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id),
    replica_id  TEXT NOT NULL,
    role        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    PRIMARY KEY (manifest_id, replica_id)
);

CREATE TABLE IF NOT EXISTS custody_events (
    manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id),
    event_id    TEXT NOT NULL,
    replica_id  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    at_ts       TEXT NOT NULL,
    digest_after TEXT,
    PRIMARY KEY (manifest_id, event_id)
);

CREATE TABLE IF NOT EXISTS read_attempts (
    manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id),
    attempt_id  TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    chunk_id    TEXT NOT NULL,
    start_sector INTEGER NOT NULL,
    end_sector   INTEGER NOT NULL,
    round        INTEGER NOT NULL,
    result       TEXT NOT NULL,
    actual_read_length INTEGER NOT NULL,
    record_json  TEXT NOT NULL,
    PRIMARY KEY (manifest_id, attempt_id)
);

CREATE TABLE IF NOT EXISTS recovery_exceptions (
    manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id),
    exception_id TEXT NOT NULL,
    start_sector INTEGER NOT NULL,
    end_sector   INTEGER NOT NULL,
    reason       TEXT NOT NULL,
    record_json  TEXT NOT NULL,
    PRIMARY KEY (manifest_id, exception_id)
);

-- Post-seal integrity inspections are append-only: every patrol run inserts
-- a new row keyed by inspection_id; rows are never updated or deleted, so a
-- re-test can never overwrite an earlier failed/inconclusive result.
CREATE TABLE IF NOT EXISTS inspections (
    inspection_id TEXT PRIMARY KEY,
    manifest_id   TEXT NOT NULL REFERENCES manifests(manifest_id),
    media_id      TEXT NOT NULL,
    replica_id    TEXT NOT NULL,
    seed          TEXT NOT NULL,
    sample_ratio  REAL NOT NULL,
    device_json   TEXT NOT NULL,
    plan_json     TEXT NOT NULL,
    report_json   TEXT NOT NULL,
    result        TEXT NOT NULL CHECK (result IN ('passed','failed','inconclusive')),
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_manifests_media ON manifests(media_id, revision);
CREATE INDEX IF NOT EXISTS idx_chunks_offset ON chunks(manifest_id, offset);
CREATE INDEX IF NOT EXISTS idx_attempts_chunk
    ON read_attempts(manifest_id, chunk_id);
CREATE INDEX IF NOT EXISTS idx_exceptions_range
    ON recovery_exceptions(manifest_id, start_sector, end_sector);
CREATE INDEX IF NOT EXISTS idx_inspections_manifest
    ON inspections(manifest_id, created_at);

-- Multi-replica joint inspection tasks are append-only: a task freezes the
-- sealed manifest, the evidence package digest, the participating replicas,
-- the unified seed, the sampling ratio, the completion window and the
-- seed-derived plan; rows are never updated or deleted.
CREATE TABLE IF NOT EXISTS joint_inspections (
    joint_id               TEXT PRIMARY KEY,
    manifest_id            TEXT NOT NULL REFERENCES manifests(manifest_id),
    media_id               TEXT NOT NULL,
    replica_ids_json       TEXT NOT NULL,
    seed                   TEXT NOT NULL,
    sample_ratio           REAL NOT NULL,
    window_start           TEXT NOT NULL,
    window_end             TEXT NOT NULL,
    plan_json              TEXT NOT NULL,
    chunk_boundaries_json  TEXT NOT NULL,
    evidence_package_digest TEXT,
    created_at             TEXT NOT NULL
);

-- Bindings from a joint task to the per-replica inspection records are
-- append-only as well: a re-test inserts a new row and rows are never
-- updated or deleted. A record referenced more than once stays on record;
-- the joint evaluation marks the task inconclusive instead of rejecting
-- the duplicate, so the attempt itself remains auditable.
CREATE TABLE IF NOT EXISTS joint_inspection_bindings (
    binding_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    joint_id      TEXT NOT NULL REFERENCES joint_inspections(joint_id),
    inspection_id TEXT NOT NULL REFERENCES inspections(inspection_id),
    replica_id    TEXT NOT NULL,
    bound_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_joint_inspections_manifest
    ON joint_inspections(manifest_id, created_at);
CREATE INDEX IF NOT EXISTS idx_joint_bindings_joint
    ON joint_inspection_bindings(joint_id, binding_id);
"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def init(self) -> None:
        conn = self.connect()
        try:
            conn.executescript(SCHEMA)
        finally:
            conn.close()


# A process-wide default; tests and configuration override it.
_default_db: Optional[Database] = None


def configure(path: str | Path) -> Database:
    global _default_db
    _default_db = Database(path)
    return _default_db


def get_db() -> Iterator[sqlite3.Connection]:
    if _default_db is None:
        configure("data/evidence.db")
    assert _default_db is not None
    conn = _default_db.connect()
    try:
        yield conn
    finally:
        conn.close()


def _dump(model: Any) -> dict[str, Any]:
    return model.model_dump(mode="json")


def get_media(conn: sqlite3.Connection, media_id: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM media WHERE media_id=?", (media_id,)).fetchone()


def get_manifest(conn: sqlite3.Connection, manifest_id: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM manifests WHERE manifest_id=?",
                        (manifest_id,)).fetchone()


def list_manifests(conn: sqlite3.Connection, media_id: str) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM manifests WHERE media_id=? ORDER BY revision", (media_id,)))


def next_revision(conn: sqlite3.Connection, media_id: str) -> int:
    row = conn.execute("SELECT COALESCE(MAX(revision),0) AS r FROM manifests WHERE media_id=?",
                       (media_id,)).fetchone()
    return int(row["r"]) + 1


def insert_manifest(conn: sqlite3.Connection, manifest_id: str, payload: ManifestCreate,
                    status: str = "draft") -> dict[str, Any]:
    """Atomically register/reuse media, supersede the parent and insert a revision."""
    media_id = payload.media.media_id
    dumped = _dump(payload)
    payload_json = canonical_json(dumped)
    payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    now = utcnow_iso()

    conn.execute("BEGIN IMMEDIATE")
    try:
        existing_media = get_media(conn, media_id)
        if existing_media is None:
            geom = payload.media.geometry
            conn.execute(
                """INSERT INTO media (media_id, evidence_label, sector_size,
                                      total_sectors, capacity_bytes, media_sn,
                                      first_manifest_id, first_registered_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (media_id, payload.media.evidence_label, geom.sector_size,
                 geom.total_sectors, geom.capacity_bytes, geom.media_sn,
                 manifest_id, now))

        revision = next_revision(conn, media_id)
        conn.execute(
            """INSERT INTO manifests (manifest_id, media_id, revision, change_kind,
                                      parent_manifest_id, superseded_by, status,
                                      payload_json, payload_digest, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (manifest_id, media_id, revision, payload.change_kind,
             payload.parent_manifest_id, None, status, payload_json,
             payload_digest, now))

        if payload.parent_manifest_id is not None:
            parent = get_manifest(conn, payload.parent_manifest_id)
            if parent is not None and parent["superseded_by"] is None:
                conn.execute(
                    "UPDATE manifests SET superseded_by=?, status='superseded' "
                    "WHERE manifest_id=?", (manifest_id, payload.parent_manifest_id))

        _insert_children(conn, manifest_id, payload)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    row = get_manifest(conn, manifest_id)
    assert row is not None
    return dict(row)


def _insert_children(conn: sqlite3.Connection, manifest_id: str,
                     payload: ManifestCreate) -> None:
    if payload.write_blocker is not None:
        wb = payload.write_blocker
        conn.execute(
            """INSERT INTO write_blocker_checks (manifest_id, blocker_id, passed, record_json)
               VALUES (?,?,?,?)""",
            (manifest_id, wb.blocker_id, int(wb.passed), canonical_json(_dump(wb))))

    for s in payload.sessions:
        conn.execute(
            "INSERT INTO sessions (manifest_id, session_id, record_json) VALUES (?,?,?)",
            (manifest_id, s.session_id, canonical_json(_dump(s))))

    for c in payload.chunks:
        conn.execute(
            """INSERT INTO chunks (manifest_id, chunk_id, session_id, idx, offset,
                                   length, sha256)
               VALUES (?,?,?,?,?,?,?)""",
            (manifest_id, c.chunk_id, c.session_id, c.index, c.offset, c.length,
             c.sha256))

    for r in payload.replicas:
        conn.execute(
            "INSERT INTO replicas (manifest_id, replica_id, role, sha256) VALUES (?,?,?,?)",
            (manifest_id, r.replica_id, r.role, r.sha256))

    for e in payload.custody_events:
        conn.execute(
            """INSERT INTO custody_events (manifest_id, event_id, replica_id, event_type,
                                           at_ts, digest_after)
               VALUES (?,?,?,?,?,?)""",
            (manifest_id, e.event_id, e.replica_id, e.event_type,
             e.at.isoformat(), e.digest_after))

    for a in payload.read_attempts:
        conn.execute(
            """INSERT INTO read_attempts (manifest_id, attempt_id, session_id,
                                          chunk_id, start_sector, end_sector,
                                          round, result, actual_read_length,
                                          record_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (manifest_id, a.attempt_id, a.session_id, a.chunk_id,
             a.start_sector, a.end_sector, a.round, a.result,
             a.actual_read_length, canonical_json(_dump(a))))

    for ex in payload.recovery_exceptions:
        conn.execute(
            """INSERT INTO recovery_exceptions (manifest_id, exception_id,
                                                start_sector, end_sector, reason,
                                                record_json)
               VALUES (?,?,?,?,?,?)""",
            (manifest_id, ex.exception_id, ex.start_sector, ex.end_sector,
             ex.reason, canonical_json(_dump(ex))))


def save_precheck(conn: sqlite3.Connection, manifest_id: str, report_json: str) -> None:
    conn.execute("UPDATE manifests SET precheck_json=? WHERE manifest_id=?",
                 (report_json, manifest_id))


def mark_sealed(conn: sqlite3.Connection, manifest_id: str, sealed_at: str,
                report_json: str, merkle_root: Optional[str],
                reconstructed_sha256: Optional[str]) -> None:
    conn.execute(
        """UPDATE manifests
           SET status='sealed', sealed_at=?, seal_report_json=?, merkle_root=?,
               reconstructed_sha256=?
         WHERE manifest_id=?""",
        (sealed_at, report_json, merkle_root, reconstructed_sha256, manifest_id))


# ---------------------------------------------------- inspections (append-only)
def insert_inspection(conn: sqlite3.Connection, report: Any,
                      plan: list[list[int]]) -> None:
    """Append one inspection record. ``report`` is an InspectionReport; the
    frozen plan (seed-derived intervals) is stored alongside so the record
    stays auditable even if the sampling algorithm ever changes."""
    device_json = canonical_json(report.device.model_dump(mode="json"))
    report_json = canonical_json(report.model_dump(mode="json"))
    conn.execute(
        """INSERT INTO inspections (inspection_id, manifest_id, media_id,
                                    replica_id, seed, sample_ratio, device_json,
                                    plan_json, report_json, result, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (report.inspection_id, report.manifest_id, report.media_id,
         report.replica_id, report.seed, report.sample_ratio, device_json,
         canonical_json(plan), report_json, report.result,
         report.created_at.isoformat()))


def get_inspection(conn: sqlite3.Connection, manifest_id: str,
                   inspection_id: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM inspections WHERE manifest_id=? AND inspection_id=?",
        (manifest_id, inspection_id)).fetchone()


def get_inspection_by_id(conn: sqlite3.Connection,
                         inspection_id: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM inspections WHERE inspection_id=?",
                        (inspection_id,)).fetchone()


def list_inspections(conn: sqlite3.Connection,
                     manifest_id: str) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM inspections WHERE manifest_id=? "
        "ORDER BY created_at, inspection_id", (manifest_id,)))


# ---------------------------------------------- joint inspections (append-only)
def insert_joint_inspection(conn: sqlite3.Connection, *, joint_id: str,
                            manifest_id: str, media_id: str,
                            replica_ids: list[str], seed: str,
                            sample_ratio: float, window_start: str,
                            window_end: str, plan: list[list[int]],
                            chunk_boundaries: list[int],
                            evidence_package_digest: Optional[str],
                            created_at: str) -> None:
    """Open one joint inspection task. The frozen plan (derived from the
    unified seed at creation time) is stored alongside so the task stays
    auditable even if the sampling algorithm ever changes."""
    conn.execute(
        """INSERT INTO joint_inspections (joint_id, manifest_id, media_id,
                                          replica_ids_json, seed, sample_ratio,
                                          window_start, window_end, plan_json,
                                          chunk_boundaries_json,
                                          evidence_package_digest, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (joint_id, manifest_id, media_id, canonical_json(replica_ids), seed,
         sample_ratio, window_start, window_end, canonical_json(plan),
         canonical_json(chunk_boundaries), evidence_package_digest,
         created_at))


def get_joint_inspection(conn: sqlite3.Connection, manifest_id: str,
                         joint_id: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM joint_inspections WHERE manifest_id=? AND joint_id=?",
        (manifest_id, joint_id)).fetchone()


def get_joint_inspection_by_id(conn: sqlite3.Connection,
                               joint_id: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM joint_inspections WHERE joint_id=?",
                        (joint_id,)).fetchone()


def list_joint_inspections(conn: sqlite3.Connection,
                           manifest_id: str) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM joint_inspections WHERE manifest_id=? "
        "ORDER BY created_at, joint_id", (manifest_id,)))


def insert_joint_binding(conn: sqlite3.Connection, joint_id: str,
                         inspection_id: str, replica_id: str,
                         bound_at: str) -> None:
    """Append one binding between a joint task and a submitted per-replica
    inspection record. ``replica_id`` is denormalized from the inspection
    record at bind time so the row stays self-contained."""
    conn.execute(
        """INSERT INTO joint_inspection_bindings (joint_id, inspection_id,
                                                  replica_id, bound_at)
           VALUES (?,?,?,?)""",
        (joint_id, inspection_id, replica_id, bound_at))


def list_joint_bindings(conn: sqlite3.Connection,
                        joint_id: str) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM joint_inspection_bindings WHERE joint_id=? "
        "ORDER BY binding_id", (joint_id,)))


def dependency_db() -> Any:
    yield from get_db()


DbDep = Depends(dependency_db)
