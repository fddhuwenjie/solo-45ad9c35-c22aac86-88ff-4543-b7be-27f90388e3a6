"""Shared pytest fixtures and synthetic-disk payload builders."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest
from fastapi.testclient import TestClient

from app.db import configure
from app.main import app


# A 32 KiB synthetic source: 64 sectors of 512 bytes, split into four 8 KiB
# chunks acquired across two sessions interrupted by a power loss.
SECTOR_SIZE = 512
TOTAL_SECTORS = 64
CHUNK_SECTORS = 16
N_CHUNKS = TOTAL_SECTORS // CHUNK_SECTORS

T0 = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)


def chunk_bytes(seq: int) -> bytes:
    h = hashlib.sha256(f"sector-block-{seq}".encode()).digest()
    return (h * ((SECTOR_SIZE * CHUNK_SECTORS) // 32 + 1))[
        :SECTOR_SIZE * CHUNK_SECTORS]


def chunk_sha(seq: int) -> str:
    return hashlib.sha256(chunk_bytes(seq)).hexdigest()


def total_image_bytes(chunk_seq: Optional[list[int]] = None) -> bytes:
    if chunk_seq is None:
        chunk_seq = list(range(N_CHUNKS))
    return b"".join(chunk_bytes(i) for i in chunk_seq)


def total_sha(chunk_seq: Optional[list[int]] = None) -> str:
    return hashlib.sha256(total_image_bytes(chunk_seq)).hexdigest()


def write_blocker(passed: bool = True, blocker_id: str = "WB-01",
                  self_test: Optional[str] = None,
                  expected: Optional[str] = None) -> dict[str, Any]:
    wb = {
        "blocker_id": blocker_id,
        "blocker_model": "Tableau SATA/USB Forensic Bridge",
        "firmware": "2.4.1",
        "mode": "read-only",
        "checked_by": "zhao.lei",
        "checked_at": T0.isoformat(),
        "passed": passed,
        "note": "verified before power-on",
    }
    if self_test is not None:
        wb["self_test_digest"] = self_test
    if expected is not None:
        wb["expected_self_test_digest"] = expected
    return wb


def sessions(chunks_per_session=(2, 2)) -> list[dict[str, Any]]:
    out = []
    cursor = 0
    for i, n in enumerate(chunks_per_session):
        start = T0 + timedelta(hours=i * 2)
        out.append({
            "session_id": f"S{i+1}",
            "started_at": start.isoformat(),
            "ended_at": (start + timedelta(minutes=40)).isoformat(),
            "operator": "zhao.lei",
            "tool": "dd-guigazi 8.20",
            "interruption": "none" if i == len(chunks_per_session) - 1
            else "power-loss",
            "note": "segmented acquisition" if i == 0 else None,
        })
        cursor += n
    return out


def build_chunks(chunk_seq: Optional[list[int]] = None,
                 sessions_split=(2, 2),
                 with_content: bool = True,
                 with_stored_path: bool = False,
                 overrides: Optional[dict[int, dict[str, Any]]] = None,
                 id_prefix: str = "C",
                 extra: Optional[list[dict[str, Any]]] = None
                 ) -> list[dict[str, Any]]:
    """Build chunk rows placed by offset; seq defines content per position."""
    if chunk_seq is None:
        chunk_seq = list(range(N_CHUNKS))
    overrides = overrides or {}
    rows: list[dict[str, Any]] = []
    for pos, seq in enumerate(chunk_seq):
        session_index = 0
        acc = 0
        for si, n in enumerate(sessions_split):
            if pos < acc + n:
                session_index = si
                break
            acc += n
        length = SECTOR_SIZE * CHUNK_SECTORS
        row = {
            "chunk_id": f"{id_prefix}{pos+1:02d}",
            "session_id": f"S{session_index+1}",
            "index": pos,
            "offset": pos * length,
            "length": length,
            "sha256": chunk_sha(seq),
            "file_size": length,
        }
        if with_stored_path:
            row["stored_path"] = f"/evidence/part{pos+1:02d}.dd"
        if with_content:
            row["content_b64"] = base64.b64encode(chunk_bytes(seq)).decode()
        row.update(overrides.get(pos, {}))
        rows.append(row)
    if extra:
        rows.extend(extra)
    return rows


def custody(replica_id: str, digest: str, *, acquired_by: str = "zhao.lei",
            seal: bool = True, transfer: bool = False,
            break_after: bool = False, role: str = "acquired") -> list[dict[str, Any]]:
    base = T0 + timedelta(hours=3)
    if role == "acquired":
        events = [
            {"event_id": f"E-{replica_id}-ACQ", "event_type": "acquired",
             "replica_id": replica_id, "at": base.isoformat(),
             "actor": acquired_by, "organization": "现场取证组",
             "digest_after": digest},
            {"event_id": f"E-{replica_id}-VRF", "event_type": "verified",
             "replica_id": replica_id,
             "at": (base + timedelta(minutes=10)).isoformat(),
             "actor": acquired_by,
             "digest_before": digest, "digest_after": digest,
             "expected_digest": digest},
        ]
    else:
        events = [
            {"event_id": f"E-{replica_id}-CPY", "event_type": "copied",
             "replica_id": replica_id, "at": base.isoformat(),
             "actor": "qian.wu", "organization": "证据管理室",
             "digest_before": digest, "digest_after": digest,
             "expected_digest": digest},
        ]
    if seal:
        events.append(
            {"event_id": f"E-{replica_id}-SEL", "event_type": "sealed",
             "replica_id": replica_id,
             "at": (base + timedelta(minutes=20)).isoformat(),
             "actor": "qian.wu", "organization": "证据管理室",
             "digest_before": digest,
             "digest_after": ("0" * 64 if break_after else digest),
             "expected_digest": digest})
    if transfer:
        events.append(
            {"event_id": f"E-{replica_id}-XFR", "event_type": "transferred",
             "replica_id": replica_id,
             "at": (T0 + timedelta(days=1)).isoformat(),
             "actor": "qian.wu", "organization": "证据管理室",
             "counterpart": "司法鉴定中心-接收人 sun.li",
             "digest_before": digest, "digest_after": digest,
             "expected_digest": digest})
    return events


def build_payload(*, media_id: str = "MEDIA-001",
                  chunk_seq: Optional[list[int]] = None,
                  with_content: bool = True,
                  chunk_overrides: Optional[dict[int, dict[str, Any]]] = None,
                  extra_chunks: Optional[list[dict[str, Any]]] = None,
                  write_blocker_row: Any = "default",
                  sessions_row: Any = "default",
                  replicas: str = "full",
                  replica_digest: Optional[str] = None,
                  custody_break: bool = False,
                  change_kind: str = "initial",
                  parent: Optional[str] = None,
                  expected_total: bool = True,
                  with_stored_path: bool = False,
                  with_attempts: bool = True,
                  id_prefix: str = "C") -> dict[str, Any]:
    """Assemble a full manifest submission. Returns a JSON-ready dict."""
    digest = replica_digest or total_sha(chunk_seq)
    if write_blocker_row == "default":
        write_blocker_row = write_blocker()
    if sessions_row == "default":
        sessions_row = sessions()
    chunks = build_chunks(chunk_seq=chunk_seq, with_content=with_content,
                          with_stored_path=with_stored_path,
                          overrides=chunk_overrides, extra=extra_chunks,
                          id_prefix=id_prefix)
    rep_rows: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    if replicas in ("full", "acquired"):
        rep_rows.append({
            "replica_id": "R-ACQ", "role": "acquired", "session_id": "S2",
            "sha256": digest, "merkle_root": None,
            "storage_location": "证物柜 A-12 / 采集工作站本地盘",
            "custodian": "zhao.lei",
            "created_at": (T0 + timedelta(hours=3)).isoformat()})
        events += custody("R-ACQ", digest, seal=(replicas == "full"),
                          transfer=False, break_after=custody_break)
    if replicas == "full":
        for rid, role, parent_id, loc, hours in (
                ("R-CPY", "copy", "R-ACQ", "办案副本盘 B-03", 4),
                ("R-ARC", "archive", "R-CPY", "封存柜 SAFE-07", 5)):
            rep_rows.append({
                "replica_id": rid, "role": role,
                "parent_replica_id": parent_id, "sha256": digest,
                "storage_location": loc, "custodian": "qian.wu",
                "created_at": (T0 + timedelta(hours=hours)).isoformat()})
            events += custody(rid, digest, seal=True, role="copy",
                              transfer=(rid == "R-ARC"))
    payload: dict[str, Any] = {
        "change_kind": change_kind,
        "parent_manifest_id": parent,
        "media": {
            "media_id": media_id,
            "evidence_label": "现场-01-嫌疑主机硬盘",
            "interface": "SATA",
            "geometry": {
                "sector_size": SECTOR_SIZE,
                "total_sectors": TOTAL_SECTORS,
                "capacity_bytes": SECTOR_SIZE * TOTAL_SECTORS,
                "media_sn": "WD-XYZ12345",
                "model": "WD3200AAJS",
                "firmware": "01.01A01",
            },
        },
        "write_blocker": write_blocker_row,
        "sessions": sessions_row,
        "chunks": chunks,
        "replicas": rep_rows,
        "custody_events": events,
    }
    if expected_total:
        payload["expected_total_sha256"] = total_sha(chunk_seq)
    if with_attempts:
        attach_read_attempts(payload)
    return payload


@pytest.fixture()
def client(tmp_path):
    db_path = tmp_path / "test_evidence.db"
    configure(db_path)
    app.state.db_path = str(db_path)
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def evidence_root(tmp_path):
    """Filesystem evidence root + a resolver pointed at it."""
    from app.content import FilesystemContentResolver
    from app.main import set_content_resolver

    root = tmp_path / "evidence"
    root.mkdir()
    set_content_resolver(FilesystemContentResolver(str(root)))
    yield root
    set_content_resolver(None)


def write_chunk_files(payload, root, *, chunk_seq=None, omit=(), corrupt=(),
                      truncate=(), swap=()):
    """Materialize each chunk's bytes at its stored_path under ``root``.

    omit/corrupt/truncate/swap are sets of chunk positions (0-based):
      omit      -> file is not written (CHUNK_FILE_UNREADABLE)
      corrupt   -> different bytes but same declared length (digest conflict)
      truncate  -> file shorter than declared length
      swap      -> pairs in ``swap`` exchange files (silent permutation)
    Returns mapping position -> absolute file path.
    """
    omit, corrupt, truncate = set(omit), set(corrupt), set(truncate)
    rows = [c for c in payload["chunks"] if "content_b64" in c
            or c.get("stored_path")]
    paths: dict[int, str] = {}
    seq = chunk_seq if chunk_seq is not None else list(range(len(rows)))
    for pos, row in enumerate(rows):
        length = row["length"]
        if pos in corrupt:
            data = b"\x99" * length
        elif pos in truncate:
            data = chunk_bytes(seq[pos])[: length // 2]
        else:
            data = chunk_bytes(seq[pos])
        rel = f"media/{row['chunk_id']}.dd"
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if pos not in omit:
            target.write_bytes(data)
        row.pop("content_b64", None)
        row["stored_path"] = rel
        paths[pos] = str(target)
    for a, b in swap:
        pa, pb = root / f"media/{rows[a]['chunk_id']}.dd", \
                 root / f"media/{rows[b]['chunk_id']}.dd"
        da, db = pa.read_bytes(), pb.read_bytes()
        pa.write_bytes(db)
        pb.write_bytes(da)
    return paths


def post_manifest(client, payload):
    return client.post("/manifests", json=payload)


def attach_read_attempts(payload, *, rounds=None, overrides=None):
    """Attach one successful read_attempt per final chunk.

    New provenance rules require the submission to show that the bytes were
    read from the source medium; a matching digest is not enough. Synthetic
    tests use this helper to supply ordinary round-1 reads. ``overrides`` maps
    a chunk_id to a partial attempt dict (used to simulate errors/retries/
    fills). ``rounds`` maps session_id -> current round (non-decreasing).
    """
    attempts = payload.get("read_attempts")
    if attempts is None:
        attempts = []
        payload["read_attempts"] = attempts
    existing = {a["chunk_id"] for a in attempts}
    rounds = rounds or {}
    geom = payload["media"]["geometry"]
    sector_size = geom["sector_size"]
    for c in payload["chunks"]:
        if c["chunk_id"] in existing:
            continue
        s0 = c["offset"] // sector_size
        s1 = s0 + c["length"] // sector_size
        sid = c["session_id"]
        rnd = rounds.get(sid, 1)
        attempt = {
            "attempt_id": f"A-{c['chunk_id']}",
            "session_id": sid,
            "chunk_id": c["chunk_id"],
            "start_sector": s0,
            "end_sector": s1,
            "round": rnd,
            "result": "read",
            "actual_read_length": (s1 - s0) * sector_size,
        }
        if overrides and c["chunk_id"] in overrides:
            attempt.update(overrides[c["chunk_id"]])
        attempts.append(attempt)
    return payload


def seal(client, manifest_id):
    return client.post(f"/manifests/{manifest_id}/seal")


def codes(report, severity=None):
    return [f["code"] for f in report["findings"]
            if severity is None or f["severity"] == severity]
