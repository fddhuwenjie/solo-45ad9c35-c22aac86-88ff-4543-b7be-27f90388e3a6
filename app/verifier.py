"""Pure verification engine.

Every rule emits a :class:`Finding` carrying the medium, the offending chunk /
session / replica / event ids and (when geometric) a half-open sector interval.
Only error findings prevent sealing; warnings preserve the audit trail.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

from .hashing import decode_b64_strict, linear_sha256, merkle_root
from .schemas import (
    ChunkInput,
    CustodyEvent,
    EvaluationReport,
    Overlap,
    ReplicaInput,
    SectorInterval,
    Severity,
)


def _keep_first_same_id(group: list[ChunkInput]) -> ChunkInput:
    return sorted(group, key=lambda c: c.chunk_id)[0]


def evaluate(payload) -> EvaluationReport:  # noqa: C901 - explicit rule sequence
    media = payload.media
    geom = media.geometry
    report = EvaluationReport(media_id=media.media_id,
                              total_sectors=geom.total_sectors,
                              expected_total_sha256=payload.expected_total_sha256 or None)

    # --------------------------------------------------------- media params --
    if geom.capacity_bytes != geom.sector_size * geom.total_sectors:
        report.error(
            "GEOMETRY_INCONSISTENT",
            f"capacity_bytes={geom.capacity_bytes} != sector_size*total_sectors="
            f"{geom.sector_size * geom.total_sectors}",
            detail={"sector_size": geom.sector_size,
                    "total_sectors": geom.total_sectors,
                    "capacity_bytes": geom.capacity_bytes})

    # ------------------------------------------------------- write blocker --
    wb = payload.write_blocker
    if wb is None:
        report.error("WRITE_BLOCKER_MISSING",
                     "no write-protector verification record supplied")
    else:
        if not wb.passed:
            report.error("WRITE_BLOCKER_FAILED",
                         f"write blocker {wb.blocker_id} check did not pass",
                         detail={"blocker_id": wb.blocker_id, "mode": wb.mode})
        if wb.mode == "unknown":
            report.warn("WRITE_BLOCKER_MODE_UNKNOWN",
                        f"write blocker {wb.blocker_id} mode is 'unknown'",
                        detail={"blocker_id": wb.blocker_id})
        if wb.expected_self_test_digest and wb.self_test_digest:
            if wb.self_test_digest != wb.expected_self_test_digest:
                report.error(
                    "WRITE_BLOCKER_SELF_TEST_MISMATCH",
                    "write-protector self-test digest differs from expected value",
                    detail={"blocker_id": wb.blocker_id,
                            "actual": wb.self_test_digest,
                            "expected": wb.expected_self_test_digest})
        elif wb.expected_self_test_digest and not wb.self_test_digest:
            report.warn("WRITE_BLOCKER_SELF_TEST_ABSENT",
                        "expected self-test digest given but none was recorded",
                        detail={"blocker_id": wb.blocker_id})

    # ------------------------------------------------------------- sessions --
    session_ids: set[str] = set()
    for s in payload.sessions:
        if s.session_id in session_ids:
            report.error("SESSION_DUPLICATE",
                        f"session {s.session_id} declared more than once",
                        session_id=s.session_id)
        session_ids.add(s.session_id)
        if s.ended_at is not None and s.ended_at < s.started_at:
            report.warn("SESSION_TIME_REVERSED",
                        f"session {s.session_id} ended before it started",
                        session_id=s.session_id)

    # ------------------------------------------------------ per-chunk rules --
    chunks: list[ChunkInput] = payload.chunks
    chunk_ids: set[str] = set()
    by_id: dict[str, ChunkInput] = {}
    decoded: dict[str, bytes] = {}

    for c in chunks:
        if c.chunk_id in chunk_ids:
            report.error("CHUNK_DUPLICATE",
                         f"chunk id {c.chunk_id} appears more than once",
                         chunk_ids=[c.chunk_id])
        chunk_ids.add(c.chunk_id)
        by_id[c.chunk_id] = c

        if c.session_id not in session_ids:
            report.error("CHUNK_SESSION_UNKNOWN",
                         f"chunk {c.chunk_id} references unknown session "
                         f"{c.session_id}",
                         chunk_ids=[c.chunk_id], session_id=c.session_id)
        if c.length <= 0:
            report.error("CHUNK_EMPTY",
                         f"chunk {c.chunk_id} has zero length",
                         chunk_ids=[c.chunk_id])
        start_aligned = c.offset % geom.sector_size == 0
        length_aligned = c.length % geom.sector_size == 0
        if not (start_aligned and length_aligned):
            report.error("CHUNK_MISALIGNED",
                         f"chunk {c.chunk_id} is not sector aligned "
                         f"(offset={c.offset}, length={c.length})",
                         chunk_ids=[c.chunk_id],
                         detail={"offset": c.offset, "length": c.length,
                                 "sector_size": geom.sector_size})
        end = c.offset + c.length
        if end > geom.capacity_bytes:
            report.error("CHUNK_OUT_OF_RANGE",
                         f"chunk {c.chunk_id} reaches byte {end} beyond capacity "
                         f"{geom.capacity_bytes}",
                         chunk_ids=[c.chunk_id],
                         start_sector=c.offset // geom.sector_size,
                         end_sector=(end + geom.sector_size - 1) // geom.sector_size)

        if c.content_b64 is not None:
            try:
                data = decode_b64_strict(c.content_b64)
            except Exception:
                report.error("CHUNK_CONTENT_BAD_BASE64",
                             f"chunk {c.chunk_id} inline content is not valid base64",
                             chunk_ids=[c.chunk_id])
            else:
                if len(data) != c.length:
                    report.error("CHUNK_CONTENT_LENGTH_MISMATCH",
                                 f"chunk {c.chunk_id} content is {len(data)} bytes, "
                                 f"declared length {c.length}",
                                 chunk_ids=[c.chunk_id],
                                 detail={"declared": c.length, "actual": len(data)})
                else:
                    decoded[c.chunk_id] = data
                    actual = linear_sha256([data])
                    if actual != c.sha256:
                        report.error("CHUNK_DIGEST_MISMATCH",
                                     f"chunk {c.chunk_id} SHA-256 does not match its "
                                     f"content",
                                     chunk_ids=[c.chunk_id],
                                     detail={"declared": c.sha256, "actual": actual})

    # correction_of must reference a real chunk
    for c in chunks:
        if c.correction_of is not None and c.correction_of not in chunk_ids:
            report.error("CHUNK_CORRECTION_TARGET_MISSING",
                         f"chunk {c.chunk_id} corrects unknown chunk "
                         f"{c.correction_of}",
                         chunk_ids=[c.chunk_id],
                         detail={"correction_of": c.correction_of})

    # ---------------- exact-range groups: redundancy vs digest conflict -----
    range_groups: dict[tuple[int, int], list[ChunkInput]] = defaultdict(list)
    for c in chunks:
        range_groups[(c.offset, c.length)].append(c)

    chosen: list[ChunkInput] = []
    for (offset, length), group in range_groups.items():
        if len(group) == 1:
            chosen.append(group[0])
            continue
        digests = {g.sha256 for g in group}
        s0, s1 = offset // geom.sector_size, (offset + length) // geom.sector_size
        if len(digests) == 1:
            keep = _keep_first_same_id(group)
            chosen.append(keep)
            report.warn("CHUNK_DUPLICATE_RANGE",
                        f"{len(group)} identical chunks cover sectors [{s0},{s1}); "
                        f"keeping {keep.chunk_id}",
                        chunk_ids=sorted(g.chunk_id for g in group),
                        start_sector=s0, end_sector=s1)
            continue

        correctors = [g for g in group if g.correction_of is not None]
        targets = {g.correction_of for g in correctors}
        old = [g for g in group if g.chunk_id in targets]
        if (len(correctors) == 1 and len(targets) == 1 and old
                and len({g.sha256 for g in old}) == 1
                and correctors[0].chunk_id not in targets):
            keep = correctors[0]
            chosen.append(keep)
            superseded = sorted(g.chunk_id for g in group if g.chunk_id != keep.chunk_id)
            report.warn("CHUNK_CORRECTION_APPLIED",
                        f"correction chunk {keep.chunk_id} replaces {superseded} at "
                        f"sectors [{s0},{s1})",
                        chunk_ids=sorted(g.chunk_id for g in group),
                        start_sector=s0, end_sector=s1,
                        detail={"kept": keep.chunk_id, "superseded": superseded})
        else:
            report.error("CHUNK_DIGEST_CONFLICT",
                         f"differing chunk digests at sectors [{s0},{s1}) without a "
                         f"valid correction_of chain",
                         chunk_ids=sorted(g.chunk_id for g in group),
                         start_sector=s0, end_sector=s1,
                         detail={"digests": sorted(digests)})
            # whole group excluded -> it shows up as a coverage gap

    # ---------------- partial overlaps via sweep line -----------------------
    events: list[tuple[int, int, ChunkInput]] = []
    for c in chosen:
        events.append((c.offset, 0, c))   # starts sort before ends => adjacency ok
        events.append((c.offset + c.length, 1, c))
    events.sort(key=lambda e: (e[0], e[1]))

    overlap_segments: list[tuple[int, int, set[str]]] = []
    active: dict[str, ChunkInput] = {}
    prev_pos: Optional[int] = None
    for pos, kind, c in events:
        if prev_pos is not None and pos > prev_pos and len(active) > 1:
            overlap_segments.append((prev_pos, pos, set(active)))
        if kind == 0:
            active[c.chunk_id] = c
        else:
            active.pop(c.chunk_id, None)
        prev_pos = pos

    overlap_invalid: set[str] = set()
    if overlap_segments:
        merged: list[list] = []
        for start, end, ids in overlap_segments:
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
                merged[-1][2] |= ids
            else:
                merged.append([start, end, set(ids)])
        for start, end, ids in merged:
            ss, es = start // geom.sector_size, end // geom.sector_size
            report.error("CHUNK_OVERLAP",
                         f"chunks {sorted(ids)} overlap on sectors [{ss},{es})",
                         chunk_ids=sorted(ids), start_sector=ss, end_sector=es)
            report.overlaps.append(Overlap(start_sector=ss, end_sector=es,
                                           chunk_ids=sorted(ids),
                                           reason="partial range overlap"))
            overlap_invalid |= ids

    effective = [c for c in chosen if c.chunk_id not in overlap_invalid]
    effective.sort(key=lambda c: (c.offset, c.chunk_id))
    report.ordered_chunk_ids = [c.chunk_id for c in effective]

    # --------------------------------------------------------- block order --
    indices = [c.index for c in effective]
    if len(indices) != len(set(indices)):
        dups = sorted({i for i in indices if indices.count(i) > 1})
        report.warn("INDEX_DUPLICATE",
                    f"declared chunk indices repeat: {dups}",
                    detail={"duplicate_indices": dups})
    if indices != sorted(indices) and effective:
        actual_order = [c.chunk_id for c in effective]
        index_order = [c.chunk_id for c in
                       sorted(effective, key=lambda c: (c.index, c.chunk_id))]
        if actual_order != index_order:
            report.error("INDEX_ORDER_MISMATCH",
                         "declared chunk index order does not match offset order",
                         chunk_ids=actual_order,
                         detail={"offset_order": actual_order,
                                 "index_order": index_order})

    # ------------------------------------------------ Merkle + linear hash --
    report.merkle_root = merkle_root([c.sha256 for c in effective])

    if effective:
        present = [c for c in effective if c.chunk_id in decoded]
        if len(present) == len(effective):
            report.reconstructed_sha256 = linear_sha256(
                [decoded[c.chunk_id] for c in effective])
        elif present:
            report.warn("TOTAL_HASH_PARTIAL",
                        f"only {len(present)}/{len(effective)} chunks carry inline "
                        f"content; linear hash cannot be recomputed")
        elif payload.expected_total_sha256:
            report.warn("TOTAL_HASH_NOT_RECOMPUTABLE",
                        "total hash declared but no chunk content available; "
                        "register content-bearing replicas/custody digests to "
                        "corroborate it")

    if report.reconstructed_sha256 and payload.expected_total_sha256:
        if report.reconstructed_sha256 != payload.expected_total_sha256:
            report.error(
                "TOTAL_HASH_MISMATCH",
                "reconstructed image SHA-256 differs from the single total hash "
                "left at the scene",
                detail={"expected": payload.expected_total_sha256,
                        "actual": report.reconstructed_sha256})
        report.total_hash_verified = (
            report.reconstructed_sha256 == payload.expected_total_sha256)

    # ----------------------------------------------- coverage reconstruction --
    if geom.total_sectors > 0:
        covered: list[list[int]] = []
        for c in effective:
            s0 = c.offset // geom.sector_size
            s1 = (c.offset + c.length) // geom.sector_size
            if s1 <= s0:
                continue
            if covered and s0 <= covered[-1][1]:
                covered[-1][1] = max(covered[-1][1], s1)
            else:
                covered.append([s0, s1])
        report.covered_intervals = [SectorInterval(start_sector=a, end_sector=b)
                                    for a, b in covered]
        gaps: list[SectorInterval] = []
        cursor = 0
        for a, b in covered:
            if a > cursor:
                gaps.append(SectorInterval(start_sector=cursor, end_sector=a))
            cursor = max(cursor, b)
        if cursor < geom.total_sectors:
            gaps.append(SectorInterval(start_sector=cursor,
                                       end_sector=geom.total_sectors))
        report.gaps = gaps
        report.covered_sectors = sum(b - a for a, b in covered)
        report.complete_coverage = (covered and covered[0][0] == 0
                                    and covered[-1][1] == geom.total_sectors
                                    and not gaps)
        if gaps:
            for g in gaps:
                report.error("COVERAGE_GAP",
                             f"uncovered sector range [{g.start_sector},"
                             f"{g.end_sector})",
                             start_sector=g.start_sector, end_sector=g.end_sector)
    elif not effective:
        report.complete_coverage = True

    # ------------------------------------------------------------ replicas ---
    replica_ids: set[str] = set()
    by_replica: dict[str, ReplicaInput] = {}
    acquired: list[ReplicaInput] = []
    for r in payload.replicas:
        if r.replica_id in replica_ids:
            report.error("REPLICA_DUPLICATE",
                         f"replica {r.replica_id} declared more than once",
                         replica_ids=[r.replica_id])
        replica_ids.add(r.replica_id)
        by_replica[r.replica_id] = r
        if r.role == "acquired":
            acquired.append(r)

    for r in payload.replicas:
        if r.role == "acquired":
            if not r.session_id or r.session_id not in session_ids:
                report.error("REPLICA_SESSION_UNKNOWN",
                             f"acquired replica {r.replica_id} is not bound to a "
                             f"known acquisition session",
                             replica_ids=[r.replica_id],
                             session_id=r.session_id)
        else:
            if not r.parent_replica_id:
                report.error("REPLICA_PARENT_MISSING",
                             f"{r.role} replica {r.replica_id} has no parent replica",
                             replica_ids=[r.replica_id])
            elif r.parent_replica_id not in replica_ids:
                report.error("REPLICA_PARENT_UNKNOWN",
                             f"replica {r.replica_id} descends from unknown replica "
                             f"{r.parent_replica_id}",
                             replica_ids=[r.replica_id,
                                          r.parent_replica_id])
            else:
                parent = by_replica[r.parent_replica_id]
                if parent.sha256 != r.sha256:
                    report.error(
                        "REPLICA_COPY_DIGEST_MISMATCH",
                        f"{r.role} replica {r.replica_id} digest differs from its "
                        f"parent {parent.replica_id}",
                        replica_ids=[parent.replica_id, r.replica_id],
                        detail={"parent": parent.sha256, "child": r.sha256})

    def _matches_image(digest: str) -> Optional[bool]:
        if report.reconstructed_sha256 is not None:
            return digest == report.reconstructed_sha256
        if payload.expected_total_sha256:
            return digest == payload.expected_total_sha256
        return None

    for r in acquired:
        ok = _matches_image(r.sha256)
        if ok is False:
            report.error(
                "ACQUIRED_DIGEST_MISMATCH",
                f"acquired replica {r.replica_id} digest does not match the "
                f"reconstructed/declared image digest",
                replica_ids=[r.replica_id],
                detail={"replica": r.sha256,
                        "expected": report.reconstructed_sha256
                        or payload.expected_total_sha256})
        if r.merkle_root and report.merkle_root and r.merkle_root != report.merkle_root:
            report.error("REPLICA_MERKLE_MISMATCH",
                         f"replica {r.replica_id} Merkle root disagrees with chunk "
                         f"reconstruction",
                         replica_ids=[r.replica_id],
                         detail={"replica": r.merkle_root,
                                 "computed": report.merkle_root})

    if not acquired:
        report.warn("REPLICA_NO_ACQUISITION",
                    "no replica with role=acquired anchors the custody chain")

    # ------------------------------------------------------ custody events --
    event_ids: set[str] = set()
    events_by_replica: dict[str, list[CustodyEvent]] = defaultdict(list)
    for e in payload.custody_events:
        if e.event_id in event_ids:
            report.error("CUSTODY_EVENT_DUPLICATE",
                         f"custody event {e.event_id} declared more than once",
                         event_id=e.event_id)
        event_ids.add(e.event_id)
        if e.replica_id not in replica_ids:
            report.error("CUSTODY_REPLICA_UNKNOWN",
                         f"event {e.event_id} references unknown replica "
                         f"{e.replica_id}",
                         event_id=e.event_id, replica_ids=[e.replica_id])
        else:
            events_by_replica[e.replica_id].append(e)

    for replica_id, evs in events_by_replica.items():
        replica = by_replica[replica_id]
        evs.sort(key=lambda x: (x.at, x.event_id))
        prev_after: Optional[str] = None
        for e in evs:
            expected_before = prev_after if prev_after is not None else replica.sha256
            if e.digest_before and e.digest_before != expected_before:
                report.error(
                    "CUSTODY_DIGEST_BREAK",
                    f"event {e.event_id}: digest_before does not chain from the "
                    f"replica/previous event",
                    replica_ids=[replica_id], event_id=e.event_id,
                    detail={"expected": expected_before,
                            "actual": e.digest_before})
            if e.digest_after and e.digest_after != replica.sha256:
                report.error(
                    "CUSTODY_DIGEST_AFTER_BREAK",
                    f"event {e.event_id}: post-event digest differs from replica "
                    f"digest (tampering or bad reseal)",
                    replica_ids=[replica_id], event_id=e.event_id,
                    detail={"expected": replica.sha256,
                            "actual": e.digest_after})
            if e.expected_digest and e.expected_digest != replica.sha256:
                report.error(
                    "CUSTODY_EXPECTED_MISMATCH",
                    f"event {e.event_id}: expected/hand-over digest does not match "
                    f"the replica",
                    replica_ids=[replica_id], event_id=e.event_id,
                    detail={"expected": replica.sha256,
                            "declared": e.expected_digest})
            prev_after = e.digest_after or expected_before

    for r in payload.replicas:
        if not events_by_replica.get(r.replica_id):
            report.warn("CUSTODY_GAP",
                        f"replica {r.replica_id} has no custody events",
                        replica_ids=[r.replica_id])

    # ------------------------------------------------------------- verdict ---
    has_errors = any(f.severity == Severity.error for f in report.findings)
    report.sealable = (not has_errors and report.complete_coverage
                       and report.merkle_root is not None)
    return report
