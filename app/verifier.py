"""Pure verification engine.

Every rule emits a :class:`Finding` carrying the medium, the offending chunk /
session / replica / event ids and (when geometric) a half-open sector interval.
Only error findings prevent sealing; warnings preserve the audit trail.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Optional

from .chains import analyze_replica_custody
from .content import ContentResolver, FilesystemContentResolver
from .hashing import merkle_root
from .schemas import (
    ChunkContentVerification,
    ChunkInput,
    EvaluationReport,
    Overlap,
    SectorInterval,
    Severity,
)


def _keep_first_same_id(group: list[ChunkInput]) -> ChunkInput:
    return sorted(group, key=lambda c: c.chunk_id)[0]


def evaluate(payload,
             resolver: Optional[ContentResolver] = None) -> EvaluationReport:
    """Evaluate a manifest payload.

    ``resolver`` supplies actual chunk bytes (inline base64 or registered file
    path). The default resolver reads inline content and any ``stored_path``
    under the process evidence roots.
    """
    if resolver is None:
        resolver = FilesystemContentResolver(())
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

    # ---- actual content verification (inline base64 or registered files) --
    # Effective chunks are streamed exactly once in reconstructed offset
    # order: each read feeds both the chunk leaf hasher and the whole-image
    # hasher. Every *registered* chunk is hard-verified -- correction_of only
    # decides which chunk represents the image range; it never exempts the
    # superseded old chunk from read/length/digest verification. An unreadable,
    # truncated or digest-conflicting old chunk is therefore a hard error that
    # blocks sealing; only effective chunks feed the whole-image hasher.
    effective_ids = {c.chunk_id for c in effective}
    content_rows: dict[str, ChunkContentVerification] = {}
    image_hasher = hashlib.sha256()

    def _content_failure_message(c: ChunkInput, code: str) -> str:
        return {
            "CHUNK_CONTENT_UNAVAILABLE":
                f"chunk {c.chunk_id}: no inline content and no registered "
                f"stored_path; digest cannot be recomputed",
            "CHUNK_FILE_UNREADABLE":
                f"chunk {c.chunk_id}: registered file {c.stored_path} cannot "
                f"be read; digest cannot be recomputed",
            "CHUNK_FILE_OUTSIDE_ROOT":
                f"chunk {c.chunk_id}: stored_path {c.stored_path} escapes the "
                f"configured evidence root",
            "CHUNK_CONTENT_BAD_BASE64":
                f"chunk {c.chunk_id}: inline content is not valid base64",
        }.get(code, f"chunk {c.chunk_id}: content unavailable ({code})")

    def _inspect_chunk(c: ChunkInput, effective_chunk: bool) -> None:
        result = (resolver.inspect(c, image_hasher) if effective_chunk
                  else resolver.inspect(c))
        row = ChunkContentVerification(
            chunk_id=c.chunk_id, source=result.source,
            readable=result.readable,
            stored_path=result.registered_path,
            length=result.length, sha256=result.sha256,
            declared_sha256=c.sha256, digest_verified=False)
        content_rows[c.chunk_id] = row
        superseded_note = ("" if effective_chunk
                           else " (chunk superseded by a correction but still "
                                "registered; its content must verify)")

        if not result.readable:
            code = result.error_code or "CHUNK_CONTENT_UNAVAILABLE"
            report.error(code,
                         _content_failure_message(c, code) + superseded_note,
                         chunk_ids=[c.chunk_id],
                         detail={**(result.error_detail or {}),
                                 "effective": effective_chunk})
            return

        if result.length != c.length:
            report.error(
                "CHUNK_CONTENT_LENGTH_MISMATCH",
                f"chunk {c.chunk_id}: actual content is {result.length} bytes "
                f"but manifest declares {c.length}" + superseded_note,
                chunk_ids=[c.chunk_id],
                detail={"declared": c.length, "actual": result.length,
                        "source": result.source,
                        "effective": effective_chunk})
            return

        row.digest_verified = result.sha256 == c.sha256
        if not row.digest_verified:
            report.error(
                "CHUNK_DIGEST_MISMATCH",
                f"chunk {c.chunk_id}: recomputed SHA-256 from {result.source} "
                f"content conflicts with the manifest" + superseded_note,
                chunk_ids=[c.chunk_id],
                detail={"declared": c.sha256, "actual": result.sha256,
                        "source": result.source,
                        "stored_path": result.registered_path,
                        "effective": effective_chunk})

    # 1) effective chunks in reconstructed offset order -> single streaming pass
    for c in effective:
        _inspect_chunk(c, True)
    # 2) superseded / deduplicated chunks: no image hashing, but hard-verified
    for c in chunks:
        if c.chunk_id not in effective_ids:
            _inspect_chunk(c, False)

    report.chunk_content = [content_rows[cid] for cid in sorted(content_rows)]
    effective_verified = sum(
        1 for cid in effective_ids if content_rows[cid].digest_verified)
    all_registered_verified = all(r.digest_verified
                                  for r in content_rows.values())
    report.all_chunk_digests_verified = (
        bool(effective) and effective_verified == len(effective)
        and all_registered_verified)

    # --------- Merkle root (declared leaf digests in reconstructed order) ----
    report.merkle_root = merkle_root([c.sha256 for c in effective])

    # ------- whole-image linear hash from the same single streaming pass -----
    if effective_verified == len(effective) and bool(effective):
        report.reconstructed_sha256 = image_hasher.hexdigest()
    if report.reconstructed_sha256 is None:
        report.error(
            "IMAGE_HASH_NOT_RECOMPUTABLE",
            "whole-image SHA-256 cannot be recomputed: one or more registered "
            "chunks are missing, unreadable, truncated or digest-conflicting",
            detail={"effective_chunks": len(effective),
                    "effective_verified": effective_verified,
                    "registered_chunks": len(content_rows)})

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

    # ---------------- replicas + minimum custody-chain integrity ------------
    def _chain_emit(severity: str, code: str, message: str, **kw) -> None:
        if severity == "error":
            report.error(code, message, **kw)
        else:
            report.warn(code, message, **kw)

    chain = analyze_replica_custody(
        payload.replicas, payload.custody_events, session_ids,
        image_digest=report.reconstructed_sha256,
        expected_total_sha256=payload.expected_total_sha256 or None,
        merkle_root=report.merkle_root,
        media_id=media.media_id,
        emit=_chain_emit)
    report.replica_chain_proven = chain.proven
    report.terminal_replica_ids = chain.terminal_replica_ids
    report.provenance_path = chain.chain_path

    # ------------------------------------------------------------- verdict ---
    has_errors = any(f.severity == Severity.error for f in report.findings)
    report.sealable = (not has_errors
                       and report.complete_coverage
                       and report.merkle_root is not None
                       and report.all_chunk_digests_verified
                       and report.reconstructed_sha256 is not None
                       and report.replica_chain_proven)
    return report
