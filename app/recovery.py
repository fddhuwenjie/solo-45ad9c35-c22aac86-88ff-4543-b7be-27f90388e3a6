"""Bad-sector retry and fill provenance analysis.

The imaging tool submits **read attempts** in acquisition order. Each attempt
records a source-medium sector interval, its retry round, the result (a real
read, an error, or declared padding/sparse-hole placement), the tool error
code, the actual transferred length and the fill declaration.

The analyzer splits overlapping attempt intervals into atomic sector ranges
and merges the rounds: a later successful read supersedes an earlier failure
for the final image segment, but every failed attempt stays on record. Every
final segment is labelled ``read`` (bytes really came from the source),
``fill`` (declared zero/pattern padding or a real sparse hole) or
``unrecovered`` (no data; sealable only when a documented exception accepts
it). Recovery rate, fill rate and the frozen unrecovered-sector policy are
computed from the same records that feed precheck, diffs, evidence packages
and recompute.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .hashing import sha256_hex
from .schemas import (
    FinalSegment,
    ReadAttemptInput,
    ReadAttemptRecord,
    RecoveryState,
)

# Default freeze policy when the manifest declares none: zero tolerance for
# unrecovered sectors that no documented exception accepts.
DEFAULT_FREEZE_POLICY = {"max_unrecovered_sectors": 0,
                        "max_unrecovered_ratio": None}


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


@dataclass
class _Slice:
    start: int
    end: int
    chunk_id: str
    chunk: Any
    reads: list[Any] = field(default_factory=list)
    errors: list[Any] = field(default_factory=list)
    fills: list[Any] = field(default_factory=list)


def analyze_recovery(
    payload: Any,
    effective_chunks: list[Any],
    resolver: Any,
    *,
    content_rows: Optional[dict[str, Any]] = None,
    emit: Optional[Callable[..., None]] = None,
) -> RecoveryState:
    """Build the recovery state for one manifest revision.

    ``effective_chunks`` are the chunks participating in image reconstruction
    (corrections/deduplication already resolved), in reconstructed offset
    order. ``resolver`` supplies range byte reads and sparse-hole status.
    ``emit(severity, code, message, **kw)`` receives findings.
    """
    media = _get(payload, "media")
    geom = _get(media, "geometry")
    sector_size = int(_get(geom, "sector_size"))
    total_sectors = int(_get(geom, "total_sectors"))
    attempts_all: list[Any] = list(_get(payload, "read_attempts") or [])
    exceptions_all: list[Any] = list(_get(payload, "recovery_exceptions") or [])
    policy_input = _get(payload, "freeze_policy")
    policy = (DEFAULT_FREEZE_POLICY if policy_input is None
              else {"max_unrecovered_sectors": _get(
                        policy_input, "max_unrecovered_sectors"),
                    "max_unrecovered_ratio": _get(
                        policy_input, "max_unrecovered_ratio")})
    session_ids = {_get(s, "session_id") for s in _get(payload, "sessions")}
    chunk_by_id = {_get(c, "chunk_id"): c for c in _get(payload, "chunks")}
    effective_ids = {_get(c, "chunk_id") for c in effective_chunks}

    def out(severity: str, code: str, message: str, **kw: Any) -> None:
        if emit is not None:
            emit(severity, code, message, **kw)

    # chunk sector ranges (effective chunks tile the image without overlap)
    chunk_ranges: dict[str, tuple[int, int]] = {}
    for c in effective_chunks:
        s0 = int(_get(c, "offset")) // sector_size
        s1 = s0 + int(_get(c, "length")) // sector_size
        chunk_ranges[_get(c, "chunk_id")] = (s0, s1)

    # ------------------------------------------------------------ records ----
    records: list[ReadAttemptRecord] = []
    order_index = {_get(a, "attempt_id"): i for i, a in enumerate(attempts_all)}

    # structural validation --------------------------------------------------
    seen_ids: set[str] = set()
    valid_attempts: list[Any] = []
    for a in attempts_all:
        aid = _get(a, "attempt_id")
        sid = _get(a, "session_id")
        cid = _get(a, "chunk_id")
        s0, s1 = int(_get(a, "start_sector")), int(_get(a, "end_sector"))
        result = _get(a, "result")
        span_bytes = (s1 - s0) * sector_size
        actual = int(_get(a, "actual_read_length"))
        valid = True

        if aid in seen_ids:
            out("error", "ATTEMPT_DUPLICATE",
                f"read attempt {aid} submitted more than once",
                chunk_ids=[cid], session_id=sid,
                start_sector=s0, end_sector=s1)
            valid = False
        seen_ids.add(aid)

        if sid not in session_ids:
            out("error", "ATTEMPT_SESSION_UNKNOWN",
                f"read attempt {aid} references unknown session {sid}",
                chunk_ids=[cid], session_id=sid,
                start_sector=s0, end_sector=s1)
            valid = False

        if cid not in chunk_by_id:
            out("error", "ATTEMPT_CHUNK_UNKNOWN",
                f"read attempt {aid} is bound to unknown chunk {cid}",
                chunk_ids=[cid], session_id=sid,
                start_sector=s0, end_sector=s1)
            valid = False

        if s0 < 0 or s1 > total_sectors:
            out("error", "ATTEMPT_OUT_OF_RANGE",
                f"read attempt {aid} covers [{s0},{s1}) beyond the source "
                f"medium [0,{total_sectors})",
                chunk_ids=[cid], session_id=sid,
                start_sector=max(0, s0),
                end_sector=min(total_sectors, s1) if total_sectors else s1,
                detail={"attempt_start": s0, "attempt_end": s1,
                        "total_sectors": total_sectors})
            valid = False

        expected_len = span_bytes if result == "read" else 0
        if actual != expected_len:
            code = ("ATTEMPT_PARTIAL_NOT_SPLIT" if result in ("read", "error")
                    else "ATTEMPT_ACTUAL_LENGTH_MISMATCH")
            if result == "read":
                msg = (f"read attempt {aid} transferred {actual} bytes for a "
                       f"{span_bytes}-byte range; a partial read must be split "
                       f"into separate read/error attempts per sector range")
            elif result == "error":
                msg = (f"failed attempt {aid} reports {actual} read bytes; "
                       f"split the sectors actually read into their own read "
                       f"attempt")
            else:
                msg = (f"fill attempt {aid} must report actual_read_length=0 "
                       f"(got {actual})")
            out("error", code, msg, chunk_ids=[cid], session_id=sid,
                start_sector=s0, end_sector=s1,
                detail={"actual_read_length": actual,
                        "expected": expected_len})
            valid = False

        records.append(ReadAttemptRecord(
            attempt_id=aid, session_id=sid, chunk_id=cid,
            start_sector=s0, end_sector=s1, round=int(_get(a, "round")),
            result=result, tool_error_code=_get(a, "tool_error_code"),
            actual_read_length=actual, fill_method=_get(a, "fill_method"),
            fill_value=_get(a, "fill_value"),
            sparse_hole=bool(_get(a, "sparse_hole")),
            sha256=_get(a, "sha256"), note=_get(a, "note"),
            effective=cid in effective_ids))
        if valid:
            valid_attempts.append(a)

    # rounds must be non-decreasing in submission order within each session
    last_round: dict[str, int] = {}
    last_index: dict[str, str] = {}
    for a in valid_attempts:
        sid = _get(a, "session_id")
        rnd = int(_get(a, "round"))
        if sid in last_round and rnd < last_round[sid]:
            out("error", "ATTEMPT_ROUND_ORDER_REVERSED",
                f"session {sid}: attempt {_get(a, 'attempt_id')} round "
                f"{rnd} comes after round {last_round[sid]} "
                f"({last_index[sid]}); retry rounds must be non-decreasing in "
                f"submission order",
                chunk_ids=[_get(a, "chunk_id")], session_id=sid,
                start_sector=int(_get(a, "start_sector")),
                end_sector=int(_get(a, "end_sector")),
                detail={"round": rnd, "previous_round": last_round[sid],
                        "previous_attempt": last_index[sid]})
        else:
            last_round[sid] = rnd
            last_index[sid] = _get(a, "attempt_id")

    # exceptions on an initial revision are never allowed
    for ex in exceptions_all:
        if _get(payload, "change_kind") == "initial":
            out("error", "RECOVERY_EXCEPTION_ON_INITIAL",
                f"recovery exception {_get(ex, 'exception_id')} requires a "
                f"derived revision (resume/target-swap/correction) with a "
                f"documented reason; it cannot be registered on the initial "
                f"manifest",
                start_sector=int(_get(ex, "start_sector")),
                end_sector=int(_get(ex, "end_sector")),
                detail={"exception_id": _get(ex, "exception_id"),
                        "reason": _get(ex, "reason")})

    # duplicate / overlapping exception declarations
    ex_sorted = sorted(exceptions_all,
                       key=lambda e: (int(_get(e, "start_sector")),
                                      int(_get(e, "end_sector")),
                                      _get(e, "exception_id")))
    for i, ex in enumerate(ex_sorted):
        a0, a1 = int(_get(ex, "start_sector")), int(_get(ex, "end_sector"))
        if a1 > total_sectors or a0 < 0:
            out("error", "RECOVERY_EXCEPTION_OUT_OF_RANGE",
                f"recovery exception {_get(ex, 'exception_id')} covers "
                f"[{a0},{a1}) beyond the source medium [0,{total_sectors})",
                start_sector=max(0, a0), end_sector=min(total_sectors, a1),
                detail={"exception_id": _get(ex, "exception_id")})
        for other in ex_sorted[:i]:
            b0, b1 = int(_get(other, "start_sector")), int(_get(other, "end_sector"))
            if a0 < b1 and b0 < a1:
                lo, hi = max(a0, b0), min(a1, b1)
                out("error", "RECOVERY_EXCEPTION_DUPLICATE",
                    f"recovery exceptions {_get(ex, 'exception_id')} and "
                    f"{_get(other, 'exception_id')} overlap on sectors "
                    f"[{lo},{hi})",
                    start_sector=lo, end_sector=hi,
                    detail={"exception_ids": [_get(other, "exception_id"),
                                              _get(ex, "exception_id")]})

    attempts_mode = bool(attempts_all)

    # ------------------------------------------------------- atomic slices --
    segments: list[FinalSegment] = []
    if attempts_mode:
        # an attempt's interval must lie inside the chunk it is bound to
        for a in valid_attempts:
            cid = _get(a, "chunk_id")
            s0, s1 = int(_get(a, "start_sector")), int(_get(a, "end_sector"))
            if s1 > total_sectors or s0 < 0:
                continue  # ATTEMPT_OUT_OF_RANGE already emitted
            if cid not in chunk_ranges:
                continue  # ATTEMPT_CHUNK_UNKNOWN already emitted
            cstart, cend = chunk_ranges[cid]
            if s0 < cstart or s1 > cend:
                out("error", "ATTEMPT_CHUNK_RANGE_MISMATCH",
                    f"read attempt {_get(a, 'attempt_id')} covers sectors "
                    f"[{s0},{s1}) but is bound to chunk {cid} "
                    f"[{cstart},{cend})",
                    chunk_ids=[cid], session_id=_get(a, "session_id"),
                    start_sector=s0, end_sector=s1,
                    detail={"attempt_id": _get(a, "attempt_id"),
                            "chunk_range": [cstart, cend]})

        segments = _build_attempt_segments(
            payload, effective_chunks, valid_attempts, chunk_ranges,
            sector_size, resolver, order_index, out)
    else:
        # Legacy manifests without a read-attempt log: a matching chunk digest
        # only proves the bytes hash correctly, never that they were read from
        # the source medium rather than zero-filled / sparse-holed after a
        # bad-sector error. Every covered sector stays unattested and sealing
        # is refused for any non-empty source medium.
        for c in effective_chunks:
            cid = _get(c, "chunk_id")
            s0, s1 = chunk_ranges[cid]
            sid = _get(c, "session_id")
            segments.append(FinalSegment(
                start_sector=s0, end_sector=s1, chunk_id=cid,
                session_id=sid if sid in session_ids else None,
                kind="unattested", content_ok=False))

        if total_sectors > 0 and effective_chunks:
            out("error", "RECOVERY_ATTESTATION_REQUIRED",
                f"manifest registers {total_sectors} source sectors but "
                f"submits no read attempts; digest matches cannot substitute "
                f"for proof that the bytes were read from the source medium "
                f"(zero fills and sparse holes after bad-sector errors are "
                f"otherwise indistinguishable from successful reads)",
                chunk_ids=sorted(_get(c, "chunk_id") for c in effective_chunks),
                start_sector=0, end_sector=total_sectors)

        # exceptions cannot accept anything without an attempt log
        for ex in exceptions_all:
            out("error", "RECOVERY_EXCEPTION_NOT_UNRECOVERED",
                f"recovery exception {_get(ex, 'exception_id')} was submitted "
                f"without read-attempt records; nothing can be proven "
                f"unrecovered, so no range can be accepted",
                start_sector=int(_get(ex, "start_sector")),
                end_sector=int(_get(ex, "end_sector")),
                detail={"exception_id": _get(ex, "exception_id")})

    # ----------------------------------------------- apply exception grants --
    seg_by_id: dict[int, FinalSegment] = {id(s): s for s in segments}
    valid_exceptions: list[Any] = []
    for ex in ex_sorted:
        a0, a1 = int(_get(ex, "start_sector")), int(_get(ex, "end_sector"))
        offending = _exception_offending_ranges(ex, segments, total_sectors)
        if a1 > total_sectors or a0 < 0 or offending:
            for lo, hi, why in offending:
                out("error", "RECOVERY_EXCEPTION_NOT_UNRECOVERED",
                    f"recovery exception {_get(ex, 'exception_id')} range "
                    f"[{lo},{hi}) is not an unrecovered sector range "
                    f"({why})",
                    start_sector=lo, end_sector=hi,
                    detail={"exception_id": _get(ex, "exception_id"),
                            "reason": why})
            continue
        valid_exceptions.append(ex)
        for s in segments:
            if s.kind == "unrecovered" and a0 < s.end_sector and s.start_sector < a1:
                s.exception_id = _get(ex, "exception_id")

    # ---------------------------------------------------------------- counts --
    def _span(kind: str) -> int:
        return sum(s.end_sector - s.start_sector for s in segments
                   if s.kind == kind)

    read_sectors = _span("read")
    filled_sectors = _span("fill")
    unattested_sectors = _span("unattested")
    unrecovered_all = _span("unrecovered")
    # sectors covered by no chunk at all are likewise unrecovered
    covered = sum(b - a for a, b in chunk_ranges.values())
    uncovered = max(0, total_sectors - covered)
    unrecovered_all += uncovered
    accepted_sectors = sum(s.end_sector - s.start_sector for s in segments
                           if s.kind == "unrecovered" and s.exception_id)
    unaccepted_unrecovered = unrecovered_all - accepted_sectors
    # Actual source-read recovery. Documented exception acceptances prove the
    # opposite of recovery -- the sectors stay non-source -- so they never
    # count as recovered; they only exempt the range from the freeze policy.
    recovered_sectors = read_sectors

    def _ratio(n: int) -> float:
        return round(n / total_sectors, 9) if total_sectors > 0 else 0.0

    # --------------------------------------------------------- freeze policy --
    # The frozen policy bounds only sectors still unrecovered that no
    # documented exception accepts. Declared fills carry explicit provenance
    # (the evidence package labels them as non-source) and are NOT charged
    # against this budget.
    freeze_ok = True
    max_n = policy["max_unrecovered_sectors"]
    max_r = policy["max_unrecovered_ratio"]
    over_n = max_n is not None and unaccepted_unrecovered > int(max_n)
    over_r = max_r is not None and _ratio(unaccepted_unrecovered) > float(max_r)
    if over_n or over_r:
        freeze_ok = False
        offending = [s for s in segments
                     if s.kind == "unrecovered" and not s.exception_id]
        intervals = sorted((s.start_sector, s.end_sector) for s in offending)
        chunk_ids = sorted({s.chunk_id for s in offending})
        session_ids_hit = sorted({s.session_id for s in offending
                                  if s.session_id})
        out("error", "UNRECOVERED_OVER_FREEZE_POLICY",
            f"{unaccepted_unrecovered} unrecovered sector(s) remain without "
            f"a documented accepted exception, exceeding the frozen policy "
            f"{policy}",
            start_sector=intervals[0][0] if intervals else None,
            end_sector=intervals[0][1] if intervals else None,
            chunk_ids=chunk_ids, session_id=(session_ids_hit[0]
                                            if len(session_ids_hit) == 1
                                            else None),
            detail={"unrecovered_sectors": unrecovered_all,
                    "filled_sectors": filled_sectors,
                    "unaccepted_unrecovered_sectors":
                        unaccepted_unrecovered,
                    "accepted_sectors": accepted_sectors,
                    "policy": policy,
                    "intervals": [{"start_sector": a, "end_sector": b}
                                  for a, b in intervals],
                    "chunk_ids": chunk_ids,
                    "session_ids": session_ids_hit})

    state = RecoveryState(
        provenance_mode=("attempts" if attempts_mode
                         else "legacy-content-only"),
        attempts=records,
        segments=segments,
        total_sectors=total_sectors,
        read_sectors=read_sectors,
        filled_sectors=filled_sectors,
        unattested_sectors=unattested_sectors,
        unrecovered_sectors=unrecovered_all,
        accepted_sectors=accepted_sectors,
        recovered_sectors=recovered_sectors,
        recovery_rate=_ratio(recovered_sectors),
        fill_rate=_ratio(filled_sectors),
        unrecovered_rate=_ratio(unaccepted_unrecovered),
        freeze_policy=policy,
        freeze_ok=freeze_ok,
        exceptions=[{"exception_id": _get(e, "exception_id"),
                     "start_sector": int(_get(e, "start_sector")),
                     "end_sector": int(_get(e, "end_sector")),
                     "reason": _get(e, "reason"),
                     "accepted_by": _get(e, "accepted_by"),
                     "accepted_at": _get(e, "accepted_at"),
                     "note": _get(e, "note"),
                     "applied": _get(e, "exception_id")
                                in {s.exception_id for s in segments}}
                    for e in ex_sorted])
    return state


def _exception_offending_ranges(ex, segments, total_sectors):
    """Return (lo, hi, why) sub-ranges of an exception that are not unrecovered."""
    a0, a1 = int(_get(ex, "start_sector")), int(_get(ex, "end_sector"))
    offending: list[tuple[int, int, str]] = []
    if a0 < 0 or a1 > total_sectors:
        offending.append((max(0, a0), min(total_sectors, a1),
                          "outside the source medium"))
    cursor = a0
    for s in sorted(segments, key=lambda x: x.start_sector):
        lo, hi = max(cursor, s.start_sector), min(a1, s.end_sector)
        if lo >= hi:
            continue
        if s.kind == "unrecovered" and not s.exception_id:
            cursor = max(cursor, hi)
            continue
        why = {"read": "already successfully read from the source",
               "fill": "already declared as zero/pattern padding or a "
                       "sparse hole",
               "unattested": "not covered by any read-attempt record; submit "
                             "attempts before it can be accepted"}.get(
            s.kind, "already accepted")
        offending.append((lo, hi, why))
        cursor = max(cursor, hi)
    if cursor < a1:
        offending.append((cursor, a1,
                          "not bound to any final chunk (coverage gap)"))
    return offending


def _build_attempt_segments(payload, effective_chunks, valid_attempts,
                            chunk_ranges, sector_size, resolver,
                            order_index, out) -> list[FinalSegment]:
    """Split overlapping attempts into atomic slices and merge the rounds."""
    effective_attempts: list[Any] = []
    for a in valid_attempts:
        cid = _get(a, "chunk_id")
        s0, s1 = int(_get(a, "start_sector")), int(_get(a, "end_sector"))
        if (cid in chunk_ranges and 0 <= s0 < s1
                and chunk_ranges[cid][0] <= s0 and s1 <= chunk_ranges[cid][1]):
            effective_attempts.append(a)

    # atomic boundaries from chunk ranges and attempt ranges
    points: set[int] = set()
    for s0, s1 in chunk_ranges.values():
        points.update((s0, s1))
    for a in effective_attempts:
        points.update((int(_get(a, "start_sector")), int(_get(a, "end_sector"))))
    bounds = sorted(points)

    def _chunk_at(sector: int) -> Optional[str]:
        for cid, (s0, s1) in chunk_ranges.items():
            if s0 <= sector < s1:
                return cid
        return None

    slices: list[_Slice] = []
    for lo, hi in zip(bounds, bounds[1:]):
        cid = _chunk_at(lo)
        if cid is None:
            continue
        sl = _Slice(start=lo, end=hi, chunk_id=cid,
                    chunk=_chunk_obj(effective_chunks, cid))
        for a in effective_attempts:
            s0, s1 = int(_get(a, "start_sector")), int(_get(a, "end_sector"))
            if s0 <= lo and hi <= s1 and _get(a, "chunk_id") == cid:
                {"read": sl.reads, "error": sl.errors,
                 "fill": sl.fills}[_get(a, "result")].append(a)
        slices.append(sl)

    return [_resolve_slice(sl, sector_size, resolver, order_index, out)
            for sl in slices]


def _chunk_obj(effective_chunks, cid):
    for c in effective_chunks:
        if _get(c, "chunk_id") == cid:
            return c
    return None


def _latest(group: list[Any], order_index: dict[str, int]) -> Any:
    # highest retry round wins; ties resolved by submission order so the
    # subsequent attempt supersedes the earlier one deterministically
    return max(group,
               key=lambda a: (int(_get(a, "round")),
                              order_index[_get(a, "attempt_id")]))


def _resolve_slice(sl: _Slice, sector_size: int, resolver,
                   order_index: dict[str, int], out) -> FinalSegment:
    chunk = sl.chunk
    cid = _get(chunk, "chunk_id")
    b0 = sl.start * sector_size - int(_get(chunk, "offset"))
    b1 = sl.end * sector_size - int(_get(chunk, "offset"))
    all_attempts = sl.reads + sl.errors + sl.fills
    attempt_ids = [_get(a, "attempt_id")
                   for a in sorted(all_attempts,
                                   key=lambda a: order_index[_get(
                                       a, "attempt_id")])]

    def base(**kw) -> FinalSegment:
        return FinalSegment(
            start_sector=sl.start, end_sector=sl.end, chunk_id=cid,
            attempts=attempt_ids, **kw)

    if not all_attempts:
        # covered by a final chunk but no attempt explains its bytes
        out("error", "ATTEMPT_PROVENANCE_MISSING",
            f"sectors [{sl.start},{sl.end}) of chunk {cid} have no read "
            f"attempt on record; the manifest cannot show whether the bytes "
            f"were read from the source or padded after a bad-sector error",
            chunk_ids=[cid], start_sector=sl.start, end_sector=sl.end)
        return FinalSegment(start_sector=sl.start, end_sector=sl.end,
                            chunk_id=cid, session_id=None, kind="unrecovered",
                            content_ok=False)

    # final intent: the highest-round attempt touching this slice wins; ties
    # resolve by submission order, so a later round-2 fill supersedes an
    # earlier round-1 read (and vice versa), while every earlier attempt --
    # including failures -- stays in the log.
    winner = _latest(all_attempts, order_index)
    latest_session = _get(winner, "session_id")

    # ---- validate every successful read against the bound chunk bytes -----
    success_conflict = False
    by_range: dict[tuple[int, int], list[Any]] = {}
    for a in sl.reads:
        by_range.setdefault(
            (int(_get(a, "start_sector")), int(_get(a, "end_sector"))),
            []).append(a)
    for (r0, r1), group in by_range.items():
        digests = {_get(a, "sha256") for a in group if _get(a, "sha256")}
        if len(digests) > 1:
            success_conflict = True
            out("error", "ATTEMPT_SUCCESS_CONFLICT",
                f"sectors [{r0},{r1}) have {len(digests)} distinct "
                f"successful read digests; later retries may supersede "
                f"failures but successful reads of the same range must agree",
                chunk_ids=[cid], session_id=_get(group[0], "session_id"),
                start_sector=max(r0, sl.start), end_sector=min(r1, sl.end),
                detail={"attempt_ids": [_get(a, "attempt_id") for a in group],
                        "digests": sorted(digests)})

    read_digest_ok = True
    winner_actual_digest: Optional[str] = None
    for a in sl.reads:
        declared = _get(a, "sha256")
        ar = resolver.read_range(
            chunk,
            int(_get(a, "start_sector")) * sector_size
            - int(_get(chunk, "offset")),
            int(_get(a, "end_sector")) * sector_size
            - int(_get(chunk, "offset")))
        if not ar.readable:
            read_digest_ok = False
            out("error", "ATTEMPT_CONTENT_UNVERIFIABLE",
                f"successful read attempt {_get(a, 'attempt_id')} cannot be "
                f"recomputed from the bound chunk {cid} ({ar.error_code})",
                chunk_ids=[cid], session_id=_get(a, "session_id"),
                start_sector=max(int(_get(a, "start_sector")), sl.start),
                end_sector=min(int(_get(a, "end_sector")), sl.end),
                detail={"attempt_id": _get(a, "attempt_id"),
                        "error_code": ar.error_code})
            continue
        digest = sha256_hex(ar.data)
        if a is winner:
            winner_actual_digest = digest
        if declared and declared != digest:
            read_digest_ok = False
            out("error", "ATTEMPT_CONTENT_DIGEST_MISMATCH",
                f"successful read attempt {_get(a, 'attempt_id')} digest "
                f"does not recompute from the bytes of bound chunk {cid}",
                chunk_ids=[cid], session_id=_get(a, "session_id"),
                start_sector=max(int(_get(a, "start_sector")), sl.start),
                end_sector=min(int(_get(a, "end_sector")), sl.end),
                detail={"attempt_id": _get(a, "attempt_id"),
                        "declared": declared, "actual": digest})

    winner_result = _get(winner, "result")

    # ------------------------------------------------------- final read -----
    if winner_result == "read":
        return base(kind="read", session_id=latest_session,
                    winning_attempt_id=_get(winner, "attempt_id"),
                    sha256=winner_actual_digest,
                    content_ok=read_digest_ok and not success_conflict)

    # ------------------------------------------------------- final fill -----
    if winner_result == "fill":
        method = _get(winner, "fill_method")
        fill_ok = True
        if method in ("zero-pad", "pattern-pad"):
            rr = resolver.read_range(chunk, b0, b1)
            if not rr.readable:
                fill_ok = False
                out("error", "FILL_CONTENT_MISMATCH",
                    f"declared {method} fill at sectors [{sl.start},"
                    f"{sl.end}) cannot be checked against chunk {cid} "
                    f"({rr.error_code})",
                    chunk_ids=[cid], session_id=latest_session,
                    start_sector=sl.start, end_sector=sl.end,
                    detail={"attempt_id": _get(winner, "attempt_id"),
                            "error_code": rr.error_code})
            else:
                value = 0 if method == "zero-pad" else int(
                    _get(winner, "fill_value"))
                expected = bytes([value]) * (b1 - b0)
                if rr.data != expected:
                    fill_ok = False
                    out("error", "FILL_CONTENT_MISMATCH",
                        f"declared {method} fill at sectors [{sl.start},"
                        f"{sl.end}) does not match the bytes stored in chunk "
                        f"{cid}",
                        chunk_ids=[cid], session_id=latest_session,
                        start_sector=sl.start, end_sector=sl.end,
                        detail={"attempt_id": _get(winner, "attempt_id"),
                                "fill_method": method, "fill_value": value})
        else:  # sparse-hole: must be a real filesystem hole
            hs = resolver.hole_status(chunk, b0, b1)
            if not hs.readable:
                fill_ok = False
                out("error", "FILL_HOLE_UNVERIFIABLE",
                    f"sparse-hole claim at sectors [{sl.start},{sl.end}) "
                    f"cannot be checked for chunk {cid} ({hs.error_code})",
                    chunk_ids=[cid], session_id=latest_session,
                    start_sector=sl.start, end_sector=sl.end,
                    detail={"attempt_id": _get(winner, "attempt_id"),
                            "error_code": hs.error_code})
            elif not hs.detection_available:
                fill_ok = False
                out("error", "FILL_HOLE_UNVERIFIABLE",
                    f"sparse-hole claim at sectors [{sl.start},{sl.end}) "
                    f"cannot be proven: sparse-hole detection is unavailable "
                    f"for this content source ({hs.source})",
                    chunk_ids=[cid], session_id=latest_session,
                    start_sector=sl.start, end_sector=sl.end,
                    detail={"attempt_id": _get(winner, "attempt_id"),
                            "source": hs.source})
            elif not hs.is_hole:
                fill_ok = False
                out("error", "FILL_CONTENT_MISMATCH",
                    f"attempt {_get(winner, 'attempt_id')} declares a sparse "
                    f"hole at sectors [{sl.start},{sl.end}) but the stored "
                    f"chunk {cid} has real bytes there",
                    chunk_ids=[cid], session_id=latest_session,
                    start_sector=sl.start, end_sector=sl.end,
                    detail={"attempt_id": _get(winner, "attempt_id"),
                            "fill_method": "sparse-hole"})

        if not sl.errors:
            out("warning", "FILL_WITHOUT_PRIOR_ERROR",
                f"declared fill at sectors [{sl.start},{sl.end}) has no "
                f"preceding failed read attempt on record",
                chunk_ids=[cid], session_id=latest_session,
                start_sector=sl.start, end_sector=sl.end,
                detail={"attempt_id": _get(winner, "attempt_id")})

        return base(kind="fill", session_id=latest_session,
                    winning_attempt_id=_get(winner, "attempt_id"),
                    fill_method=method, fill_value=_get(winner, "fill_value"),
                    sparse_hole=bool(_get(winner, "sparse_hole")),
                    content_ok=fill_ok)

    # ------------------------------------------------ final failed read -----
    return base(kind="unrecovered", session_id=latest_session,
                winning_attempt_id=_get(winner, "attempt_id"),
                tool_error_code=_get(winner, "tool_error_code"),
                content_ok=False)
