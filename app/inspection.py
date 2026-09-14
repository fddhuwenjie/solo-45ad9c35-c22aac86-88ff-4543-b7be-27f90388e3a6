"""Post-seal integrity inspection of handed-over replicas.

Once a sealed image is transferred, the copy's medium can silently
degenerate. Re-hashing the whole disk on every patrol run has two forensic
weaknesses: an aborted read leaves no clue *which* sectors are damaged, and
an ad-hoc spot check cannot prove afterwards that the sampled ranges were
not cherry-picked to dodge known-bad areas.

An inspection therefore freezes the replica, the random seed, the sampling
ratio, the chunk boundaries, the read timestamps and the device identity.
The service deterministically regenerates the sample set from the seed —
always covering the first and last sector and every chunk seam, filled up to
the requested ratio with random sectors — and compares each submitted
reading against the sealed evidence package interval by interval. Expected
digests come exclusively from the baseline frozen at sealing time: inline
chunk bytes are embedded in the sealed submission, while a file-backed chunk
must first re-read to exactly its sealed length and SHA-256. A reference
file rewritten, truncated or deleted after sealing cannot restore that
baseline, so the affected interval is inconclusive — an unchanged copy's
correct digest can never be reported as a conflict.

Verdicts:

* ``failed`` — a sampled interval's actual digest provably conflicts with
  the sealed evidence, or the inspected replica cannot be tied to the sealed
  chain (unknown replica / digest mismatch): the copy demonstrably changed;
* ``inconclusive`` — nothing proven divergent, but the run could not fully
  verify: missing intervals, duplicate or out-of-plan readings, submitted
  read failures, or sealed bytes no longer recomputable;
* ``passed`` — the full deterministic plan was read and every digest
  matched.

Records are append-only: a re-test inserts a new row and never overwrites an
earlier failure, so the first-change time of every divergent interval
survives later (possibly transient) passes.
"""
from __future__ import annotations

import hashlib
import math
import random
from datetime import timezone
from typing import Any, Optional

from .schemas import (
    DivergentInterval,
    Finding,
    InspectionCreate,
    InspectionIntervalResult,
    InspectionReport,
    SectorInterval,
    Severity,
)

# Seed namespace: keeps inspection sampling independent from any other
# random.Random(seed) use of the same seed string.
SEED_NAMESPACE = "split-image-inspection/v1"


def as_utc(dt: Any) -> Any:
    """Normalize a datetime to tz-aware UTC so first-change comparisons never
    mix naive and aware timestamps across inspection records."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def generate_sample_plan(total_sectors: int,
                         chunk_boundaries: list[int],
                         sample_ratio: float,
                         seed: str) -> list[list[int]]:
    """Deterministically derive the sampled sector intervals.

    Always covers the first and last sector and both sectors straddling
    every internal chunk seam; the remaining budget (``sample_ratio`` of the
    medium) is filled with a seeded random pick without replacement.
    Consecutive selected sectors are merged into half-open intervals
    ``[start, end)``. The same ``(total_sectors, boundaries, ratio, seed)``
    always yields the same plan, so the frozen seed proves the sampled
    ranges were not chosen after the fact.
    """
    if total_sectors <= 0:
        return []
    mandatory: set[int] = {0, total_sectors - 1}
    for b in chunk_boundaries:
        if 0 < b < total_sectors:
            mandatory.add(b - 1)
            mandatory.add(b)
    target = math.ceil(total_sectors * sample_ratio)
    target = min(max(target, len(mandatory)), total_sectors)
    pool = [s for s in range(total_sectors) if s not in mandatory]
    rng = random.Random(f"{SEED_NAMESPACE}:{seed}")
    extra = rng.sample(pool, min(target - len(mandatory), len(pool)))
    selected = sorted(mandatory | set(extra))
    intervals: list[list[int]] = []
    for s in selected:
        if intervals and s == intervals[-1][1]:
            intervals[-1][1] += 1
        else:
            intervals.append([s, s + 1])
    return intervals


def chunk_sector_ranges(payload: Any, ordered_chunk_ids: list[str],
                        sector_size: int) -> list[tuple[str, int, int]]:
    """``(chunk_id, start_sector, end_sector)`` of the effective chunks in
    reconstructed offset order (the tiling the sealed image was built from).
    """
    by_id = {c.chunk_id: c for c in payload.chunks}
    ranges: list[tuple[str, int, int]] = []
    for cid in ordered_chunk_ids:
        c = by_id.get(cid)
        if c is None:
            continue
        s0 = c.offset // sector_size
        s1 = (c.offset + c.length) // sector_size
        ranges.append((cid, s0, s1))
    return ranges


def internal_seams(ranges: list[tuple[str, int, int]]) -> list[int]:
    """Sector indices where a new chunk starts (the chunk seams), sorted."""
    return sorted(s0 for _, s0, _ in ranges if s0 > 0)


def sealed_baseline_ok(chunk: Any, resolver: Any,
                       cache: dict[str, bool]) -> bool:
    """Whether the digest frozen at sealing time can still be reproduced for
    this chunk from the bytes available at inspection time.

    Inline content is embedded in the sealed submission itself, so its
    baseline is always restorable. A file-backed chunk only registered a
    ``stored_path``: its current bytes witness the sealed baseline *only*
    when they still re-read to exactly the length and SHA-256 frozen at seal
    time. A reference file rewritten, truncated or deleted after sealing must
    never masquerade as the baseline — otherwise an unchanged copy would be
    falsely reported as corrupt. Such a chunk yields an inconclusive
    interval, never a digest conflict.
    """
    cid = chunk.chunk_id
    cached = cache.get(cid)
    if cached is not None:
        return cached
    if chunk.content_b64 is not None:
        cache[cid] = True
        return True
    inspect = getattr(resolver, "inspect", None)
    if inspect is not None:
        result = inspect(chunk)
        ok = bool(result.readable and result.length == chunk.length
                  and result.sha256 == chunk.sha256)
    else:
        # Resolvers exposing only the byte-range API: re-read the whole chunk
        # and compare its length/digest with the frozen baseline directly.
        result = resolver.read_range(chunk, 0, chunk.length)
        ok = (result.readable and result.data is not None
              and len(result.data) == chunk.length
              and hashlib.sha256(result.data).hexdigest() == chunk.sha256)
    cache[cid] = ok
    return ok


def expected_interval_digest(payload: Any,
                             ranges: list[tuple[str, int, int]],
                             sector_size: int,
                             start_sector: int, end_sector: int,
                             resolver: Any,
                             baseline_cache: dict[str, bool]) -> Optional[str]:
    """Recompute the sealed digest of one sampled interval from the actual
    chunk bytes (inline content or registered files). An interval may span a
    chunk seam, so the bytes are assembled slice by slice in offset order.

    Every file-backed slice is first authenticated against the chunk digest
    frozen at sealing time: expected digests come exclusively from the frozen
    baseline, never from whatever a registered path happens to hold now.
    Returns None when any required slice is no longer readable, or when the
    current bytes no longer reproduce the frozen baseline — the caller must
    then mark the interval unverifiable (inconclusive), not conflicting.
    """
    by_id = {c.chunk_id: c for c in payload.chunks}
    h = hashlib.sha256()
    for cid, c0, c1 in ranges:
        lo, hi = max(start_sector, c0), min(end_sector, c1)
        if lo >= hi:
            continue
        chunk = by_id[cid]
        if not sealed_baseline_ok(chunk, resolver, baseline_cache):
            return None
        result = resolver.read_range(chunk, (lo - c0) * sector_size,
                                     (hi - c0) * sector_size)
        if not result.readable or result.data is None:
            return None
        h.update(result.data)
    return h.hexdigest()


def _chunks_overlapping(ranges: list[tuple[str, int, int]],
                        start_sector: int, end_sector: int) -> list[str]:
    return [cid for cid, c0, c1 in ranges
            if max(start_sector, c0) < min(end_sector, c1)]


def _prior_divergences(prior_reports: list[InspectionReport]
                       ) -> dict[tuple[str, int, int], tuple[Any, str]]:
    """Earliest observed divergence per (replica, start, end) from history."""
    first: dict[tuple[str, int, int], tuple[Any, str]] = {}
    for rep in prior_reports:
        for d in rep.divergent_intervals:
            key = (d.replica_id, d.start_sector, d.end_sector)
            when = as_utc(d.first_change_at or d.read_at)
            if when is None:
                continue
            if key not in first or when < first[key][0]:
                first[key] = (when, d.first_inspection_id or rep.inspection_id)
    return first


def evaluate_inspection(payload: InspectionCreate,
                        *,
                        manifest_row: Any,
                        sealed_payload: Any,
                        sealed_report: Any,
                        resolver: Any,
                        prior_reports: list[InspectionReport],
                        evidence_package_digest: Optional[str],
                        created_at: str) -> InspectionReport:
    """Evaluate one inspection submission against the sealed manifest.

    ``prior_reports`` are the append-only earlier inspections of the same
    manifest (used to keep first-change times stable across re-tests).
    """
    media_id = manifest_row["media_id"]
    geom = sealed_payload.media.geometry
    sector_size = int(geom.sector_size)
    total_sectors = int(geom.total_sectors)
    image_digest = sealed_report.reconstructed_sha256
    findings: list[Finding] = []

    def error(code: str, message: str, **kw: Any) -> None:
        findings.append(Finding(code=code, severity=Severity.error,
                                message=message, media_id=media_id, **kw))

    # ------------------------------------------------ replica chain binding --
    # The inspected medium must be a replica the sealed manifest actually
    # registered, carrying the sealed image digest; otherwise the patrol read
    # an object the evidence chain cannot account for.
    replicas = {r.replica_id: r for r in sealed_payload.replicas}
    replica = replicas.get(payload.replica_id)
    chain_broken = False
    if replica is None:
        error("INSPECTION_REPLICA_UNKNOWN",
              f"inspected replica {payload.replica_id} is not registered in "
              f"the sealed manifest; the replica chain is broken",
              replica_ids=[payload.replica_id])
        chain_broken = True
    elif image_digest and replica.sha256 != image_digest:
        error("INSPECTION_REPLICA_DIGEST_MISMATCH",
              f"replica {payload.replica_id} digest in the sealed manifest "
              f"differs from the sealed image digest; the replica chain is "
              f"broken",
              replica_ids=[payload.replica_id],
              detail={"replica": replica.sha256, "sealed_image": image_digest})
        chain_broken = True

    # ------------------------------------------------ frozen sample plan ----
    ranges = chunk_sector_ranges(sealed_payload,
                                 sealed_report.ordered_chunk_ids, sector_size)
    seams = internal_seams(ranges)
    plan = generate_sample_plan(total_sectors, seams, payload.sample_ratio,
                                payload.seed)
    plan_set = {(s0, s1) for s0, s1 in plan}

    # ------------------------------------------- submitted readings shape ---
    by_interval: dict[tuple[int, int], Any] = {}
    shape_violations = False
    for rd in payload.readings:
        key = (rd.start_sector, rd.end_sector)
        if rd.start_sector >= total_sectors or rd.end_sector > total_sectors:
            error("INSPECTION_READING_OUT_OF_BOUNDS",
                  f"reading [{rd.start_sector},{rd.end_sector}) exceeds the "
                  f"medium geometry ({total_sectors} sectors)",
                  replica_ids=[payload.replica_id],
                  start_sector=rd.start_sector, end_sector=rd.end_sector)
            shape_violations = True
            continue
        if key not in plan_set:
            error("INSPECTION_READING_OUT_OF_BOUNDS",
                  f"reading [{rd.start_sector},{rd.end_sector}) is outside "
                  f"the frozen sample plan derived from the seed",
                  replica_ids=[payload.replica_id],
                  start_sector=rd.start_sector, end_sector=rd.end_sector)
            shape_violations = True
            continue
        if key in by_interval:
            error("INSPECTION_READING_DUPLICATE",
                  f"interval [{rd.start_sector},{rd.end_sector}) was "
                  f"submitted more than once",
                  replica_ids=[payload.replica_id],
                  start_sector=rd.start_sector, end_sector=rd.end_sector)
            shape_violations = True
            continue
        by_interval[key] = rd

    # --------------------------------------- per-interval digest comparison --
    # Cache of frozen-baseline authentication per file-backed chunk: at most
    # one full re-read per chunk even when many sampled intervals overlap it.
    baseline_cache: dict[str, bool] = {}
    prior_first = _prior_divergences(prior_reports)
    intervals: list[InspectionIntervalResult] = []
    divergent: list[DivergentInterval] = []
    verified_sectors = 0
    covered_sectors = 0
    has_gap = False
    has_conflict = False

    for s0, s1 in plan:
        chunk_ids = _chunks_overlapping(ranges, s0, s1)
        rd = by_interval.get((s0, s1))
        if rd is None:
            error("INSPECTION_INTERVAL_MISSING",
                  f"planned sample interval [{s0},{s1}) has no reading; the "
                  f"seed-derived plan was not fully executed",
                  replica_ids=[payload.replica_id],
                  start_sector=s0, end_sector=s1,
                  detail={"chunk_ids": chunk_ids})
            has_gap = True
            intervals.append(InspectionIntervalResult(
                start_sector=s0, end_sector=s1, status="missing",
                chunk_ids=chunk_ids))
            continue

        # A read that the tool reported as failed did not return any bytes,
        # so it cannot contribute to covered or verified sectors.
        if rd.error:
            expected = expected_interval_digest(sealed_payload, ranges,
                                                sector_size, s0, s1, resolver,
                                                baseline_cache)
            error("INSPECTION_READ_FAILED",
                  f"replica {payload.replica_id} could not read sectors "
                  f"[{s0},{s1}): {rd.error}",
                  replica_ids=[payload.replica_id],
                  start_sector=s0, end_sector=s1,
                  detail={"tool_error": rd.error, "chunk_ids": chunk_ids})
            has_gap = True
            intervals.append(InspectionIntervalResult(
                start_sector=s0, end_sector=s1, status="read-failed",
                expected_sha256=expected, read_at=rd.read_at,
                error=rd.error, chunk_ids=chunk_ids))
            continue
        # The replica genuinely returned bytes for this in-plan interval, so
        # it counts as covered even if the frozen baseline is unavailable.
        covered_sectors += s1 - s0
        expected = expected_interval_digest(sealed_payload, ranges,
                                            sector_size, s0, s1, resolver,
                                            baseline_cache)
        if expected is None:
            error("INSPECTION_EXPECTED_UNRECOMPUTABLE",
                  f"sealed bytes for sectors [{s0},{s1}) are no longer "
                  f"readable or no longer reproduce the digest frozen at "
                  f"sealing time; the expected digest cannot be recomputed "
                  f"from the frozen baseline",
                  replica_ids=[payload.replica_id],
                  start_sector=s0, end_sector=s1,
                  detail={"chunk_ids": chunk_ids})
            has_gap = True
            intervals.append(InspectionIntervalResult(
                start_sector=s0, end_sector=s1, status="unverifiable",
                actual_sha256=rd.sha256, read_at=rd.read_at,
                chunk_ids=chunk_ids))
            continue
        if rd.sha256 != expected:
            error("INSPECTION_DIGEST_CONFLICT",
                  f"replica {payload.replica_id} sectors [{s0},{s1}) digest "
                  f"conflicts with the sealed evidence package",
                  replica_ids=[payload.replica_id],
                  start_sector=s0, end_sector=s1,
                  detail={"expected": expected, "actual": rd.sha256,
                          "chunk_ids": chunk_ids})
            has_conflict = True
            key = (payload.replica_id, s0, s1)
            read_at = as_utc(rd.read_at)
            first_at, first_id = prior_first.get(key, (None, None))
            if first_at is None or read_at < first_at:
                first_at, first_id = read_at, payload.inspection_id
            divergent.append(DivergentInterval(
                start_sector=s0, end_sector=s1,
                replica_id=payload.replica_id,
                expected_sha256=expected, actual_sha256=rd.sha256,
                read_at=read_at, first_change_at=first_at,
                first_inspection_id=first_id))
            intervals.append(InspectionIntervalResult(
                start_sector=s0, end_sector=s1, status="digest-conflict",
                expected_sha256=expected, actual_sha256=rd.sha256,
                read_at=rd.read_at, chunk_ids=chunk_ids))
            continue
        verified_sectors += s1 - s0
        intervals.append(InspectionIntervalResult(
            start_sector=s0, end_sector=s1, status="match",
            expected_sha256=expected, actual_sha256=rd.sha256,
            read_at=rd.read_at, chunk_ids=chunk_ids))

    planned_sectors = sum(s1 - s0 for s0, s1 in plan)
    if chain_broken or has_conflict:
        result = "failed"
    elif has_gap or shape_violations:
        result = "inconclusive"
    else:
        result = "passed"

    first_change_at = min((d.first_change_at for d in divergent
                           if d.first_change_at is not None), default=None)
    if first_change_at is not None:
        first_change_at = as_utc(first_change_at)
    return InspectionReport(
        inspection_id=payload.inspection_id,
        manifest_id=manifest_row["manifest_id"],
        media_id=media_id,
        replica_id=payload.replica_id,
        result=result,
        seed=payload.seed,
        sample_ratio=payload.sample_ratio,
        device=payload.device,
        chunk_boundaries=seams,
        planned_intervals=[SectorInterval(start_sector=a, end_sector=b)
                           for a, b in plan],
        planned_sectors=planned_sectors,
        covered_sectors=covered_sectors,
        verified_sectors=verified_sectors,
        total_sectors=total_sectors,
        sample_coverage=(planned_sectors / total_sectors
                         if total_sectors else 1.0),
        coverage_rate=(covered_sectors / planned_sectors
                       if planned_sectors else 1.0),
        verified_rate=(verified_sectors / planned_sectors
                       if planned_sectors else 1.0),
        intervals=intervals,
        divergent_intervals=divergent,
        first_change_at=first_change_at,
        findings=findings,
        evidence_package_digest=evidence_package_digest,
        image_sha256=image_digest,
        merkle_root=sealed_report.merkle_root,
        created_at=created_at)
