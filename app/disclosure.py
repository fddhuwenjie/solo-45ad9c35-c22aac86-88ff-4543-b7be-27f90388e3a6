"""Selective disclosure proofs for sealed chunked images.

A court or external reviewer usually needs to inspect only a few chunks and
must not obtain the whole image for that. This module issues Merkle
inclusion proofs that bind individually delivered chunks to the root frozen
at sealing time:

* the adopted leaf ordering is the sealed tree ordering exactly — the
  effective chunks in ``ordered_chunk_ids`` order (correction-superseded
  chunks are not leaves);
* selectors are explicit ``chunk_id`` values or sector ranges that line up
  EXACTLY with effective chunk boundaries (a range that cuts a chunk, runs
  past the medium or lands in a gap is refused);
* every disclosed leaf gets its zero-based leaf index, the left/right
  sibling digest at each level and an explicit odd-node promotion step, so
  an external verifier reproduces the same odd-promotion Merkle rule
  without knowing anything but the leaf digest and the path;
* the frozen manifest revision, the evidence package digest, the Merkle
  algorithm specification and the leaf ordering rule are pinned into every
  proof, which is then self-digested for the append-only issuance record.

Verification is a pure function of the leaf digest, the proof path and the
frozen root: no manifest, evidence package, database or chunk bytes are
consulted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .evidence import MERKLE_SPEC
from .hashing import canonical_bytes, merkle_root, sha256_hex
from .schemas import (
    DISCLOSURE_FORMAT,
    DISCLOSURE_LEAF_ORDERING,
    DisclosureLeafOrderingEntry,
    DisclosureLeafProof,
    DisclosureProof,
    DisclosureProofCreate,
    DisclosureProofStep,
    DisclosureVerifyRequest,
    DisclosureVerifyResult,
    SectorInterval,
)


class DisclosureError(Exception):
    """A request that cannot produce a proof. Carries an HTTP status so the
    route layer can map it directly (nothing is stored on error)."""

    def __init__(self, code: str, message: str, *,
                 status_code: int = 422, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.detail = {"code": code, "message": message, **extra}


@dataclass(frozen=True)
class DisclosureLeaf:
    index: int
    chunk_id: str
    digest: str
    start_sector: int
    end_sector: int


def build_leaves(sealed_payload: Any, ordered_chunk_ids: list[str],
                 sector_size: int) -> list[DisclosureLeaf]:
    """The frozen leaf sequence: effective chunks in reconstructed offset
    order (the exact order the sealed Merkle root was computed from)."""
    by_id = {c.chunk_id: c for c in sealed_payload.chunks}
    leaves: list[DisclosureLeaf] = []
    for i, cid in enumerate(ordered_chunk_ids):
        chunk = by_id.get(cid)
        if chunk is None:
            # A sealed report can never point outside its own manifest; this
            # would indicate a broken sealed record, not a client error.
            raise DisclosureError(
                "DISCLOSURE_FROZEN_ORDER_INCONSISTENT",
                f"ordered chunk {cid} is absent from the sealed manifest",
                status_code=500, chunk_id=cid)
        leaves.append(DisclosureLeaf(
            index=i, chunk_id=cid, digest=chunk.sha256,
            start_sector=chunk.offset // sector_size,
            end_sector=(chunk.offset + chunk.length) // sector_size))
    if not leaves:
        raise DisclosureError(
            "DISCLOSURE_TREE_EMPTY",
            "the sealed manifest has no effective chunk leaves",
            status_code=409)
    return leaves


def _parent(position: str, cur_hex: str, sibling_hex: Optional[str]) -> str:
    if position == "promoted":
        return cur_hex
    assert sibling_hex is not None
    if position == "left":
        return sha256_hex(bytes.fromhex(cur_hex) + bytes.fromhex(sibling_hex))
    return sha256_hex(bytes.fromhex(sibling_hex) + bytes.fromhex(cur_hex))


def build_merkle_proof(leaf_digests: list[str], leaf_index: int
                       ) -> list[DisclosureProofStep]:
    """The inclusion path for one leaf under the sealed odd-promotion rule.

    Step ``level`` is applied to the node on that level: a ``left``/``right``
    step names the sibling digest and its side, a ``promoted`` step records
    that the node was the lone odd child and went up unchanged. Every step
    also carries the resulting parent digest, so a verifier recomputing the
    path sees a tampered sibling immediately, not only at the root.
    """
    if not leaf_digests:
        raise ValueError("cannot build a proof over an empty tree")
    if not 0 <= leaf_index < len(leaf_digests):
        raise ValueError("leaf_index out of range")
    level = list(leaf_digests)
    idx = leaf_index
    steps: list[DisclosureProofStep] = []
    level_no = 0
    while len(level) > 1:
        cur = level[idx]
        if idx % 2 == 1:
            position = "right"
            sibling: Optional[str] = level[idx - 1]
        elif idx + 1 < len(level):
            position = "left"
            sibling = level[idx + 1]
        else:
            position = "promoted"
            sibling = None
        parent = _parent(position, cur, sibling)
        steps.append(DisclosureProofStep(
            level=level_no, position=position, sibling_digest=sibling,
            result_digest=parent))
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(sha256_hex(bytes.fromhex(level[i])
                                      + bytes.fromhex(level[i + 1])))
            else:
                nxt.append(level[i])  # odd-node promotion
        level = nxt
        idx //= 2
        level_no += 1
    return steps


def verify_leaf_proof(leaf_index: int, leaf_count: int,
                      leaf_digest: str, steps: list[DisclosureProofStep],
                      root_hex: str) -> DisclosureVerifyResult:
    """Recompute the root from one leaf and its path. Pure: only the leaf
    digest, the proof steps and the caller-supplied frozen root are used."""

    def fail(code: str, message: str) -> DisclosureVerifyResult:
        return DisclosureVerifyResult(
            valid=False, leaf_index=leaf_index, leaf_count=leaf_count,
            leaf_digest=leaf_digest, merkle_root=root_hex,
            error_code=code, error=message)

    if leaf_count < 1:
        return fail("DISCLOSURE_VERIFY_BAD_SHAPE", "leaf_count must be >= 1")
    if leaf_index >= leaf_count:
        return fail("DISCLOSURE_LEAF_INDEX_OUT_OF_RANGE",
                    f"leaf_index {leaf_index} is outside the 0..{leaf_count - 1} tree")
    try:
        cur = leaf_digest
        bytes.fromhex(cur)
        bytes.fromhex(root_hex)
    except ValueError:
        return fail("DISCLOSURE_VERIFY_BAD_SHAPE",
                    "leaf digest and root must be lowercase hex SHA-256")

    idx = leaf_index
    remaining = leaf_count
    level_no = 0
    for step in steps:
        if remaining <= 1:
            return fail("DISCLOSURE_PATH_NOT_CLOSED",
                        "the proof carries extra steps after reaching the root")
        if idx % 2 == 1:
            expected_position = "right"
        elif idx == remaining - 1:
            expected_position = "promoted"
        else:
            expected_position = "left"
        if step.level != level_no:
            return fail("DISCLOSURE_STEP_LEVEL_MISMATCH",
                        f"step {level_no} targets level {step.level}, "
                        f"expected {level_no}")
        if step.position != expected_position:
            return fail("DISCLOSURE_STEP_POSITION_MISMATCH",
                        f"level {level_no}: proof says {step.position}, but "
                        f"index {idx} in a level of {remaining} nodes must be "
                        f"{expected_position}")
        if step.position != "promoted" and not step.sibling_digest:
            return fail("DISCLOSURE_STEP_POSITION_MISMATCH",
                        f"level {level_no}: hash step is missing its sibling digest")
        if step.position == "promoted" and step.sibling_digest:
            return fail("DISCLOSURE_STEP_POSITION_MISMATCH",
                        f"level {level_no}: promotion step must not carry a sibling")
        try:
            parent = _parent(step.position, cur, step.sibling_digest)
        except ValueError:
            return fail("DISCLOSURE_VERIFY_BAD_SHAPE",
                        f"level {level_no}: sibling digest is not valid hex")
        if step.result_digest != parent:
            return fail("DISCLOSURE_STEP_DIGEST_MISMATCH",
                        f"level {level_no}: recombining the node with the "
                        f"declared sibling yields {parent}, not the recorded "
                        f"{step.result_digest}")
        cur = parent
        idx //= 2
        remaining = (remaining + 1) // 2
        level_no += 1

    if remaining != 1:
        return fail("DISCLOSURE_PATH_NOT_CLOSED",
                    f"the path ends at level {level_no} with {remaining} "
                    f"nodes still open; it never closes to a single root")
    recomputed = cur
    if recomputed != root_hex:
        return DisclosureVerifyResult(
            valid=False, leaf_index=leaf_index, leaf_count=leaf_count,
            leaf_digest=leaf_digest, merkle_root=root_hex,
            recomputed_root=recomputed,
            error_code="DISCLOSURE_ROOT_MISMATCH",
            error="the proof recomputes to a different root than the frozen "
                  "Merkle root; the disclosed leaf is not part of the sealed tree")
    return DisclosureVerifyResult(
        valid=True, leaf_index=leaf_index, leaf_count=leaf_count,
        leaf_digest=leaf_digest, merkle_root=root_hex,
        recomputed_root=recomputed)


def evaluate_verification(req: DisclosureVerifyRequest) -> DisclosureVerifyResult:
    """Stateless verification endpoint logic."""
    result = verify_leaf_proof(req.leaf_index, req.leaf_count, req.leaf_digest,
                               req.proof_steps, req.merkle_root)
    result.proof_id = req.proof_id
    result.chunk_id = req.chunk_id
    return result


def _valid_boundaries(leaves: list[DisclosureLeaf],
                      total_sectors: int) -> list[int]:
    bounds = {0, total_sectors}
    bounds.update(leaf.start_sector for leaf in leaves if leaf.start_sector > 0)
    return sorted(b for b in bounds if 0 <= b <= total_sectors)


def resolve_selection(req: DisclosureProofCreate,
                      leaves: list[DisclosureLeaf],
                      all_chunk_ids: set[str],
                      total_sectors: int
                      ) -> list[tuple[DisclosureLeaf, set[str]]]:
    """Apply the request selectors to the frozen leaf sequence.

    Returns each selected leaf with the selectors naming it (in request
    order: chunk ids first, then ranges). A chunk replaced by a correction,
    an unknown chunk, a range crossing a chunk boundary, an out-of-medium
    range, a gap/partial chunk or selecting the same leaf twice all refuse
    the whole request — proofs are never issued for ambiguous selections.
    """
    by_id = {leaf.chunk_id: leaf for leaf in leaves}
    selected: dict[int, set[str]] = {}

    def mark(leaf: DisclosureLeaf, selector: str) -> None:
        selected.setdefault(leaf.index, set()).add(selector)

    for cid in req.chunk_ids:
        leaf = by_id.get(cid)
        if leaf is None:
            if cid in all_chunk_ids:
                raise DisclosureError(
                    "DISCLOSURE_CHUNK_SUPERSEDED",
                    f"chunk {cid} was superseded by a correction and is not a "
                    f"leaf of the sealed Merkle tree; disclose the effective "
                    f"chunk that replaced it instead",
                    chunk_id=cid,
                    effective_chunk_ids=[leaf.chunk_id for leaf in leaves])
            raise DisclosureError(
                "DISCLOSURE_CHUNK_NOT_FOUND",
                f"chunk {cid} is not registered in the sealed manifest",
                chunk_id=cid)
        mark(leaf, "chunk_id")

    boundaries = _valid_boundaries(leaves, total_sectors)
    for rng in req.sector_ranges:
        s0, s1 = rng.start_sector, rng.end_sector
        if s1 > total_sectors:
            raise DisclosureError(
                "DISCLOSURE_RANGE_OUT_OF_BOUNDS",
                f"sector range [{s0},{s1}) exceeds the sealed medium geometry "
                f"({total_sectors} sectors)",
                start_sector=s0, end_sector=s1, total_sectors=total_sectors)
        overlapping = [leaf for leaf in leaves
                       if max(leaf.start_sector, s0) < min(leaf.end_sector, s1)]
        aligned = bool(
            overlapping
            and overlapping[0].start_sector == s0
            and overlapping[-1].end_sector == s1
            and all(overlapping[i + 1].index == overlapping[i].index + 1
                    and overlapping[i].end_sector == overlapping[i + 1].start_sector
                    for i in range(len(overlapping) - 1)))
        if not aligned:
            raise DisclosureError(
                "DISCLOSURE_RANGE_NOT_ALIGNED",
                f"sector range [{s0},{s1}) must line up exactly with effective "
                f"chunk boundaries and fully contain every chunk it starts in",
                start_sector=s0, end_sector=s1,
                valid_boundaries=boundaries)
        for leaf in overlapping:
            mark(leaf, "sector_range")

    if not selected:
        raise DisclosureError(
            "DISCLOSURE_SELECTION_EMPTY",
            "the disclosure request selects no chunk")

    duplicated = [leaves[idx].chunk_id for idx, selectors in selected.items()
                  if len(selectors) > 1]
    if duplicated:
        raise DisclosureError(
            "DISCLOSURE_DUPLICATE_LEAF",
            "the same sealed leaf is selected by more than one selector; list "
            "each disclosed chunk exactly once",
            chunk_ids=sorted(duplicated))

    return [(leaves[idx], selected[idx]) for idx in sorted(selected)]


def _rationale(leaf: DisclosureLeaf, selectors: set[str],
               req: DisclosureProofCreate) -> str:
    parts: list[str] = []
    if "chunk_id" in selectors:
        parts.append(f"explicitly requested by chunk_id {leaf.chunk_id}")
    if "sector_range" in selectors:
        covering = [r for r in req.sector_ranges
                    if r.start_sector <= leaf.start_sector
                    and r.end_sector >= leaf.end_sector]
        span = ", ".join(f"[{r.start_sector},{r.end_sector})" for r in covering)
        parts.append(
            f"covered by requested sector range {span}, which aligns exactly "
            f"with the effective chunk boundary of {leaf.chunk_id} "
            f"(sectors [{leaf.start_sector},{leaf.end_sector}))")
    return "; ".join(parts)


def _merge_leaf_ranges(chosen: list[DisclosureLeaf]) -> list[SectorInterval]:
    intervals = sorted((leaf.start_sector, leaf.end_sector) for leaf in chosen)
    merged: list[list[int]] = []
    for s0, s1 in intervals:
        if merged and s0 <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], s1)
        else:
            merged.append([s0, s1])
    return [SectorInterval(start_sector=a, end_sector=b) for a, b in merged]


def build_disclosure_proof(*, request: DisclosureProofCreate,
                           manifest_row: Any,
                           sealed_payload: Any,
                           ordered_chunk_ids: list[str],
                           frozen_root: Optional[str],
                           evidence_package_digest: str,
                           created_at: str) -> DisclosureProof:
    """Assemble and self-verify one disclosure proof. Raises
    :class:`DisclosureError` for any selection that cannot be proven."""
    geom = sealed_payload.media.geometry
    sector_size = int(geom.sector_size)
    total_sectors = int(geom.total_sectors)
    leaves = build_leaves(sealed_payload, ordered_chunk_ids, sector_size)

    digests = [leaf.digest for leaf in leaves]
    if not frozen_root:
        raise DisclosureError(
            "DISCLOSURE_FROZEN_ROOT_MISSING",
            "the sealed manifest carries no Merkle root",
            status_code=500)
    # Defense in depth: the frozen record must itself be internally coherent
    # before any proof is issued under its root.
    recomputed_root = merkle_root(digests)
    if recomputed_root != frozen_root:
        raise DisclosureError(
            "DISCLOSURE_FROZEN_ROOT_INCONSISTENT",
            "the Merkle root frozen in the sealed manifest does not recompute "
            "from the frozen ordered chunk leaves; no proof can be issued",
            status_code=500,
            frozen_root=frozen_root, recomputed_root=recomputed_root)

    all_chunk_ids = {c.chunk_id for c in sealed_payload.chunks}
    chosen = resolve_selection(request, leaves, all_chunk_ids, total_sectors)

    leaf_proofs: list[DisclosureLeafProof] = []
    for leaf, selectors in chosen:
        steps = build_merkle_proof(digests, leaf.index)
        check = verify_leaf_proof(leaf.index, len(leaves), leaf.digest,
                                  steps, frozen_root)
        if not check.valid:
            raise DisclosureError(
                "DISCLOSURE_PROOF_SELF_CHECK_FAILED",
                f"generated proof for chunk {leaf.chunk_id} does not close to "
                f"the frozen root ({check.error_code})",
                status_code=500, chunk_id=leaf.chunk_id,
                error_code=check.error_code)
        leaf_proofs.append(DisclosureLeafProof(
            chunk_id=leaf.chunk_id, leaf_index=leaf.index,
            leaf_digest=leaf.digest, start_sector=leaf.start_sector,
            end_sector=leaf.end_sector,
            selected_by=sorted(selectors),
            selection_rationale=_rationale(leaf, selectors, request),
            proof_steps=steps))

    chosen_leaves = [leaf for leaf, _ in chosen]
    covered = _merge_leaf_ranges(chosen_leaves)
    proof = DisclosureProof(
        format=DISCLOSURE_FORMAT,
        proof_id=request.proof_id,
        manifest_id=manifest_row["manifest_id"],
        media_id=manifest_row["media_id"],
        revision=int(manifest_row["revision"]),
        evidence_package_digest=evidence_package_digest,
        merkle_root=frozen_root,
        leaf_ordering_rule=DISCLOSURE_LEAF_ORDERING,
        merkle_spec=dict(MERKLE_SPEC),
        leaf_count=len(leaves),
        ordered_leaves=[DisclosureLeafOrderingEntry(
            leaf_index=leaf.index, chunk_id=leaf.chunk_id,
            start_sector=leaf.start_sector, end_sector=leaf.end_sector)
            for leaf in leaves],
        request={
            "chunk_ids": list(request.chunk_ids),
            "sector_ranges": [r.model_dump() for r in request.sector_ranges],
            "requested_by": request.requested_by,
            "reason": request.reason,
            "note": request.note,
        },
        covered_sector_ranges=covered,
        covered_sectors=sum(iv.end_sector - iv.start_sector for iv in covered),
        total_sectors=total_sectors,
        leaf_proofs=leaf_proofs,
        created_at=created_at)
    proof.disclosure_digest = sha256_hex(canonical_bytes(
        proof.model_dump(exclude={"disclosure_digest"}, mode="json")))
    return proof
