"""Reproducible JSON evidence packages and revision comparison."""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Optional

from .hashing import canonical_bytes, sha256_hex
from .schemas import (
    DiffReport,
    EvaluationReport,
    FieldChange,
    ManifestCreate,
)

PACKAGE_FORMAT = "split-image-evidence/v1"
MERKLE_SPEC = {
    "algorithm": "sha256",
    "leaf": "sha256(chunk bytes), hex encoded, in reconstructed offset order",
    "internal": "sha256(left_digest_bytes + right_digest_bytes)",
    "odd_node": "promoted unchanged to the next level",
}


def payload_from_row(row: sqlite3.Row) -> ManifestCreate:
    return ManifestCreate.model_validate(json.loads(row["payload_json"]))


def report_from_json(raw: Optional[str]) -> Optional[EvaluationReport]:
    return EvaluationReport.model_validate(json.loads(raw)) if raw else None


def _sorted_findings(report: EvaluationReport) -> list[dict[str, Any]]:
    items = [f.model_dump(mode="json") for f in report.findings]
    items.sort(key=lambda f: (f["severity"], f["code"],
                              json.dumps(f, sort_keys=True, ensure_ascii=False)))
    return items


def build_evidence_package(row: sqlite3.Row,
                           report: EvaluationReport,
                           *,
                           status_override: Optional[str] = None,
                           sealed_at_override: Optional[str] = None
                           ) -> dict[str, Any]:
    """Assemble a deterministic, self-describing evidence package.

    Everything needed to recompute the roots (canonical submission, Merkle
    recipe and coverage map) is included. ``evidence_package_digest`` covers
    the package with that field removed, so re-fetching and recomputing yields
    the same digest. ``status_override``/``sealed_at_override`` let the sealing
    endpoint construct the package before the sealed state is committed, so a
    package-building failure never leaves the manifest half-sealed.
    """
    payload = payload_from_row(row)
    payload_obj = payload.model_dump(mode="json")

    package: dict[str, Any] = {
        "package": {
            "format": PACKAGE_FORMAT,
            "manifest_id": row["manifest_id"],
            "media_id": row["media_id"],
            "revision": row["revision"],
            "status": status_override or row["status"],
            "change_kind": row["change_kind"],
            "parent_manifest_id": row["parent_manifest_id"],
            "superseded_by": row["superseded_by"],
            "created_at": row["created_at"],
            "sealed_at": (sealed_at_override if sealed_at_override is not None
                          else row["sealed_at"]),
            "payload_digest": row["payload_digest"],
        },
        "submission": payload_obj,
        "computed": {
            "ordered_chunk_ids": report.ordered_chunk_ids,
            "merkle_root": report.merkle_root,
            "merkle_spec": MERKLE_SPEC,
            "reconstructed_sha256": report.reconstructed_sha256,
            "expected_total_sha256": report.expected_total_sha256,
            "total_hash_verified": report.total_hash_verified,
            "all_chunk_digests_verified": report.all_chunk_digests_verified,
            "chunk_content": [c.model_dump() for c in report.chunk_content],
            "replica_chain_proven": report.replica_chain_proven,
            "provenance_path": report.provenance_path,
            "terminal_replica_ids": report.terminal_replica_ids,
            "coverage": {
                "total_sectors": report.total_sectors,
                "covered_sectors": report.covered_sectors,
                "complete": report.complete_coverage,
                "covered_intervals": [i.model_dump() for i in
                                      report.covered_intervals],
                "gaps": [i.model_dump() for i in report.gaps],
                "overlaps": [o.model_dump() for o in report.overlaps],
            },
            "recovery": report.recovery.model_dump(mode="json"),
        },
        "findings": _sorted_findings(report),
        "sealable": report.sealable,
        "recompute": {
            "canonical_json": "json.dumps(obj, sort_keys=True, "
                              "separators=(',', ':'), ensure_ascii=False)",
            "linear_hash": "sha256(concatenation of chunk bytes in "
                           "ordered_chunk_ids order)",
            "chunk_content": "each effective chunk's SHA-256 is recomputed "
                             "from inline content_b64 or the registered "
                             "stored_path and compared with its declared digest",
            "merkle": MERKLE_SPEC,
            "replica_custody_chain": "acquired replica -> same-digest copies -> "
                                     "terminal replica with sealed+transferred "
                                     "events; every event's digest_before/"
                                     "digest_after must equal the replica digest",
            "checks": [
                "payload_digest == sha256(canonical_json(submission))",
                "every effective chunk digest recomputes from actual bytes",
                "merkle_root recomputed from ordered chunk sha256 leaves",
                "coverage intervals equal full [0,total_sectors) without overlap",
                "reconstructed_sha256 == expected_total_sha256 when present",
                "read attempts split overlapping ranges into atomic segments; "
                "later successful reads supersede earlier failures while "
                "failure records stay; final segments are labelled read/fill/"
                "unrecovered and fill bytes/sparse holes match the image",
                "successful read digests recompute from the bound chunks and "
                "no two successful reads of the same range disagree",
                "documented recovery exceptions only cover still-unrecovered "
                "sectors and unrecovered-but-unaccepted sectors fit the frozen "
                "policy; recovery/fill rates match",
                "replica digests chain acquisition -> copy -> archive",
                "custody digest_before/digest_after chain per replica",
                "a terminal replica records both sealed and transferred events",
            ],
        },
    }
    package["evidence_package_digest"] = sha256_hex(canonical_bytes(package))
    return package


def package_digest(package: dict[str, Any]) -> str:
    body = {k: v for k, v in package.items() if k != "evidence_package_digest"}
    return sha256_hex(canonical_bytes(body))


def diff_manifests(left_row: sqlite3.Row,
                   right_row: sqlite3.Row,
                   left_report: EvaluationReport,
                   right_report: EvaluationReport) -> DiffReport:
    left = payload_from_row(left_row)
    right = payload_from_row(right_row)

    media_fields = ("evidence_label", "interface")
    geom_fields = ("sector_size", "total_sectors", "capacity_bytes",
                   "media_sn", "model", "firmware")
    field_changes: list[FieldChange] = []
    for f in media_fields:
        lv, rv = getattr(left.media, f), getattr(right.media, f)
        if lv != rv:
            field_changes.append(FieldChange(field=f"media.{f}", left=lv, right=rv))
    for f in geom_fields:
        lv, rv = getattr(left.media.geometry, f), getattr(right.media.geometry, f)
        if lv != rv:
            field_changes.append(FieldChange(field=f"media.geometry.{f}",
                                             left=lv, right=rv))

    def _ids(seq, attr):
        return {getattr(x, attr): x for x in seq}

    ls, rs = _ids(left.sessions, "session_id"), _ids(right.sessions, "session_id")
    lc, rc = _ids(left.chunks, "chunk_id"), _ids(right.chunks, "chunk_id")
    lr, rr = _ids(left.replicas, "replica_id"), _ids(right.replicas, "replica_id")
    le, re = _ids(left.custody_events, "event_id"), _ids(right.custody_events,
                                                          "event_id")
    la, ra = _ids(left.read_attempts, "attempt_id"), \
        _ids(right.read_attempts, "attempt_id")
    lx, rx = _ids(left.recovery_exceptions, "exception_id"), \
        _ids(right.recovery_exceptions, "exception_id")

    chunk_digest_changed = sorted(cid for cid in lc.keys() & rc.keys()
                                  if lc[cid].sha256 != rc[cid].sha256
                                  or lc[cid].offset != rc[cid].offset
                                  or lc[cid].length != rc[cid].length)

    def _attempt_signature(a):
        return (a.session_id, a.chunk_id, a.start_sector, a.end_sector,
                a.round, a.result, a.tool_error_code, a.actual_read_length,
                a.fill_method, a.fill_value, a.sparse_hole, a.sha256)

    attempts_changed = sorted(aid for aid in la.keys() & ra.keys()
                              if _attempt_signature(la[aid])
                              != _attempt_signature(ra[aid]))

    return DiffReport(
        left_manifest_id=left_row["manifest_id"],
        right_manifest_id=right_row["manifest_id"],
        left_change_kind=left_row["change_kind"],
        right_change_kind=right_row["change_kind"],
        media_field_changes=field_changes,
        sessions_added=sorted(rs.keys() - ls.keys()),
        sessions_removed=sorted(ls.keys() - rs.keys()),
        chunks_added=sorted(rc.keys() - lc.keys()),
        chunks_removed=sorted(lc.keys() - rc.keys()),
        chunk_digests_changed=chunk_digest_changed,
        replicas_added=sorted(rr.keys() - lr.keys()),
        replicas_removed=sorted(lr.keys() - rr.keys()),
        events_added=sorted(re.keys() - le.keys()),
        events_removed=sorted(le.keys() - re.keys()),
        merkle_root_left=left_report.merkle_root,
        merkle_root_right=right_report.merkle_root,
        reconstructed_sha256_left=left_report.reconstructed_sha256,
        reconstructed_sha256_right=right_report.reconstructed_sha256,
        attempts_added=sorted(ra.keys() - la.keys()),
        attempts_removed=sorted(la.keys() - ra.keys()),
        attempt_results_changed=attempts_changed,
        exceptions_added=sorted(rx.keys() - lx.keys()),
        exceptions_removed=sorted(lx.keys() - rx.keys()),
        recovery_rate_left=left_report.recovery.recovery_rate,
        recovery_rate_right=right_report.recovery.recovery_rate,
        unrecovered_sectors_left=left_report.recovery.unrecovered_sectors,
        unrecovered_sectors_right=right_report.recovery.unrecovered_sectors,
        accepted_sectors_left=left_report.recovery.accepted_sectors,
        accepted_sectors_right=right_report.recovery.accepted_sectors,
    )
