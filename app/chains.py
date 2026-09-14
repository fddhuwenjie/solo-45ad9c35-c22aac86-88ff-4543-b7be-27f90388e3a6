"""Minimum provenance-chain integrity for replicas and custody events.

A manifest can only be sealed when the records actually prove digest
continuity from the acquired image, through every copy, to a sealed and
handed-over terminal replica:

* at least one ``acquired`` replica bound to a known session;
* every non-acquired replica descends (same digest) from an existing replica;
* the acquired replica has an ``acquired`` event, each copy has a ``copied``
  event, and at least one terminal (leaf) replica has both ``sealed`` and
  ``transferred`` events;
* every replica carries at least one custody event and per-event
  digest_before/digest_after chaining is intact.

The analysis is pure over plain dicts/Pydantic rows so the evidence package
``/evidence/recompute`` endpoint can rerun it offline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

REQUIRED_EVENT_BY_ROLE = {
    "acquired": "acquired",
    "copy": "copied",
    "archive": "copied",
}


@dataclass
class ChainState:
    replica_ok: bool = False
    custody_ok: bool = False
    proven: bool = False
    terminal_replica_ids: list[str] = field(default_factory=list)
    chain_path: list[str] = field(default_factory=list)


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def analyze_replica_custody(
    replicas: list[Any],
    custody_events: list[Any],
    session_ids: set[str],
    *,
    image_digest: Optional[str] = None,
    expected_total_sha256: Optional[str] = None,
    merkle_root: Optional[str] = None,
    media_id: Optional[str] = None,
    emit: Optional[Callable[..., None]] = None,
) -> ChainState:
    """Validate the replica/custody graph.

    ``emit(severity, code, message, **kw)`` receives findings; when omitted a
    collecting emitter is built. Returns the resulting :class:`ChainState`.
    """
    findings: list[tuple[str, str, str, dict]] = []

    def out(severity: str, code: str, message: str, **kw: Any) -> None:
        findings.append((severity, code, message, kw))
        if emit is not None:
            emit(severity, code, message, **kw)

    state = ChainState()

    # ------------------------------------------------------------ registry --
    by_id: dict[str, Any] = {}
    dup: set[str] = set()
    for r in replicas:
        rid = _get(r, "replica_id")
        if rid in by_id:
            out("error", "REPLICA_DUPLICATE",
                f"replica {rid} declared more than once", replica_ids=[rid])
            dup.add(rid)
        by_id[rid] = r

    acquired = [r for r in replicas if _get(r, "role") == "acquired"]
    terminals = [rid for rid, r in by_id.items()
                 if rid not in {_get(x, "parent_replica_id") for x in replicas
                                if _get(x, "parent_replica_id")}]
    state.terminal_replica_ids = sorted(terminals)

    if not replicas:
        out("error", "REPLICA_CHAIN_EMPTY",
            "no storage replicas registered; cannot prove the image was ever "
            "acquired")
    if not acquired:
        out("error", "REPLICA_NO_ACQUISITION",
            "no replica with role=acquired anchors the provenance chain")

    # An actual replication stage is mandatory: the acquired replica alone,
    # even with acquired/sealed/transferred events, does not prove that the
    # image was ever copied or archived.
    copied_replicas = [r for r in replicas
                       if _get(r, "role") in ("copy", "archive")]
    if not copied_replicas:
        out("error", "REPLICA_CHAIN_NO_COPY_STAGE",
            "the only replica is role=acquired; a copy/archive replica is "
            "required to prove a real replication stage before hand-over",
            replica_ids=[_get(r, "replica_id") for r in acquired])

    # per-replica structural rules
    structurally_valid = (bool(replicas) and bool(acquired)
                          and bool(copied_replicas) and not dup)
    image_ok_for: set[str] = set()
    image_digest = image_digest or expected_total_sha256
    for r in replicas:
        rid = _get(r, "replica_id")
        role = _get(r, "role")
        if role == "acquired":
            sid = _get(r, "session_id")
            if not sid or sid not in session_ids:
                out("error", "REPLICA_SESSION_UNKNOWN",
                    f"acquired replica {rid} is not bound to a known acquisition "
                    f"session", replica_ids=[rid], session_id=sid)
                structurally_valid = False
            if image_digest is not None and _get(r, "sha256") != image_digest:
                out("error", "ACQUIRED_DIGEST_MISMATCH",
                    f"acquired replica {rid} digest does not match the "
                    f"reconstructed/declared image digest",
                    replica_ids=[rid],
                    detail={"replica": _get(r, "sha256"),
                            "expected": image_digest})
                structurally_valid = False
            else:
                image_ok_for.add(rid)
            rep_merkle = _get(r, "merkle_root")
            if rep_merkle and merkle_root and rep_merkle != merkle_root:
                out("error", "REPLICA_MERKLE_MISMATCH",
                    f"replica {rid} Merkle root disagrees with chunk reconstruction",
                    replica_ids=[rid],
                    detail={"replica": rep_merkle, "computed": merkle_root})
                structurally_valid = False
        else:
            parent_id = _get(r, "parent_replica_id")
            if not parent_id:
                out("error", "REPLICA_PARENT_MISSING",
                    f"{role} replica {rid} has no parent replica",
                    replica_ids=[rid])
                structurally_valid = False
            elif parent_id not in by_id:
                out("error", "REPLICA_PARENT_UNKNOWN",
                    f"replica {rid} descends from unknown replica {parent_id}",
                    replica_ids=[rid, parent_id])
                structurally_valid = False
            else:
                parent = by_id[parent_id]
                if _get(parent, "sha256") != _get(r, "sha256"):
                    out("error", "REPLICA_COPY_DIGEST_MISMATCH",
                        f"{role} replica {rid} digest differs from its parent "
                        f"{parent_id}",
                        replica_ids=[parent_id, rid],
                        detail={"parent": _get(parent, "sha256"),
                                "child": _get(r, "sha256")})
                    structurally_valid = False

    # ------------------------------------------------------------ events ----
    event_ids: set[str] = set()
    events_by_replica: dict[str, list[Any]] = {rid: [] for rid in by_id}
    custody_present = bool(custody_events)
    for e in custody_events:
        eid = _get(e, "event_id")
        rid = _get(e, "replica_id")
        if eid in event_ids:
            out("error", "CUSTODY_EVENT_DUPLICATE",
                f"custody event {eid} declared more than once", event_id=eid)
        event_ids.add(eid)
        if rid not in by_id:
            out("error", "CUSTODY_REPLICA_UNKNOWN",
                f"event {eid} references unknown replica {rid}",
                event_id=eid, replica_ids=[rid])
        else:
            events_by_replica[rid].append(e)

    if not custody_events:
        out("error", "CUSTODY_CHAIN_EMPTY",
            "no custody events registered; acquisition -> copy -> seal -> "
            "transfer continuity cannot be proven")

    custody_valid = bool(custody_events)
    required_types: dict[str, set[str]] = {}
    for rid, r in by_id.items():
        evs = sorted(events_by_replica.get(rid, []),
                     key=lambda x: (str(_get(x, "at")), str(_get(x, "event_id"))))
        role = _get(r, "role")
        required = {REQUIRED_EVENT_BY_ROLE.get(role, "")}
        required.discard("")
        present_types = {_get(e, "event_type") for e in evs}
        required_types[rid] = required

        if not evs:
            out("error", "CUSTODY_NO_EVENTS",
                f"replica {rid} has no custody events", replica_ids=[rid])
            custody_valid = False
            out("error", "CUSTODY_EVENT_MISSING",
                f"replica {rid} ({role}) lacks required custody event "
                f"{sorted(required)}",
                replica_ids=[rid],
                detail={"required": sorted(required), "present": []})
            continue

        missing = required - present_types
        if missing:
            out("error", "CUSTODY_EVENT_MISSING",
                f"replica {rid} ({role}) lacks required custody event "
                f"{sorted(missing)}",
                replica_ids=[rid],
                event_id=None,
                detail={"required": sorted(missing), "present": sorted(present_types)})
            custody_valid = False

        # per-event before/after chaining
        prev_after: Optional[str] = None
        replica_digest = _get(r, "sha256")
        for e in evs:
            expected_before = (prev_after if prev_after is not None
                               else replica_digest)
            db = _get(e, "digest_before")
            da = _get(e, "digest_after")
            ed = _get(e, "expected_digest")
            if db and db != expected_before:
                out("error", "CUSTODY_DIGEST_BREAK",
                    f"event {_get(e, 'event_id')}: digest_before does not chain "
                    f"from the replica/previous event",
                    replica_ids=[rid], event_id=_get(e, "event_id"),
                    detail={"expected": expected_before, "actual": db})
                custody_valid = False
            if da and da != replica_digest:
                out("error", "CUSTODY_DIGEST_AFTER_BREAK",
                    f"event {_get(e, 'event_id')}: post-event digest differs from "
                    f"replica digest (tampering or bad reseal)",
                    replica_ids=[rid], event_id=_get(e, "event_id"),
                    detail={"expected": replica_digest, "actual": da})
                custody_valid = False
            if ed and ed != replica_digest:
                out("error", "CUSTODY_EXPECTED_MISMATCH",
                    f"event {_get(e, 'event_id')}: expected/hand-over digest does "
                    f"not match the replica",
                    replica_ids=[rid], event_id=_get(e, "event_id"),
                    detail={"expected": replica_digest, "declared": ed})
                custody_valid = False
            prev_after = da or expected_before

    # terminal replica must be sealed AND transferred
    sealed_terminals: list[str] = []
    for rid in terminals:
        types_present = {_get(e, "event_type")
                         for e in events_by_replica.get(rid, [])}
        if {"sealed", "transferred"} <= types_present:
            sealed_terminals.append(rid)
        elif rid in by_id:
            missing = sorted({"sealed", "transferred"} - types_present)
            out("error", "CUSTODY_TERMINAL_NOT_HANDED_OVER",
                f"terminal replica {rid} is missing {missing} events; no record "
                f"proves sealing and hand-over of the final image",
                replica_ids=[rid],
                detail={"missing": missing,
                        "present": sorted(types_present)})
            custody_valid = False

    # --------------------- continuity path acquired -> terminal -------------
    # The proven path must exist structurally independent of the other errors:
    # even when per-replica/custody checks fail elsewhere, the absence of a
    # copy/archive stage on any acquisition -> terminal path is reported.
    proven = False
    chain_path: list[str] = []
    if bool(acquired):
        children: dict[str, list[str]] = {}
        for r in replicas:
            pid = _get(r, "parent_replica_id")
            if pid:
                children.setdefault(pid, []).append(_get(r, "replica_id"))

        def walk(rid: str, path: list[str], saw_copy: bool = False) -> bool:
            role = _get(by_id.get(rid), "role")
            saw_copy = saw_copy or role in ("copy", "archive")
            types_present = {_get(e, "event_type")
                             for e in events_by_replica.get(rid, [])}
            req = required_types.get(rid, set())
            if not req <= types_present:
                return False
            # Success requires a real replication stage on the path; an
            # acquired replica can never terminate the proven chain by itself.
            if rid in sealed_terminals and saw_copy:
                chain_path[:] = path + [rid]
                return True
            for child in sorted(children.get(rid, [])):
                if walk(child, path + [rid], saw_copy):
                    return True
            return False

        proven = any(walk(_get(r, "replica_id"), []) for r in acquired)

    if replicas and not proven:
        out("error", "REPLICA_CHAIN_UNPROVEN",
            "records cannot prove digest continuity from acquisition through "
            "a copy/archive replica to a sealed, transferred terminal")

    state.replica_ok = structurally_valid
    state.custody_ok = custody_valid
    # proven requires the reachable copy-stage path AND every structural and
    # custody check above (digest chaining included).
    state.proven = proven and structurally_valid and custody_valid
    state.chain_path = chain_path
    return state
