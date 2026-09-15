"""Post-seal custody transfer continuation.

The ``custody_events`` frozen into a sealed manifest end at the sealing-time
hand-over: a copy handed over again afterwards has no continuation entry in
the sealed record, and two transfers initiated in parallel by the same
holder would silently fork the custody chain. This module continues the
chain off-chain-record without touching the sealed manifest:

* a **proposal** cites the sealed manifest, the evidence package digest, the
  replica and the CURRENT custody chain head it extends, and freezes the
  handing-over party, the receiving party, the location and the validity
  window;
* the receiver answers with a **receipt** binding the inspection records of
  that replica completed inside the window;
* the service checks both party identities against the proposal, the
  uniqueness of the predecessor head (the chain advances only from the live
  tip, so a parallel transfer that consumed the head first wins and the
  chain can never fork), the attribution and conclusion of every bound
  inspection (must belong to the transferred replica, must be ``passed``),
  digest continuity (receipt package digest == sealed package digest) and
  time ordering (receipt and inspection readings inside the window);
* an effective receipt mints the next chain head with a SHA-256 hash link
  to its predecessor; an expired window, a duplicate receipt, an occupied
  head, a failed/inconclusive inspection or a package digest mismatch leave
  the transfer without effect — but the attempt is appended to the record
  all the same, so the rejection basis stays auditable.

The genesis head of every replica is derived from the sealed manifest's
frozen custody events (its terminal event); later heads come from effective
receipts. The chain state is a pure function of the stored append-only
records, so history queries and the JSON transfer package always reassemble
the same proposal, receipts, inspection references and rejection basis.
"""
from __future__ import annotations

from typing import Any, Optional

from .hashing import canonical_bytes, sha256_hex
from .inspection import as_utc
from .schemas import (
    TRANSFER_PACKAGE_FORMAT,
    CustodyChainHead,
    CustodyChainReplicaView,
    CustodyTransferInspectionRef,
    CustodyTransferProposal,
    CustodyTransferReceiptCreate,
    CustodyTransferReceiptReport,
    Finding,
    InspectionReport,
    Severity,
)

HEAD_FORMAT = "split-image-custody-head/v1"


def genesis_head_id(replica_id: str) -> str:
    """Deterministic id of the chain head derived from the sealed record."""
    return f"HEAD-SEALED-{replica_id}"


def transfer_head_id(proposal_id: str) -> str:
    """Deterministic id of the head an effective receipt of ``proposal_id``
    mints."""
    return f"HEAD-{proposal_id}"


def _head_digest(payload: dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes(payload))


def genesis_heads(sealed_payload: Any, *, manifest_id: str,
                  evidence_package_digest: Optional[str],
                  image_sha256: Optional[str],
                  created_at: Any) -> dict[str, CustodyChainHead]:
    """Derive the genesis chain head of every registered replica from the
    sealed manifest's frozen custody events.

    The head anchors on the replica's terminal (latest) custody event; the
    current custodian is that event's counterpart (the receiving party of a
    hand-over) or its actor. The head digest commits to the manifest, the
    replica, the terminal event, the replica digest and the sealed evidence
    package, so the post-seal chain is hash-anchored in the sealed record.
    """
    events_by_replica: dict[str, list[Any]] = {}
    for e in sealed_payload.custody_events:
        events_by_replica.setdefault(e.replica_id, []).append(e)
    heads: dict[str, CustodyChainHead] = {}
    for replica in sealed_payload.replicas:
        rid = replica.replica_id
        events = sorted(events_by_replica.get(rid, []),
                        key=lambda e: (e.at.isoformat(), e.event_id))
        terminal = events[-1] if events else None
        custodian = replica.custodian
        if terminal is not None:
            custodian = terminal.counterpart or terminal.actor
        head_id = genesis_head_id(rid)
        digest = _head_digest({
            "format": HEAD_FORMAT,
            "source": "sealed",
            "manifest_id": manifest_id,
            "replica_id": rid,
            "terminal_event_id": terminal.event_id if terminal else None,
            "event_type": terminal.event_type if terminal else None,
            "replica_sha256": replica.sha256,
            "evidence_package_digest": evidence_package_digest,
        })
        heads[rid] = CustodyChainHead(
            head_id=head_id, manifest_id=manifest_id, replica_id=rid,
            source="sealed", predecessor_head_id=None,
            predecessor_head_digest=None, head_digest=digest,
            custodian=custodian,
            terminal_event_id=terminal.event_id if terminal else None,
            proposal_id=None, receipt_id=None,
            evidence_package_digest=evidence_package_digest,
            image_sha256=image_sha256,
            at=terminal.at if terminal else None,
            created_at=created_at)
    return heads


def build_chains(genesis: dict[str, CustodyChainHead],
                 receipts: list[CustodyTransferReceiptReport]
                 ) -> dict[str, list[CustodyChainHead]]:
    """Replay the append-only receipt records onto the genesis heads.

    Only effective receipts extend a chain, each from the tip it was
    evaluated against (enforced at insertion time), so the replay can never
    fork: ``chains[rid][-1]`` is the live head of replica ``rid``.
    """
    chains: dict[str, list[CustodyChainHead]] = {
        rid: [head] for rid, head in genesis.items()}
    for rep in receipts:
        if not rep.effective or rep.new_head is None:
            continue
        chains.setdefault(rep.replica_id, []).append(rep.new_head)
    return chains


def current_tips(genesis: dict[str, CustodyChainHead],
                 receipts: list[CustodyTransferReceiptReport]
                 ) -> dict[str, CustodyChainHead]:
    """The live chain head of every replica."""
    return {rid: heads[-1] for rid, heads in
            build_chains(genesis, receipts).items() if heads}


def chain_views(genesis: dict[str, CustodyChainHead],
                receipts: list[CustodyTransferReceiptReport]
                ) -> list[CustodyChainReplicaView]:
    """Per-replica chain view for the history endpoint, in replica order."""
    views: list[CustodyChainReplicaView] = []
    for rid, heads in build_chains(genesis, receipts).items():
        tip = heads[-1]
        views.append(CustodyChainReplicaView(
            replica_id=rid, heads=heads, current_head_id=tip.head_id,
            current_head_digest=tip.head_digest,
            current_custodian=tip.custodian))
    return views


def mint_transfer_head(*, proposal: CustodyTransferProposal,
                       receipt: CustodyTransferReceiptCreate,
                       predecessor: CustodyChainHead,
                       image_sha256: Optional[str],
                       created_at: Any) -> CustodyChainHead:
    """Mint the next chain head for an effective receipt, hash-linked to the
    predecessor head the proposal was anchored to."""
    head_id = transfer_head_id(proposal.proposal_id)
    digest = _head_digest({
        "format": HEAD_FORMAT,
        "source": "transfer",
        "manifest_id": proposal.manifest_id,
        "replica_id": proposal.replica_id,
        "predecessor_head_id": predecessor.head_id,
        "predecessor_head_digest": predecessor.head_digest,
        "proposal_id": proposal.proposal_id,
        "receipt_id": receipt.receipt_id,
        "from_party": proposal.from_party,
        "to_party": proposal.to_party,
        "location": proposal.location,
        "received_at": as_utc(receipt.received_at).isoformat(),
        "evidence_package_digest": proposal.evidence_package_digest,
        "inspection_ids": list(receipt.inspection_ids),
    })
    return CustodyChainHead(
        head_id=head_id, manifest_id=proposal.manifest_id,
        replica_id=proposal.replica_id, source="transfer",
        predecessor_head_id=predecessor.head_id,
        predecessor_head_digest=predecessor.head_digest,
        head_digest=digest, custodian=proposal.to_party,
        terminal_event_id=None, proposal_id=proposal.proposal_id,
        receipt_id=receipt.receipt_id,
        evidence_package_digest=proposal.evidence_package_digest,
        image_sha256=image_sha256,
        at=as_utc(receipt.received_at), created_at=created_at)


def _inspection_ref(inspection: Optional[InspectionReport], *,
                    inspection_id: str,
                    replica_id: str,
                    window_start: Any,
                    window_end: Any) -> CustodyTransferInspectionRef:
    """Resolve one bound inspection record and the checks applied to it."""
    if inspection is None:
        return CustodyTransferInspectionRef(
            inspection_id=inspection_id, attribution_ok=False,
            conclusion_ok=False, within_window=False)
    read_ats = [as_utc(iv.read_at) for iv in inspection.intervals
                if iv.read_at is not None]
    within = bool(read_ats) and all(window_start <= t <= window_end
                                    for t in read_ats)
    return CustodyTransferInspectionRef(
        inspection_id=inspection_id,
        replica_id=inspection.replica_id,
        result=inspection.result,
        seed=inspection.seed,
        sample_ratio=inspection.sample_ratio,
        first_read_at=min(read_ats) if read_ats else None,
        last_read_at=max(read_ats) if read_ats else None,
        verified_sectors=inspection.verified_sectors,
        attribution_ok=inspection.replica_id == replica_id,
        conclusion_ok=inspection.result == "passed",
        within_window=within)


def evaluate_receipt(payload: CustodyTransferReceiptCreate, *,
                     proposal: CustodyTransferProposal,
                     media_id: str,
                     current_tip: CustodyChainHead,
                     sealed_package_digest: Optional[str],
                     image_sha256: Optional[str],
                     inspections: dict[str, InspectionReport],
                     receipt_id_seen: bool,
                     proposal_fulfilled: bool,
                     created_at: Any) -> CustodyTransferReceiptReport:
    """Evaluate one receipt attempt against the live chain state.

    Every check failure leaves the transfer without effect (no new head is
    minted) but is recorded as a finding, so the stored attempt keeps its
    rejection basis. ``current_tip`` is the live chain head of the
    transferred replica at insertion time; ``receipt_id_seen`` /
    ``proposal_fulfilled`` come from the append-only receipt history.
    """
    findings: list[Finding] = []

    def error(code: str, message: str, **kw: Any) -> None:
        findings.append(Finding(code=code, severity=Severity.error,
                                message=message, media_id=media_id, **kw))

    replica_id = proposal.replica_id

    # ---- duplicate receipt: the id was used before, or the proposal already
    # has an effective receipt -- a fulfilled proposal cannot be receipted
    # again.
    if receipt_id_seen:
        error("TRANSFER_RECEIPT_DUPLICATE",
              f"receipt id {payload.receipt_id} was already submitted; "
              f"receipt records are append-only and a re-submission must use "
              f"a new receipt_id",
              detail={"receipt_id": payload.receipt_id})
    if proposal_fulfilled:
        error("TRANSFER_RECEIPT_DUPLICATE",
              f"proposal {proposal.proposal_id} already has an effective "
              f"receipt; the transfer completed and cannot be receipted "
              f"again",
              detail={"proposal_id": proposal.proposal_id})

    # ---- predecessor uniqueness: the chain advances only from the live tip.
    # A parallel transfer that consumed the same head first wins; this
    # proposal's anchor is stale and the chain does not fork.
    if proposal.predecessor_head_id != current_tip.head_id:
        error("TRANSFER_HEAD_OCCUPIED",
              f"chain head {proposal.predecessor_head_id} of replica "
              f"{replica_id} is no longer the live head "
              f"({current_tip.head_id}); another transfer consumed it first "
              f"and the custody chain does not fork",
              replica_ids=[replica_id],
              detail={"predecessor_head_id": proposal.predecessor_head_id,
                      "live_head_id": current_tip.head_id})

    # ---- digest continuity: the receiver must attest the exact package
    # frozen at sealing time.
    if (sealed_package_digest is not None
            and payload.evidence_package_digest != sealed_package_digest):
        error("TRANSFER_PACKAGE_MISMATCH",
              "the receipt attests a different evidence package digest than "
              "the one frozen at sealing time; the transferred object is not "
              "the sealed image",
              replica_ids=[replica_id],
              detail={"submitted_digest": payload.evidence_package_digest,
                      "sealed_digest": sealed_package_digest})

    # ---- party identities: the receipt must come from the parties the
    # proposal named.
    mismatched: dict[str, dict[str, str]] = {}
    if payload.handed_over_by != proposal.from_party:
        mismatched["handed_over_by"] = {
            "expected": proposal.from_party, "actual": payload.handed_over_by}
    if payload.received_by != proposal.to_party:
        mismatched["received_by"] = {
            "expected": proposal.to_party, "actual": payload.received_by}
    if mismatched:
        error("TRANSFER_PARTY_MISMATCH",
              "the receipt parties differ from the proposal; both the "
              "handing-over and the receiving party must match the frozen "
              "proposal",
              replica_ids=[replica_id], detail=mismatched)

    # ---- time ordering: the declared hand-over moment must fall inside the
    # proposal's validity window.
    window_start = as_utc(proposal.window_start)
    window_end = as_utc(proposal.window_end)
    received_at = as_utc(payload.received_at)
    if received_at is not None and received_at > window_end:
        error("TRANSFER_WINDOW_EXPIRED",
              f"the hand-over was declared at {received_at.isoformat()}, "
              f"after the proposal's validity window closed at "
              f"{window_end.isoformat()}; the predecessor proposal has "
              f"expired",
              replica_ids=[replica_id],
              detail={"received_at": received_at.isoformat(),
                      "window_end": window_end.isoformat()})
    if received_at is not None and received_at < window_start:
        error("TRANSFER_RECEIPT_BEFORE_WINDOW",
              f"the hand-over was declared at {received_at.isoformat()}, "
              f"before the proposal's validity window opened at "
              f"{window_start.isoformat()}",
              replica_ids=[replica_id],
              detail={"received_at": received_at.isoformat(),
                      "window_start": window_start.isoformat()})

    # ---- bound inspections: attribution (this replica), conclusion
    # (passed), and completion inside the validity window.
    refs: list[CustodyTransferInspectionRef] = []
    for iid in payload.inspection_ids:
        insp = inspections.get(iid)
        ref = _inspection_ref(insp, inspection_id=iid, replica_id=replica_id,
                              window_start=window_start, window_end=window_end)
        refs.append(ref)
        if insp is None:
            error("TRANSFER_INSPECTION_UNKNOWN",
                  f"inspection {iid} is not stored for this manifest; only "
                  f"recorded inspections of the sealed manifest can be bound",
                  replica_ids=[replica_id],
                  detail={"inspection_id": iid})
            continue
        if not ref.attribution_ok:
            error("TRANSFER_INSPECTION_REPLICA_MISMATCH",
                  f"inspection {iid} patrolled replica {insp.replica_id}, "
                  f"not the transferred replica {replica_id}",
                  replica_ids=[replica_id, insp.replica_id],
                  detail={"inspection_id": iid})
        if not ref.conclusion_ok:
            error("TRANSFER_INSPECTION_NOT_PASSED",
                  f"inspection {iid} of replica {replica_id} concluded "
                  f"'{insp.result}'; only a passed inspection proves the "
                  f"replica intact at hand-over",
                  replica_ids=[replica_id],
                  detail={"inspection_id": iid, "result": insp.result})
        if not ref.within_window:
            error("TRANSFER_INSPECTION_OUT_OF_WINDOW",
                  f"inspection {iid} of replica {replica_id} was not "
                  f"completed inside the proposal's validity window "
                  f"{window_start.isoformat()} .. {window_end.isoformat()}",
                  replica_ids=[replica_id],
                  detail={"inspection_id": iid,
                          "first_read_at": (ref.first_read_at.isoformat()
                                            if ref.first_read_at else None),
                          "last_read_at": (ref.last_read_at.isoformat()
                                           if ref.last_read_at else None)})

    effective = not findings
    new_head = None
    if effective:
        new_head = mint_transfer_head(
            proposal=proposal, receipt=payload, predecessor=current_tip,
            image_sha256=image_sha256, created_at=created_at)
    return CustodyTransferReceiptReport(
        receipt_id=payload.receipt_id,
        proposal_id=proposal.proposal_id,
        manifest_id=proposal.manifest_id,
        media_id=media_id,
        replica_id=replica_id,
        effective=effective,
        handed_over_by=payload.handed_over_by,
        received_by=payload.received_by,
        received_at=payload.received_at,
        location=payload.location,
        evidence_package_digest=payload.evidence_package_digest,
        inspection_ids=list(payload.inspection_ids),
        inspection_refs=refs,
        new_head=new_head,
        findings=findings,
        created_at=created_at)


def proposal_digest(record: CustodyTransferProposal) -> str:
    """Self digest of a proposal record (the field itself excluded)."""
    return sha256_hex(canonical_bytes(
        record.model_dump(exclude={"proposal_digest"}, mode="json")))


def transfer_status(receipts: list[CustodyTransferReceiptReport]) -> str:
    """Roll up the receipt attempts of one proposal."""
    if not receipts:
        return "pending"
    if any(r.effective for r in receipts):
        return "completed"
    return "rejected"


def build_transfer_package(proposal: CustodyTransferProposal, *,
                           media_id: str,
                           receipts: list[CustodyTransferReceiptReport]
                           ) -> dict[str, Any]:
    """Assemble the self-describing JSON transfer package: the proposal,
    every receipt attempt with its rejection basis, and the resolved
    inspection references. The package digest covers the package with the
    digest field removed, so any party can recompute it."""
    effective = next((r for r in receipts if r.effective), None)
    refs: dict[str, CustodyTransferInspectionRef] = {}
    for r in receipts:
        for ref in r.inspection_refs:
            refs.setdefault(ref.inspection_id, ref)
    package: dict[str, Any] = {
        "format": TRANSFER_PACKAGE_FORMAT,
        "manifest_id": proposal.manifest_id,
        "media_id": media_id,
        "replica_id": proposal.replica_id,
        "evidence_package_digest": proposal.evidence_package_digest,
        "status": transfer_status(receipts),
        "proposal": proposal.model_dump(mode="json"),
        "receipts": [r.model_dump(mode="json") for r in receipts],
        "inspection_refs": [refs[iid].model_dump(mode="json")
                            for iid in sorted(refs)],
        "new_head": (effective.new_head.model_dump(mode="json")
                     if effective and effective.new_head else None),
        "transfer_package_digest": None,
    }
    package["transfer_package_digest"] = sha256_hex(
        canonical_bytes({k: v for k, v in package.items()
                         if k != "transfer_package_digest"}))
    return package
