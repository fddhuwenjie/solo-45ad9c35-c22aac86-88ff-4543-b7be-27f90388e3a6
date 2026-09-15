"""Post-seal custody transfer continuation tests.

The custody_events frozen into a sealed manifest end at the sealing-time
hand-over. A transfer proposal cites the sealed manifest, the evidence
package digest, the replica and the CURRENT custody chain head, and freezes
both parties, the location and the validity window; the receiver's receipt
binds the inspections of that replica completed inside the window. The
service checks party identities, predecessor uniqueness, inspection
attribution/conclusion, digest continuity and time ordering. An effective
receipt mints the next hash-linked chain head; an expired window, a
duplicate receipt, an occupied head, a failed/inconclusive inspection or a
package digest mismatch leave the transfer without effect, but the attempt
is appended to the record all the same. The sealed manifest's own
custody_events keep being read by the original logic.
"""
from __future__ import annotations

import hashlib
import json

from tests.conftest import build_payload, post_manifest, seal
from tests.test_inspection import (
    T_READ,
    get_plan,
    make_readings,
    sealed_manifest,
    submit,
)

WINDOW = ("2026-10-01T00:00:00+00:00", "2026-10-02T00:00:00+00:00")
FROM_PARTY = "司法鉴定中心-接收人 sun.li"
TO_PARTY = "档案馆 zhou.qi"


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def get_chain(client, mid):
    r = client.get(f"/manifests/{mid}/custody-chain")
    assert r.status_code == 200, r.text
    return r.json()


def tip_of(chain, replica_id):
    view = next(r for r in chain["replicas"] if r["replica_id"] == replica_id)
    return view["current_head_id"]


def package_digest(client, mid):
    return client.get(f"/manifests/{mid}/evidence-package") \
        .json()["evidence_package_digest"]


def propose(client, mid, *, proposal_id="TP-1", replica_id="R-ARC",
            head=None, digest=None, window=WINDOW, from_party=FROM_PARTY,
            to_party=TO_PARTY, location="证据管理室 SAFE-07"):
    body = {
        "proposal_id": proposal_id,
        "evidence_package_digest": digest or package_digest(client, mid),
        "replica_id": replica_id,
        "predecessor_head_id": head or tip_of(get_chain(client, mid),
                                              replica_id),
        "from_party": from_party,
        "to_party": to_party,
        "location": location,
        "window_start": window[0],
        "window_end": window[1],
    }
    return client.post(f"/manifests/{mid}/custody-transfers", json=body)


def receive(client, mid, proposal_id="TP-1", *, receipt_id="RC-1",
            digest=None, inspection_ids=("I-1",), received_by=TO_PARTY,
            handed_over_by=FROM_PARTY, received_at="2026-10-01T12:00:00+00:00"):
    body = {
        "receipt_id": receipt_id,
        "evidence_package_digest": digest or package_digest(client, mid),
        "handed_over_by": handed_over_by,
        "received_by": received_by,
        "received_at": received_at,
        "inspection_ids": list(inspection_ids),
    }
    return client.post(
        f"/manifests/{mid}/custody-transfers/{proposal_id}/receipts",
        json=body)


def pass_inspection(client, mid, *, inspection_id="I-1", replica_id="R-ARC",
                    read_at=T_READ, **kw):
    plan = get_plan(client, mid)
    r = submit(client, mid, plan, inspection_id=inspection_id,
               replica_id=replica_id,
               readings=make_readings(plan["planned_intervals"],
                                      read_at=read_at, **kw))
    assert r.status_code == 201, r.text
    return r.json()


def get_package(client, mid, proposal_id="TP-1"):
    r = client.get(f"/manifests/{mid}/custody-transfers/{proposal_id}")
    assert r.status_code == 200, r.text
    return r.json()


def codes_of(report):
    return [f["code"] for f in report["findings"]]


# ------------------------------------------------------------ chain state --
def test_chain_state_derives_genesis_heads_from_sealed_events(client):
    mid = sealed_manifest(client, "M-CT-CHAIN")
    chain = get_chain(client, mid)
    assert chain["manifest_id"] == mid
    assert chain["media_id"] == "M-CT-CHAIN"
    assert chain["evidence_package_digest"] == package_digest(client, mid)
    assert chain["merkle_root"]
    views = {r["replica_id"]: r for r in chain["replicas"]}
    assert set(views) == {"R-ACQ", "R-CPY", "R-ARC"}
    for rid, view in views.items():
        assert [h["head_id"] for h in view["heads"]] == [f"HEAD-SEALED-{rid}"]
        head = view["heads"][0]
        assert head["source"] == "sealed"
        assert head["predecessor_head_id"] is None
        assert len(head["head_digest"]) == 64
        assert view["current_head_id"] == head["head_id"]
        assert view["current_head_digest"] == head["head_digest"]
        assert head["terminal_event_id"]
        assert head["evidence_package_digest"] == \
            chain["evidence_package_digest"]
    # the terminal transferred event names the receiving party as custodian
    assert views["R-ARC"]["current_custodian"] == FROM_PARTY
    # deterministic: a second read derives the same digests
    assert get_chain(client, mid) == chain


def test_chain_state_requires_sealed_manifest(client):
    mid = post_manifest(client, build_payload(media_id="M-CT-DRAFT")) \
        .json()["manifest_id"]
    r = client.get(f"/manifests/{mid}/custody-chain")
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "TRANSFER_REQUIRES_SEALED"
    assert client.get("/manifests/MF-NOPE/custody-chain").status_code == 404


# ------------------------------------------------------- proposal creation --
def test_proposal_creation_freezes_context(client):
    mid = sealed_manifest(client, "M-CT-PROP")
    digest = package_digest(client, mid)
    head = tip_of(get_chain(client, mid), "R-ARC")
    r = propose(client, mid)
    assert r.status_code == 201, r.text
    prop = r.json()
    assert prop["proposal_id"] == "TP-1"
    assert prop["manifest_id"] == mid
    assert prop["media_id"] == "M-CT-PROP"
    assert prop["replica_id"] == "R-ARC"
    assert prop["evidence_package_digest"] == digest
    assert prop["predecessor_head_id"] == head
    assert len(prop["predecessor_head_digest"]) == 64
    assert prop["from_party"] == FROM_PARTY
    assert prop["to_party"] == TO_PARTY
    assert prop["location"] == "证据管理室 SAFE-07"
    assert prop["window_start"].replace("Z", "+00:00") == WINDOW[0]
    assert prop["window_end"].replace("Z", "+00:00") == WINDOW[1]
    assert len(prop["proposal_digest"]) == 64
    # the proposal is anchored to the live head's hash link
    chain = get_chain(client, mid)
    arc = next(v for v in chain["replicas"] if v["replica_id"] == "R-ARC")
    assert prop["predecessor_head_digest"] == arc["current_head_digest"]
    # pending until a receipt arrives
    listing = client.get(f"/manifests/{mid}/custody-transfers").json()
    assert [s["proposal_id"] for s in listing] == ["TP-1"]
    assert listing[0]["status"] == "pending"
    assert listing[0]["receipt_count"] == 0
    assert listing[0]["new_head_id"] is None


def test_proposal_creation_validation(client):
    mid = sealed_manifest(client, "M-CT-PVAL")
    digest = package_digest(client, mid)
    head = tip_of(get_chain(client, mid), "R-ARC")
    # unknown manifest -> 404
    assert propose(client, "MF-NOPE", digest="0" * 64,
                   head="HEAD-SEALED-R-ARC").status_code == 404
    # unsealed manifest -> 409
    draft = post_manifest(client, build_payload(media_id="M-CT-PDRAFT")) \
        .json()["manifest_id"]
    r = propose(client, draft, digest="0" * 64, head="HEAD-SEALED-R-ARC")
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "TRANSFER_REQUIRES_SEALED"
    # evidence package digest mismatch -> 422, nothing stored
    r = propose(client, mid, digest="0" * 64)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "TRANSFER_EVIDENCE_PACKAGE_MISMATCH"
    assert r.json()["detail"]["sealed_digest"] == digest
    # unknown replica -> 422
    r = propose(client, mid, replica_id="R-GHOST", head="HEAD-SEALED-R-GHOST")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "TRANSFER_REPLICA_UNKNOWN"
    # unknown chain head -> 422
    r = propose(client, mid, head="HEAD-NOPE")
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "TRANSFER_HEAD_UNKNOWN"
    # a head of ANOTHER replica is unknown for this replica's chain
    r = propose(client, mid, replica_id="R-ARC",
                head=tip_of(get_chain(client, mid), "R-CPY"))
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "TRANSFER_HEAD_UNKNOWN"
    # malformed window / identical parties -> 422 (schema)
    assert propose(client, mid, window=(WINDOW[1], WINDOW[0])) \
        .status_code == 422
    assert propose(client, mid, from_party=TO_PARTY).status_code == 422
    # nothing was stored by the rejected attempts
    assert client.get(f"/manifests/{mid}/custody-transfers").json() == []
    # a valid proposal, then its id is frozen (append-only)
    assert propose(client, mid).status_code == 201
    r = propose(client, mid)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "TRANSFER_PROPOSAL_DUPLICATE"


# ------------------------------------------------------------- happy path --
def test_effective_receipt_mints_hash_linked_head(client):
    mid = sealed_manifest(client, "M-CT-OK")
    pass_inspection(client, mid)
    genesis = tip_of(get_chain(client, mid), "R-ARC")
    assert propose(client, mid).status_code == 201
    r = receive(client, mid)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["effective"] is True
    assert rep["findings"] == []
    assert rep["receipt_id"] == "RC-1"
    assert rep["proposal_id"] == "TP-1"
    assert rep["replica_id"] == "R-ARC"
    head = rep["new_head"]
    assert head["head_id"] == "HEAD-TP-1"
    assert head["source"] == "transfer"
    assert head["predecessor_head_id"] == genesis
    assert head["custodian"] == TO_PARTY
    assert head["proposal_id"] == "TP-1"
    assert head["receipt_id"] == "RC-1"
    # resolved inspection references are frozen into the receipt
    ref = rep["inspection_refs"][0]
    assert ref["inspection_id"] == "I-1"
    assert ref["replica_id"] == "R-ARC"
    assert ref["result"] == "passed"
    assert ref["attribution_ok"] and ref["conclusion_ok"]
    assert ref["within_window"] is True
    # the chain advanced exactly one hash-linked head
    chain = get_chain(client, mid)
    arc = next(v for v in chain["replicas"] if v["replica_id"] == "R-ARC")
    assert [h["head_id"] for h in arc["heads"]] == [genesis, "HEAD-TP-1"]
    new_head = arc["heads"][1]
    assert new_head["predecessor_head_digest"] == arc["heads"][0]["head_digest"]
    assert new_head["head_digest"] != arc["heads"][0]["head_digest"]
    assert arc["current_head_id"] == "HEAD-TP-1"
    assert arc["current_custodian"] == TO_PARTY
    # the other replicas' chains are untouched
    cpy = next(v for v in chain["replicas"] if v["replica_id"] == "R-CPY")
    assert len(cpy["heads"]) == 1
    # listing reflects completion
    listing = client.get(f"/manifests/{mid}/custody-transfers").json()
    assert listing[0]["status"] == "completed"
    assert listing[0]["receipt_count"] == 1
    assert listing[0]["new_head_id"] == "HEAD-TP-1"


def test_transfer_package_restores_proposal_receipts_and_refs(client):
    mid = sealed_manifest(client, "M-CT-PKG")
    pass_inspection(client, mid)
    assert propose(client, mid).status_code == 201
    assert receive(client, mid).json()["effective"] is True
    pkg = get_package(client, mid)
    assert pkg["format"] == "split-image-custody-transfer/v1"
    assert pkg["status"] == "completed"
    assert pkg["manifest_id"] == mid
    assert pkg["replica_id"] == "R-ARC"
    assert pkg["proposal"]["proposal_id"] == "TP-1"
    assert pkg["proposal"]["from_party"] == FROM_PARTY
    assert len(pkg["receipts"]) == 1
    assert pkg["receipts"][0]["effective"] is True
    assert pkg["receipts"][0]["inspection_ids"] == ["I-1"]
    assert pkg["inspection_refs"][0]["inspection_id"] == "I-1"
    assert pkg["new_head"]["head_id"] == "HEAD-TP-1"
    # self digest: recomputable from the package with the field removed
    declared = pkg["transfer_package_digest"]
    body = {k: v for k, v in pkg.items() if k != "transfer_package_digest"}
    recomputed = hashlib.sha256(canon(body).encode("utf-8")).hexdigest()
    assert declared == recomputed


def test_chain_continues_across_multiple_transfers(client):
    mid = sealed_manifest(client, "M-CT-MULTI")
    pass_inspection(client, mid, inspection_id="I-1")
    assert propose(client, mid, proposal_id="TP-1").status_code == 201
    assert receive(client, mid, "TP-1", receipt_id="RC-1").json()["effective"]
    # second transfer anchored to the freshly minted head
    pass_inspection(client, mid, inspection_id="I-2")
    head = tip_of(get_chain(client, mid), "R-ARC")
    assert head == "HEAD-TP-1"
    r = propose(client, mid, proposal_id="TP-2", head=head,
                from_party=TO_PARTY, to_party="复核中心 wang.wu")
    assert r.status_code == 201, r.text
    assert r.json()["predecessor_head_id"] == "HEAD-TP-1"
    r = receive(client, mid, "TP-2", receipt_id="RC-2",
                inspection_ids=("I-2",), handed_over_by=TO_PARTY,
                received_by="复核中心 wang.wu")
    assert r.json()["effective"] is True
    chain = get_chain(client, mid)
    arc = next(v for v in chain["replicas"] if v["replica_id"] == "R-ARC")
    assert [h["head_id"] for h in arc["heads"]] == \
        ["HEAD-SEALED-R-ARC", "HEAD-TP-1", "HEAD-TP-2"]
    # every link is hash-chained to its predecessor
    for prev, cur in zip(arc["heads"], arc["heads"][1:]):
        assert cur["predecessor_head_digest"] == prev["head_digest"]
    assert arc["current_custodian"] == "复核中心 wang.wu"


# ------------------------------------------------------- receipt failures --
def test_receipt_window_expired_is_stored_but_ineffective(client):
    mid = sealed_manifest(client, "M-CT-EXP")
    pass_inspection(client, mid)
    assert propose(client, mid).status_code == 201
    r = receive(client, mid, received_at="2026-10-02T00:00:01+00:00")
    assert r.status_code == 201  # the attempt is appended, not rejected
    rep = r.json()
    assert rep["effective"] is False
    assert rep["new_head"] is None
    assert "TRANSFER_WINDOW_EXPIRED" in codes_of(rep)
    # no head minted; the chain tip is still the genesis head
    chain = get_chain(client, mid)
    arc = next(v for v in chain["replicas"] if v["replica_id"] == "R-ARC")
    assert [h["head_id"] for h in arc["heads"]] == ["HEAD-SEALED-R-ARC"]
    # the rejected attempt stays on record with its rejection basis
    pkg = get_package(client, mid)
    assert pkg["status"] == "rejected"
    assert len(pkg["receipts"]) == 1
    assert pkg["receipts"][0]["effective"] is False
    assert codes_of(pkg["receipts"][0]) == ["TRANSFER_WINDOW_EXPIRED"]
    listing = client.get(f"/manifests/{mid}/custody-transfers").json()
    assert listing[0]["status"] == "rejected"


def test_receipt_before_window_is_ineffective(client):
    mid = sealed_manifest(client, "M-CT-EARLY")
    pass_inspection(client, mid)
    assert propose(client, mid).status_code == 201
    r = receive(client, mid, received_at="2026-09-30T23:00:00+00:00")
    assert r.json()["effective"] is False
    assert "TRANSFER_RECEIPT_BEFORE_WINDOW" in codes_of(r.json())


def test_receipt_duplicate_is_stored_but_ineffective(client):
    mid = sealed_manifest(client, "M-CT-DUP")
    pass_inspection(client, mid)
    assert propose(client, mid).status_code == 201
    assert receive(client, mid).json()["effective"] is True
    # same receipt id again -> duplicate, appended but ineffective
    r = receive(client, mid)
    assert r.status_code == 201
    assert r.json()["effective"] is False
    assert "TRANSFER_RECEIPT_DUPLICATE" in codes_of(r.json())
    # a NEW receipt id for an already fulfilled proposal is also a duplicate
    r = receive(client, mid, receipt_id="RC-2")
    assert r.json()["effective"] is False
    assert "TRANSFER_RECEIPT_DUPLICATE" in codes_of(r.json())
    # all three attempts are on record; the chain advanced exactly once
    pkg = get_package(client, mid)
    assert pkg["status"] == "completed"
    assert len(pkg["receipts"]) == 3
    assert [rc["effective"] for rc in pkg["receipts"]] == [True, False, False]
    chain = get_chain(client, mid)
    arc = next(v for v in chain["replicas"] if v["replica_id"] == "R-ARC")
    assert [h["head_id"] for h in arc["heads"]] == \
        ["HEAD-SEALED-R-ARC", "HEAD-TP-1"]


def test_parallel_proposals_cannot_fork_the_chain(client):
    mid = sealed_manifest(client, "M-CT-FORK")
    pass_inspection(client, mid, inspection_id="I-1")
    pass_inspection(client, mid, inspection_id="I-2")
    genesis = tip_of(get_chain(client, mid), "R-ARC")
    # the same holder opens two transfers against the same live head
    assert propose(client, mid, proposal_id="TP-A", head=genesis,
                   to_party="档案馆 zhou.qi").status_code == 201
    assert propose(client, mid, proposal_id="TP-B", head=genesis,
                   to_party="备份库 liu.bei").status_code == 201
    # the first effective receipt consumes the head
    r = receive(client, mid, "TP-A", receipt_id="RC-A",
                inspection_ids=("I-1",), received_by="档案馆 zhou.qi")
    assert r.json()["effective"] is True
    # the second proposal's receipt finds the head occupied: no fork
    r = receive(client, mid, "TP-B", receipt_id="RC-B",
                inspection_ids=("I-2",), received_by="备份库 liu.bei")
    assert r.status_code == 201
    rep = r.json()
    assert rep["effective"] is False
    assert rep["new_head"] is None
    assert "TRANSFER_HEAD_OCCUPIED" in codes_of(rep)
    chain = get_chain(client, mid)
    arc = next(v for v in chain["replicas"] if v["replica_id"] == "R-ARC")
    assert [h["head_id"] for h in arc["heads"]] == [genesis, "HEAD-TP-A"]
    # a new proposal must anchor to the consumed chain's live head
    r = propose(client, mid, proposal_id="TP-C", head=genesis)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "TRANSFER_HEAD_OCCUPIED"
    assert r.json()["detail"]["live_head_id"] == "HEAD-TP-A"


def test_receipt_package_digest_mismatch(client):
    mid = sealed_manifest(client, "M-CT-BADPKG")
    pass_inspection(client, mid)
    assert propose(client, mid).status_code == 201
    r = receive(client, mid, digest="f" * 64)
    assert r.status_code == 201
    rep = r.json()
    assert rep["effective"] is False
    assert "TRANSFER_PACKAGE_MISMATCH" in codes_of(rep)
    detail = next(f for f in rep["findings"]
                  if f["code"] == "TRANSFER_PACKAGE_MISMATCH")["detail"]
    assert detail["sealed_digest"] == package_digest(client, mid)


def test_receipt_party_mismatch(client):
    mid = sealed_manifest(client, "M-CT-PARTY")
    pass_inspection(client, mid)
    assert propose(client, mid).status_code == 201
    # an impostor receiver
    r = receive(client, mid, received_by="冒名者 mao.ming")
    assert r.json()["effective"] is False
    assert "TRANSFER_PARTY_MISMATCH" in codes_of(r.json())
    # a wrong handing-over party
    r = receive(client, mid, receipt_id="RC-2",
                handed_over_by="无关人员 wu.guan")
    assert r.json()["effective"] is False
    assert "TRANSFER_PARTY_MISMATCH" in codes_of(r.json())
    # the genuine receipt still goes through afterwards
    r = receive(client, mid, receipt_id="RC-3")
    assert r.json()["effective"] is True


def test_receipt_inspection_attribution_and_conclusion(client):
    mid = sealed_manifest(client, "M-CT-INSP")
    pass_inspection(client, mid, inspection_id="I-ARC")
    # an inspection of ANOTHER replica
    pass_inspection(client, mid, inspection_id="I-CPY", replica_id="R-CPY")
    # a FAILED inspection (digest conflict on the archive replica)
    plan = get_plan(client, mid)
    r = submit(client, mid, plan, inspection_id="I-FAIL", replica_id="R-ARC",
               readings=make_readings(plan["planned_intervals"],
                                      corrupt={(0, 1)}))
    assert r.json()["result"] == "failed"
    # an INCONCLUSIVE inspection (a planned interval left unread)
    r = submit(client, mid, plan, inspection_id="I-HOLE", replica_id="R-ARC",
               readings=make_readings(plan["planned_intervals"],
                                      skip={(63, 64)}))
    assert r.json()["result"] == "inconclusive"
    assert propose(client, mid).status_code == 201
    # attribution: the bound inspection belongs to another replica
    r = receive(client, mid, inspection_ids=("I-CPY",))
    assert r.json()["effective"] is False
    assert "TRANSFER_INSPECTION_REPLICA_MISMATCH" in codes_of(r.json())
    # conclusion: failed / inconclusive inspections never hand over
    r = receive(client, mid, receipt_id="RC-2", inspection_ids=("I-FAIL",))
    assert r.json()["effective"] is False
    assert "TRANSFER_INSPECTION_NOT_PASSED" in codes_of(r.json())
    r = receive(client, mid, receipt_id="RC-3", inspection_ids=("I-HOLE",))
    assert r.json()["effective"] is False
    assert "TRANSFER_INSPECTION_NOT_PASSED" in codes_of(r.json())
    # unknown inspection record
    r = receive(client, mid, receipt_id="RC-4", inspection_ids=("I-GHOST",))
    assert r.json()["effective"] is False
    assert "TRANSFER_INSPECTION_UNKNOWN" in codes_of(r.json())
    # mixing a good inspection with a failed one is still ineffective
    r = receive(client, mid, receipt_id="RC-5",
                inspection_ids=("I-ARC", "I-FAIL"))
    assert r.json()["effective"] is False
    # the clean inspection alone succeeds; every attempt stays on record
    r = receive(client, mid, receipt_id="RC-6", inspection_ids=("I-ARC",))
    assert r.json()["effective"] is True
    pkg = get_package(client, mid)
    assert len(pkg["receipts"]) == 6
    assert pkg["status"] == "completed"


def test_receipt_inspection_out_of_window(client):
    mid = sealed_manifest(client, "M-CT-OUTWIN")
    # the patrol happened on 2026-10-01 ...
    pass_inspection(client, mid)
    # ... but the proposal window opens a day later
    late_window = ("2026-10-03T00:00:00+00:00", "2026-10-04T00:00:00+00:00")
    assert propose(client, mid, window=late_window).status_code == 201
    r = receive(client, mid, received_at="2026-10-03T12:00:00+00:00")
    assert r.status_code == 201
    rep = r.json()
    assert rep["effective"] is False
    assert "TRANSFER_INSPECTION_OUT_OF_WINDOW" in codes_of(rep)
    ref = rep["inspection_refs"][0]
    assert ref["within_window"] is False
    assert ref["conclusion_ok"] is True  # the patrol itself passed


def test_receipt_requires_existing_proposal_and_sealed_manifest(client):
    mid = sealed_manifest(client, "M-CT-STRUCT")
    # unknown proposal -> 404, nothing stored
    r = receive(client, mid, "TP-GHOST")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "TRANSFER_PROPOSAL_UNKNOWN"
    # unknown manifest -> 404
    assert receive(client, "MF-NOPE", "TP-1", digest="0" * 64) \
        .status_code == 404
    # unsealed manifest -> 409
    draft = post_manifest(client, build_payload(media_id="M-CT-RDRAFT")) \
        .json()["manifest_id"]
    r = receive(client, draft, "TP-1")
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "TRANSFER_REQUIRES_SEALED"
    # receipt schema: empty / duplicated inspection ids -> 422
    assert propose(client, mid).status_code == 201
    body = {"receipt_id": "RC-X",
            "evidence_package_digest": package_digest(client, mid),
            "handed_over_by": FROM_PARTY, "received_by": TO_PARTY,
            "received_at": "2026-10-01T12:00:00+00:00", "inspection_ids": []}
    assert client.post(f"/manifests/{mid}/custody-transfers/TP-1/receipts",
                       json=body).status_code == 422
    body["inspection_ids"] = ["I-1", "I-1"]
    assert client.post(f"/manifests/{mid}/custody-transfers/TP-1/receipts",
                       json=body).status_code == 422


# ------------------------------------------------------- history & package --
def test_ineffective_attempt_then_successful_retry_stays_on_record(client):
    mid = sealed_manifest(client, "M-CT-RETRY")
    pass_inspection(client, mid)
    assert propose(client, mid).status_code == 201
    # first attempt binds an unknown inspection: ineffective, but appended
    r = receive(client, mid, receipt_id="RC-1", inspection_ids=("I-GHOST",))
    assert r.json()["effective"] is False
    # a corrected attempt within the window still takes effect
    r = receive(client, mid, receipt_id="RC-2", inspection_ids=("I-1",))
    assert r.json()["effective"] is True
    pkg = get_package(client, mid)
    assert pkg["status"] == "completed"
    assert [rc["receipt_id"] for rc in pkg["receipts"]] == ["RC-1", "RC-2"]
    assert pkg["receipts"][0]["effective"] is False
    assert codes_of(pkg["receipts"][0]) == ["TRANSFER_INSPECTION_UNKNOWN"]
    assert pkg["receipts"][1]["effective"] is True
    # the minted head comes from the effective attempt
    assert pkg["new_head"]["receipt_id"] == "RC-2"


def test_history_lists_every_proposal_with_status(client):
    mid = sealed_manifest(client, "M-CT-HIST")
    pass_inspection(client, mid, inspection_id="I-1")
    pass_inspection(client, mid, inspection_id="I-2")
    # one completed transfer
    assert propose(client, mid, proposal_id="TP-1").status_code == 201
    assert receive(client, mid, "TP-1", receipt_id="RC-1",
                   inspection_ids=("I-1",)).json()["effective"]
    # one rejected transfer (expired window)
    assert propose(client, mid, proposal_id="TP-2", replica_id="R-CPY") \
        .status_code == 201
    r = receive(client, mid, "TP-2", receipt_id="RC-2",
                inspection_ids=("I-2",),
                received_at="2026-10-05T00:00:00+00:00")
    assert r.json()["effective"] is False
    # one still pending
    assert propose(client, mid, proposal_id="TP-3", replica_id="R-ACQ") \
        .status_code == 201
    listing = client.get(f"/manifests/{mid}/custody-transfers").json()
    by_id = {s["proposal_id"]: s for s in listing}
    assert by_id["TP-1"]["status"] == "completed"
    assert by_id["TP-1"]["new_head_id"] == "HEAD-TP-1"
    assert by_id["TP-2"]["status"] == "rejected"
    assert by_id["TP-2"]["receipt_count"] == 1
    assert by_id["TP-2"]["new_head_id"] is None
    assert by_id["TP-3"]["status"] == "pending"
    assert by_id["TP-3"]["receipt_count"] == 0
    # per-replica chains: only R-ARC advanced
    chain = get_chain(client, mid)
    views = {v["replica_id"]: v for v in chain["replicas"]}
    assert len(views["R-ARC"]["heads"]) == 2
    assert len(views["R-CPY"]["heads"]) == 1
    assert len(views["R-ACQ"]["heads"]) == 1
    # unknown manifest -> 404 on every transfer endpoint
    assert client.get("/manifests/MF-NOPE/custody-transfers").status_code == 404
    assert client.get("/manifests/MF-NOPE/custody-transfers/TP-1") \
        .status_code == 404
    assert client.get(f"/manifests/{mid}/custody-transfers/TP-GHOST") \
        .status_code == 404


def test_sealed_manifest_and_custody_events_stay_untouched(client):
    mid = sealed_manifest(client, "M-CT-IMMUT")
    before = client.get(f"/manifests/{mid}").json()
    pass_inspection(client, mid)
    assert propose(client, mid).status_code == 201
    assert receive(client, mid).json()["effective"] is True
    after = client.get(f"/manifests/{mid}").json()
    # the sealed manifest (payload, digest, status) is byte-identical; the
    # frozen custody_events keep being served by the original route
    assert after == before
    assert len(after["payload"]["custody_events"]) > 0
    assert after["status"] == "sealed"
    # re-running precheck still evaluates the original custody chain only
    rep = client.post(f"/manifests/{mid}/precheck").json()
    assert rep["sealable"] is True
