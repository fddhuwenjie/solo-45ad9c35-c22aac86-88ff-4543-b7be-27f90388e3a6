"""Regression tests for bad-sector retry / fill provenance rules.

Covers the three provenance defects:

1. a manifest without read-attempt records can never seal even when every
   chunk digest matches (an all-zero chunk after a bad-sector error is
   otherwise indistinguishable from a successful read) --
   RECOVERY_ATTESTATION_REQUIRED;
2. a documented manual exception may accept still-unrecovered sectors only on
   a derived revision, but accepted_sectors never counts as recovered: the
   reported source-read recovery rate excludes accepted sectors and is
   identical across precheck, diffs, the evidence package and recompute;
3. sealing an exception-bearing revision returns the evidence package (no
   datetime serialization 500) and a failed seal never changes status.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import os

from tests.conftest import (
    SECTOR_SIZE,
    build_payload,
    chunk_bytes,
    post_manifest,
    seal,
    write_chunk_files,
)


# ------------------------------------------------ defect 1: attestation ----
def test_zero_chunk_without_attempts_is_not_read_and_seal_rejected(client):
    # Every chunk is verifiable all-zero content with matching declared
    # digest, but no read attempt claims the bytes came from the source. A
    # matching digest must not substitute for proof of a source-medium read.
    payload = build_payload(media_id="M-ATTEST-1", with_attempts=False)
    zero = b"\x00" * (16 * SECTOR_SIZE)
    zd = hashlib.sha256(zero).hexdigest()
    for c in payload["chunks"]:
        c["content_b64"] = base64.b64encode(zero).decode()
        c["sha256"] = zd
    image = zero * len(payload["chunks"])
    total = hashlib.sha256(image).hexdigest()
    payload["expected_total_sha256"] = total
    for r in payload["replicas"]:
        r["sha256"] = total
    for e in payload["custody_events"]:
        for k in ("digest_before", "digest_after", "expected_digest"):
            if e.get(k):
                e[k] = total

    created = post_manifest(client, payload).json()
    report = created["report"]
    assert report["all_chunk_digests_verified"] is True
    assert report["total_hash_verified"] is True
    assert report["complete_coverage"] is True
    assert report["sealable"] is False
    codes = {f["code"] for f in report["findings"] if f["severity"] == "error"}
    assert "RECOVERY_ATTESTATION_REQUIRED" in codes
    rec = report["recovery"]
    assert rec["provenance_mode"] == "legacy-content-only"
    assert rec["unattested_sectors"] == 64
    assert rec["read_sectors"] == 0 and rec["recovery_rate"] == 0.0
    assert all(s["kind"] == "unattested" for s in rec["segments"])

    r = seal(client, created["manifest_id"])
    assert r.status_code == 409
    blockers = {f["code"]
                for f in r.json()["detail"]["blocking_findings"]}
    assert "RECOVERY_ATTESTATION_REQUIRED" in blockers
    assert client.get(f"/manifests/{created['manifest_id']}").json()[
        "status"] == "draft"

    # evidence package recompute must also refuse to call it valid
    pkg = client.get(
        f"/manifests/{created['manifest_id']}/evidence-package").json()
    recalc = client.post("/evidence/recompute", json=pkg).json()
    assert recalc["valid"] is False
    assert recalc["checks"]["recovery_provenance_ok"] is False


def test_full_read_attempts_seal_even_when_image_bytes_are_zero(client):
    # Same all-zero image, but the tool submits round-1 successful read
    # attempts for every sector: provenance is explicit and sealing succeeds.
    payload = build_payload(media_id="M-ATTEST-2")
    zero = b"\x00" * (16 * SECTOR_SIZE)
    zd = hashlib.sha256(zero).hexdigest()
    for c in payload["chunks"]:
        c["content_b64"] = base64.b64encode(zero).decode()
        c["sha256"] = zd
        for a in payload["read_attempts"]:
            if a["chunk_id"] == c["chunk_id"]:
                a["sha256"] = zd
    image = zero * len(payload["chunks"])
    total = hashlib.sha256(image).hexdigest()
    payload["expected_total_sha256"] = total
    for r in payload["replicas"]:
        r["sha256"] = total
    for e in payload["custody_events"]:
        for k in ("digest_before", "digest_after", "expected_digest"):
            if e.get(k):
                e[k] = total
    created = post_manifest(client, payload).json()
    assert created["report"]["sealable"] is True, created["report"]["findings"]
    assert created["report"]["recovery"]["read_sectors"] == 64
    assert created["report"]["recovery"]["recovery_rate"] == 1.0
    assert seal(client, created["manifest_id"]).status_code == 200


# ------------------- defect 2: exceptions accept, never recover -------------
def _payload_with_one_bad_sector(parent=None, change_kind="resume",
                                 recover_bad=False, fill_bad=False):
    """Derived revision: sector 20 of C02 errors in round 1.

    Sector 20 is left unrecovered by default (the chunk bytes there are
    zeroes, but the read attempts never claim them). ``recover_bad=True``
    adds a round-2 successful re-read of the true bytes; ``fill_bad=True``
    declares a round-2 zero-pad fill of the zero bytes.
    """
    payload = build_payload(media_id="M-EXC", change_kind=change_kind,
                            parent=parent)
    data = bytearray(chunk_bytes(1))
    data[4 * SECTOR_SIZE:5 * SECTOR_SIZE] = b"\x00" * SECTOR_SIZE
    c02 = next(c for c in payload["chunks"] if c["chunk_id"] == "C02")
    c02["content_b64"] = base64.b64encode(bytes(data)).decode()
    c02["sha256"] = hashlib.sha256(bytes(data)).hexdigest()
    image = b"".join(bytes(data) if i == 1 else chunk_bytes(i) for i in range(4))
    total = hashlib.sha256(image).hexdigest()
    payload["expected_total_sha256"] = total
    for r in payload["replicas"]:
        r["sha256"] = total
    for e in payload["custody_events"]:
        for k in ("digest_before", "digest_after", "expected_digest"):
            if e.get(k):
                e[k] = total
    # replace the whole-chunk C02 read attempt by the split retry record
    payload["read_attempts"] = [
        a for a in payload["read_attempts"] if a["chunk_id"] != "C02"]
    payload["read_attempts"].extend([
        {"attempt_id": "A-C02a", "session_id": c02["session_id"],
         "chunk_id": "C02", "start_sector": 16, "end_sector": 20,
         "round": 1, "result": "read",
         "actual_read_length": 4 * SECTOR_SIZE,
         "sha256": hashlib.sha256(chunk_bytes(1)[:4 * SECTOR_SIZE]).hexdigest()},
        {"attempt_id": "A-C02b", "session_id": c02["session_id"],
         "chunk_id": "C02", "start_sector": 20, "end_sector": 21,
         "round": 1, "result": "error", "actual_read_length": 0,
         "tool_error_code": "UNC-0x40"},
        {"attempt_id": "A-C02c", "session_id": c02["session_id"],
         "chunk_id": "C02", "start_sector": 21, "end_sector": 32,
         "round": 1, "result": "read",
         "actual_read_length": 11 * SECTOR_SIZE,
         "sha256": hashlib.sha256(
             chunk_bytes(1)[5 * SECTOR_SIZE:]).hexdigest()},
    ])
    if fill_bad:
        payload["read_attempts"].append(
            {"attempt_id": "A-C02f", "session_id": c02["session_id"],
             "chunk_id": "C02", "start_sector": 20, "end_sector": 21,
             "round": 2, "result": "fill", "actual_read_length": 0,
             "fill_method": "zero-pad", "fill_value": 0})
    if recover_bad:
        payload["read_attempts"].append(
            {"attempt_id": "A-C02d", "session_id": c02["session_id"],
             "chunk_id": "C02", "start_sector": 20, "end_sector": 21,
             "round": 2, "result": "read",
             "actual_read_length": SECTOR_SIZE,
             "sha256": hashlib.sha256(
                 chunk_bytes(1)[4 * SECTOR_SIZE:5 * SECTOR_SIZE]).hexdigest()})
    return payload


def test_exception_accepts_does_not_count_as_recovered_and_rates_consistent(
        client):
    v1 = post_manifest(client, build_payload(media_id="M-EXC")).json()
    assert seal(client, v1["manifest_id"]).status_code == 200

    # v2: sector 20 failed, no fill, no exception: the chunk bytes there are
    # the tool-written zeroes (digest verifies) but the attempt log shows the
    # sector was never read -> frozen zero policy rejects sealing
    p2 = _payload_with_one_bad_sector(parent=v1["manifest_id"])
    v2 = post_manifest(client, p2).json()
    assert v2["report"]["sealable"] is False
    assert "UNRECOVERED_OVER_FREEZE_POLICY" in {
        f["code"] for f in v2["report"]["findings"] if f["severity"] == "error"}
    bad = next(s for s in v2["report"]["recovery"]["segments"]
               if s["start_sector"] == 20)
    assert bad["kind"] == "unrecovered"
    assert bad["winning_attempt_id"] == "A-C02b"

    # v3 correction: the padding declaration is withdrawn, sector 20 stays
    # unrecovered and is accepted by a documented manual exception
    p3 = _payload_with_one_bad_sector(parent=v2["manifest_id"],
                                      change_kind="correction")
    p3["recovery_exceptions"] = [{
        "exception_id": "EX-1", "start_sector": 20, "end_sector": 21,
        "reason": "physically unreadable after three retry passes; "
                  "prosecution and defense jointly accept the range",
        "accepted_by": "zhao.lei",
        "accepted_at": "2026-09-11T10:00:00+00:00"}]
    v3 = post_manifest(client, p3).json()
    report = v3["report"]
    assert report["sealable"] is True, report["findings"]

    rec = report["recovery"]
    # the accepted sector is NOT recovered: only 63 of 64 sectors were read
    assert rec["accepted_sectors"] == 1
    assert rec["unrecovered_sectors"] == 1
    assert rec["recovered_sectors"] == 63
    assert rec["read_sectors"] == 63
    assert rec["recovery_rate"] == round(63 / 64, 9)
    seg = next(s for s in rec["segments"] if s["start_sector"] == 20)
    assert seg["kind"] == "unrecovered" and seg["exception_id"] == "EX-1"
    # the failed attempt is retained on record
    assert seg["winning_attempt_id"] == "A-C02b"
    error_attempts = [a for a in rec["attempts"] if a["result"] == "error"]
    assert [a["attempt_id"] for a in error_attempts] == ["A-C02b"]

    # same numbers on the recovery endpoint and in the evidence package
    endpoint = client.get(
        f"/manifests/{v3['manifest_id']}/recovery").json()
    assert endpoint["recovery_rate"] == rec["recovery_rate"]
    assert endpoint["recovered_sectors"] == 63

    sealed = seal(client, v3["manifest_id"])
    assert sealed.status_code == 200, sealed.text
    body = sealed.json()
    pkg = body["evidence_package"]
    pkg_recovery = pkg["computed"]["recovery"]
    assert pkg_recovery["recovery_rate"] == rec["recovery_rate"]
    assert pkg_recovery["recovered_sectors"] == 63
    assert pkg_recovery["accepted_sectors"] == 1

    recalc = client.post("/evidence/recompute", json=pkg).json()
    assert recalc["valid"] is True, recalc
    assert recalc["recovery"]["recovery_rate"] == round(63 / 64, 9)
    assert recalc["recovery"]["recovered_sectors"] == 63
    assert recalc["recovery"]["accepted_sectors"] == 1

    # diffs use the same records/rate on both sides
    diff = client.get("/diffs", params={"left": v2["manifest_id"],
                                       "right": v3["manifest_id"]}).json()
    assert diff["exceptions_added"] == ["EX-1"]
    assert diff["recovery_rate_left"] == round(63 / 64, 9)
    assert diff["recovery_rate_right"] == round(63 / 64, 9)
    assert diff["accepted_sectors_left"] == 0
    assert diff["accepted_sectors_right"] == 1

    # tampering the exception reason breaks payload + stored-state agreement
    tampered = copy.deepcopy(pkg)
    tampered["submission"]["recovery_exceptions"][0]["reason"] = "changed"
    bad = client.post("/evidence/recompute", json=tampered).json()
    assert bad["valid"] is False
    assert bad["checks"]["payload_digest_ok"] is False


def test_exception_on_initial_revision_rejected_422(client):
    payload = _payload_with_one_bad_sector(parent=None, change_kind="initial")
    payload["recovery_exceptions"] = [{
        "exception_id": "EX-INITIAL", "start_sector": 20, "end_sector": 21,
        "reason": "cannot be accepted on the initial manifest",
        "accepted_by": "zhao.lei",
        "accepted_at": "2026-09-11T10:00:00+00:00"}]
    r = post_manifest(client, payload)
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "EXCEPTION_REVISION_REQUIRED"


def test_exception_over_read_range_is_rejected(client):
    v1 = post_manifest(client, build_payload(media_id="M-EXC2")).json()
    # derived correction wrongly accepts a successfully read sector (21):
    # acceptance may only cover still-unrecovered ranges
    p2 = build_payload(media_id="M-EXC2", change_kind="correction",
                      parent=v1["manifest_id"])
    p2["recovery_exceptions"] = [{
        "exception_id": "EX-BAD", "start_sector": 21, "end_sector": 22,
        "reason": "tried to accept a sector that was actually read",
        "accepted_by": "zhao.lei",
        "accepted_at": "2026-09-11T10:00:00+00:00"}]
    v2 = post_manifest(client, p2).json()
    assert v2["report"]["sealable"] is False
    assert "RECOVERY_EXCEPTION_NOT_UNRECOVERED" in {
        f["code"] for f in v2["report"]["findings"] if f["severity"] == "error"}


# -------------------------------------- defect 3: seal atomicity + package --
def test_successful_exception_seal_returns_package_without_500(client):
    v1 = post_manifest(client, build_payload(media_id="M-EXC")).json()
    p2 = _payload_with_one_bad_sector(parent=v1["manifest_id"])
    v2 = post_manifest(client, p2).json()
    p3 = _payload_with_one_bad_sector(parent=v2["manifest_id"],
                                      change_kind="correction")
    p3["recovery_exceptions"] = [{
        "exception_id": "EX-1", "start_sector": 20, "end_sector": 21,
        "reason": "physically unreadable after three retry passes",
        "accepted_by": "zhao.lei",
        "accepted_at": "2026-09-11T10:00:00+00:00"}]
    v3 = post_manifest(client, p3).json()

    sealed = seal(client, v3["manifest_id"])
    assert sealed.status_code == 200, sealed.text
    body = sealed.json()
    assert body["status"] == "sealed"
    assert body["evidence_package"]["package"]["status"] == "sealed"
    from datetime import datetime
    assert datetime.fromisoformat(
        body["evidence_package"]["package"]["sealed_at"].replace(
            "Z", "+00:00")) == datetime.fromisoformat(body["sealed_at"])
    assert body["evidence_package_digest"] == \
        body["evidence_package"]["evidence_package_digest"]
    # accepted_at serializes inside the package (previously raised
    # "Object of type datetime is not JSON serializable" -> 500)
    ex = body["evidence_package"]["computed"]["recovery"]["exceptions"][0]
    assert ex["exception_id"] == "EX-1"
    assert isinstance(ex["accepted_at"], str)


def test_real_sparse_hole_is_recognized_as_declared_fill(client, evidence_root):
    # File-backed chunk whose unrecovered tail is a real filesystem sparse
    # hole (SEEK_DATA). The tool declares the hole in a round-2 fill attempt;
    # the segment is provenanced as a fill and sealing succeeds with the
    # reduced source-read recovery rate.
    from pathlib import Path
    payload = build_payload(media_id="M-HOLE")
    write_chunk_files(payload, evidence_root)
    c02 = next(c for c in payload["chunks"] if c["chunk_id"] == "C02")
    path = Path(c02["stored_path"])
    if not path.is_absolute():
        path = evidence_root / path
    pre = path.read_bytes()
    # sectors 24..32 (bytes 8SS..16SS of C02) become a real sparse hole:
    # truncate down to the data prefix, then extend the logical size without
    # writing so the tail is unallocated.
    fd = os.open(str(path), os.O_RDWR)
    os.ftruncate(fd, 8 * SECTOR_SIZE)
    os.ftruncate(fd, 16 * SECTOR_SIZE)
    os.close(fd)
    assert path.stat().st_size == 16 * SECTOR_SIZE
    assert path.read_bytes()[8 * SECTOR_SIZE:] == b"\x00" * (8 * SECTOR_SIZE)
    zeroed = pre[:8 * SECTOR_SIZE] + b"\x00" * (8 * SECTOR_SIZE)
    c02["sha256"] = hashlib.sha256(zeroed).hexdigest()
    image = b"".join(zeroed if i == 1 else chunk_bytes(i) for i in range(4))
    total = hashlib.sha256(image).hexdigest()
    payload["expected_total_sha256"] = total
    for r_ in payload["replicas"]:
        r_["sha256"] = total
    for e in payload["custody_events"]:
        for k in ("digest_before", "digest_after", "expected_digest"):
            if e.get(k):
                e[k] = total
    payload["read_attempts"] = [
        a for a in payload["read_attempts"] if a["chunk_id"] != "C02"]
    payload["read_attempts"].extend([
        {"attempt_id": "A-C02a", "session_id": c02["session_id"],
         "chunk_id": "C02", "start_sector": 16, "end_sector": 24,
         "round": 1, "result": "read",
         "actual_read_length": 8 * SECTOR_SIZE,
         "sha256": hashlib.sha256(pre[:8 * SECTOR_SIZE]).hexdigest()},
        {"attempt_id": "A-C02b", "session_id": c02["session_id"],
         "chunk_id": "C02", "start_sector": 24, "end_sector": 32,
         "round": 1, "result": "error", "actual_read_length": 0,
         "tool_error_code": "UNC-0x40"},
        {"attempt_id": "A-C02h", "session_id": c02["session_id"],
         "chunk_id": "C02", "start_sector": 24, "end_sector": 32,
         "round": 2, "result": "fill", "actual_read_length": 0,
         "fill_method": "sparse-hole", "sparse_hole": True}])
    created = post_manifest(client, payload).json()
    report = created["report"]
    assert report["sealable"] is True, report["findings"]
    seg = next(s for s in report["recovery"]["segments"]
               if s["start_sector"] == 24)
    assert seg["kind"] == "fill" and seg["sparse_hole"] is True
    assert seg["fill_method"] == "sparse-hole"
    # 8 of 64 sectors are declared fill, not source reads
    assert report["recovery"]["filled_sectors"] == 8
    assert report["recovery"]["read_sectors"] == 56
    assert report["recovery"]["recovery_rate"] == round(56 / 64, 9)
    sealed = seal(client, created["manifest_id"])
    assert sealed.status_code == 200, sealed.text
    pkg = sealed.json()["evidence_package"]
    recalc = client.post("/evidence/recompute", json=pkg).json()
    assert recalc["valid"] is True
    assert recalc["recovery"]["recovery_rate"] == round(56 / 64, 9)


def test_sparse_hole_claim_over_real_bytes_rejected(client, evidence_root):
    from pathlib import Path
    payload = build_payload(media_id="M-HOLE-FALSE")
    write_chunk_files(payload, evidence_root)
    c02 = next(c for c in payload["chunks"] if c["chunk_id"] == "C02")
    # no hole punched at all: every C02 sector holds real bytes, yet the tool
    # falsely declares sectors 24..32 as a sparse hole
    path = Path(c02["stored_path"])
    if not path.is_absolute():
        path = evidence_root / path
    pre = path.read_bytes()
    payload["read_attempts"] = [
        a for a in payload["read_attempts"] if a["chunk_id"] != "C02"]
    payload["read_attempts"].extend([
        {"attempt_id": "A-C02a", "session_id": c02["session_id"],
         "chunk_id": "C02", "start_sector": 16, "end_sector": 24,
         "round": 1, "result": "read",
         "actual_read_length": 8 * SECTOR_SIZE,
         "sha256": hashlib.sha256(pre[:8 * SECTOR_SIZE]).hexdigest()},
        {"attempt_id": "A-C02b", "session_id": c02["session_id"],
         "chunk_id": "C02", "start_sector": 24, "end_sector": 32,
         "round": 1, "result": "read",
         "actual_read_length": 8 * SECTOR_SIZE,
         "sha256": hashlib.sha256(pre[8 * SECTOR_SIZE:]).hexdigest()},
        {"attempt_id": "A-C02h", "session_id": c02["session_id"],
         "chunk_id": "C02", "start_sector": 24, "end_sector": 32,
         "round": 2, "result": "fill", "actual_read_length": 0,
         "fill_method": "sparse-hole", "sparse_hole": True}])
    report = post_manifest(client, payload).json()["report"]
    assert report["sealable"] is False
    assert "FILL_CONTENT_MISMATCH" in {
        f["code"] for f in report["findings"] if f["severity"] == "error"}


def test_later_round_fill_supersedes_earlier_failure_with_records_retained(
        client):
    # Round 1 fails to read sector 20; a later round-2 declared zero-pad fill
    # supersedes the failure for the final segment. The failure record stays.
    data = bytearray(chunk_bytes(1))
    data[4 * SECTOR_SIZE:5 * SECTOR_SIZE] = b"\x00" * SECTOR_SIZE
    payload = build_payload(media_id="M-LATER-FILL")
    c02 = next(c for c in payload["chunks"] if c["chunk_id"] == "C02")
    c02["content_b64"] = base64.b64encode(bytes(data)).decode()
    c02["sha256"] = hashlib.sha256(bytes(data)).hexdigest()
    payload["read_attempts"] = [
        a for a in payload["read_attempts"] if a["chunk_id"] != "C02"]
    payload["read_attempts"].extend([
        {"attempt_id": "A-C02a", "session_id": "S1", "chunk_id": "C02",
         "start_sector": 16, "end_sector": 20, "round": 1, "result": "read",
         "actual_read_length": 4 * SECTOR_SIZE,
         "sha256": hashlib.sha256(chunk_bytes(1)[:4 * SECTOR_SIZE]).hexdigest()},
        {"attempt_id": "A-C02e", "session_id": "S1", "chunk_id": "C02",
         "start_sector": 20, "end_sector": 21, "round": 1, "result": "error",
         "actual_read_length": 0, "tool_error_code": "UNC-0x40"},
        {"attempt_id": "A-C02c", "session_id": "S1", "chunk_id": "C02",
         "start_sector": 21, "end_sector": 32, "round": 1, "result": "read",
         "actual_read_length": 11 * SECTOR_SIZE,
         "sha256": hashlib.sha256(
             chunk_bytes(1)[5 * SECTOR_SIZE:]).hexdigest()},
        {"attempt_id": "A-C02f", "session_id": "S1", "chunk_id": "C02",
         "start_sector": 20, "end_sector": 21, "round": 2, "result": "fill",
         "actual_read_length": 0, "fill_method": "zero-pad",
         "fill_value": 0},
    ])
    image = b"".join(bytes(data) if i == 1 else chunk_bytes(i) for i in range(4))
    total = hashlib.sha256(image).hexdigest()
    payload["expected_total_sha256"] = total
    for r_ in payload["replicas"]:
        r_["sha256"] = total
    for e in payload["custody_events"]:
        for k in ("digest_before", "digest_after", "expected_digest"):
            if e.get(k):
                e[k] = total
    report = post_manifest(client, payload).json()["report"]
    assert report["sealable"] is True, report["findings"]
    seg = next(s for s in report["recovery"]["segments"]
               if s["start_sector"] == 20)
    assert seg["kind"] == "fill"
    assert seg["winning_attempt_id"] == "A-C02f"
    assert "A-C02e" in seg["attempts"]  # earlier failure retained
    assert report["recovery"]["filled_sectors"] == 1
    assert report["recovery"]["read_sectors"] == 63
    assert report["recovery"]["recovery_rate"] == round(63 / 64, 9)


def test_failed_seal_never_writes_sealed_state(client):
    p1 = build_payload(media_id="M-SEAL-ATOM", chunk_seq=[0, 1],
                       sessions_row=[
                           {"session_id": "S1",
                            "started_at": "2026-09-10T09:00:00+00:00",
                            "ended_at": "2026-09-10T09:40:00+00:00",
                            "operator": "zhao.lei", "tool": "dd-guigazi",
                            "interruption": "power-loss"}])
    p1["sessions"] = p1["sessions"][:1]
    p1["chunks"] = [c for c in p1["chunks"] if c["session_id"] == "S1"]
    p1["read_attempts"] = [a for a in p1["read_attempts"]
                           if a["chunk_id"] in {c["chunk_id"]
                                                for c in p1["chunks"]}]
    p1["replicas"] = []
    p1["custody_events"] = []
    p1["expected_total_sha256"] = None
    v1 = post_manifest(client, p1).json()
    assert v1["report"]["sealable"] is False

    first = seal(client, v1["manifest_id"])
    assert first.status_code == 409
    # repeatable: still a draft, still 409, no seal timestamp
    for _ in range(2):
        row = client.get(f"/manifests/{v1['manifest_id']}").json()
        assert row["status"] == "draft" and row["sealed_at"] is None
        again = seal(client, v1["manifest_id"])
        assert again.status_code == 409
