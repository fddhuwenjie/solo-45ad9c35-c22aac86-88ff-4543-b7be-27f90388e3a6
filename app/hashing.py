"""Deterministic hashing primitives: canonical JSON, SHA-256, binary Merkle tree.

The Merkle tree follows the common forensic convention used for chunked
images: leaves are the chunk SHA-256 digests in reconstructed offset order;
an odd node promotes its only child to the next level until a single root
remains. Internal nodes hash the raw concatenation of the two child digests.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Iterable, Optional


def canonical_json(obj: Any) -> str:
    """Serialize JSON with sorted keys and no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def canonical_bytes(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_canonical(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))


def decode_b64_strict(value: str) -> bytes:
    # validate=True rejects missing padding and non-alphabet characters.
    return base64.b64decode(value.encode("ascii"), validate=True)


def linear_sha256(parts: Iterable[bytes]) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.hexdigest()


def _pairs(seq: list[str]) -> Iterable[tuple[Optional[str], Optional[str]]]:
    for i in range(0, len(seq), 2):
        left = seq[i]
        right = seq[i + 1] if i + 1 < len(seq) else None
        yield left, right


def merkle_root(leaf_hex_digests: list[str]) -> Optional[str]:
    """Compute the Merkle root from ordered hex leaf digests.

    None when there are no leaves. Odd children are promoted (the lone digest
    becomes the parent unchanged), so the tree stays deterministic for any
    chunk count.
    """
    if not leaf_hex_digests:
        return None
    level = list(leaf_hex_digests)
    while len(level) > 1:
        nxt: list[str] = []
        for left, right in _pairs(level):
            if right is None:
                nxt.append(left)  # odd-node promotion
            else:
                nxt.append(sha256_hex(bytes.fromhex(left) + bytes.fromhex(right)))
        level = nxt
    return level[0]
