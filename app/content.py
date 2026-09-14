"""Chunk content resolution.

When a chunk carries no inline ``content_b64`` the verifier must read the
actual bytes from the registered file path (``stored_path``) so that every
chunk digest and the whole-image linear hash can be recomputed. Resolution is
sandboxed to a configured evidence root so a manifest cannot make the service
read arbitrary host files.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

from .hashing import decode_b64_strict

READ_CHUNK = 1024 * 1024  # 1 MiB streaming reads


@dataclass
class ChunkContentResult:
    """Outcome of locating and hashing a chunk's actual bytes."""

    chunk_id: str
    source: str                       # "inline" | "file" | "none"
    readable: bool
    length: Optional[int] = None
    sha256: Optional[str] = None
    stored_path: Optional[str] = None       # absolute resolved path (host-local)
    registered_path: Optional[str] = None   # path as declared in the manifest
    error_code: Optional[str] = None        # finding code when not readable
    error_detail: Optional[dict] = None


class ContentResolver(Protocol):
    def inspect(self, chunk, *linear_hashers) -> ChunkContentResult:
        """Locate/hash one chunk.

        Any extra ``linear_hashers`` are fed the same bytes during the single
        streaming read (used to accumulate the offset-order whole-image hash).
        """
        ...

    def hash_linear(self, chunks_in_offset_order) -> Optional[str]:
        """Stream the given chunks in order and return the linear SHA-256.

        Returns None if any chunk content is unavailable.
        """
        ...


class FilesystemContentResolver:
    """Resolve inline content first, then ``stored_path`` under evidence_root."""

    def __init__(self, evidence_roots):
        if isinstance(evidence_roots, (str, os.PathLike)):
            evidence_roots = [evidence_roots]
        self.roots = [Path(r).resolve() for r in evidence_roots]

    # ------------------------------------------------------------ helpers --
    def _resolve_path(self, stored_path: str) -> tuple[Optional[Path], Optional[str]]:
        candidate = Path(stored_path)
        if not candidate.is_absolute():
            for root in self.roots:
                resolved = (root / candidate).resolve()
                if self._within(root, resolved):
                    return resolved, None
            return None, "CHUNK_FILE_OUTSIDE_ROOT"
        resolved = candidate.resolve()
        for root in self.roots:
            if self._within(root, resolved):
                return resolved, None
        return None, "CHUNK_FILE_OUTSIDE_ROOT"

    @staticmethod
    def _within(root: Path, target: Path) -> bool:
        try:
            target.relative_to(root)
        except ValueError:
            return False
        return True

    def inspect(self, chunk, *linear_hashers) -> ChunkContentResult:
        """Verify one chunk. Extra hashers receive the same bytes in one read."""
        if chunk.content_b64 is not None:
            try:
                data = decode_b64_strict(chunk.content_b64)
            except Exception:
                return ChunkContentResult(
                    chunk_id=chunk.chunk_id, source="inline", readable=False,
                    error_code="CHUNK_CONTENT_BAD_BASE64")
            leaf = hashlib.sha256(data)
            for h in linear_hashers:
                h.update(data)
            return ChunkContentResult(
                chunk_id=chunk.chunk_id, source="inline", readable=True,
                length=len(data), sha256=leaf.hexdigest())

        if not chunk.stored_path:
            return ChunkContentResult(
                chunk_id=chunk.chunk_id, source="none", readable=False,
                error_code="CHUNK_CONTENT_UNAVAILABLE",
                error_detail={"reason": "neither content_b64 nor stored_path "
                                        "supplied"})

        path, outside = self._resolve_path(chunk.stored_path)
        if outside:
            return ChunkContentResult(
                chunk_id=chunk.chunk_id, source="file", readable=False,
                stored_path=None, registered_path=chunk.stored_path,
                error_code=outside,
                error_detail={"stored_path": chunk.stored_path,
                              "roots": [str(r) for r in self.roots]})
        leaf = hashlib.sha256()
        size = 0
        try:
            with open(path, "rb") as fh:
                while True:
                    block = fh.read(READ_CHUNK)
                    if not block:
                        break
                    leaf.update(block)
                    for h in linear_hashers:
                        h.update(block)
                    size += len(block)
        except FileNotFoundError:
            return ChunkContentResult(
                chunk_id=chunk.chunk_id, source="file", readable=False,
                stored_path=None, registered_path=chunk.stored_path,
                error_code="CHUNK_FILE_UNREADABLE",
                error_detail={"stored_path": chunk.stored_path,
                              "reason": "not found"})
        except (IsADirectoryError, PermissionError, OSError) as exc:
            return ChunkContentResult(
                chunk_id=chunk.chunk_id, source="file", readable=False,
                stored_path=None, registered_path=chunk.stored_path,
                error_code="CHUNK_FILE_UNREADABLE",
                error_detail={"stored_path": chunk.stored_path,
                              "reason": str(exc)})
        return ChunkContentResult(
            chunk_id=chunk.chunk_id, source="file", readable=True,
            length=size, sha256=leaf.hexdigest(),
            stored_path=str(path),
            registered_path=chunk.stored_path)

    def hash_linear(self, chunks_in_offset_order) -> Optional[str]:
        h = hashlib.sha256()
        for chunk in chunks_in_offset_order:
            result = self.inspect(chunk, h)
            if not result.readable:
                return None
        return h.hexdigest()
