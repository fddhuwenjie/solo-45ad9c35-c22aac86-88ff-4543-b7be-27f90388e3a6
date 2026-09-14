"""Chunk content resolution.

When a chunk carries no inline ``content_b64`` the verifier must read the
actual bytes from the registered file path (``stored_path``) so that every
chunk digest and the whole-image linear hash can be recomputed. Resolution is
sandboxed to a configured evidence root so a manifest cannot make the service
read arbitrary host files.

Beyond whole-chunk hashing, bad-sector provenance needs two finer operations:

* :meth:`read_range` returns the exact bytes of a sector sub-range of a chunk,
  so the digest declared by a successful read attempt can be recomputed and a
  fill declaration's bytes can be compared with the image;
* :meth:`hole_status` reports whether that byte range is a real filesystem
  sparse hole (``SEEK_HOLE``), i.e. the imaging tool wrote nothing instead of
  reading zeroes from the source.
"""
from __future__ import annotations

import errno
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


@dataclass
class RangeReadResult:
    """Exact bytes of a byte sub-range inside one chunk."""

    readable: bool
    data: Optional[bytes] = None
    source: str = "none"
    stored_path: Optional[str] = None
    registered_path: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class HoleStatusResult:
    """Whether a byte range of a chunk is a real filesystem sparse hole."""

    readable: bool                    # the range was inspectable
    detection_available: bool         # the platform/filesystem supports SEEK_DATA
    is_hole: bool = False
    source: str = "none"
    stored_path: Optional[str] = None
    registered_path: Optional[str] = None
    error_code: Optional[str] = None



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

    def read_range(self, chunk, byte_start: int, byte_end: int) -> RangeReadResult:
        """Return the exact bytes ``[byte_start, byte_end)`` of one chunk.

        Used to recompute a successful read attempt's sector-range digest and
        to compare a declared fill pattern against the bytes actually stored
        in the image.
        """
        ...

    def hole_status(self, chunk, byte_start: int, byte_end: int) -> HoleStatusResult:
        """Report whether the range is a real filesystem sparse hole."""
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

    def _resolve_chunk_path(self, chunk) -> tuple[
            Optional[Path], Optional[str], Optional[str]]:
        path, outside = self._resolve_path(chunk.stored_path)
        if outside:
            return None, outside, chunk.stored_path
        return path, None, chunk.stored_path

    def _inline_bytes(self, chunk) -> tuple[Optional[bytes], Optional[str]]:
        if chunk.content_b64 is None:
            return None, None
        try:
            return decode_b64_strict(chunk.content_b64), None
        except Exception:
            return None, "CHUNK_CONTENT_BAD_BASE64"

    def inspect(self, chunk, *linear_hashers) -> ChunkContentResult:
        """Verify one chunk. Extra hashers receive the same bytes in one read."""
        if chunk.content_b64 is not None:
            data, bad = self._inline_bytes(chunk)
            if bad:
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

        path, outside, registered = self._resolve_chunk_path(chunk)
        if outside:
            return ChunkContentResult(
                chunk_id=chunk.chunk_id, source="file", readable=False,
                stored_path=None, registered_path=registered,
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
                stored_path=None, registered_path=registered,
                error_code="CHUNK_FILE_UNREADABLE",
                error_detail={"stored_path": chunk.stored_path,
                              "reason": "not found"})
        except (IsADirectoryError, PermissionError, OSError) as exc:
            return ChunkContentResult(
                chunk_id=chunk.chunk_id, source="file", readable=False,
                stored_path=None, registered_path=registered,
                error_code="CHUNK_FILE_UNREADABLE",
                error_detail={"stored_path": chunk.stored_path,
                              "reason": str(exc)})
        return ChunkContentResult(
            chunk_id=chunk.chunk_id, source="file", readable=True,
            length=size, sha256=leaf.hexdigest(),
            stored_path=str(path), registered_path=registered)

    # ----------------------------------------- bad-sector provenance API ----
    def read_range(self, chunk, byte_start: int, byte_end: int) -> RangeReadResult:
        """Read the exact bytes of a chunk sub-range (sector aligned callers)."""
        length = byte_end - byte_start
        if chunk.content_b64 is not None:
            data, bad = self._inline_bytes(chunk)
            if bad:
                return RangeReadResult(readable=False, source="inline",
                                       error_code=bad)
            if byte_end > len(data):
                return RangeReadResult(
                    readable=False, source="inline",
                    error_code="CHUNK_CONTENT_LENGTH_MISMATCH")
            return RangeReadResult(readable=True,
                                   data=data[byte_start:byte_end],
                                   source="inline")

        if not chunk.stored_path:
            return RangeReadResult(readable=False, source="none",
                                   error_code="CHUNK_CONTENT_UNAVAILABLE")
        path, outside, registered = self._resolve_chunk_path(chunk)
        if outside:
            return RangeReadResult(readable=False, source="file",
                                   registered_path=registered, error_code=outside)
        try:
            with open(path, "rb") as fh:
                fh.seek(byte_start)
                data = b""
                remaining = length
                while remaining > 0:
                    block = fh.read(min(READ_CHUNK, remaining))
                    if not block:
                        break  # truncation: caller compares length
                    data += block
                    remaining -= len(block)
        except FileNotFoundError:
            return RangeReadResult(readable=False, source="file",
                                   registered_path=registered,
                                   error_code="CHUNK_FILE_UNREADABLE")
        except (IsADirectoryError, PermissionError, OSError):
            return RangeReadResult(readable=False, source="file",
                                   registered_path=registered,
                                   error_code="CHUNK_FILE_UNREADABLE")
        if len(data) != length:
            return RangeReadResult(readable=False, data=None, source="file",
                                   stored_path=str(path),
                                   registered_path=registered,
                                   error_code="CHUNK_CONTENT_LENGTH_MISMATCH")
        return RangeReadResult(readable=True, data=data, source="file",
                               stored_path=str(path), registered_path=registered)

    def hole_status(self, chunk, byte_start: int, byte_end: int) -> HoleStatusResult:
        """Whether ``[byte_start, byte_end)`` is a sparse hole.

        Inline base64 content can never be a sparse hole (the bytes were
        transferred explicitly). Files use ``SEEK_DATA``/``SEEK_HOLE`` when the
        platform/filesystem supports them; otherwise ``detection_available`` is
        False so the caller cannot mistake "unknown" for "hole".
        """
        if chunk.content_b64 is not None:
            _, bad = self._inline_bytes(chunk)
            if bad:
                return HoleStatusResult(readable=False, detection_available=True,
                                        source="inline", error_code=bad)
            return HoleStatusResult(readable=True, detection_available=True,
                                    is_hole=False, source="inline")

        if not chunk.stored_path:
            return HoleStatusResult(readable=False, detection_available=False,
                                    source="none",
                                    error_code="CHUNK_CONTENT_UNAVAILABLE")
        path, outside, registered = self._resolve_chunk_path(chunk)
        if outside:
            return HoleStatusResult(readable=False, detection_available=False,
                                    source="file", registered_path=registered,
                                    error_code=outside)
        try:
            fd = os.open(str(path), os.O_RDONLY)
        except FileNotFoundError:
            return HoleStatusResult(readable=False, detection_available=False,
                                    source="file", registered_path=registered,
                                    error_code="CHUNK_FILE_UNREADABLE")
        except (IsADirectoryError, PermissionError, OSError):
            return HoleStatusResult(readable=False, detection_available=False,
                                    source="file", registered_path=registered,
                                    error_code="CHUNK_FILE_UNREADABLE")
        try:
            seek_data = getattr(os, "SEEK_DATA", None)
            if seek_data is None:
                return HoleStatusResult(readable=True, detection_available=False,
                                        source="file", stored_path=str(path),
                                        registered_path=registered)
            try:
                # SEEK_DATA at a data/hole boundary can return the boundary
                # itself; probe the midpoint of the requested range. The range
                # is a hole when no data extent starts before its end.
                midpoint = byte_start + (byte_end - byte_start) // 2
                next_data = os.lseek(fd, midpoint, os.SEEK_DATA)
                is_hole = next_data >= byte_end
            except OSError as exc:
                if exc.errno == errno.ENXIO:
                    # no data from midpoint to EOF: tail region is one hole
                    is_hole = True
                else:
                    return HoleStatusResult(
                        readable=True, detection_available=False,
                        source="file", stored_path=str(path),
                        registered_path=registered)
            return HoleStatusResult(readable=True, detection_available=True,
                                    is_hole=is_hole, source="file",
                                    stored_path=str(path),
                                    registered_path=registered)
        finally:
            os.close(fd)

    def hash_linear(self, chunks_in_offset_order) -> Optional[str]:
        h = hashlib.sha256()
        for chunk in chunks_in_offset_order:
            result = self.inspect(chunk, h)
            if not result.readable:
                return None
        return h.hexdigest()
