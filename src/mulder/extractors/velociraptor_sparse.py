"""Reconstruct Velociraptor sparse uploads using their JSON range indexes.

Format reference: Velocidex/velociraptor reporting/container.go,
Container.maybeCollectSparseFile. Missing protobuf JSON integers mean zero.
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from mulder.extractors.velociraptor import CollectionError, read_metadata

MAX_UPLOAD_BYTES = 2 * 1024**3
_BLOCK = 1024 * 1024


@dataclass(frozen=True)
class SparseRange:
    file_offset: int
    original_offset: int
    file_length: int
    length: int


def sparse_ranges(
    archive: zipfile.ZipFile,
    member: str,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> list[SparseRange]:
    """Validate the entire map before creating or writing a reconstructed file."""
    document = read_metadata(archive, member + ".idx")
    rows = document.get("ranges")
    if not isinstance(rows, list) or not rows or len(rows) > 100_000:
        raise CollectionError("Invalid sparse index: expected 1..100000 ranges")
    ranges: list[SparseRange] = []
    packed_end = original_end = 0
    for row in rows:
        if not isinstance(row, dict):
            raise CollectionError("Invalid sparse index range")
        values = [
            row.get(k, 0) for k in ("file_offset", "original_offset", "file_length", "length")
        ]
        if any(type(value) is not int or value < 0 for value in values):
            raise CollectionError("Sparse offsets and lengths must be nonnegative integers")
        segment = SparseRange(*values)
        if (
            segment.length == 0
            or segment.file_length not in (0, segment.length)
            or segment.file_offset != packed_end
            or segment.original_offset < original_end
        ):
            raise CollectionError("Inconsistent or overlapping sparse ranges")
        packed_end += segment.file_length
        original_end = segment.original_offset + segment.length
        if original_end > max_bytes:
            raise CollectionError("Reconstructed upload exceeds size limit")
        ranges.append(segment)
    if packed_end != archive.getinfo(member).file_size:
        raise CollectionError("Sparse index does not cover the stored upload exactly")
    return ranges


def write_upload(
    archive: zipfile.ZipFile,
    member: str,
    output: BinaryIO,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> dict[str, object]:
    """Stream regular or sparse bytes, returning hashes of both representations."""
    entry = archive.getinfo(member)
    if entry.is_dir() or member.endswith(".idx"):
        raise CollectionError("Choose an uploaded data file, not a directory or .idx sidecar")
    if entry.file_size > max_bytes:
        raise CollectionError("Stored upload exceeds size limit")
    sparse = member + ".idx" in archive.namelist()
    ranges = (
        sparse_ranges(archive, member, max_bytes)
        if sparse
        else [SparseRange(0, 0, entry.file_size, entry.file_size)]
    )
    stored_hash = hashlib.sha256()
    expanded_hash = hashlib.sha256()
    written = 0
    padding = bytes(_BLOCK)

    def zeroes(size: int) -> None:
        while size:
            block = padding[: min(size, _BLOCK)]
            output.write(block)
            expanded_hash.update(block)
            size -= len(block)

    with archive.open(entry) as source:
        for segment in ranges:
            zeroes(segment.original_offset - written)
            remaining = segment.file_length
            while remaining:
                block = source.read(min(remaining, _BLOCK))
                if not block:
                    raise CollectionError("Truncated stored upload")
                output.write(block)
                stored_hash.update(block)
                expanded_hash.update(block)
                remaining -= len(block)
            zeroes(segment.length - segment.file_length)
            written = segment.original_offset + segment.length
        if source.read(1):
            raise CollectionError("Unmapped bytes in stored upload")
    return {
        "sha256": expanded_hash.hexdigest(),
        "stored_sha256": stored_hash.hexdigest(),
        "size_bytes": written,
        "stored_size_bytes": entry.file_size,
        "sparse_reconstructed": sparse,
        "sparse_range_count": len(ranges) if sparse else 0,
        "sparse_index_sha256": (
            hashlib.sha256(archive.read(member + ".idx")).hexdigest() if sparse else None
        ),
    }
