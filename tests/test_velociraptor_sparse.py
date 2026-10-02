"""Sparse ranges must reconstruct exact bytes, or fail without guessing."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest

from mulder.extractors.velociraptor import CollectionError
from mulder.extractors.velociraptor_sparse import write_upload


def _archive(data: bytes, ranges: list[dict[str, object]]) -> zipfile.ZipFile:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("uploads/file", data)
        archive.writestr("uploads/file.idx", json.dumps({"ranges": ranges}))
    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def test_leading_middle_and_trailing_holes() -> None:
    ranges: list[dict[str, object]] = [
        {"length": 3},
        {"original_offset": 3, "file_length": 2, "length": 2},
        {"file_offset": 2, "original_offset": 5, "length": 4},
        {"file_offset": 2, "original_offset": 9, "file_length": 2, "length": 2},
        {"file_offset": 4, "original_offset": 11, "length": 2},
    ]
    with _archive(b"abcd", ranges) as archive:
        output = io.BytesIO()
        details = write_upload(archive, "uploads/file", output)
    expected = bytes(3) + b"ab" + bytes(4) + b"cd" + bytes(2)
    assert output.getvalue() == expected
    assert details["size_bytes"] == 13
    assert details["sha256"] == hashlib.sha256(expected).hexdigest()
    assert details["stored_sha256"] == hashlib.sha256(b"abcd").hexdigest()


@pytest.mark.parametrize(
    "ranges",
    [
        [{"length": -1}],
        [{"length": True}],
        [{"length": "3"}],
        [{"file_length": 2, "length": 1}],
        [{"file_offset": 1, "file_length": 4, "length": 4}],
        [{"file_length": 3, "length": 3}],
        [
            {"file_length": 2, "length": 2},
            {"file_offset": 2, "original_offset": 1, "file_length": 2, "length": 2},
        ],
        [],
    ],
)
def test_invalid_maps(ranges: list[dict[str, object]]) -> None:
    with _archive(b"abcd", ranges) as archive, pytest.raises(CollectionError):
        output = io.BytesIO()
        write_upload(archive, "uploads/file", output)
    assert output.getvalue() == b""


def test_expansion_limit() -> None:
    with (
        _archive(b"", [{"length": 100}]) as archive,
        pytest.raises(CollectionError, match="size limit"),
    ):
        write_upload(archive, "uploads/file", io.BytesIO(), max_bytes=10)


def test_all_hole_file() -> None:
    with _archive(b"", [{"length": 5}]) as archive:
        output = io.BytesIO()
        write_upload(archive, "uploads/file", output)
        assert output.getvalue() == bytes(5)
