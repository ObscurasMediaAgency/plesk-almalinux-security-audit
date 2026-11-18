from __future__ import annotations

import os
from pathlib import Path

import pytest

from plesk_audit.file_reader import BoundedFileReader, FileNotAllowedError


def reader(tmp_path: Path, *names: str, limit: int = 1024) -> BoundedFileReader:
    return BoundedFileReader(limit, allowed=frozenset(str(tmp_path / n) for n in names))


def test_reads_allowed_file_and_redacts(tmp_path: Path) -> None:
    (tmp_path / "a").write_text("x=1\ntoken=abc123\n")
    result = reader(tmp_path, "a").read(str(tmp_path / "a"))
    assert result.status == "ok"
    assert "x=1" in result.content and "abc123" not in result.content


def test_rejects_path_outside_allow_list(tmp_path: Path) -> None:
    with pytest.raises(FileNotAllowedError):
        reader(tmp_path, "a").read(str(tmp_path / "other"))


def test_symlink_to_disallowed_target_is_refused(tmp_path: Path) -> None:
    (tmp_path / "target").write_text("data")
    (tmp_path / "link").symlink_to(tmp_path / "target")
    result = reader(tmp_path, "link").read(str(tmp_path / "link"))
    assert result.status == "outside_allow_list" and result.content == ""


def test_truncates_large_file(tmp_path: Path) -> None:
    (tmp_path / "big").write_bytes(b"a" * 5000)
    result = reader(tmp_path, "big", limit=1024).read(str(tmp_path / "big"))
    assert result.truncated is True and len(result.content) == 1024


def test_missing_and_non_regular(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "fifo")
    files = reader(tmp_path, "missing", "fifo")
    assert files.read(str(tmp_path / "missing")).status == "missing"
    assert files.read(str(tmp_path / "fifo")).status == "not_regular"
