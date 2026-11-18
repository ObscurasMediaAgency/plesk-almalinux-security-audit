from __future__ import annotations

import os
from pathlib import Path

import pytest

from plesk_audit.file_reader import BoundedFileReader, FileNotAllowedError, is_allowed_file


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


def test_tail_reads_end_of_file(tmp_path: Path) -> None:
    (tmp_path / "log").write_bytes(b"a" * 3000 + b"END")
    result = reader(tmp_path, "log", limit=1024).read(str(tmp_path / "log"), tail=True)
    assert result.truncated is True and result.content.endswith("END")
    assert len(result.content) == 1024


@pytest.mark.parametrize(
    ("path", "allowed"),
    [
        ("/etc/sudoers.d/deploy", True),
        ("/etc/sudoers.d/../shadow", False),
        ("/etc/sudoers.d/a.b", False),
        ("/home/alice/.ssh/authorized_keys", True),
        ("/home/alice/.ssh/id_ed25519", False),
        ("/var/www/vhosts/example.test/.ssh/authorized_keys", True),
        ("/etc/shadow", False),
    ],
)
def test_allow_list_patterns(path: str, allowed: bool) -> None:
    assert is_allowed_file(path) is allowed


def test_list_dir_metadata_only(tmp_path: Path) -> None:
    d = tmp_path / "d"
    d.mkdir()
    (d / "b").write_text("secret content")
    (d / "a").mkdir()
    (d / "c").symlink_to(d / "b")
    files = BoundedFileReader(1024, allowed_dirs=frozenset({str(d)}), max_dir_entries=10)
    result = files.list_dir(str(d))
    assert result.status == "ok"
    assert [(e.name, e.kind) for e in result.entries] == [
        ("a", "dir"),
        ("b", "file"),
        ("c", "symlink"),
    ]
    with pytest.raises(FileNotAllowedError):
        files.list_dir(str(tmp_path))


def test_list_dir_refuses_symlinked_dir_and_truncates(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    for i in range(3):
        (real / str(i)).write_text("x")
    (tmp_path / "link").symlink_to(real)
    allowed = frozenset({str(real), str(tmp_path / "link"), str(tmp_path / "missing")})
    files = BoundedFileReader(1024, allowed_dirs=allowed, max_dir_entries=2)
    assert files.list_dir(str(tmp_path / "link")).status == "outside_allow_list"
    assert files.list_dir(str(tmp_path / "missing")).status == "missing"
    listing = files.list_dir(str(real))
    assert listing.truncated is True and len(listing.entries) == 2
