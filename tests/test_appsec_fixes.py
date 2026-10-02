"""Regression tests for fixes made after the Phase 6 appsec scan (docs/security-scans.md)."""
import io
import os
import stat
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.prepare_training_data import safe_extract  # noqa: E402


def make_tar(tmp_path, members):
    """members: list of (name, kind, payload) with kind in file | dir | symlink | hardlink."""
    path = tmp_path / "t.tar"
    with tarfile.open(path, "w") as tar:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = payload.encode()
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, payload
                tar.addfile(info)
            elif kind == "hardlink":
                info.type, info.linkname = tarfile.LNKTYPE, payload
                tar.addfile(info)
    return path


def test_a_normal_archive_is_extracted(tmp_path):
    src = make_tar(tmp_path, [("repo/", "dir", None), ("repo/data/a.csv", "file", "x,y\n1,2\n")])
    dest = tmp_path / "out"
    dest.mkdir()
    with tarfile.open(src) as tar:
        safe_extract(tar, dest)
    assert (dest / "repo" / "data" / "a.csv").read_text() == "x,y\n1,2\n"


@pytest.mark.skipif(sys.platform == "win32" or not hasattr(tarfile, "data_filter"),
                    reason="file modes only exist on POSIX, and the extraction filter needs Python 3.12 (or a patched 3.10/3.11)")
def test_extraction_does_not_take_its_modes_from_the_archive(tmp_path):
    """A directory stored as 0o644 came out untraversable on Linux (this test's first failure, in CI: Windows ignores modes so it never showed locally),
    and a setuid member would have stayed setuid. The extraction filter normalises both."""
    path = tmp_path / "modes.tar"
    with tarfile.open(path, "w") as tar:
        d = tarfile.TarInfo("repo/")
        d.type, d.mode = tarfile.DIRTYPE, 0o644
        tar.addfile(d)
        f = tarfile.TarInfo("repo/a.txt")
        f.size, f.mode = 1, 0o4755
        tar.addfile(f, io.BytesIO(b"x"))
    dest = tmp_path / "out"
    dest.mkdir()
    with tarfile.open(path) as tar:
        safe_extract(tar, dest)
    assert os.access(dest / "repo", os.X_OK)
    assert (dest / "repo" / "a.txt").read_bytes() == b"x"
    assert stat.S_IMODE((dest / "repo" / "a.txt").stat().st_mode) & 0o7000 == 0


WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="a backslash is a path separator only on Windows; on POSIX it is an ordinary filename character")


@pytest.mark.parametrize("name", ["../escape.txt", "repo/../../escape.txt", "/tmp/absolute-escape.txt", pytest.param("..\\escape.txt", marks=WINDOWS_ONLY)])
def test_a_member_that_would_leave_the_destination_is_refused_and_nothing_is_written(tmp_path, name):
    src = make_tar(tmp_path, [("ok.txt", "file", "fine"), (name, "file", "evil")])
    dest = tmp_path / "out"
    dest.mkdir()
    with tarfile.open(src) as tar, pytest.raises(SystemExit, match="refusing"):
        safe_extract(tar, dest)
    assert not (tmp_path / "escape.txt").exists() and not (dest / "ok.txt").exists()      # validated before anything is extracted


@pytest.mark.parametrize("kind,payload", [("symlink", "/etc/passwd"), ("symlink", "../outside"), ("hardlink", "ok.txt")])
def test_links_are_refused(tmp_path, kind, payload):
    src = make_tar(tmp_path, [("ok.txt", "file", "fine"), ("link", kind, payload)])
    dest = tmp_path / "out"
    dest.mkdir()
    with tarfile.open(src) as tar, pytest.raises(SystemExit, match="links and special files"):
        safe_extract(tar, dest)


# ---- the proxy must still wire the upstream's pipes (a `# nosec` comment once swallowed them: caught only by the stdio test hanging) ----------

def test_the_mcp_proxy_starts_its_upstream_with_all_three_pipes(monkeypatch):
    import subprocess

    from gateway.actions import mcp_proxy

    seen = {}

    class Stop(Exception):
        pass

    def fake_popen(cmd, **kwargs):
        seen["cmd"], seen["kwargs"] = cmd, kwargs
        raise Stop()

    monkeypatch.setattr(mcp_proxy.subprocess, "Popen", fake_popen)
    with pytest.raises(Stop):
        mcp_proxy.run_stdio(["upstream", "--flag"], proxy=None)
    assert seen["cmd"] == ["upstream", "--flag"]
    assert seen["kwargs"]["stdin"] == subprocess.PIPE and seen["kwargs"]["stdout"] == subprocess.PIPE
    assert seen["kwargs"]["stderr"] is not None and seen["kwargs"]["text"] is True
