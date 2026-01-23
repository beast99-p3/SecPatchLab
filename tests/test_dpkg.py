import subprocess

from secpatchlab.core.dpkg import compare_versions


def test_compare_versions_true(monkeypatch):
    def fake_run(cmd, check):
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert compare_versions("1.0", "lt", "2.0") is True


def test_compare_versions_false(monkeypatch):
    def fake_run(cmd, check):
        raise subprocess.CalledProcessError(returncode=1, cmd=cmd)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert compare_versions("2.0", "lt", "1.0") is False
