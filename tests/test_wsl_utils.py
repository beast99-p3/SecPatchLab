import pytest


def test_wsl_list_distros_strips_nuls(monkeypatch):
    from secpatchlab.core import utils

    class Dummy:
        def __init__(self, stdout: str):
            self.stdout = stdout

    def fake_run(*args, **kwargs):
        # Typical captured UTF-16LE-ish text ends up with embedded NULs.
        return Dummy("U\x00b\x00u\x00n\x00t\x00u\x00\r\nD\x00e\x00b\x00i\x00a\x00n\x00\r\n")

    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    distros = utils.wsl_list_distros()
    assert distros == ["Ubuntu", "Debian"]


def test_pick_wsl_distro_no_ubuntu_includes_seed_demo_hint(monkeypatch):
    from secpatchlab.core import utils

    monkeypatch.setattr(utils, "wsl_list_distros", lambda: ["Debian", "docker-desktop"])
    monkeypatch.delenv("SECPATCHLAB_WSL_DISTRO", raising=False)

    with pytest.raises(utils.CommandError) as excinfo:
        utils.pick_wsl_distro()

    msg = str(excinfo.value)
    assert "No Ubuntu WSL distro found" in msg
    assert "seed-demo" in msg


def test_pick_wsl_distro_requested_missing_lists_available(monkeypatch):
    from secpatchlab.core import utils

    monkeypatch.setattr(utils, "wsl_list_distros", lambda: ["Ubuntu-22.04", "Debian"])
    monkeypatch.setenv("SECPATCHLAB_WSL_DISTRO", "Ubuntu-24.04")

    with pytest.raises(utils.CommandError) as excinfo:
        utils.pick_wsl_distro()

    msg = str(excinfo.value)
    assert "Requested WSL distro" in msg
    assert "Ubuntu-22.04" in msg
