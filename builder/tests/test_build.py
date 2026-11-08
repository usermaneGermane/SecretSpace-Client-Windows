"""The builder's decisions, with a fake command runner: no process starts."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import build                                                   # noqa: E402

PROJECT = build.project_dir()          # the real repo: its files all exist
PY_OUT = "3.13.5\nC:\\Python313\\python.exe"


class FakeRunner:
    """Answers commands from a table of (substring -> Result); records calls."""

    def __init__(self, answers=None, default=build.Result(0, "")):
        self.answers = answers or {}
        self.default = default
        self.calls = []

    def __call__(self, cmd, cwd=None, env=None, on_line=None):
        self.calls.append((cmd, env))
        text = " ".join(cmd)
        for needle, result in self.answers.items():
            if needle in text:
                return result
        return self.default


def healthy(**overrides):
    answers = {"import sys; print(sys.version": build.Result(0, PY_OUT)}
    answers.update(overrides)
    return FakeRunner(answers)


def checks_by_name(checks):
    return {c.name: c for c in checks}


def has_iscc():
    return r"C:\Inno\ISCC.exe"


# --- finding Python --------------------------------------------------------
def test_prefers_the_py_launcher():
    py = build.find_python(healthy())
    assert py.cmd == ["py", "-3"] and py.version == "3.13.5"


def test_skips_a_broken_candidate():
    """e.g. no py launcher, or the Microsoft Store placeholder (exit 9009)."""
    runner = FakeRunner({"py -3 -c": build.Result(9009, "Python was not found"),
                         "python -c": build.Result(0, PY_OUT)})
    assert build.find_python(runner).cmd == ["python"]


def test_no_python_at_all():
    assert build.find_python(FakeRunner(default=build.Result(127, ""))) is None


# --- the checklist ---------------------------------------------------------
def test_everything_present_means_ready():
    checks = build.check_all(PROJECT, healthy(), find_iscc=has_iscc)
    assert build.can_build(checks), [(c.name, c.detail) for c in checks]
    assert build.fix_commands(checks, PROJECT) == []


def test_missing_libraries_are_installed_from_requirements():
    runner = healthy(**{"import customtkinter": build.Result(1, ""),
                        "import PIL": build.Result(1, "")})
    checks = build.check_all(PROJECT, runner, find_iscc=has_iscc)
    libs = checks_by_name(checks)["PassMan's libraries"]
    assert not libs.ok and libs.fix == "pip"
    assert libs.detail == "missing: customtkinter, Pillow"
    [(label, cmd)] = build.fix_commands(checks, PROJECT,
                                        build.find_python(runner))
    assert cmd[-2:] == ["-r", os.path.join(PROJECT, "requirements.txt")]


def test_missing_pyinstaller_is_its_own_install():
    runner = healthy(**{"import PyInstaller": build.Result(1, "")})
    checks = build.check_all(PROJECT, runner, find_iscc=has_iscc)
    [(label, cmd)] = build.fix_commands(checks, PROJECT,
                                        build.find_python(runner))
    assert cmd[-3:] == ["pip", "install", "pyinstaller"]


def test_without_python_the_rest_waits_and_winget_is_offered():
    runner = FakeRunner(default=build.Result(127, ""))
    checks = build.check_all(PROJECT, runner, find_iscc=has_iscc)
    by = checks_by_name(checks)
    assert by["Python 3"].fix == "winget-python"
    assert by["PyInstaller"].detail == "needs Python first"
    [(label, cmd)] = build.fix_commands(checks, PROJECT, None)
    assert cmd[0] == "winget" and cmd[-1] == build.WINGET_PYTHON
    assert "--scope" in cmd and cmd[cmd.index("--scope") + 1] == "user"
    assert not build.can_build(checks)


def test_missing_inno_setup_offers_winget():
    checks = build.check_all(PROJECT, healthy(), find_iscc=lambda: None)
    [(label, cmd)] = build.fix_commands(checks, PROJECT,
                                        build.find_python(healthy()))
    assert cmd[-1] == build.WINGET_INNO


def test_missing_tkinter_is_a_manual_step():
    runner = healthy(**{"import tkinter": build.Result(1, "")})
    checks = build.check_all(PROJECT, runner, find_iscc=has_iscc)
    assert checks_by_name(checks)["tkinter"].fix == "manual"
    assert any("tcl/tk" in s for s in build.manual_steps(checks))
    assert build.fix_commands(checks, PROJECT, build.find_python(runner)) == []


def test_a_broken_source_file_blocks_the_build():
    runner = healthy(**{"import gui": build.Result(
        1, "Traceback...\nModuleNotFoundError: No module named 'sync'")})
    checks = build.check_all(PROJECT, runner, find_iscc=has_iscc)
    imp = checks_by_name(checks)["The app imports cleanly"]
    assert not imp.ok and "No module named 'sync'" in imp.detail


def test_an_incomplete_folder_is_reported(tmp_path):
    checks = build.check_all(str(tmp_path), healthy(), find_iscc=has_iscc)
    files = checks_by_name(checks)["PassMan source files"]
    assert not files.ok and "Copy the whole project folder" in files.detail


# --- versions and paths ----------------------------------------------------
def test_version_is_read_from_version_py():
    import re
    assert re.fullmatch(r"\d+\.\d+\.\d+(-(alpha|beta|rc)\.\d+)?",
                        build.app_version(PROJECT))


@pytest.mark.parametrize("text, numbers", [
    ("2.11.0", "2.11.0.0"), ("3.0.0-alpha.1", "3.0.0.1"), ("3.0.0", "3.0.0.0")])
def test_file_version(text, numbers):
    assert build.file_version(text) == numbers


def test_file_version_refuses_junk():
    with pytest.raises(ValueError):
        build.file_version("3.0.0-dev")


def test_file_version_agrees_with_the_app():
    import sys
    sys.path.insert(0, os.path.join(PROJECT, "sourceFiles"))
    import version
    assert build.file_version(version.__version__) == ".".join(
        str(n) for n in version.file_version())


def test_iscc_found_in_the_per_user_location(monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\x\AppData\Local")
    found = build.find_iscc(exists=lambda p: "AppData" in p)
    assert found == r"C:\Users\x\AppData\Local\Programs\Inno Setup 6\ISCC.exe"


# --- the build -------------------------------------------------------------
@pytest.fixture
def project(tmp_path):
    (tmp_path / "sourceFiles").mkdir()
    (tmp_path / "sourceFiles" / "version.py").write_text(
        '__version__ = "9.8.7"\n')
    (tmp_path / "PassMan.exe").write_text("last time's build")
    return str(tmp_path)


def test_build_runs_the_steps_in_order(project):
    runner = FakeRunner()
    py = build.Python(["py", "-3"], "3.13.5", "python.exe")
    assert build.build(project, py, r"C:\Inno\ISCC.exe", log=lambda s: None,
                       runner=runner, exists=lambda p: True)
    cmds = [" ".join(c) for c, _ in runner.calls]
    assert "PassMan-installer.spec" in cmds[0]
    assert "/DAppVersion=9.8.7" in cmds[1] and "PassMan.iss" in cmds[1]
    assert "/DFileVersion=9.8.7.0" in cmds[1]
    assert len(cmds) == 2


def test_the_portable_exe_is_no_longer_built(project):
    runner = FakeRunner()
    build.build(project, build.Python(["py"], "3", "p"), "iscc",
                log=lambda s: None, runner=runner, exists=lambda p: True)
    cmds = [" ".join(c) for c, _ in runner.calls]
    assert not any(c.endswith("PassMan.spec") for c in cmds)
    assert not any("--distpath " + project + " " in c for c in cmds)


def test_only_the_app_is_built():
    """The server has its own repository and its own build."""
    steps = build.build_steps("P", build.Python(["py"], "3", "p"), "iscc", "1.0.0")
    products = [os.path.basename(product) for _, _, product in steps]
    assert products == ["PassMan.exe", "PassMan-Client-Installer.exe"]


def test_old_outputs_are_removed_before_building(project):
    build.build(project, build.Python(["py"], "3", "p"), "iscc",
                log=lambda s: None, runner=FakeRunner(),
                exists=lambda p: True)
    # A portable exe left by 2.2 or earlier must not pass for a new build.
    assert not os.path.exists(os.path.join(project, "PassMan.exe"))


def test_an_old_installer_is_removed_too(project):
    old = os.path.join(project, "PassMan-Client-Installer.exe")
    with open(old, "w") as f:
        f.write("last time's build")
    build.remove_previous(project)
    assert not os.path.exists(old)


def test_build_stops_at_the_first_failure(project):
    runner = FakeRunner({"PassMan-installer.spec": build.Result(1, "boom")})
    lines = []
    ok = build.build(project, build.Python(["py"], "3", "p"), "iscc",
                     log=lines.append, runner=runner, exists=lambda p: True)
    assert not ok
    assert not any("iscc" in c for c, _ in runner.calls)
    assert any(line.startswith("FAILED") for line in lines)


def test_a_missing_product_counts_as_failure(project):
    """Exit code 0 is not enough: PyInstaller can 'succeed' and write nothing."""
    ok = build.build(project, build.Python(["py"], "3", "p"), "iscc",
                     log=lambda s: None, runner=FakeRunner(),
                     exists=lambda p: False)
    assert not ok

