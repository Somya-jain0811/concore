"""Tests for the stricter concore process detection logic.

Verifies that is_concore_study_process() correctly identifies real concore
study processes while rejecting false positives like editors, git, and IDEs
that happen to have "concore" in their command line.

Import bypasses concore_cli.__init__ (which pulls in click) so the test
runs even when click isn't installed — keeps the CI matrix lean.
"""

import sys
import os
import importlib
import pytest

# direct import avoids the concore_cli.__init__ → click dependency chain
_mod_path = os.path.join(
    os.path.dirname(__file__), os.pardir,
    "concore_cli", "commands", "process_utils.py",
)
spec = importlib.util.spec_from_file_location("process_utils", _mod_path)
process_utils = importlib.util.module_from_spec(spec)
spec.loader.exec_module(process_utils)

is_concore_study_process = process_utils.is_concore_study_process


# -- Processes that SHOULD be detected (true positives) --

@pytest.mark.parametrize("cmdline,desc", [
    (["python", "concore_plant.py"], "typical study node"),
    (["python3", "concore_controller.py", "--port", "5555"], "study node with args"),
    (["python", "-u", "concore.py"], "unbuffered concore.py"),
    (["python.exe", "concore.py"], "Windows python.exe"),
    (["python3.11", "concore_sensor.py"], "versioned python"),
    (["python", "-m", "concore", "run"], "module invocation"),
    (["C:\\Python311\\python.exe", "concore_observer.py"], "full path python"),
    (["concorekill.bat"], "Windows kill script"),
    (["cmd.exe", "/c", "concorekill.bat"], "kill script via cmd"),
    (["concore", "build", "workflow.graphml"], "CLI build command"),
    (["concore", "stop"], "CLI stop command"),
    (["concore", "watch", "./study"], "CLI watch command"),
])
def test_true_positives(cmdline, desc):
    """Real concore processes must always be detected."""
    proc = {"pid": 1234, "name": "python", "cmdline": cmdline}
    assert is_concore_study_process(proc) is True, f"missed: {desc}"


# -- Processes that MUST NOT be detected (false positives the old code hit) --

@pytest.mark.parametrize("cmdline,desc", [
    (["code", "concore/README.md"], "VS Code editing concore file"),
    (["vim", "/home/user/concore/concore_base.py"], "vim editing concore source"),
    (["git", "-C", "concore", "pull"], "git pull inside concore repo"),
    (["git", "log", "--oneline", "concore/stop.py"], "git log on concore file"),
    (["grep", "-r", "concore", "./src"], "grep searching for concore"),
    (["cat", "/tmp/concore_debug.log"], "reading a concore log file"),
    (["less", "concore/README.md"], "less viewing concore docs"),
    (["find", ".", "-name", "concore*"], "find searching for concore files"),
    (["notepad.exe", "C:\\repos\\concore\\concore.py"], "notepad editing concore"),
    (["explorer.exe", "C:\\repos\\concore"], "Windows explorer in concore dir"),
])
def test_false_positives_rejected(cmdline, desc):
    """Editors, git, and tools touching concore files must NOT be killed."""
    proc = {"pid": 5678, "name": cmdline[0], "cmdline": cmdline}
    assert is_concore_study_process(proc) is False, f"false positive: {desc}"


# -- PID registry takes priority --

def test_pid_registry_match():
    """A PID in the registry should be detected even with an empty cmdline."""
    proc = {"pid": 9999, "name": "python", "cmdline": []}
    assert is_concore_study_process(proc, registered_pids={9999}) is True


def test_pid_registry_miss():
    """A PID NOT in the registry with innocent cmdline should be rejected."""
    proc = {"pid": 1111, "name": "code", "cmdline": ["code", "concore/foo.py"]}
    assert is_concore_study_process(proc, registered_pids={9999}) is False


# -- Edge cases --

def test_empty_cmdline():
    """Process with no cmdline (zombie, kernel thread) should not match."""
    proc = {"pid": 42, "name": "python", "cmdline": []}
    assert is_concore_study_process(proc) is False


def test_none_cmdline():
    """Process where psutil returns None for cmdline."""
    proc = {"pid": 42, "name": "python", "cmdline": None}
    assert is_concore_study_process(proc) is False


# -- cwd marker-file detection --

def test_cwd_markers_match(tmp_path):
    """Process in a dir with concore runtime files should be detected."""
    # create the marker files mkconcore.py generates for study nodes
    (tmp_path / "concore.iport").touch()
    (tmp_path / "concore.py").touch()
    proc = {"pid": 7777, "name": "python", "cmdline": ["python", "some_script.py"]}
    assert is_concore_study_process(proc, cwd=str(tmp_path)) is True


def test_cwd_markers_missing():
    """Process with no cwd (or non-study dir) should not match on markers."""
    proc = {"pid": 7777, "name": "python", "cmdline": ["python", "some_script.py"]}
    assert is_concore_study_process(proc, cwd=None) is False
