"""Shared concore process detection logic.

The old substring check ("concore" in cmdline) was dangerously broad — it
matched editors, git, IDEs, and anything else that happened to touch a file
with "concore" in its path.  This module provides a strict detector that
won't nuke your VS Code session when you run ``concore stop``.

See: https://github.com/ControlCore-Project/concore/issues/XXX
"""

import ntpath
import os
import re
import glob

# Matches command lines that are actually *running* concore study code:
#   python concore_xxx.py …  |  python -m concore …  |  python3 ./concore.py …
# Does NOT match:  code concore/README.md  |  git -C concore pull
_CONCORE_EXEC_RE = re.compile(
    r"""
    (?:python[23w]?[\d.]*)          # python interpreter (python, python3, python3.11, pythonw …)
    (?:\.exe)?                      # optional .exe on Windows
    \s+.*?                          # optional flags like -u, -m, etc.
    (?:                             # the actual concore entry point — one of:
        concore(?:_\w+)?\.py        #   concore.py, concore_plant.py, concore_controller.py …
      | -m\s+concore                #   python -m concore …
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Known concore CLI entry points — matched as standalone tokens so
# "concore stop" or "concore build" are caught but "vim concore/foo" is not.
_CLI_TOKEN_RE = re.compile(
    r"(?:^|\s|[/\\])concore(?:\.exe)?\s+(?:stop|status|build|watch|init|validate|doctor|setup|inspect|editor)",
    re.IGNORECASE,
)

# PID registry written by concore.py at study startup
_PID_REGISTRY_FILENAME = "concorekill_pids.txt"


def _load_registered_pids():
    """Collect PIDs from all concorekill_pids.txt files found under cwd."""
    pids = set()
    # search current dir and one level deep (covers typical study layouts)
    for pattern in [_PID_REGISTRY_FILENAME, os.path.join("*", _PID_REGISTRY_FILENAME)]:
        for path in glob.glob(pattern):
            try:
                with open(path, "r") as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped.isdigit():
                            pids.add(int(stripped))
            except OSError:
                continue
    return pids


def _has_concore_markers(cwd):
    """True if cwd contains concore runtime files (concore.iport + concore.py).

    mkconcore.py copies these into every generated study node directory,
    so their presence is a reliable signal that the process is a real
    concore node — not an editor or git operation.
    """
    if not cwd:
        return False
    try:
        if not os.path.isfile(os.path.join(cwd, "concore.iport")):
            return False
        return os.path.isfile(os.path.join(cwd, "concore.py")) or os.path.isfile(
            os.path.join(cwd, "concoredocker.py")
        )
    except OSError:
        return False


def is_concore_study_process(proc_info, registered_pids=None, cwd=None):
    """Return True only if *proc_info* is genuinely a concore study process.

    Detection priority:
      1. PID found in the concorekill_pids.txt registry  (most reliable)
      2. Process is running concorekill.bat               (Windows kill script)
      3. Command line matches a concore execution pattern  (regex, not substring)
      4. CLI invocation (concore stop, concore build, …)
      5. Working directory contains concore runtime markers (concore.iport)

    Args:
        proc_info: dict with keys "pid", "name", "cmdline" (from psutil).
        registered_pids: optional pre-loaded set of ints from the PID registry.
        cwd: optional working directory of the process (for marker-file check).
    """
    pid = proc_info.get("pid")
    cmdline = proc_info.get("cmdline") or []
    cmdline_str = " ".join(cmdline) if cmdline else ""

    # 1. Trust the PID registry — concore.py registers every study process
    if registered_pids and pid in registered_pids:
        return True

    # 2. concorekill.bat — ntpath.basename handles both / and \ separators
    if any(ntpath.basename(str(arg)).lower() == "concorekill.bat" for arg in cmdline):
        return True

    # 3. Strict regex: must look like an actual concore execution
    if _CONCORE_EXEC_RE.search(cmdline_str):
        return True

    # 4. CLI invocation (concore stop, concore build, etc.) — but NOT the
    #    current process (already filtered by callers via current_pid check)
    if _CLI_TOKEN_RE.search(cmdline_str):
        return True

    # 5. Working dir has concore runtime files (concore.iport + concore.py)
    if _has_concore_markers(cwd):
        return True

    return False
