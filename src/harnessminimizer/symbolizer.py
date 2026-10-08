"""Keep target library search paths out of external LLVM symbolizers.

The bundled launchers exec the user's selected symbolizer in the same process.
They restore only LD_LIBRARY_PATH, preserving the environment that existed
before HarnessMinimizer added target libraries. No probes or temporary files are
needed, and nested runtime environments reuse the original selection.
"""
from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
import shutil


_LAUNCHERS = Path(__file__).resolve().parent / "symbolizers"
_LD_PRESENT = "HARNESSMINIMIZER_SYMBOLIZER_LD_LIBRARY_PATH_SET"
_LD_VALUE = "HARNESSMINIMIZER_SYMBOLIZER_LD_LIBRARY_PATH"


@lru_cache(maxsize=32)
def _find_llvm_symbolizer(configured: str | None, search_path: str, cwd: str) -> str | None:
    # Explicitly empty, missing, or non-LLVM selections retain their existing
    # semantics, including addr2line's different wire protocol.
    if configured == "":
        return None
    selected = configured if configured is not None else "llvm-symbolizer"
    if not Path(selected).name.startswith("llvm-symbolizer"):
        return None
    found = shutil.which(selected, path=search_path)
    if found is None:
        return None
    # Preserve symlink/launcher paths; only make relative selections independent
    # of the reducer's changing working directories.
    return os.path.abspath(os.path.join(cwd, found))


def isolate_symbolizer_environment(env: dict[str, str]) -> None:
    """Prepare env BEFORE adding target directories to LD_LIBRARY_PATH."""
    search_path = env.get("PATH", os.defpath)
    cwd = os.getcwd()
    for sanitizer in ("ASAN", "UBSAN"):
        variable = f"{sanitizer}_SYMBOLIZER_PATH"
        real_variable = f"HARNESSMINIMIZER_REAL_{sanitizer}_SYMBOLIZER"
        launcher = str(_LAUNCHERS / sanitizer.lower() / "llvm-symbolizer")
        configured = env.get(variable)
        if configured == launcher and env.get(real_variable):
            continue
        selected = _find_llvm_symbolizer(configured, search_path, cwd)
        if selected is None or selected == launcher:
            continue
        if _LD_PRESENT not in env:
            env[_LD_PRESENT] = "1" if "LD_LIBRARY_PATH" in env else "0"
            env[_LD_VALUE] = env.get("LD_LIBRARY_PATH", "")
        env[real_variable] = selected
        env[variable] = launcher
