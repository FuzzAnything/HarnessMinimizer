from pathlib import Path

from harnessreducer.safe_files import copy_regular_file, open_regular_file


def open_debug_log(path: Path, *, read_only: bool = False):
    return open_regular_file(path, read_only=read_only, lock=True)


def copy_debug_log(source_path: Path, destination: Path) -> bool:
    return copy_regular_file(source_path, destination, lock_source=True, create_parent=True)
