from contextlib import ExitStack, contextmanager, suppress
import fcntl
import os
from pathlib import Path
import secrets
import shutil
import stat


@contextmanager
def _open_directory(path: Path, *, create: bool):
    flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor or ".", flags)
    try:
        parts = path.parts[1:] if path.anchor else path.parts
        for part in parts:
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                with suppress(FileExistsError):
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _require_regular_file(info: os.stat_result, path: Path) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise OSError(f"Expected a regular file with a single link: {path}")


@contextmanager
def open_regular_file(path: Path, *, read_only: bool = True, lock: bool = False):
    access = os.O_RDONLY if read_only else os.O_WRONLY | os.O_CREAT | os.O_APPEND
    with _open_directory(path.parent, create=not read_only) as directory_fd:
        fd = os.open(path.name, access | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY,
                     0o600, dir_fd=directory_fd)
    with os.fdopen(fd, "rb" if read_only else "a", encoding=None if read_only else "utf-8") as handle:
        _require_regular_file(os.fstat(fd), path)
        if lock:
            fcntl.flock(fd, fcntl.LOCK_SH if read_only else fcntl.LOCK_EX)
        yield handle


def copy_regular_file(
    source_path: Path, destination: Path, *, skip_empty: bool = False,
    lock_source: bool = False, create_parent: bool = False,
) -> bool:
    """Atomically copy a single-link regular file. Return False for a missing or skipped source."""
    with ExitStack() as opened:
        try:
            source = opened.enter_context(open_regular_file(source_path, lock=lock_source))
        except FileNotFoundError:
            return False
        source_info = os.fstat(source.fileno())
        if skip_empty and not source_info.st_size:
            return False
        parent = opened.enter_context(_open_directory(destination.parent, create=create_parent))
        try:
            current = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None:
            _require_regular_file(current, destination)
            if os.path.samestat(source_info, current):
                return True

        # Publish a complete private copy. Replacing this directory entry never
        # follows a destination link, including one swapped in during the copy.
        temporary = f".copy-{secrets.token_hex(16)}"
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as target:
                shutil.copyfileobj(source, target)
            os.replace(temporary, destination.name, src_dir_fd=parent, dst_dir_fd=parent)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=parent)
            raise
    return True
