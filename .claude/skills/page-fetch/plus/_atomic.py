"""Shared atomic-write and file-lock helpers for the plus value layer.

`cache.put`, `winners._save`, and `observe._rotate_if_needed` previously
reimplemented the same `write tmp + os.replace` (cache/winners) or skipped
locking entirely (observe rotate race, follow-up #20). Centralizing both
patterns here means one well-tested implementation guards every JSON/JSONL
file the layer owns.

Functions:
- `atomic_write_text(path, text)` — write a string to `path` via
  `<path>.tmp.<pid>` then `os.replace` it into place. Best-effort cleanup
  of the tmp file on failure. Parent directory is created.
- `atomic_write_json(path, data, ...)` — convenience wrapper that serializes
  `data` with `json.dumps(ensure_ascii=False)` then delegates.
- `exclusive_lock(path)` — context manager holding an exclusive OS file
  lock on `<path>.lock` for read-modify-write coordination. Required by
  `winners._save` (D12) — atomic replace prevents *torn writes* but two
  concurrent processes can each load → mutate → write and still lose data.
  Also used by `observe._rotate_if_needed` (#20) so two threads can't both
  decide to rotate the same JSONL file simultaneously.

POSIX uses `fcntl.flock`; native Windows uses `msvcrt` byte-range locking.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl  # type: ignore[import-not-found]
except ImportError:  # native Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write `text` to `path` atomically.

    Writes to `<path>.tmp.<pid>` first, then `os.replace`s it into place so a
    concurrent reader either sees the old file or the new file in full — never
    a half-written document. The pid suffix lets multiple processes write the
    same target without colliding on the tmp name.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        tmp.write_text(text, encoding=encoding)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_json(
    path: Path,
    data: Any,
    *,
    indent: int | None = None,
    sort_keys: bool = False,
) -> None:
    """Serialize `data` to JSON and write atomically via `atomic_write_text`."""
    atomic_write_text(
        path,
        json.dumps(data, ensure_ascii=False, indent=indent, sort_keys=sort_keys),
    )


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive OS file lock on `<path>.lock` for the block.

    Used to serialize read-modify-write sequences (winners.json) and
    file-rotation decisions (observation log) — both cases where atomic
    replace alone is insufficient because the *decision* of what to write
    depends on what is already on disk.

    The lock file is `<path>.lock` (created on demand) rather than `path`
    itself so the data file's own metadata/size doesn't change while the
    lock is held.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with lock_path.open("a+b") as fh:
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        else:
            # Lock one real byte; separate processes coordinate on the same range.
            if fh.seek(0, os.SEEK_END) == 0:
                fh.write(b"\0")
                fh.flush()
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            else:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
