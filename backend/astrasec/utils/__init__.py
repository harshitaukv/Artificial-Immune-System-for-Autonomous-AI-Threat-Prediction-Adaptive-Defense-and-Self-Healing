"""Small shared helpers."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import joblib


def atomic_dump(obj: Any, path, **kwargs) -> None:
    """Write a joblib file so that a crash or kill mid-write can never leave a
    truncated model behind: write to a temporary file in the same folder, then
    atomically replace the target."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    try:
        joblib.dump(obj, tmp, **kwargs)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


__all__ = ["atomic_dump"]
