"""Private, atomic local report writes without following destination symlinks."""

import os
from pathlib import Path
import tempfile


def write_private_text(path, content):
    """Replace a local report with a UTF-8 file readable only by its owner.

    A failed write leaves any previous report intact. This is not a guarantee of
    filesystem crash durability, secure deletion, or protection of parent folders.
    """
    destination = Path(path)
    if destination.is_symlink():
        raise ValueError("Report destination must not be a symlink")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                         prefix=".scanner-report-", delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        return destination
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
