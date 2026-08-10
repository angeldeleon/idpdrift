"""Baseline persistence.

The state file is the tool's memory: without it every run looks like a first run
and no drift is ever detected. It holds one snapshot per scope — a scope being
one source pointed at one tenant — so two configs sharing a state file keep
separate baselines instead of diffing against each other's directory.

Two properties matter beyond correctness.

**It is an inventory of privileged access.** Who holds Global Administrator,
which applications can read all mail, which conditional access policies have
exclusions and who is in them. That is a target list, and it is the first thing
worth stealing from the host this runs on. Created ``0600``, and every open goes
through a file descriptor with ``O_NOFOLLOW`` so it cannot be redirected at a
file somebody else can read.

**A corrupt baseline degrades, a hostile one fails.** An unparseable file is
treated as "no baseline": losing drift detection for one run is a far better
failure mode than a monitoring job that stops running. A symlink or a FIFO at the
state path is not a corruption, it is somebody's idea, and it raises.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from .models import Snapshot

log = logging.getLogger(__name__)

STATE_VERSION = 1
DEFAULT_STATE_PATH = ".idpdrift/state.json"

# A state file larger than this is either a bug or an attempt to exhaust memory
# on a host that also holds a directory access token.
_MAX_STATE_BYTES = 100 * 1024 * 1024
_READ_CHUNK = 1024 * 1024


class StateError(Exception):
    """The state file could not be read or written safely."""


class SnapshotStore:
    """Reads and writes the previous-scan baseline."""

    def __init__(self, path: str | Path = DEFAULT_STATE_PATH, *, scope: str = "default") -> None:
        self.path = Path(path).expanduser()
        # Snapshots are namespaced by scope so that two configs sharing a state
        # file cannot diff against each other's tenant. Without this every id
        # misses on lookup, drift silently returns nothing, and the report still
        # claims it compared against a baseline.
        self.scope = scope or "default"
        self._snapshots: dict[str, Snapshot] = {}
        self._loaded = False

    # ------------------------------------------------------------------

    def _read_bytes(self) -> bytes | None:
        """Read the state file through a descriptor, or return None if absent.

        Opened with ``O_NOFOLLOW`` so a symlink planted in the state directory
        cannot make this read — and later, through :meth:`save`, write — some
        other file. Checked through a descriptor rather than by path: ``islink()``
        followed by ``open()`` is two lookups of the same name and the attacker
        owns what happens in between.

        ``O_NONBLOCK`` is here for the same reason as ``O_NOFOLLOW`` and against
        the same attacker. Opening a FIFO for reading blocks *inside* ``os.open``
        until a writer appears, so the regular-file check below never gets the
        chance to reject one: a named pipe left at the state path hangs every run
        indefinitely rather than failing, and for a scheduled monitor that means
        the reports simply stop arriving with nothing in the log. Cleared once the
        descriptor is known to be a regular file, where a short read would be a
        liability rather than a guard.
        """
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError as exc:
            # ELOOP lands here: the path is a symlink and we refused to follow it.
            raise StateError(f"cannot open state file {self.path}: {exc}") from exc

        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise StateError(f"state file {self.path} is not a regular file; refusing to open it")
            if info.st_size > _MAX_STATE_BYTES:
                raise StateError(f"state file {self.path} is implausibly large ({info.st_size} bytes)")
            os.set_blocking(fd, True)
            if stat.S_IMODE(info.st_mode) & 0o077:
                # Repair through the descriptor, not the path. This file lists
                # who administers the tenant.
                log.warning("state file %s was readable by others; tightening to 0600", self.path)
                os.fchmod(fd, 0o600)

            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, _READ_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_STATE_BYTES:
                    raise StateError(f"state file {self.path} exceeds {_MAX_STATE_BYTES} bytes")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def load(self) -> dict[str, Snapshot]:
        """Load every snapshot in the file, keyed by scope."""
        if self._loaded:
            return self._snapshots
        self._loaded = True

        raw_bytes = self._read_bytes()
        if raw_bytes is None:
            log.info("no existing state at %s; this run establishes the baseline", self.path)
            return self._snapshots

        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning("ignoring unreadable state file %s: %s", self.path, exc)
            return self._snapshots

        if not isinstance(raw, dict):
            log.warning("ignoring malformed state file %s: root is not an object", self.path)
            return self._snapshots

        version = raw.get("version")
        if version != STATE_VERSION:
            log.warning(
                "state file %s has version %r (expected %d); ignoring and rebuilding the baseline",
                self.path,
                version,
                STATE_VERSION,
            )
            return self._snapshots

        snapshots_raw = raw.get("snapshots")
        if not isinstance(snapshots_raw, dict):
            return self._snapshots

        for scope, payload in snapshots_raw.items():
            try:
                self._snapshots[str(scope)] = Snapshot.from_dict(payload)
            except (ValueError, TypeError) as exc:
                log.warning("skipping malformed snapshot for scope %s: %s", scope, exc)

        log.info("loaded baseline for %d scope(s) from %s", len(self._snapshots), self.path)
        return self._snapshots

    def get(self) -> Snapshot | None:
        """The baseline for this store's scope, or None."""
        return self.load().get(self.scope)

    def check_readable(self) -> None:
        """Fail before collection if the state file cannot be opened safely.

        Collecting a whole directory and then discovering the baseline is a FIFO
        wastes an API budget and, worse, reports posture with no drift while
        looking like a successful run.
        """
        self.load()

    # ------------------------------------------------------------------

    def save(self, snapshot: Snapshot) -> None:
        """Persist *snapshot* under this store's scope, merging over the rest.

        Merging rather than replacing means pointing the tool at a second tenant
        for one run does not discard the first tenant's history.
        """
        merged = dict(self.load())
        merged[self.scope] = snapshot

        payload: dict[str, Any] = {
            "version": STATE_VERSION,
            "snapshots": {scope: snap.to_dict() for scope, snap in sorted(merged.items())},
        }
        serialized = json.dumps(payload, indent=2, ensure_ascii=False)

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StateError(f"cannot create state directory {self.path.parent}: {exc}") from exc

        # Write to a temp file in the *same* directory so os.replace is a true
        # atomic rename rather than a cross-filesystem copy. An interrupted run
        # must not be able to leave a truncated file that silently wipes the
        # baseline and re-reports the whole directory as new.
        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=".idpdrift-state-", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            os.fchmod(tmp_fd, 0o600)
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        except OSError as exc:
            raise StateError(f"cannot write state file {self.path}: {exc}") from exc
        finally:
            # On success os.replace already consumed the temp file; this only
            # fires when the write failed partway and left one behind.
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)

        self._snapshots = merged
        log.info("saved baseline for scope %s to %s", self.scope, self.path)
