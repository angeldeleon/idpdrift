"""Pseudonymisation of identity identifiers.

A report from this tool is a list of named employees and what they can do. In the
EU and UK that is personal data under GDPR without qualification — a user
principal name is an identifier and a job title in one string — and the reports
travel: they get pasted into tickets, posted to a Slack channel with a wider
membership than the security team, and attached to change requests.

So identifiers are pseudonymised by default. The security team still gets what it
needs — "the same account keeps appearing" — because the mapping is *stable*, and
can resolve a specific pseudonym back to an account through the identity provider
when an investigation actually warrants it.

The mechanism is HMAC-SHA256 under a locally generated salt:

* **Deterministic**, so drift detection works across runs.
* **Not reversible** by anyone holding the report but not the salt.
* **Not enumerable**, unlike a plain hash — a directory of ten thousand
  ``firstname.lastname@company.com`` addresses is a trivially small space to
  brute-force a bare SHA256 over.

The salt lives beside the state file at ``0600``. Deleting it makes every previous
pseudonym unresolvable and resets the baseline, which is the correct behaviour
for a "forget this tenant" operation.

Application and policy names are **not** pseudonymised. They are organisational
objects rather than people, and a finding that says "an application you cannot
identify gained Mail.ReadWrite" is useless.
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import stat
import tempfile
from enum import Enum
from hashlib import sha256
from pathlib import Path

log = logging.getLogger(__name__)

_SALT_BYTES = 32
_PSEUDONYM_HEX = 12


class PrivacyMode(str, Enum):
    """How identity identifiers appear in output.

    ``PSEUDONYMOUS`` is the default. ``IDENTIFIED`` is a deliberate choice an
    operator makes with knowledge of their own legal position, not something the
    tool should quietly assume on their behalf.
    """

    PSEUDONYMOUS = "pseudonymous"
    IDENTIFIED = "identified"

    @classmethod
    def parse(cls, raw: str) -> PrivacyMode:
        try:
            return cls(str(raw).strip().lower())
        except ValueError as exc:
            valid = ", ".join(m.value for m in cls)
            raise ValueError(f"unknown privacy mode {raw!r} (expected one of: {valid})") from exc


class Pseudonymiser:
    """Maps identifiers to stable, non-reversible labels."""

    def __init__(self, salt_path: str | Path, *, mode: PrivacyMode = PrivacyMode.PSEUDONYMOUS) -> None:
        self.mode = mode
        self.salt_path = Path(salt_path).expanduser()
        self._salt: bytes | None = None

    @property
    def salt(self) -> bytes:
        if self._salt is None:
            self._salt = self._load_or_create_salt()
        return self._salt

    def _load_or_create_salt(self) -> bytes:
        """Read the salt, or create one.

        Every filesystem operation goes through a file descriptor opened with
        ``O_NOFOLLOW``, never through the path. Following a symlink here would
        let anyone who can write the state directory (plausible when this runs
        from cron as a service account) point the salt at a file of their
        choosing: they would learn the salt, making every pseudonym in every past
        report enumerable, and the "tighten permissions" branch would chmod their
        target to 0600 — ``chmod 600 /etc/passwd`` is a working denial of service.

        ``O_NONBLOCK`` matters as much as ``O_NOFOLLOW``, and against the same
        attacker. Opening a FIFO for reading blocks until something opens the
        write end, and it blocks *inside* ``os.open`` — before the regular-file
        check below ever runs. A named pipe left in the state directory therefore
        hangs every scheduled run forever, with no timeout and no log line, which
        for a monitoring tool is the worst shape of failure: the reports simply
        stop arriving. The flag is cleared once the descriptor is known to be a
        regular file, where a short read would be a liability rather than a guard.
        """
        try:
            fd = os.open(self.salt_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return self._create_salt()
        except OSError as exc:
            raise ValueError(f"cannot read salt file {self.salt_path}: {exc}") from exc

        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"salt path {self.salt_path} is not a regular file")
            os.set_blocking(fd, True)
            data = os.read(fd, _SALT_BYTES * 4)
            if len(data) < 16:
                raise ValueError(
                    f"salt file {self.salt_path} is too short to be usable; "
                    "delete it to regenerate (this resets all pseudonyms and the baseline)"
                )
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o077:
                # A group- or world-readable salt lets anyone on the box
                # re-identify every account in every report ever produced.
                log.warning(
                    "salt file %s is readable by others (mode %o); tightening to 0600",
                    self.salt_path,
                    mode,
                )
                os.fchmod(fd, 0o600)
            return data
        finally:
            os.close(fd)

    def _create_salt(self) -> bytes:
        """Create the salt atomically.

        Written to a temporary file and linked into place, rather than
        ``O_CREAT|O_EXCL`` followed by a write. The naive version leaves a window
        in which the file exists but is empty: a concurrent run reads zero bytes
        and fails, and if the process is killed inside that window the empty file
        persists and *every* subsequent run fails forever — with the only
        advertised remedy being to delete it, which destroys every pseudonym and
        the baseline with it.
        """
        self.salt_path.parent.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_bytes(_SALT_BYTES)

        fd, tmp_name = tempfile.mkstemp(prefix=".idpdrift-salt-", dir=str(self.salt_path.parent))
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, salt)
            os.fsync(fd)
        finally:
            os.close(fd)

        try:
            # link() is atomic and fails if the target exists, so a concurrent
            # creator cannot be clobbered. rename() would silently overwrite,
            # leaving two running scans with different salts in memory.
            os.link(tmp_name, self.salt_path)
        except FileExistsError:
            os.unlink(tmp_name)
            return self._load_or_create_salt()
        except OSError:
            # Filesystems without hard links (some network mounts). rename is
            # still atomic; it just cannot detect a lost race.
            os.replace(tmp_name, self.salt_path)
            log.info("generated a new pseudonymisation salt at %s", self.salt_path)
            return salt
        else:
            os.unlink(tmp_name)

        log.info("generated a new pseudonymisation salt at %s", self.salt_path)
        return salt

    def principal_label(self, identifier: str, name: str) -> str:
        """Return the label a human sees for this identity."""
        if self.mode is PrivacyMode.IDENTIFIED:
            return name or identifier
        return self.pseudonym("id", identifier or name)

    def pseudonym(self, namespace: str, value: str) -> str:
        """Stable pseudonym for *value* within *namespace*.

        The namespace stops the same string colliding across contexts — an
        account id and a group id that happen to match should not produce the
        same label.
        """
        digest = hmac.new(self.salt, f"{namespace}:{value}".encode(), sha256).hexdigest()
        return f"{namespace}-{digest[:_PSEUDONYM_HEX]}"
