"""Source protocol.

A source is anything that can produce an :class:`~idpdrift.models.IdentityState`.
Every source is **read-only by construction** — it fetches or reads, and has no
API for creating, granting or revoking anything. That is the property that makes
this tool safe to point at a production tenant, and it should stay true of any
source added later.

The second obligation on a source is coverage. Every source declares, per facet,
whether it read it, confirmed it is empty, or could not tell — and "could not
tell" is the required answer when a scope was refused, a page limit was hit, or
the provider has no equivalent concept. A source that reports an unread facet as
empty turns this tool into a false-alarm generator, and the alarms will be about
people's access, which is the sort a team stops reading quickly.
"""

from __future__ import annotations

from typing import Protocol

from ..models import IdentityState


class SourceError(Exception):
    """The source could not be read.

    Raised for genuine failures — unreachable endpoint, unreadable file, rejected
    credentials. Never raised for "the tenant has no guests", which is a
    legitimate answer the caller handles separately.
    """


class Source(Protocol):
    """Produces one collection of identity state."""

    name: str

    def collect(self) -> IdentityState: ...
