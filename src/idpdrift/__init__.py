"""idpdrift — identity and access drift detection for security teams.

Read-only by construction. It reads the current state of an identity provider
through APIs the operator already has, compares it against a stored baseline,
and reports what *changed*. It creates nothing, grants nothing, revokes nothing,
and has no code path that writes to a tenant.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
