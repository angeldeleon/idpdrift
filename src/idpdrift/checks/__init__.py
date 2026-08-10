"""Check implementations.

Importing this package registers every built-in check. A new check should
``@register("name")`` in a module imported here and add its name to
``idpdrift.config.ALL_CHECKS``; the CI invariants job fails the build if the two
lists disagree, because a check an operator can select and no code implements is
a permanently green, permanently blind scan.

Every check here is deterministic: same state in, same findings out. Nothing in
this package consults a model, and nothing here chooses a severity — the band
comes from the table in :mod:`idpdrift.severity`.
"""

from __future__ import annotations

# Imported for their registration side effects.
from . import (  # noqa: F401  (side-effect imports)
    auth_strength,
    conditional_access,
    dormancy,
    guests,
    oauth_grants,
    privileged_roles,
    service_principals,
)
from .base import CheckContext, get_check, register, registered_checks

__all__ = ["CheckContext", "get_check", "register", "registered_checks"]
