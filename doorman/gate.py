"""The one decision Caddy asks for: may this session see this host? Pure, so it is easy to test exhaustively."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    status: int            # 200 allowed, 401 log in, 403 not on your list
    user: str | None = None
    role: str | None = None


def decide(user, session, host: str, now: float, apex: str) -> Decision:
    if user is None or session is None or session.revoked_at is not None or session.expires_at <= now or user.disabled:
        return Decision(401)
    h = (host or "").split(":")[0].strip().lower()
    if user.role == "owner" or h == apex or h in user.sites:
        return Decision(200, user.name, user.role)
    return Decision(403, user.name, user.role)
