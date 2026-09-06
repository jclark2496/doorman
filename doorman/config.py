"""Configuration from the environment. Nothing secret lives here: the service has no access codes."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_HOSTS = "example.com,notes.example.com,photos.example.com,files.example.com,archive.example.com"
DEFAULT_ALIASES = "notes=notes.example.com,photos=photos.example.com,files=files.example.com,archive=archive.example.com"


def _hosts(value: str) -> list[str]:
    return [h.strip().lower() for h in value.split(",") if h.strip()]


def _aliases(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in value.split(","):
        if "=" in pair:
            name, host = pair.split("=", 1)
            out[name.strip().lower()] = host.strip().lower()
    return out


@dataclass(frozen=True)
class Config:
    port: int = 8401
    origin: str = "https://example.com"
    rp_id: str = "example.com"
    rp_name: str = "Example"
    cookie_domain: str = ".example.com"
    cookie_name: str = "doorman_session"
    db_path: str = "/opt/doorman/data/auth.db"
    session_days: int = 30
    renew_days: int = 15
    owner_name: str = "ada"
    hosts: list[str] = field(default_factory=lambda: _hosts(DEFAULT_HOSTS))
    aliases: dict[str, str] = field(default_factory=lambda: _aliases(DEFAULT_ALIASES))
    login_path: str = "/login.html"
    denied_path: str = "/denied.html"

    def __post_init__(self) -> None:
        # Both of these are otherwise found one request at a time: an empty list raised on every
        # request, and a list that does not carry the origin's own host denied the apex to everyone.
        if not self.hosts:
            raise ValueError("AUTH_HOSTS must list at least one host")
        if self.apex not in self.hosts:
            raise ValueError(f"AUTH_HOSTS must contain the origin's host ({self.apex or 'none'})")

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        return cls(
            port=int(env.get("AUTH_PORT", "8401")),
            origin=env.get("AUTH_ORIGIN", "https://example.com").rstrip("/"),
            rp_id=env.get("AUTH_RP_ID", "example.com"),
            rp_name=env.get("AUTH_RP_NAME", "Example"),
            cookie_domain=env.get("AUTH_COOKIE_DOMAIN", ".example.com"),
            cookie_name=env.get("AUTH_COOKIE_NAME", "doorman_session"),
            db_path=env.get("AUTH_DB", "/opt/doorman/data/auth.db"),
            session_days=int(env.get("AUTH_SESSION_DAYS", "30")),
            renew_days=int(env.get("AUTH_RENEW_DAYS", "15")),
            owner_name=env.get("AUTH_OWNER_NAME", "ada"),
            hosts=_hosts(env.get("AUTH_HOSTS", DEFAULT_HOSTS)),
            aliases=_aliases(env.get("AUTH_SITE_ALIASES", DEFAULT_ALIASES)),
        )

    @property
    def apex(self) -> str:
        """The origin's own host, not a position in the list. Every session is allowed the apex, so
        deriving it from the order of AUTH_HOSTS would let reordering that line in the env file open a
        different site to every guest."""
        return urlsplit(self.origin).hostname or ""

    def host_for(self, name: str) -> str | None:
        """A short site name (notes) or a full host -> the host, or None if it is not one of ours."""
        n = (name or "").strip().lower()
        if n in self.aliases:
            return self.aliases[n]
        return n if n in self.hosts else None
