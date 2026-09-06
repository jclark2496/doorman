# doorman

> Paste-ready content for the Notion project page. Everything below is current as
> of 6 September 2026.

**One login for every site you own.**

Status: **live** — running in front of five hosts since 6 Sep 2026
Repo: https://github.com/jclark2496/doorman (public, MIT)
Language: Python 3, one dependency (`webauthn>=2.5,<3`)
Size: ~1,000 lines of service, ~1,300 lines of tests, 87 tests, no network

---

## What it is

A small auth service that sits in front of a whole domain. You sign in once with
Face ID or Touch ID and every site behind it opens. Anyone else gets three words
and two digits — `coral-lounger-palm-42` — good for exactly the sites and days
you named, on up to three browsers. Someone you trust can be given a passkey of
their own, enrolled on their first visit.

Caddy asks it about every request via `forward_auth`, so a site is gated whether
it is a folder of HTML or an app on a port. No library, no SDK, no change to the
site itself.

There is no shared password anywhere in it and no secret in its config. The only
state is one SQLite file of people, their public keys, and their live sessions.

## The one constraint

Every site it protects has to be the same registrable domain or a subdomain of
it. The session cookie is scoped to a domain and a passkey's relying-party ID
must be a registrable domain — that is the browser's rule for both, and no amount
of configuration changes it. Sites on another domain need their own instance.

## Where it came from

Built first as the auth service for a private personal site, then extracted and
made generic. The private deployment and this repo now share a design but not a
codebase — changes have to be carried across deliberately.

## What's in the repo

| Path | What |
| --- | --- |
| `doorman/` | the service: config, store, gate, passkeys, sessions, routes |
| `tests/` | 87 tests, `python -m unittest discover -s tests -t .` |
| `web/` | reference front end: login, denied, admin |
| `docs/runbook.md` | standing it up on one box behind Caddy |
| `examples/` | Caddyfile, systemd unit, env file, demo server |

`gate.py` is a pure function of (user, session, host, now) — no database, no
clock of its own — so the rule that decides everything can be read in one sitting
and tested exhaustively.

## Try it in thirty seconds

```
git clone https://github.com/jclark2496/doorman.git && cd doorman
python3 examples/demo-server.py
```

Then `http://127.0.0.1:8600/admin.html`, or `/login.html` and the code
`coral-lounger-palm-42`. It fakes the service in memory.

## Done

- [x] WebAuthn registration and authentication, discoverable credentials, user verification required
- [x] Invite codes: three words and two digits, per-site, per-day, up to three browsers
- [x] Member invites that enroll a passkey on first visit
- [x] Caddy `forward_auth` gate, with login and denied redirects
- [x] Owner operations: list, invite, grant, deny, extend, revoke, manage keys
- [x] Reference front end for all three pages a visitor sees
- [x] Runbook, Caddyfile, systemd unit, env example
- [x] Extracted, genericised, public under MIT
- [x] 87 tests including three that exist because of real production failures

## Next

- [ ] Card on forkthis.ai — handoff written (`docs/forkthis-handoff.md`), waiting on Hermes
- [ ] Decide whether the private deployment tracks this repo or stays a fork
- [ ] No rate limit on `admin/*` (owner-only, so low risk, but it is not there)
- [ ] Nothing prunes expired sessions or invites; the table grows forever
- [ ] Not audited by anyone but me

## Three decisions worth remembering

**Extending sends nothing.** Giving someone longer moves their invite and every
browser they are signed in on to the same date, so the laptop they are reading on
carries on. Re-inviting would work but mints a code they must redeem — the answer
to "give Bob another week" should not be "message Bob". It only ever moves a
deadline forward.

**Revoking asks the right question.** For someone with a passkey the choice is
not yes/no, it is whether their key survives: keep it and they can be let back in
with a click, remove it and they need a fresh invite.

**Two tests exist because of two broken deployments.** An unquoted value with a
space in the env file (systemd accepts it, `sh` does not), and a health check
that raced a `Type=simple` unit's socket. Both are now tested against the shipped
text rather than a copy of it, because a copy keeps passing after the original
drifts.
