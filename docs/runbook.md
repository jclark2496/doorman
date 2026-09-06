# Running doorman

Standing it up on one Linux box behind Caddy, and the handful of things you do
to it afterwards. Every command here is meant to be pasted as written.

Two facts shape everything below.

**One cookie, one domain.** The session cookie is scoped to `.example.com`, and
a passkey is bound to a relying-party ID that is a registrable domain. Both mean
every site doorman protects has to be that domain or a subdomain of it.
`notes.example.com` and `photos.example.com` share a login; `example.net` cannot,
and no amount of configuration changes that — it is how the browser scopes both
things. Sites on other domains need their own doorman.

**The service holds no secret.** There is no shared code, no signing key, no API
token in the config. What it holds is a SQLite file of people, their public keys,
and their live sessions. That is why the env file below can be read by anyone who
can read the box, and why losing it means re-enrolling rather than a breach.

---

## 1. The box

A user that owns nothing else, and a directory it can write to:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin doorman
sudo mkdir -p /opt/doorman/data
sudo chown -R doorman:doorman /opt/doorman
```

Code and its virtualenv:

```bash
sudo -u doorman git clone https://github.com/jclark2496/doorman.git /opt/doorman/app
sudo -u doorman python3 -m venv /opt/doorman/venv
sudo -u doorman /opt/doorman/venv/bin/pip install -r /opt/doorman/app/requirements.txt
```

## 2. The env file

Copy `examples/doorman.env.example` to `/opt/doorman/doorman.env` and edit it.

```bash
sudo cp /opt/doorman/app/examples/doorman.env.example /opt/doorman/doorman.env
sudo chown doorman:doorman /opt/doorman/doorman.env
sudo chmod 640 /opt/doorman/doorman.env
```

Set at least `AUTH_ORIGIN`, `AUTH_RP_ID`, `AUTH_COOKIE_DOMAIN`, `AUTH_HOSTS` and
`AUTH_OWNER_NAME`. `AUTH_HOSTS` must contain the origin's own host or the service
refuses to start — a list that omits it would deny the front door to everyone,
and finding that out one request at a time is worse than not booting.

**Quote any value with a space in it.** systemd will accept
`AUTH_RP_NAME=Some Site`, and `sh` will not: sourcing that line runs `Site` as a
command. The shipped example quotes it, and a test in this repo sources the file
with `sh` on every run so the file cannot drift back. Both readers strip the
quotes, so quoting costs nothing.

## 3. The unit

Copy `examples/doorman.service` to `/etc/systemd/system/`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now doorman.service
```

It is `Type=simple`, so systemd reports it `active` the moment the process
starts — before the socket is bound. Every check after a restart in this runbook
is therefore wrapped in a bounded retry rather than a bare `curl`, which is why
they all look the same:

```bash
( url=http://127.0.0.1:8401/_auth/health; n=15
  while [ "$n" -gt 0 ]; do
    body=$(curl -fs "$url") && { printf '%s\n' "$body"; break; }
    n=$((n - 1)); sleep 1
  done
  [ "$n" -gt 0 ] || { curl -fsS "$url" >/dev/null; echo "STOP: $url did not answer within 15s. That is past a cold start, so the unit you just restarted is not listening rather than slow. Read 'journalctl -u <that unit> -n 50 --no-pager' and its 'systemctl status' before going on."; exit 1; } )
```

Expected output, and nothing else: `{"ok": true}`

The retries are silent on purpose. A cold start can take ten seconds, and
`curl -fsS` on every attempt would print a connection-refused line each time — a
dozen red errors in front of a check that is succeeding. Only the final attempt,
made after the bound is exhausted, shows its error, so a real failure still tells
you why before the `STOP` line.

## 4. Caddy

`examples/Caddyfile` has the whole shape. The two things that matter:

- `/_auth/*` on the origin reverse-proxies to `127.0.0.1:8401`. This is the only
  path doorman serves, and it must be reachable on the origin, because that is
  where the login page and the cookie live.
- Every protected host imports the `gate` snippet, which is a `forward_auth` to
  the same service. Caddy asks doorman about each request and doorman answers
  with 200, a redirect to the login page, or a redirect to the denied page.

Leave the login and denied pages themselves outside the gate, or nobody can
reach the door to knock on it. That is the `@open` matcher in the example.

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

## 5. Your own passkey

Nothing can be administered until the owner has a key. Ask for an enrollment
link, open it on a device with a biometric, and make one:

```bash
sudo -u doorman /opt/doorman/venv/bin/python /opt/doorman/app/doorman.py enroll-owner
```

It prints a link good for fifteen minutes. It is single-use: redeeming it clears
any other enrollment ticket outstanding, so a link that leaks after you have used
it is worth nothing.

This is also the recovery path. If you lose every key, run it again on the box.

## 6. Afterwards

Everything else is done as the owner, either from the reference admin page or
from the CLI. The CLI covers the two things you might need without a browser:

```bash
doorman.py list                    # users, roles, keys, live sessions
doorman.py revoke <name> [--keys]  # ends their sessions and invites
doorman.py revoke-all-sessions     # everyone signs in again; keys survive
```

### Deploying a change

Code goes into a new directory beside the live one and is swapped in, so a
restart that fails has somewhere to fall back to:

```bash
sudo -u doorman git -C /opt/doorman/app fetch origin
sudo -u doorman git -C /opt/doorman/app checkout main
sudo -u doorman git -C /opt/doorman/app pull
sudo -u doorman /opt/doorman/venv/bin/pip install -q -r /opt/doorman/app/requirements.txt
sudo systemctl restart doorman.service
```

Then the same check as before — the unit is `Type=simple` here too:

```bash
( url=http://127.0.0.1:8401/_auth/health; n=15
  while [ "$n" -gt 0 ]; do
    body=$(curl -fs "$url") && { printf '%s\n' "$body"; break; }
    n=$((n - 1)); sleep 1
  done
  [ "$n" -gt 0 ] || { curl -fsS "$url" >/dev/null; echo "STOP: $url did not answer within 15s. That is past a cold start, so the unit you just restarted is not listening rather than slow. Read 'journalctl -u <that unit> -n 50 --no-pager' and its 'systemctl status' before going on."; exit 1; } )
```

### Backing it up

One SQLite file, and it is the only state there is:

```bash
sudo -u doorman sqlite3 /opt/doorman/data/auth.db ".backup '/opt/doorman/data/auth-$(date +%F).db'"
```

Losing it does not expose anything — it holds public keys, not private ones —
but everyone has to enroll again, so keep a copy somewhere.

### When something is wrong

```bash
sudo journalctl -u doorman.service -n 50 --no-pager
sudo systemctl status doorman.service
```

The service logs one line per decision it refuses, and a line whenever a
passkey's signature counter fails to advance — the only clone signal WebAuthn
offers. Synced passkeys keep no counter, so that line is a prompt to look rather
than proof of anything.
