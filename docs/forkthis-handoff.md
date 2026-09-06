# Hermes: add doorman to forkthis.ai

A new project shipped and wants a card on the projects page. Two files change on
one box — no service restart, no Caddy change.

**The box is VPS1, `root@145.223.75.97`.** Not VPS2. Everything doorman and
sandalsrocks has been deployed to recently lives on `2.25.183.70`; forkthis.ai
does not. Confirm before you write anything:

```bash
dig +short forkthis.ai A        # expect 145.223.75.97
ssh root@145.223.75.97 "ls /var/www/forkthis.ai/assets/js/projects.js"
```

Every command below runs on that box, over ssh.

**doorman** — <https://github.com/jclark2496/doorman> (public)
One login for every site you own: passkeys for the owner, three-word invite
codes for guests, and a Caddy `forward_auth` gate in front of each host. ~1,000
lines of Python, one dependency, 87 tests.

## Two things to do

### 1. The image

`assets/shots/doorman.jpg`, 1200×750 to match the others. It is already made and
public — do not re-crop or re-shoot it:

```bash
ssh root@145.223.75.97 "curl -fsSL -o /var/www/forkthis.ai/assets/shots/doorman.jpg https://raw.githubusercontent.com/jclark2496/doorman/main/docs/screenshots/forkthis-card.jpg"
```

Verify it landed and is the right size before going on:

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://forkthis.ai/assets/shots/doorman.jpg
```

### 2. The entry

Add this to `PROJECTS` in `/var/www/forkthis.ai/assets/js/projects.js`. Put it
first in the array — it is the newest — unless the file's order is deliberate
and you can see it is not newest-first, in which case match whatever that order
is and say which you chose.

```js
  {id:"doorman",n:"doorman",tags:["security","tools"],stage:"live",gh:"https://github.com/jclark2496/doorman",shot:"assets/shots/doorman.jpg",
   line:"One login for every site you own: passkeys for you, a three-word code for everyone else, and a gate in front of each site.",
   more:"A small auth service that sits in front of a whole domain. You sign in once with Face ID or Touch ID and every site behind it opens; anyone else gets three words and two digits, good for exactly the sites and days you named, on up to three browsers. Someone you trust can be given a passkey of their own, enrolled on their first visit. Caddy asks it about every request, so a site is gated whether it is a folder of HTML or an app on a port — no library, no SDK, no change to the site. About a thousand lines of Python, one dependency, and a SQLite file, with no shared password anywhere in it."},
```

`tags` uses the vocabulary already on the page (`security`, `ai`, `tools`,
`sites`, `design`). `gh` renders as a `github ->` link — the comment at the top
of `projects.js` says it is "not shown yet", but the render code at line ~62 does
show it. Leave that stale comment alone unless you are fixing it deliberately.

## Verify

```bash
curl -s https://forkthis.ai/assets/js/projects.js | grep -c '"doorman"'
```
Expected: at least 1.

Then load <https://forkthis.ai> in a browser and confirm the card renders with
its image and that `github ->` opens the repo. The page builds its list from that
array at runtime, so a syntax error there takes out **every** project, not just
this one — check the browser console is clean before you call it done.

## Rollback

Keep a copy of `projects.js` before editing and restore it if the page comes up
empty:

```bash
ssh root@145.223.75.97 "cp /var/www/forkthis.ai/assets/js/projects.js /var/www/forkthis.ai/assets/js/projects.js.bak"
```

Take that backup **before** editing, not after.

```bash
ssh root@145.223.75.97 "cp /var/www/forkthis.ai/assets/js/projects.js.bak /var/www/forkthis.ai/assets/js/projects.js"
```

## Constraints

- forkthis.ai on VPS1 only. Do not touch VPS2, any other site, the auth service,
  or Caddy. The two files above are the whole change.
- Do not modify or push any repository.
- If the projects page renders empty after the edit, restore the backup and
  report rather than debugging live.
