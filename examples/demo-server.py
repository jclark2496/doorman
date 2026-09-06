#!/usr/bin/env python3
"""Serves web/ and fakes just enough of doorman to drive the reference pages.

    python3 examples/demo-server.py     # then open http://127.0.0.1:8600/login.html

There is no database, no passkey and no real check here — it answers as the owner and keeps its
edits in memory, so a restart brings the seed back. It exists so the pages can be looked at, which
is not something a unit test can do for you.

    /login.html   the passkey path needs a real browser; the invite path works with the codes below
    /admin.html   the whole thing works
    /denied.html?host=photos.example.com

Invite codes it accepts: coral-lounger-palm-42 (works) · full-full-full-00 (an invite already full)
"""
import json, os, http.server, socketserver, time, urllib.parse

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "web")
DAY = 86400
NOW = int(time.time())

PEOPLE = [
    {"name": "jill", "role": "member", "disabled": False, "passkeys": 1,
     "sites": ["notes", "photos"], "hosts": [],
     "invites": [{"kind": "member", "expires": NOW + 20 * DAY, "browsers_used": 1, "max_browsers": 1,
                  "consumed": True, "active": False}],
     "sessions": [{"created": NOW - 9 * DAY, "last_seen": NOW - 2 * DAY, "expires": NOW + 21 * DAY,
                   "user_agent": "Safari"}]},
    {"name": "bob", "role": "guest", "disabled": False, "passkeys": 0,
     "sites": ["notes"], "hosts": [],
     "invites": [{"kind": "guest", "expires": NOW + 4 * DAY, "browsers_used": 2, "max_browsers": 3,
                  "consumed": False, "active": True}],
     "sessions": [{"created": NOW - 2 * DAY, "last_seen": NOW - 3600, "expires": NOW + 4 * DAY,
                   "user_agent": "iPhone"}]},
    {"name": "sam", "role": "guest", "disabled": True, "passkeys": 0,
     "sites": [], "hosts": [], "invites": [], "sessions": []},
]


LABEL = """<script>
setTimeout(function () { document.getElementById("where").textContent = %s; }, 60);
</script>"""

SHOW = """<script>
setTimeout(function () {
  var want = %s, row = %s;
  var li = [].slice.call(document.querySelectorAll(".who")).filter(function (e) {
    return e.querySelector(".n").textContent === row; })[0];
  if (want === "handoff") {
    document.getElementById("who").value = "ana";
    [].slice.call(document.querySelectorAll("#chips .chip"))[0].click();
    document.getElementById("askForm").dispatchEvent(new Event("submit", {bubbles: true, cancelable: true}));
    return;
  }
  if (!li) return;
  [].slice.call(li.querySelectorAll(".acts button")).filter(function (b) {
    return b.textContent.toLowerCase() === want; })[0].click();
}, 400);
</script>"""


def find(name):
    return next((p for p in PEOPLE if p["name"] == name), None)


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def log_message(self, *a):
        pass

    def _json(self, status, obj):
        b = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        # A screenshot convenience, and nothing the real service does. Either page accepts
        # ?where=example.com to relabel the host line, and /admin.html also takes ?open=time&row=bob
        # to click that row's button once the page has loaded, so the drawers and the handoff can be
        # captured headlessly. web/ is never modified.
        head = self.path.split("?", 1)[0]
        if "?" in self.path and head in ("/admin.html", "/login.html", "/denied.html"):
            q = dict(urllib.parse.parse_qsl(self.path.split("?", 1)[1]))
            html = open(os.path.join(ROOT, head.lstrip("/")), encoding="utf-8").read()
            if q.get("where"):
                html = html.replace("</body>", LABEL % json.dumps(q["where"]) + "</body>")
            if q.get("open"):
                html = html.replace("</body>", SHOW % (json.dumps(q["open"]), json.dumps(q.get("row", "bob"))) + "</body>")
            b = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if self.path == "/_auth/me":
            return self._json(200, {"name": "ada", "role": "owner", "expires": NOW + 30 * DAY,
                                    "hosts": ["*"], "sites": ["*"]})
        if self.path == "/_auth/admin/guests":
            return self._json(200, {"guests": PEOPLE})
        return super().do_GET()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        p = self.path

        if p == "/_auth/login/options":
            return self._json(200, {"challenge_id": "c1", "options": {
                "challenge": "AAECAwQFBgcICQoLDA0ODw", "rpId": "example.com",
                "allowCredentials": [], "userVerification": "required", "timeout": 60000}})

        if p == "/_auth/invite/redeem":
            code = body.get("code", "")
            if code == "full-full-full-00":
                return self._json(403, {"error": "full"})
            if code == "coral-lounger-palm-42":
                return self._json(200, {"name": "bob", "role": "guest", "sites": ["notes"]})
            return self._json(401, {"error": "permission denied"})

        if p == "/_auth/admin/invite":
            code = "coral-lounger-palm-42"
            sites = body.get("sites") or []
            one = "?next=https%3A%2F%2F" + sites[0] + ".example.com%2F" if len(sites) == 1 else ""
            return self._json(200, {"name": body.get("name"), "kind": body.get("kind") or "guest",
                                    "code": code, "link": "https://example.com/login.html" + one + "#i=" + code,
                                    "expires": NOW + 7 * DAY, "sites": sites, "hosts": sites})

        if p == "/_auth/admin/sites":
            person = find(body.get("name"))
            if not person:
                return self._json(404, {"error": "no such guest"})
            s = set(person["sites"]) | set(body.get("grant") or [])
            person["sites"] = sorted(s - set(body.get("deny") or []))
            return self._json(200, {"name": person["name"], "role": person["role"],
                                    "sites": person["sites"], "hosts": person["sites"]})

        if p == "/_auth/admin/extend":
            person = find(body.get("name"))
            if not person:
                return self._json(404, {"error": "no such guest"})
            if person["disabled"]:
                return self._json(400, {"error": person["name"] + " is revoked. Invite them again to let them back in."})
            until = NOW + int((body.get("ttl") or "7d")[:-1]) * DAY
            moved = 0
            for i in person["invites"]:
                if not i["consumed"] and i["expires"] < until:
                    i["expires"] = until
                    moved += 1
            for ss in person["sessions"]:
                if ss["expires"] < until:
                    ss["expires"] = until
                    moved += 1
            return self._json(200, {"name": person["name"], "expires": until, "moved": moved})

        if p == "/_auth/admin/revoke":
            person = find(body.get("name"))
            if not person:
                return self._json(404, {"error": "no such guest"})
            person["disabled"] = True
            person["sessions"] = []
            person["invites"] = []
            drop = body.get("keys") is True or person["role"] == "guest"
            if drop:
                person["passkeys"] = 0
            return self._json(200, {"ok": True, "name": person["name"], "keys_removed": drop})

        return self._json(404, {"error": "no such path"})


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 8600), H) as s:
    print("doorman demo on http://127.0.0.1:8600 — try /login.html and /admin.html", flush=True)
    s.serve_forever()
