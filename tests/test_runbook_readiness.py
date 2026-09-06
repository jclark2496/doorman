import re, socket, subprocess, threading, time, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

RUNBOOK = Path(__file__).resolve().parents[1] / "docs" / "runbook.md"

# The runbook restarts five Type=simple units, so systemd reports every one of them `active` before
# its listener has bound. Each check that follows such a restart is wrapped in one bounded retry,
# written identically at every site. This file runs the text as shipped rather than a copy of it:
# a copy would keep passing after the runbook drifted, which is the only failure that matters here.
HEALTH = "_auth/health"          # the auth service's health endpoint, wherever it appears
FIRST_LINE = re.compile(r"^\( url=(?P<url>\S+); n=(?P<n>\d+)$")
OPEN, CLOSE = "( url=", "} )"   # a site starts at this line prefix and ends at the subshell close


def idiom_sites(text):
    """Every occurrence of the retry idiom in the runbook, verbatim, as (start, end, block).

    An occurrence starts at a line beginning `( url=` and ends at the subshell's closing `} )`."""
    sites = []
    for m in re.finditer("(?m)^" + re.escape(OPEN), text):
        end = text.index(CLOSE, m.start()) + len(CLOSE)
        sites.append((m.start(), end, text[m.start():end]))
    return sites


def instantiate(block, url, tries):
    """The block exactly as the runbook has it, with only its parameter line re-pointed.

    That line is the only part the runbook itself varies between sites, so substituting it is
    what an operator does by hand; everything below it is run byte-for-byte as shipped."""
    first, rest = block.split("\n", 1)
    assert FIRST_LINE.match(first), first
    return f"( url={url}; n={tries}\n{rest}"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class LateListener:
    """An HTTP server that deliberately does not exist for `delay` seconds -- the shape of a
    Type=simple unit that systemd has already reported `active`."""

    BODY = b'{"ok": true}'

    def __init__(self, port, delay):
        self.port, self.delay, self.httpd = port, delay, None

    def __enter__(self):
        threading.Thread(target=self._serve_later, daemon=True).start()
        return self

    def _serve_later(self):
        time.sleep(self.delay)
        body = self.BODY

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", self.port), H)
        self.httpd.serve_forever()

    def __exit__(self, *exc):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()


class RunbookReadinessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = RUNBOOK.read_text()
        cls.sites = idiom_sites(cls.text)

    def run_idiom(self, url, tries, timeout=60):
        script = instantiate(self.sites[0][2], url, tries)
        return subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=timeout)

    def test_one_idiom_is_used_at_every_site(self):
        """Recognisable on sight means literally identical: the URL on the parameter line is the
        only thing allowed to differ, so no site can quietly grow a shorter bound or a softer stop."""
        self.assertGreaterEqual(len(self.sites), 2, "the runbook has lost the retry idiom")
        bodies = {block.split("\n", 1)[1] for _, _, block in self.sites}
        self.assertEqual(len(bodies), 1, "the retry idiom is not written identically at every site")
        for _, _, block in self.sites:
            m = FIRST_LINE.match(block.split("\n", 1)[0])
            self.assertIsNotNone(m, block)
            self.assertEqual(m.group("n"), "15", "the bound must stay at 15, as deploy-auth.sh has it")

    def test_it_keeps_asking_until_a_late_listener_binds(self):
        """The reported defect: the listener was three seconds behind the restart. The idiom has to
        wait it out and still print the body the runbook tells the operator to expect."""
        port = free_port()
        with LateListener(port, delay=3):
            r = self.run_idiom(f"http://127.0.0.1:{port}/_auth/health", 15)
        self.assertEqual(r.returncode, 0, f"exited {r.returncode}: {r.stderr.strip()}")
        self.assertEqual(r.stdout.strip(), '{"ok": true}')
        self.assertNotIn("STOP:", r.stdout)

    def test_a_successful_run_prints_only_the_body_no_retry_noise(self):
        """The actual defect this hotfix closes: `curl -fsS` on every attempt prints its own
        connection-refused line, so a real run against a service that takes ~12s to bind produces
        a dozen `curl: (7) Failed to connect ...` lines before the body -- even though the check
        is succeeding. The runbook's prose promises only the body. Pin the absence of the noise,
        not just the presence of the body, since the noise is what was fixed."""
        port = free_port()
        with LateListener(port, delay=6):
            r = self.run_idiom(f"http://127.0.0.1:{port}/_auth/health", 15)
        self.assertEqual(r.returncode, 0, f"exited {r.returncode}: {r.stderr.strip()}")
        self.assertEqual(r.stdout, '{"ok": true}\n', f"stdout must be exactly the body, got {r.stdout!r}")
        self.assertEqual(r.stderr, "", f"a successful run must print nothing on stderr, got {r.stderr!r}")

    def test_it_stops_and_exits_nonzero_when_nothing_ever_listens(self):
        """Bound shortened from 15 to 3 so the suite stays fast; nothing else about the block
        changes. A real failure must be loud and must leave a non-zero status behind."""
        port = free_port()          # nothing is ever bound here
        r = self.run_idiom(f"http://127.0.0.1:{port}/_auth/health", 3)
        self.assertNotEqual(r.returncode, 0, "an exhausted retry must not look like success")
        self.assertTrue(r.stdout.startswith("STOP:"), f"stdout was {r.stdout!r}")
        self.assertIn(str(port), r.stdout, "the stop message must name the check that failed")

    def test_an_exhausted_run_also_surfaces_the_underlying_error(self):
        """Silencing the retries must not leave the operator with nothing but 'did not answer' --
        on exhaustion the idiom makes one last attempt with errors shown, so the real cause
        (connection refused, TLS, a 502 from Caddy) is visible before the STOP line."""
        port = free_port()          # nothing is ever bound here
        r = self.run_idiom(f"http://127.0.0.1:{port}/_auth/health", 3)
        self.assertNotEqual(r.returncode, 0, "an exhausted retry must not look like success")
        self.assertTrue(r.stdout.startswith("STOP:"), f"stdout was {r.stdout!r}")
        self.assertIn("curl:", r.stderr, f"the underlying curl error must be surfaced, got {r.stderr!r}")
        self.assertIn(str(port), r.stderr, "the surfaced error must name the check that failed")

    def test_every_health_check_in_the_runbook_is_inside_the_idiom(self):
        """The assertion that stops this coming back. A bare `curl .../_auth/health` after a restart
        is the defect itself, so every mention of that endpoint anywhere in the runbook has to fall
        inside one of the retry blocks found above -- prose included, since prose gets pasted."""
        hits = [m.start() for m in re.finditer(re.escape(HEALTH), self.text)]
        self.assertTrue(hits, "the runbook no longer checks the auth service's health at all")
        for i in hits:
            line = self.text.count("\n", 0, i) + 1
            self.assertTrue(
                any(start <= i < end for start, end, _ in self.sites),
                f"{HEALTH} on line {line} of {RUNBOOK.name} is not inside the retry idiom",
            )
