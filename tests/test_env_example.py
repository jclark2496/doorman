import subprocess, unittest
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parents[1] / "examples" / "doorman.env.example"

# What this file is meant to hand its readers, spelled out here rather than parsed back out of the
# file: reading it with Python is exactly what would miss an unquoted space, because Python is not
# the reader that breaks on one. `AUTH_RP_NAME=Example` shipped for a while and cost a
# deployment -- sh read it as the assignment `AUTH_RP_NAME=Some` followed by the command `Site`.
EXPECTED = {
    "AUTH_PORT": "8401",
    "AUTH_ORIGIN": "https://example.com",
    "AUTH_RP_ID": "example.com",
    "AUTH_RP_NAME": "Example",
    "AUTH_COOKIE_DOMAIN": ".example.com",
    "AUTH_COOKIE_NAME": "doorman_session",
    "AUTH_DB": "/opt/doorman/data/auth.db",
    "AUTH_SESSION_DAYS": "30",
    "AUTH_RENEW_DAYS": "15",
    "AUTH_OWNER_NAME": "ada",
    "AUTH_HOSTS": "example.com,notes.example.com,photos.example.com,files.example.com,archive.example.com",
    "AUTH_SITE_ALIASES": "notes=notes.example.com,photos=photos.example.com,files=files.example.com,archive=archive.example.com",
}

# Sourced the way the runbook sources it, then every name printed back. `?` makes a name the file
# failed to set abort the shell rather than come back as an empty string.
DUMP = 'set -a\n. "$1"\nset +a\n' + "".join(f'printf "%s\\n" "{n}=${{{n}?not set}}"\n' for n in EXPECTED)


class EnvExampleTest(unittest.TestCase):
    def test_the_shipped_file_sources_in_posix_sh_and_yields_every_intended_value(self):
        """systemd reads this file as an EnvironmentFile, but three runbook commands source it with
        `sh` -- so a value containing a space or a metacharacter has to be quoted. Run a real shell
        rather than a parser: the parser is what missed it last time."""
        r = subprocess.run(["/bin/sh", "-ec", DUMP, "sh", str(ENV_FILE)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, f"sourcing failed ({r.returncode}): {r.stderr.strip()}")
        got = dict(line.split("=", 1) for line in r.stdout.splitlines())
        self.assertEqual(got, EXPECTED)

    def test_every_assignment_in_the_file_is_covered_above(self):
        """So a variable added later is checked too, instead of being sourced but never compared."""
        names = [ln.split("=", 1)[0] for ln in ENV_FILE.read_text().splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertEqual(sorted(names), sorted(EXPECTED))
