import contextlib
import http.server
import io
import json
import os
import socketserver
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from dave import cli, updates

HITS = {"n": 0, "tag": "v9.9.9", "fail": False}


class FakeGitHub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        HITS["n"] += 1
        if HITS["fail"] or not self.path.endswith("/repos/me/dave/releases/latest"):
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"tag_name": HITS["tag"], "draft": False, "prerelease": False}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


class TTY(io.StringIO):
    def isatty(self):
        return True


class UpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeGitHub)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.api = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        HITS.update(n=0, tag="v9.9.9", fail=False)
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": self.tmp.name}, clear=False)
        self.env.start()
        for k in ("CI", "DAVE_NO_UPDATE_CHECK", "DAVE_INSTALL_METHOD"):
            os.environ.pop(k, None)
        self.p = [mock.patch.object(updates, "API", self.api), mock.patch.object(updates, "REPO", "me/dave")]
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()
        self.env.stop()
        self.tmp.cleanup()

    def test_compare(self):
        self.assertTrue(updates.is_newer("0.10.0", "0.9.9"))
        self.assertFalse(updates.is_newer("0.4.0", "0.4.0"))
        self.assertFalse(updates.is_newer("garbage", "0.4.0"))

    def test_cache_once_a_day(self):
        self.assertEqual(updates.latest(), "9.9.9")
        self.assertEqual(updates.latest(), "9.9.9")
        self.assertEqual(HITS["n"], 1)
        self.assertEqual(updates.latest(now=time.time() + 25 * 3600), "9.9.9")
        self.assertEqual(HITS["n"], 2)

    def test_failure_is_cached_and_silent(self):
        HITS["fail"] = True
        self.assertIsNone(updates.latest())
        self.assertIsNone(updates.latest())
        self.assertEqual(HITS["n"], 1)

    def test_invalid_tag_ignored(self):
        HITS["tag"] = "nightly-build"
        self.assertIsNone(updates.fetch_latest())

    def test_disabled(self):
        with mock.patch.dict(os.environ, {"CI": "true"}):
            self.assertTrue(updates.disabled())
        with mock.patch.dict(os.environ, {"DAVE_NO_UPDATE_CHECK": "1"}):
            self.assertTrue(updates.disabled())
        with mock.patch.object(updates, "REPO", "OWNER/dave"):
            self.assertTrue(updates.disabled())
        self.assertFalse(updates.disabled())

    def test_hints(self):
        for method, expected in [("deb", "apt install"), ("docker", "docker pull ghcr.io/me/dave:9.9.9"),
                                 ("pipx", "pipx upgrade"), ("docker-wrapper", "install.sh --docker")]:
            with mock.patch.dict(os.environ, {"DAVE_INSTALL_METHOD": method}):
                self.assertIn(expected, updates.upgrade_hint("9.9.9", "fr"))
        self.assertIn("est disponible", updates.upgrade_hint("9.9.9", "fr"))

    def test_notice_only_on_terminal(self):
        check = updates.BackgroundCheck()
        tty, pipe = TTY(), io.StringIO()
        updates.maybe_notify(check, "fr", stream=pipe)
        self.assertEqual(pipe.getvalue(), "")
        updates.maybe_notify(check, "fr", stream=tty)
        self.assertIn("9.9.9", tty.getvalue())

    def test_update_check_command(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["update-check", "--plain"]), 10)
        self.assertEqual(out.getvalue().strip(), "9.9.9")
        HITS["tag"] = "v" + updates.__version__
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["update-check"]), 0)
        HITS["fail"] = True
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["update-check"]), 3)

    def test_scan_output_untouched(self):
        """Le JSON d'un scan ne doit jamais contenir l'avis de mise à jour (il part sur stderr)."""
        out = io.StringIO()
        fix = Path(__file__).parent / "fixtures" / "secure-compose.yml"
        with contextlib.redirect_stdout(out):
            cli.main(["compose", str(fix), "--format", "json"])
        json.loads(out.getvalue())


if __name__ == "__main__":
    unittest.main()
