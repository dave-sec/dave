import contextlib
import http.server
import io
import json
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path

from dave import cli
from dave.compose_audit import audit_compose, parse_port, find_compose_files
from dave.explain import ExplainError, explain
from dave.findings import Finding
from dave.network_probe import probe

FIX = Path(__file__).parent / "fixtures"


def ids(findings):
    return sorted(f.rule_id for f in findings)


class ComposeTests(unittest.TestCase):
    def test_insecure(self):
        fs = audit_compose(FIX / "insecure-compose.yml")
        by = {}
        for f in fs:
            by.setdefault(f.rule_id, []).append(f)
        self.assertEqual(len(by["DV001"]), 2)
        self.assertEqual({f.service for f in by["DV001"]}, {"ollama", "open-webui"})
        self.assertEqual(by["DV002"][0].service, "n8n")
        self.assertEqual(by["DV002"][0].severity, "critical")
        self.assertIn("DV003", by)
        self.assertIn("DV004", by)
        self.assertEqual({f.service for f in by["DV005"]}, {"ollama"})
        self.assertEqual({f.service for f in by["DV006"]}, {"ollama", "n8n"})
        self.assertIn("DV007", by)
        self.assertIn("DV008", by)
        self.assertEqual(len(by["DV009"]), 1)
        self.assertIn("OPENAI_API_KEY", by["DV009"][0].detail)
        self.assertNotIn("sk-test", by["DV009"][0].evidence)  # le secret n'est jamais affiché

    def test_line_numbers(self):
        fs = audit_compose(FIX / "insecure-compose.yml")
        ollama = [f for f in fs if f.service == "ollama"]
        self.assertTrue(all(f.line == 2 for f in ollama))

    def test_secure_has_no_findings(self):
        self.assertEqual(audit_compose(FIX / "secure-compose.yml"), [])

    def test_edge_ports(self):
        fs = audit_compose(FIX / "edge-ports.yml")
        self.assertEqual(ids(fs), ["DV001", "DV001"])

    def test_parse_port(self):
        self.assertEqual(parse_port("11434:11434"), (None, "11434", 11434))
        self.assertEqual(parse_port("127.0.0.1:3000:8080"), ("127.0.0.1", "3000", 8080))
        self.assertEqual(parse_port("8000"), (None, None, 8000))
        self.assertEqual(parse_port("8080:8080/tcp"), (None, "8080", 8080))
        self.assertEqual(parse_port("[::1]:8001:8000"), ("::1", "8001", 8000))
        self.assertEqual(parse_port({"target": 80, "published": 8080, "host_ip": "0.0.0.0"}), ("0.0.0.0", "8080", 80))

    def test_french(self):
        fs = audit_compose(FIX / "insecure-compose.yml", lang="fr")
        titles = {f.title for f in fs}
        self.assertIn("Socket Docker monté dans un conteneur", titles)

    def test_find_files(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a").mkdir()
            (Path(d) / "a" / "compose.yaml").write_text("services: {}\n")
            (Path(d) / "docker-compose.prod.yml").write_text("services: {}\n")
            (Path(d) / "other.yml").write_text("x: 1\n")
            names = sorted(p.name for p in find_compose_files(Path(d)))
            self.assertEqual(names, ["compose.yaml", "docker-compose.prod.yml"])


class _Ollama(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/tags":
            self._json({"models": [{"name": "llama3.2"}, {"name": "qwen3"}]})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length))
        self._json({"response": "explained:" + payload["model"]})


class _Plain(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>hello</html>")


def _serve(handler):
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _free_port():
    s = socketserver.TCPServer(("127.0.0.1", 0), _Plain)
    port = s.server_address[1]
    s.server_close()
    return port


class ProbeAndExplainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ollama, cls.oport = _serve(_Ollama)
        cls.plain, cls.pport = _serve(_Plain)

    @classmethod
    def tearDownClass(cls):
        for s in (cls.ollama, cls.plain):
            s.shutdown()
            s.server_close()

    def test_probe(self):
        closed = _free_port()
        fs = probe("127.0.0.1", {self.oport: "Ollama", self.pport: "Open WebUI", closed: "n8n"})
        by = {f.rule_id: f for f in fs}
        self.assertEqual(ids(fs), ["DV101", "DV102"])
        self.assertEqual(by["DV101"].severity, "info")  # cible locale
        self.assertIn("2 model", by["DV101"].evidence)

    def test_explain(self):
        f = Finding("DV002", "critical", "t", "d", "fix", "x")
        explain([f], f"http://127.0.0.1:{self.oport}", "qwen3", "fr")
        self.assertEqual(f.ai_explanation, "explained:qwen3")

    def test_explain_unreachable(self):
        with self.assertRaises(ExplainError):
            explain([Finding("DV002", "critical", "t", "d", "f", "x")], f"http://127.0.0.1:{_free_port()}", "m", timeout=2)


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(argv)
        return code, buf.getvalue()

    def test_exit_codes(self):
        code, _ = self.run_cli(["compose", str(FIX / "insecure-compose.yml"), "--lang", "en"])
        self.assertEqual(code, 1)
        code, out = self.run_cli(["compose", str(FIX / "secure-compose.yml"), "--lang", "en"])
        self.assertEqual(code, 0)
        self.assertIn("No issues found", out)
        code, _ = self.run_cli(["compose", "/nope/compose.yml"])
        self.assertEqual(code, 2)

    def test_fail_on_critical(self):
        code, _ = self.run_cli(["compose", str(FIX / "edge-ports.yml"), "--fail-on", "critical"])
        self.assertEqual(code, 0)

    def test_json_and_sarif(self):
        _, out = self.run_cli(["compose", str(FIX / "insecure-compose.yml"), "--format", "json"])
        data = json.loads(out)
        self.assertEqual(data["findings"][0]["severity"], "critical")
        _, out = self.run_cli(["compose", str(FIX / "insecure-compose.yml"), "--format", "sarif"])
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])
        self.assertIn("region", sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"])

    def test_output_file_fr(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.txt"
            self.run_cli(["compose", str(FIX / "insecure-compose.yml"), "--lang", "fr", "-o", str(out)])
            content = out.read_text(encoding="utf-8")
            self.assertIn("Correctif", content)
            self.assertNotIn("\033[", content)


if __name__ == "__main__":
    unittest.main()
