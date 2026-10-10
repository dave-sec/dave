import contextlib
import http.server
import io
import json
import shutil
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path

import yaml

from dave import cli
from dave.advisories import matching, parse_version
from dave.compose_audit import audit_compose
from dave.config import apply
from dave.host_audit import audit_host
from dave.network_probe import probe
from dave.report import score

FIX = Path(__file__).parent / "fixtures"


class RulesV2(unittest.TestCase):
    def test_vector_compose(self):
        fs = audit_compose(FIX / "vector-compose.yml")
        got = sorted((f.rule_id, f.service) for f in fs)
        self.assertIn(("DV011", "ollama"), got)
        self.assertIn(("DV010", "qdrant"), got)
        self.assertNotIn(("DV010", "qdrant-secure"), got)
        self.assertNotIn(("DV006", "legacy"), got)          # ignoré en commentaire
        self.assertFalse([f for f in fs if f.service == "silenced"])  # tout ignoré
        cve = [f for f in fs if f.rule_id == "DV011"][0]
        self.assertIn("CVE-2024-37032", cve.detail)
        self.assertEqual(cve.severity, "critical")

    def test_advisories(self):
        self.assertEqual(parse_version("v0.1.33-rocm"), (0, 1, 33))
        self.assertTrue(matching("Ollama", "0.1.33"))
        self.assertFalse(matching("Ollama", "0.1.34"))
        self.assertFalse(matching("Ollama", "latest"))

    def test_config_ignore(self):
        fs = audit_compose(FIX / "insecure-compose.yml")
        kept = apply(fs, {"ignore": ["DV006"], "ignore_services": {"DV005": ["ollama"]}})
        self.assertFalse([f for f in kept if f.rule_id == "DV006"])
        self.assertFalse([f for f in kept if f.rule_id == "DV005"])
        self.assertTrue([f for f in kept if f.rule_id == "DV001"])

    def test_host_audit(self):
        fs = audit_host([FIX / "systemd" / "ollama.service.d", FIX / "systemd" / "ollama-safe.service"])
        self.assertEqual([f.rule_id for f in fs], ["DV012"])
        self.assertEqual(fs[0].line, 3)

    def test_score(self):
        self.assertEqual(score([]), (100, "A"))
        fs = audit_compose(FIX / "insecure-compose.yml")
        self.assertEqual(score(fs)[1], "F")


class _Svc(http.server.BaseHTTPRequestHandler):
    routes = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path in self.routes:
            body = json.dumps(self.routes[self.path]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def serve(routes):
    handler = type("H", (_Svc,), {"routes": routes})
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class ProbeV2(unittest.TestCase):
    def test_old_ollama_and_open_qdrant(self):
        o, op = serve({"/api/tags": {"models": []}, "/api/version": {"version": "0.1.32"}})
        q, qp = serve({"/collections": {"result": {"collections": []}, "status": "ok"}})
        try:
            fs = probe("127.0.0.1", {op: "Ollama", qp: "Qdrant"})
        finally:
            for s in (o, q):
                s.shutdown()
                s.server_close()
        ids = sorted(f.rule_id for f in fs)
        self.assertEqual(ids, ["DV101", "DV103", "DV104"])
        self.assertEqual([f for f in fs if f.rule_id == "DV103"][0].severity, "critical")


class FixV2(unittest.TestCase):
    def test_fix_write_keeps_valid_yaml(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "docker-compose.yml"
            shutil.copy(FIX / "insecure-compose.yml", target)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli.main(["fix", str(target), "--write", "--lang", "en"])
            self.assertTrue((Path(d) / "docker-compose.yml.bak").exists())
            yaml.safe_load(target.read_text())  # toujours du YAML valide
            after = {f.rule_id for f in audit_compose(target)}
            self.assertNotIn("DV001", after)
            self.assertNotIn("DV008", after)
            self.assertIn("127.0.0.1:11434:11434", target.read_text())

    def test_fix_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "compose.yaml"
            shutil.copy(FIX / "insecure-compose.yml", target)
            before = target.read_text()
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli.main(["fix", str(target)])
            self.assertEqual(before, target.read_text())
            self.assertIn("+      - \"127.0.0.1:3000:8080\"", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
