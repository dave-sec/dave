import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from dave.compose_audit import audit_compose
from dave.env_audit import audit_env_files, audit_firewall
from dave.extras import badge_svg, compare, render_html
from dave.findings import Finding
from dave.fixer import interactive
from dave.mcp_config_audit import audit_mcp_config
from dave.proxy_audit import audit_proxy_file
from dave.report import render_json

FIX = Path(__file__).parent / "fixtures"


class FirewallTests(unittest.TestCase):
    def test_ufw_enabled(self):
        fs = audit_firewall([FIX / "insecure-compose.yml"], conf=FIX / "ufw-enabled.conf")
        self.assertEqual([f.rule_id for f in fs], ["DV014"])
        self.assertIn("ollama:11434", fs[0].detail)

    def test_ufw_disabled_or_safe(self):
        self.assertEqual(audit_firewall([FIX / "insecure-compose.yml"], conf=FIX / "ufw-disabled.conf"), [])
        self.assertEqual(audit_firewall([FIX / "secure-compose.yml"], conf=FIX / "ufw-enabled.conf"), [])


class McpConfigTests(unittest.TestCase):
    def test_claude_config(self):
        fs = audit_mcp_config(FIX / "mcp" / "claude_desktop_config.json")
        got = sorted((f.rule_id, f.service) for f in fs)
        self.assertEqual(got, [("DV015", "github"), ("DV016", "files")])
        self.assertNotIn("ghp_", fs[0].evidence + fs[1].evidence)

    def test_vscode_home(self):
        fs = audit_mcp_config(FIX / "mcp" / "vscode-mcp.json")
        self.assertEqual([(f.rule_id, f.service) for f in fs], [("DV016", "fs")])


class ProxyTests(unittest.TestCase):
    def test_nginx(self):
        fs = audit_proxy_file(FIX / "proxy" / "ai.conf")
        self.assertEqual([(f.rule_id, f.service, f.line) for f in fs], [("DV017", "Ollama", 1)])

    def test_caddy(self):
        fs = audit_proxy_file(FIX / "proxy" / "Caddyfile")
        self.assertEqual([(f.rule_id, f.service) for f in fs], [("DV017", "Ollama")])


@unittest.skipUnless(shutil.which("git"), "git required")
class EnvGitTests(unittest.TestCase):
    def git(self, d, *a):
        subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)

    def test_env_states(self):
        with tempfile.TemporaryDirectory() as d:
            self.git(d, "init", "-q")
            self.git(d, "config", "user.email", "t@t")
            self.git(d, "config", "user.name", "t")
            (Path(d) / ".env").write_text("OPENAI_API_KEY=sk-x\n")
            (Path(d) / ".env.example").write_text("OPENAI_API_KEY=\n")
            fs = audit_env_files(Path(d))
            self.assertEqual([(f.rule_id, f.severity) for f in fs], [("DV018", "medium")])
            (Path(d) / ".gitignore").write_text(".env\n")
            self.assertEqual(audit_env_files(Path(d)), [])
            self.git(d, "add", "-f", ".env")
            self.git(d, "commit", "-qm", "oops")
            fs = audit_env_files(Path(d), lang="fr")
            self.assertEqual(fs[0].severity, "high")
            self.assertIn("commité", fs[0].detail)

    def test_not_a_repo(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".env").write_text("X=1\n")
            self.assertEqual(audit_env_files(Path(d)), [])


class ReportExtrasTests(unittest.TestCase):
    def test_html_escapes(self):
        f = Finding("DV009", "medium", "<b>t</b>", "d", "fix", "x.yml", evidence="<script>alert(1)</script>")
        out = render_html([f], "fr")
        self.assertNotIn("<script>alert", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("Rapport de sécurité Dave", out)

    def test_badge(self):
        self.assertIn(">A</text>", badge_svg([]))
        self.assertIn(">F</text>", badge_svg(audit_compose(FIX / "insecure-compose.yml")))

    def test_baseline(self):
        old = audit_compose(FIX / "insecure-compose.yml")
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "old.json"
            base.write_text(render_json(old))
            new = [f for f in old if f.rule_id != "DV002"] + [Finding("DV010", "high", "t", "d", "f", "q.yml", "qdrant")]
            diff = compare(new, base)
            self.assertEqual([f["rule_id"] for f in diff["fixed"]], ["DV002"])
            self.assertEqual([f["rule_id"] for f in diff["new"]], ["DV010"])


class InteractiveTests(unittest.TestCase):
    def test_accept_first_only(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "compose.yaml"
            shutil.copy(FIX / "insecure-compose.yml", target)
            answers = iter(["y", "n", "n", "n"])
            n = interactive(target, audit_compose(target), ask=lambda _: next(answers), out=lambda *_: None)
            self.assertEqual(n, 1)
            text = target.read_text()
            self.assertEqual(text.count("127.0.0.1:"), 1)
            self.assertTrue((Path(d) / "compose.yaml.bak").exists())


if __name__ == "__main__":
    unittest.main()
