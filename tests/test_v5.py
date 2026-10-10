import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from dave import cli, walk
from dave.compose_audit import audit_compose, find_compose_files
from dave.fixer import patch_lines

FIX = Path(__file__).parent / "fixtures"


class CasaOSTests(unittest.TestCase):
    def test_long_syntax_fix(self):
        path = FIX / "casaos-compose.yml"
        fs = audit_compose(path)
        dv1 = [f for f in fs if f.rule_id == "DV001"]
        self.assertEqual(len(dv1), 2)
        lines = path.read_text().splitlines()
        fixed = patch_lines(lines, fs)
        text = "\n".join(fixed)
        self.assertEqual(text.count("host_ip: 127.0.0.1"), 2)
        data = yaml.safe_load(text)
        self.assertEqual(data["services"]["ollama"]["ports"][0]["host_ip"], "127.0.0.1")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "docker-compose.yml"
            p.write_text(text + "\n")
            self.assertFalse([f for f in audit_compose(p) if f.rule_id == "DV001"])
            self.assertEqual(patch_lines(text.splitlines(), audit_compose(p)), text.splitlines())  # idempotent


class WalkTests(unittest.TestCase):
    def test_depth_and_media_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "apps" / "a").mkdir(parents=True)
            (root / "apps" / "a" / "docker-compose.yml").write_text("services: {}\n")
            deep = root / "x1" / "x2" / "x3" / "x4" / "x5"
            deep.mkdir(parents=True)
            (deep / "compose.yaml").write_text("services: {}\n")
            (root / "immich" / "library").mkdir(parents=True)
            (root / "immich" / "library" / "compose.yml").write_text("services: {}\n")
            found = [p.relative_to(root).as_posix() for p in find_compose_files(root)]
            self.assertEqual(found, ["apps/a/docker-compose.yml"])
            old = walk.MAX_DEPTH
            walk.MAX_DEPTH = 6
            try:
                self.assertEqual(len(find_compose_files(root)), 2)
            finally:
                walk.MAX_DEPTH = old


class JsonOutTests(unittest.TestCase):
    def test_json_out_with_baseline(self):
        with tempfile.TemporaryDirectory() as d:
            j1, j2 = Path(d) / "1.json", Path(d) / "2.json"
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["compose", str(FIX / "insecure-compose.yml"), "--json-out", str(j1)])
                cli.main(["compose", str(FIX / "casaos-compose.yml"), "--json-out", str(j2), "--baseline", str(j1),
                          "--format", "html", "-o", str(Path(d) / "r.html")])
            data = json.loads(j2.read_text())
            self.assertEqual(data["baseline"]["new"], 2)
            self.assertGreater(data["baseline"]["fixed"], 5)
            self.assertIn("<html", (Path(d) / "r.html").read_text())


if __name__ == "__main__":
    unittest.main()


class MultiDirTests(unittest.TestCase):
    def test_scan_several_directories(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            shutil.copy(FIX / "casaos-compose.yml", Path(d1) / "docker-compose.yml")
            shutil.copy(FIX / "openclaw-compose.yml", Path(d2) / "compose.yaml")
            out = Path(d1) / "r.json"
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["scan", d1, d2, "--json-out", str(out)])
            sources = {Path(f["source"]).parent for f in json.loads(out.read_text())["findings"] if f["rule_id"] == "DV001"}
            self.assertEqual(sources, {Path(d1), Path(d2)})
