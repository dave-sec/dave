import io
import json
import unittest
from pathlib import Path

from dave.compose_audit import audit_compose
from dave.fixer import patch_lines
from dave.mcp_server import Server
from dave.openclaw_audit import audit_config, native_audit

FIX = Path(__file__).parent / "fixtures"
OC = FIX / "openclaw"


class OpenClawTests(unittest.TestCase):
    def test_lan_json5(self):
        fs = audit_config(OC / "lan.json")
        self.assertEqual([(f.rule_id, f.severity) for f in fs], [("DV013", "medium")])
        self.assertEqual(fs[0].line, 7)
        self.assertIn("18789", fs[0].fix)

    def test_loopback_ignores_nested_bind(self):
        self.assertEqual(audit_config(OC / "loopback.json"), [])

    def test_tailnet_low_and_port(self):
        fs = audit_config(OC / "tailnet.json")
        self.assertEqual(fs[0].severity, "low")
        self.assertIn("19000", fs[0].fix)

    def test_commented_bind_ignored(self):
        self.assertEqual(audit_config(OC / "commented.json"), [])

    def test_missing_file(self):
        self.assertEqual(audit_config(OC / "nope.json"), [])

    def test_compose_port_18789(self):
        fs = audit_compose(FIX / "openclaw-compose.yml")
        dv1 = [f for f in fs if f.rule_id == "DV001"]
        self.assertEqual(len(dv1), 1)
        self.assertIn("OpenClaw", dv1[0].detail)
        lines = (FIX / "openclaw-compose.yml").read_text().splitlines()
        self.assertIn('      - "127.0.0.1:18789:18789"', patch_lines(lines, dv1))

    def test_native_audit_raw_output(self):
        fs = native_audit(binary=str(FIX / "fake-openclaw.sh"))
        self.assertEqual(fs[0].rule_id, "DV105")
        self.assertEqual(fs[0].severity, "info")
        self.assertIn("gateway token is blank", fs[0].evidence)
        self.assertIn("1", fs[0].detail)

    def test_native_audit_absent(self):
        self.assertEqual(native_audit(binary=None) if False else native_audit(binary=str(FIX / "nope")), [])


class McpTests(unittest.TestCase):
    def setUp(self):
        self.srv = Server(root=FIX, allowed_hosts={"127.0.0.1"})

    def rpc(self, method, params=None, mid=1):
        msg = {"jsonrpc": "2.0", "method": method}
        if mid is not None:
            msg["id"] = mid
        if params is not None:
            msg["params"] = params
        return self.srv.handle(msg)

    def call(self, name, args):
        return self.rpc("tools/call", {"name": name, "arguments": args})["result"]

    def test_initialize_and_list(self):
        r = self.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t"}})
        self.assertEqual(r["result"]["protocolVersion"], "2025-03-26")
        self.assertIn("tools", r["result"]["capabilities"])
        names = {t["name"] for t in self.rpc("tools/list")["result"]["tools"]}
        self.assertEqual(names, {"dave_scan_compose", "dave_fix_preview", "dave_host_audit", "dave_probe", "dave_rule"})

    def test_unknown_protocol_falls_back(self):
        r = self.rpc("initialize", {"protocolVersion": "1999-01-01"})
        self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")

    def test_scan(self):
        res = self.call("dave_scan_compose", {"path": "insecure-compose.yml", "lang": "fr"})
        self.assertFalse(res["isError"])
        data = json.loads(res["content"][0]["text"])
        self.assertEqual(data["grade"], "F")
        self.assertEqual(data["findings"][0]["severity"], "critical")

    def test_path_traversal_refused(self):
        res = self.call("dave_scan_compose", {"path": "../../../../etc"})
        self.assertTrue(res["isError"])
        self.assertIn("outside", res["content"][0]["text"])

    def test_fix_preview_is_read_only(self):
        before = (FIX / "insecure-compose.yml").read_text()
        res = self.call("dave_fix_preview", {"path": "insecure-compose.yml"})
        self.assertIn("127.0.0.1:11434:11434", res["content"][0]["text"])
        self.assertEqual(before, (FIX / "insecure-compose.yml").read_text())

    def test_probe_host_allowlist(self):
        res = self.call("dave_probe", {"host": "10.0.0.5"})
        self.assertTrue(res["isError"])
        self.assertIn("DAVE_MCP_ALLOWED_HOSTS", res["content"][0]["text"])

    def test_rule(self):
        data = json.loads(self.call("dave_rule", {"rule_id": "dv013"})["content"][0]["text"])
        self.assertEqual(data["id"], "DV013")
        self.assertTrue(data["references"])

    def test_protocol_edges(self):
        self.assertIsNone(self.rpc("notifications/initialized", mid=None))
        self.assertEqual(self.rpc("nope")["error"]["code"], -32601)
        out = io.StringIO()
        self.srv.serve(io.StringIO('not json\n{"jsonrpc":"2.0","id":7,"method":"ping"}\n'), out)
        lines = [json.loads(l) for l in out.getvalue().splitlines()]
        self.assertEqual(lines[0]["error"]["code"], -32700)
        self.assertEqual(lines[1], {"jsonrpc": "2.0", "id": 7, "result": {}})


if __name__ == "__main__":
    unittest.main()
