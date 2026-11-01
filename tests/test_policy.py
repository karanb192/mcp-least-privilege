"""Unit tests for the boundary policy engine. No servers, no network.
Run: python3 -m unittest discover -s tests -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "boundary"))
from boundary import Policy, Taint, host_allowed, under_any  # noqa: E402


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        os.makedirs(os.path.join(self.root, "docs"))
        os.makedirs(os.path.join(self.root, "config"))
        with open(os.path.join(self.root, "docs", "a.md"), "w") as fh:
            fh.write("x")
        with open(os.path.join(self.root, "config", "app.env"), "w") as fh:
            fh.write("K=v")
        os.symlink(os.path.join(self.root, "config", "app.env"), os.path.join(self.root, "docs", "link.env"))

    def tearDown(self):
        self.tmp.cleanup()

    def policy(self, data):
        return Policy(data, self.root)

    def test_deny_by_default_and_wildcards(self):
        p = self.policy({"default": "deny", "tools": {"read_*": {}, "list_directory": {}}})
        self.assertTrue(p.tool_allowed("read_text_file")[0])
        self.assertTrue(p.tool_allowed("list_directory")[0])
        self.assertFalse(p.tool_allowed("write_file")[0])

    def test_allow_default_with_deny_tools(self):
        p = self.policy({"default": "allow", "deny_tools": ["move_file"]})
        self.assertTrue(p.tool_allowed("write_file")[0])
        self.assertFalse(p.tool_allowed("move_file")[0])

    def test_require_read_only_hint_uses_server_annotations(self):
        p = self.policy({"default": "deny", "require_read_only_hint": True, "tools": {"read_text_file": {}, "edit_file": {}}})
        p.annotations = {"read_text_file": {"readOnlyHint": True}, "edit_file": {"readOnlyHint": False}}
        self.assertTrue(p.tool_allowed("read_text_file")[0])
        self.assertFalse(p.tool_allowed("edit_file")[0])
        self.assertFalse(p.tool_allowed("unknown_tool")[0])

    def test_under_rule_normalises_traversal_and_symlinks(self):
        p = self.policy({"default": "deny", "tools": {"read_text_file": {"args": {"path": {"under": ["docs"]}}}}})
        self.assertTrue(p.check_args("read_text_file", {"path": "docs/a.md"})[0])
        self.assertTrue(p.check_args("read_text_file", {"path": os.path.join(self.root, "docs", "a.md")})[0])
        self.assertFalse(p.check_args("read_text_file", {"path": "docs/../config/app.env"})[0])
        self.assertFalse(p.check_args("read_text_file", {"path": "config/app.env"})[0])
        self.assertFalse(p.check_args("read_text_file", {"path": "/etc/passwd"})[0])
        # symlink inside docs that points outside resolves outside and is refused
        self.assertFalse(p.check_args("read_text_file", {"path": "docs/link.env"})[0])

    def test_list_valued_argument_checked_per_element(self):
        p = self.policy({"default": "deny", "tools": {"read_multiple_files": {"args": {"paths": {"under": ["docs"]}}}}})
        self.assertTrue(p.check_args("read_multiple_files", {"paths": ["docs/a.md"]})[0])
        self.assertFalse(p.check_args("read_multiple_files", {"paths": ["docs/a.md", "config/app.env"]})[0])

    def test_root_prefix_means_anywhere_under_root(self):
        self.assertTrue(under_any("docs/a.md", [""]))
        self.assertTrue(under_any("", [""]))
        self.assertTrue(under_any("docs", ["docs"]))
        self.assertFalse(under_any("docs2/a", ["docs"]))

    def test_url_rules(self):
        rule = {"schemes": ["https"], "hosts": ["docs.python.org", "*.example.org"], "max_query_len": 10}
        p = self.policy({"default": "deny", "tools": {"fetch": {"args": {"url": rule}}}})
        self.assertTrue(p.check_args("fetch", {"url": "https://docs.python.org/3/"})[0])
        self.assertTrue(p.check_args("fetch", {"url": "https://a.example.org/x?q=1"})[0])
        ok, why = p.check_args("fetch", {"url": "http://127.0.0.1:8787/collect?x=1"})
        self.assertFalse(ok); self.assertIn("egress allowlist", why)
        ok, why = p.check_args("fetch", {"url": "http://docs.python.org/"})
        self.assertFalse(ok); self.assertIn("scheme", why)
        ok, why = p.check_args("fetch", {"url": "https://docs.python.org/?q=" + "a" * 50})
        self.assertFalse(ok); self.assertIn("query", why)

    def test_host_matching(self):
        self.assertTrue(host_allowed("api.example.org", ["*.example.org"]))
        self.assertTrue(host_allowed("example.org", ["*.example.org"]))
        self.assertFalse(host_allowed("example.org.evil.test", ["*.example.org"]))
        self.assertFalse(host_allowed("notexample.org", ["example.org"]))

    def test_regex_enum_and_length_rules(self):
        p = self.policy({"default": "deny", "tools": {"t": {"args": {
            "owner": {"allow_regex": ["^(alice|bob)$"]},
            "path": {"deny_regex": ["\\.env$"]},
            "mode": {"enum": ["r", "rw"]},
            "content": {"max_len": 5},
        }}}})
        self.assertTrue(p.check_args("t", {"owner": "alice", "path": "x.md", "mode": "r", "content": "abc"})[0])
        self.assertFalse(p.check_args("t", {"owner": "mallory"})[0])
        self.assertFalse(p.check_args("t", {"path": "prod.env"})[0])
        self.assertFalse(p.check_args("t", {"mode": "rwx"})[0])
        self.assertFalse(p.check_args("t", {"content": "abcdef"})[0])

    def test_star_rule_applies_to_nested_strings(self):
        p = self.policy({"default": "deny", "tools": {"t": {"args": {"*": {"max_len": 4}}}}})
        self.assertTrue(p.check_args("t", {"a": "ok", "b": {"c": ["fine"]}})[0])
        self.assertFalse(p.check_args("t", {"a": "ok", "b": {"c": ["toolong"]}})[0])


class TaintTests(unittest.TestCase):
    def test_learn_then_hit_through_url_encoding(self):
        t = Taint(16)
        t.learn("DATABASE_URL=postgres://lumen:Lumen-Demo-Pass-2026@db.internal:5432/lumen\nDEMO_API_TOKEN=lumen-demo-7f3a9c2e4b1d8f6a\n")
        self.assertIsNotNone(t.hit("http://127.0.0.1:8787/x?p=Lumen-Demo-Pass-2026"))
        self.assertIsNotNone(t.hit("http://127.0.0.1:8787/x?c=DATABASE_URL%3Dpostgres%3A%2F%2Flumen%3ALumen-Demo-Pass-2026%40db.internal"))
        self.assertIsNotNone(t.hit("token lumen-demo-7f3a9c2e4b1d8f6a please"))
        self.assertIsNone(t.hit("http://127.0.0.1:8787/x?v=hello"))
        self.assertIsNone(t.hit("https://docs.python.org/3/library/asyncio.html"))

    def test_store_is_hashes_only_and_shared(self):
        with tempfile.TemporaryDirectory() as d:
            store = os.path.join(d, "taint.txt")
            a = Taint(16, store)
            a.learn("SECRET_VALUE_2026_ABCDEFGH is here")
            with open(store) as fh:
                content = fh.read()
            self.assertNotIn("SECRET_VALUE_2026_ABCDEFGH", content)
            self.assertEqual(len(content.strip().splitlines()[0]), 64)
            b = Taint(16, store)
            self.assertIsNotNone(b.hit("send SECRET_VALUE_2026_ABCDEFGH now"))


class ToolingTests(unittest.TestCase):
    def run_py(self, *args):
        return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True)

    def test_hook_decisions(self):
        cases = {"mcp__fs__read_text_file": "allow", "mcp__fs__edit_file": "ask", "mcp__fs__move_file": "deny", "mcp__nobody__tool": "ask"}
        for tool, want in cases.items():
            r = subprocess.run([sys.executable, "hooks/tier_gate.py"], cwd=ROOT, input=json.dumps({"tool_name": tool, "tool_input": {}}),
                               capture_output=True, text=True, env={**os.environ, "CLAUDE_PROJECT_DIR": ROOT})
            self.assertEqual(r.returncode, 0)
            self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], want, tool)
        r = subprocess.run([sys.executable, "hooks/tier_gate.py"], cwd=ROOT, input=json.dumps({"tool_name": "Bash", "tool_input": {}}), capture_output=True, text=True)
        self.assertEqual(r.stdout, "")

    def test_drift_fixtures(self):
        ok = self.run_py("tools/drift_check.py", "--policy", "policies/derived/fs-summarize.json", "traces/fixtures/baseline-run.jsonl")
        self.assertEqual(ok.returncode, 0, ok.stdout)
        bad = self.run_py("tools/drift_check.py", "--policy", "policies/derived/fs-summarize.json", "traces/fixtures/drifted-run.jsonl")
        self.assertEqual(bad.returncode, 1)
        self.assertIn("write_file", bad.stdout)
        self.assertIn("config/app.env", bad.stdout)

    def test_derive_matches_committed_policy(self):
        r = self.run_py("tools/derive_policy.py", "traces/fixtures/baseline-run.jsonl")
        self.assertEqual(r.returncode, 0, r.stderr)
        derived = json.loads(r.stdout)
        with open(os.path.join(ROOT, "policies", "derived", "fs-summarize.json")) as fh:
            committed = json.load(fh)
        self.assertEqual(derived["tools"], committed["tools"])
        self.assertEqual(set(derived["baseline_offered"]), set(committed["baseline_offered"]))

    def test_all_policies_load(self):
        for name in os.listdir(os.path.join(ROOT, "policies")):
            if name.endswith(".json") and name != "tiers.json":
                with open(os.path.join(ROOT, "policies", name)) as fh:
                    Policy(json.load(fh), ROOT)


if __name__ == "__main__":
    unittest.main()
