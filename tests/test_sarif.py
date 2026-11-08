import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.sarif import build_sarif, rule_id, write_sarif  # noqa: E402


class SarifTests(unittest.TestCase):
    def test_empty_findings_are_valid(self) -> None:
        document = build_sarif([])
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(document["runs"][0]["results"], [])
        self.assertEqual(document["runs"][0]["tool"]["driver"]["name"], "DevSecOps Analyzer")
        self.assertEqual(document["runs"][0]["tool"]["driver"]["rules"], [])

    def test_rule_id_slug(self) -> None:
        self.assertEqual(rule_id("SQL Injection"), "sql-injection")
        self.assertEqual(rule_id("XSS"), "xss")
        self.assertEqual(rule_id("???"), "security-finding")

    def test_result_location_and_fingerprint(self) -> None:
        document = build_sarif(
            [
                {
                    "name": "SQL Injection",
                    "file_name": "app/db.py",
                    "line_number": "40-42",
                    "recommendation": "Use a parameterized query.",
                    "severity": "critical",
                }
            ]
        )
        result = document["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "sql-injection")
        self.assertEqual(result["level"], "error")
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 40)
        self.assertIsInstance(region["startLine"], int)
        self.assertEqual(
            result["partialFingerprints"]["primaryLocationLineHash"],
            "app/db.py:40:sql-injection",
        )
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "app/db.py")
        rules = document["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["properties"]["security-severity"], "9.0")

    def test_write_sarif_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out" / "results.sarif"
            write_sarif(path, [])
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["version"], "2.1.0")
            self.assertEqual(loaded["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()
