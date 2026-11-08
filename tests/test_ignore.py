import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.ignore import (  # noqa: E402
    IgnoreRules,
    filter_findings,
    filter_source_files,
    locate_ignore_file,
    parse_line_number,
)


class ParseLineNumberTests(unittest.TestCase):
    def test_digits_and_fallback(self) -> None:
        self.assertEqual(parse_line_number("42"), 42)
        self.assertEqual(parse_line_number("12-18"), 12)
        self.assertEqual(parse_line_number("satır 7"), 7)
        self.assertEqual(parse_line_number("yok"), 1)


class IgnoreRulesTests(unittest.TestCase):
    def _rules(self, text: str) -> IgnoreRules:
        with tempfile.TemporaryDirectory() as tmp:
            ignore_path = Path(tmp) / ".devsecopsignore"
            ignore_path.write_text(text, encoding="utf-8")
            return IgnoreRules.parse(ignore_path)

    def test_none_skips_nothing(self) -> None:
        rules = IgnoreRules.none()
        self.assertFalse(rules.should_skip_file("app/main.py"))
        self.assertFalse(rules.should_skip_finding("app/main.py", 10, "x = 1"))

    def test_comments_and_blank_lines(self) -> None:
        rules = self._rules("# sadece yorum\n\n  \ntest_vuln.py\n")
        self.assertTrue(rules.should_skip_file("test_vuln.py"))
        self.assertFalse(rules.should_skip_file("app/main.py"))

    def test_basename_and_nested_file(self) -> None:
        rules = self._rules("test_vuln.py\n")
        self.assertTrue(rules.should_skip_file("test_vuln.py"))
        self.assertTrue(rules.should_skip_file("samples/test_vuln.py"))

    def test_directory_prefix(self) -> None:
        rules = self._rules("vendor/\n")
        self.assertTrue(rules.should_skip_file("vendor/pkg.py"))
        self.assertTrue(rules.should_skip_file("vendor/nested/a.py"))
        self.assertFalse(rules.should_skip_file("app/vendor.py"))

    def test_glob(self) -> None:
        rules = self._rules("*.generated.py\n")
        self.assertTrue(rules.should_skip_file("models.generated.py"))
        self.assertTrue(rules.should_skip_file("app/models.generated.py"))
        self.assertFalse(rules.should_skip_file("app/models.py"))

    def test_line_and_range(self) -> None:
        rules = self._rules("app/legacy.py:42\napp/auth.py:100-120\n")
        self.assertFalse(rules.should_skip_file("app/legacy.py"))
        self.assertTrue(rules.should_skip_finding("app/legacy.py", 42))
        self.assertFalse(rules.should_skip_finding("app/legacy.py", 41))
        self.assertTrue(rules.should_skip_finding("app/auth.py", 100))
        self.assertTrue(rules.should_skip_finding("app/auth.py", 120))
        self.assertFalse(rules.should_skip_finding("app/auth.py", 99))

    def test_inline_marker_without_ignore_file(self) -> None:
        rules = IgnoreRules.none()
        self.assertTrue(
            rules.should_skip_finding(
                "app/main.py",
                8,
                'password = "x"  # devsecops:ignore',
            )
        )

    def test_filter_source_files_and_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".devsecopsignore").write_text(
                "skip_me.py\nkeep.py:3\n",
                encoding="utf-8",
            )
            skip_me = root / "skip_me.py"
            keep = root / "keep.py"
            skip_me.write_text("print(1)\n", encoding="utf-8")
            keep.write_text("a=1\nb=2\nc=3  # secret\n", encoding="utf-8")
            rules = IgnoreRules.load([root])
            source = {
                str(skip_me): skip_me.read_text(encoding="utf-8"),
                str(keep): keep.read_text(encoding="utf-8"),
            }
            kept, skipped = filter_source_files(source, rules)
            self.assertEqual(skipped, ["skip_me.py"])
            self.assertEqual(list(kept.keys()), [str(keep)])

            findings = [
                {"file_name": "keep.py", "line_number": "3", "name": "Secret"},
                {"file_name": "keep.py", "line_number": "1", "name": "OK"},
                {
                    "file_name": "keep.py",
                    "line_number": "2",
                    "name": "Inline",
                },
            ]
            contents = {"keep.py": "a=1\nb=2  # devsecops:ignore\nc=3  # secret\n"}
            filtered = filter_findings(findings, rules, contents)
            names = [item["name"] for item in filtered]
            self.assertEqual(names, ["OK"])

    def test_project_ignore_skips_fixture_file(self) -> None:
        rules = IgnoreRules.load([ROOT])
        self.assertTrue(rules.enabled)
        self.assertTrue(rules.should_skip_file("test_vuln.py"))
        self.assertFalse(rules.should_skip_file("app/main.py"))

    def test_locate_nested_zipball_ignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            extract = Path(tmp) / "owner_repo"
            nested = extract / "owner-repo-abc123"
            nested.mkdir(parents=True)
            (nested / ".devsecopsignore").write_text("secret.py\n", encoding="utf-8")
            found = locate_ignore_file([extract])
            self.assertIsNotNone(found)
            self.assertEqual(found, nested / ".devsecopsignore")
            rules = IgnoreRules.load([extract])
            self.assertTrue(rules.enabled)
            self.assertTrue(rules.should_skip_file("secret.py"))


if __name__ == "__main__":
    unittest.main()
