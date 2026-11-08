import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.pr_comment import COMMENT_MARKER, build_comment_body  # noqa: E402


class PrCommentTests(unittest.TestCase):
    def test_clean_scan_mentions_zero_findings(self) -> None:
        body = build_comment_body([], 3)
        self.assertIn(COMMENT_MARKER, body)
        self.assertIn("3 dosya tarandı", body)
        self.assertIn("**0** kritik/yüksek bulgu", body)
        self.assertIn("Kritik veya yüksek seviyeli zafiyet bulunamadı.", body)

    def test_finding_line_is_listed(self) -> None:
        body = build_comment_body(
            [
                {
                    "name": "XSS",
                    "file_name": "main.py",
                    "line_number": "45",
                    "recommendation": "Lütfen girdiyi temizleyin.",
                }
            ],
            3,
        )
        self.assertIn("`main.py` 45. satırda **XSS** tespit edildi.", body)
        self.assertIn("Lütfen girdiyi temizleyin.", body)


if __name__ == "__main__":
    unittest.main()
