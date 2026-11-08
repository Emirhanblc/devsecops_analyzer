"""`.devsecopsignore` ve satır içi `devsecops:ignore` işaretini uygular."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

IGNORE_FILENAME = ".devsecopsignore"
INLINE_MARKER = "devsecops:ignore"


def parse_line_number(value: object) -> int:
    """Bulgu satırından ilk tam sayıyı üretir. Sayı yoksa 1 döner."""
    digits = ""
    for character in str(value):
        if character.isdigit():
            digits += character
        elif digits:
            break
    return int(digits) if digits else 1


def locate_ignore_file(search_roots: list[Path]) -> Path | None:
    """
    Ignore dosyasını tarama kökünde, yoksa GitHub zipball'unun
    tek iç klasöründe arar.
    """
    for root in search_roots:
        root = Path(root)
        candidate = root / IGNORE_FILENAME
        if candidate.is_file():
            return candidate
        try:
            children = [
                path
                for path in root.iterdir()
                if path.is_dir() and not path.name.startswith(".")
            ]
        except OSError:
            continue
        if len(children) == 1:
            nested = children[0] / IGNORE_FILENAME
            if nested.is_file():
                return nested
    return None


def _nth_line(source: str, line_number: int) -> str:
    if line_number < 1:
        return ""
    lines = source.splitlines()
    index = line_number - 1
    if index >= len(lines):
        return ""
    return lines[index]


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


@dataclass
class IgnoreRules:
    """Dosya glob'ları ve satır aralıklarını tutar."""

    root: Path
    enabled: bool = False
    file_patterns: list[str] = field(default_factory=list)
    line_rules: list[tuple[str, int, int]] = field(default_factory=list)

    @classmethod
    def none(cls, root: Path | None = None) -> IgnoreRules:
        return cls(root=Path(root) if root else Path("."), enabled=False)

    @classmethod
    def load(cls, search_roots: list[Path]) -> IgnoreRules:
        ignore_path = locate_ignore_file(search_roots)
        if ignore_path is None:
            fallback = Path(search_roots[0]) if search_roots else Path(".")
            return cls.none(fallback)
        return cls.parse(ignore_path)

    @classmethod
    def parse(cls, ignore_path: Path) -> IgnoreRules:
        rules = cls(root=ignore_path.parent.resolve(), enabled=True)
        try:
            text = ignore_path.read_text(encoding="utf-8")
        except OSError:
            return cls.none(ignore_path.parent)

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            path_pattern, start, end = _split_line_rule(line)
            if start is not None and end is not None:
                rules.line_rules.append((_normalize_path(path_pattern), start, end))
            else:
                rules.file_patterns.append(line.replace("\\", "/"))
        return rules

    def relative_path(self, file_path: str | Path) -> str:
        try:
            return Path(file_path).resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return _normalize_path(str(file_path))

    def should_skip_file(self, relative_path: str) -> bool:
        if not self.enabled:
            return False
        path = _normalize_path(relative_path)
        return any(_file_matches(path, pattern) for pattern in self.file_patterns)

    def should_skip_finding(
        self,
        relative_path: str,
        line: int,
        source_line: str | None = None,
    ) -> bool:
        if source_line and INLINE_MARKER in source_line:
            return True
        if not self.enabled:
            return False
        path = _normalize_path(relative_path)
        for pattern, start, end in self.line_rules:
            if _file_matches(path, pattern) and start <= line <= end:
                return True
        return False


def filter_source_files(
    source_files: dict[str, str],
    rules: IgnoreRules,
) -> tuple[dict[str, str], list[str]]:
    """Dosya kalıbına uyanları Groq çağrısından çıkarır."""
    if not rules.enabled:
        return source_files, []

    kept: dict[str, str] = {}
    skipped: list[str] = []
    for file_path, content in source_files.items():
        relative = rules.relative_path(file_path)
        if rules.should_skip_file(relative):
            skipped.append(relative)
            continue
        kept[file_path] = content
    return kept, skipped


def filter_findings(
    findings: list[dict],
    rules: IgnoreRules,
    contents_by_relative: dict[str, str],
) -> list[dict]:
    """Satır kuralı veya `# devsecops:ignore` ile eşleşen bulguları eler."""
    kept: list[dict] = []
    for finding in findings:
        file_name = str(finding.get("file_name") or finding.get("dosya_adi") or "")
        line = parse_line_number(
            finding.get("line_number") or finding.get("satir_numarasi") or 1
        )
        source = contents_by_relative.get(file_name, "")
        source_line = _nth_line(source, line)
        if rules.should_skip_finding(file_name, line, source_line):
            continue
        kept.append(finding)
    return kept


def _split_line_rule(line: str) -> tuple[str, int | None, int | None]:
    if ":" not in line:
        return line, None, None
    path_part, rest = line.rsplit(":", 1)
    rest = rest.strip()
    if rest.isdigit():
        number = int(rest)
        return path_part, number, number
    if "-" in rest:
        start_text, end_text = rest.split("-", 1)
        if start_text.strip().isdigit() and end_text.strip().isdigit():
            start = int(start_text)
            end = int(end_text)
            if start > end:
                start, end = end, start
            return path_part, start, end
    return line, None, None


def _file_matches(relative_path: str, pattern: str) -> bool:
    path = _normalize_path(relative_path)
    is_directory = pattern.endswith("/")
    pat = _normalize_path(pattern)
    if is_directory:
        pat = pat.rstrip("/")
        return path == pat or path.startswith(pat + "/")

    if fnmatch.fnmatch(path, pat):
        return True
    name = Path(path).name
    if fnmatch.fnmatch(name, pat):
        return True
    if "/" not in pat and path.endswith("/" + pat):
        return True
    return False
