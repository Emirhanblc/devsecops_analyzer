"""Bulguları GitHub Code Scanning'in okuduğu SARIF 2.1.0 belgesine çevirir."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .ignore import parse_line_number

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "DevSecOps Analyzer"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://github.com/Emirhanblc/devsecops_analyzer"


def rule_id(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "security-finding"


def first_line_number(value: object) -> int:
    return parse_line_number(value)


def _severity(finding: dict) -> str:
    text = str(finding.get("severity") or finding.get("seviye") or "high").strip().lower()
    return "critical" if text == "critical" else "high"


def _security_severity(severity: str) -> str:
    return "9.0" if severity == "critical" else "7.0"


def build_sarif(findings: list[dict]) -> dict:
    """Boş bulgu listesinde bile geçerli bir SARIF belgesi döndürür."""
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []

    for finding in findings:
        name = str(finding.get("name") or finding.get("zafiyet_adi") or "Bilinmeyen")
        file_name = str(
            finding.get("file_name") or finding.get("dosya_adi") or "unknown"
        ).replace("\\", "/")
        suggestion = str(
            finding.get("recommendation")
            or finding.get("cozum_onerisi")
            or "Manuel inceleme yapın."
        )
        line = first_line_number(
            finding.get("line_number") or finding.get("satir_numarasi") or 1
        )
        severity = _severity(finding)
        identifier = rule_id(name)

        if identifier not in rules_by_id:
            rules_by_id[identifier] = {
                "id": identifier,
                "name": identifier,
                "shortDescription": {"text": name},
                "fullDescription": {"text": name},
                "help": {"text": suggestion, "markdown": suggestion},
                "defaultConfiguration": {"level": "error"},
                "properties": {
                    "tags": ["security", "owasp"],
                    "precision": "medium",
                    "security-severity": _security_severity(severity),
                },
            }

        results.append(
            {
                "ruleId": identifier,
                "level": "error",
                "message": {"text": f"{name} — {suggestion}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_name.lstrip("/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": line},
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": f"{file_name}:{line}:{identifier}"
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(path: Path, findings: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = build_sarif(findings)
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
