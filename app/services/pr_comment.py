"""Pull request üzerine tarama özeti yazar veya var olan yorumu günceller."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

from .ignore import parse_line_number

COMMENT_MARKER = "<!-- devsecops-analyzer -->"
API_VERSION = "2022-11-28"


def maybe_comment_on_pull_request(
    findings: list[dict],
    scanned_file_count: int,
) -> None:
    """
    Yalnızca GitHub Actions pull_request işinde ve GITHUB_TOKEN varken yazar.
    Aksi halde sessizce çıkar. API hatası taramayı düşürmez.
    """
    if os.getenv("GITHUB_EVENT_NAME") != "pull_request":
        return

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print(
            "Uyarı: --comment-pr için GITHUB_TOKEN yok; PR yorumu atlandı.",
            flush=True,
        )
        return

    repository = os.getenv("GITHUB_REPOSITORY")
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if not repository or not event_path:
        print("Uyarı: GitHub PR bağlamı eksik; yorum atlandı.", flush=True)
        return

    pull_number = _pull_request_number(Path(event_path))
    if pull_number is None:
        print("Uyarı: Pull request numarası okunamadı; yorum atlandı.", flush=True)
        return

    api_root = os.getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    comments_url = f"{api_root}/repos/{repository}/issues/{pull_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    }
    body = build_comment_body(findings, scanned_file_count)

    try:
        existing_id = _find_existing_comment_id(comments_url, headers)
        if existing_id is None:
            response = requests.post(
                comments_url,
                headers=headers,
                json={"body": body},
                timeout=30,
            )
        else:
            response = requests.patch(
                f"{api_root}/repos/{repository}/issues/comments/{existing_id}",
                headers=headers,
                json={"body": body},
                timeout=30,
            )
        if response.status_code >= 400:
            print(
                f"Uyarı: PR yorumu yazılamadı (HTTP {response.status_code}).",
                flush=True,
            )
            return
    except requests.RequestException as error:
        print(f"Uyarı: PR yorumu yazılamadı: {error}", flush=True)
        return

    action = "güncellendi" if existing_id else "eklendi"
    print(f"PR yorumu {action}.", flush=True)


def build_comment_body(findings: list[dict], scanned_file_count: int) -> str:
    lines = [
        COMMENT_MARKER,
        "## DevSecOps Analizörü",
        "",
        f"{scanned_file_count} dosya tarandı. "
        f"**{len(findings)}** kritik/yüksek bulgu.",
        "",
    ]
    if not findings:
        lines.append("Kritik veya yüksek seviyeli zafiyet bulunamadı.")
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(findings, start=1):
        name = finding.get("name") or finding.get("zafiyet_adi") or "Bilinmeyen"
        file_name = (
            finding.get("file_name") or finding.get("dosya_adi") or "Bilinmeyen"
        )
        line = parse_line_number(
            finding.get("line_number") or finding.get("satir_numarasi") or 1
        )
        suggestion = (
            finding.get("recommendation")
            or finding.get("cozum_onerisi")
            or "Manuel inceleme yapın."
        )
        lines.append(
            f"{index}. `{file_name}` {line}. satırda **{name}** tespit edildi. "
            f"{suggestion}"
        )
    return "\n".join(lines) + "\n"


def _pull_request_number(event_path: Path) -> int | None:
    try:
        payload = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"Uyarı: GitHub olay dosyası okunamadı: {error}", file=sys.stderr, flush=True)
        return None
    pull_request = payload.get("pull_request") or {}
    number = pull_request.get("number") or payload.get("number")
    try:
        return int(number)
    except (TypeError, ValueError):
        return None


def _find_existing_comment_id(comments_url: str, headers: dict) -> int | None:
    response = requests.get(
        comments_url,
        headers=headers,
        params={"per_page": 100},
        timeout=30,
    )
    response.raise_for_status()
    for comment in response.json():
        body = comment.get("body") or ""
        if COMMENT_MARKER in body:
            try:
                return int(comment["id"])
            except (KeyError, TypeError, ValueError):
                return None
    return None
