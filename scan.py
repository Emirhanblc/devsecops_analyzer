"""
CI/CD güvenlik taraması.

GitHub Actions içindeki `python scan.py` adımı (veya yerel çalıştırma)
bu dosyayı başlatır. `app/` ve bu dosyayı Groq ile tarar; kritik veya
yüksek seviyeli zafiyet bulunursa süreç 1 koduyla çıkar ve pipeline
kırmızıya düşer.

`python scan.py --fixture` yalnızca kasıtlı olarak zafiyetli
`test_vuln.py` dosyasını tarar. SQL Injection bildirirse süreç 0 ile
çıkar. Bildirmezse 1, Groq çağrısı düşerse 2 ile çıkar.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import NoReturn, Optional

import typer
from dotenv import load_dotenv


# Yerelde .env, GitHub Actions'ta ise workflow env bloğu kullanılır.
load_dotenv()

# Bu script proje kökündedir; tarama bu dizine göre yapılır.
PROJECT_ROOT = Path(__file__).resolve().parent

# Groq'a aynı anda gidecek istek sayısı ve istekler arası bekleme.
# Groq on-demand katmanı dakikada yaklaşık 7000 girdi tokeni veriyor.
# Beş paralel istek bu limiti aşıp 429 üretiyor; iki istek sınırın altında kalır.
MAX_CONCURRENT = 2
REQUEST_DELAY_SECONDS = 2
VALID_LEVELS = ("critical", "high")


def fail(message: str, code: int = 2) -> NoReturn:
    """Yapılandırma hatasında pipeline'ı net bir mesajla durdurur."""
    print(f"Hata: {message}", file=sys.stderr, flush=True)
    raise SystemExit(code)


def github_line(value: object) -> str:
    """GitHub Actions açıklaması için satır numarasının ilk rakamlarını alır."""
    from app.services.ignore import parse_line_number

    return str(parse_line_number(value))


def relative_name(file_path: str, root: Path = PROJECT_ROOT) -> str:
    """Mutlak yolu raporlarda görünen göreli yola çevirir."""
    resolved = Path(file_path).resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix().replace("\\", "/")


def collect_source_files(mode: str, scan_path: Path | None) -> dict[str, str]:
    """
    Taranacak kaynak dosyalarını toplar.

    Varsayılan modda temp_repos, test_vuln.py ve diğer kök scriptler
    alınmaz. Yalnızca uygulama kodu (app/) ve scan.py taranır.
    Fixture modu tek dosyaya bakar: test_vuln.py.
    `--path` verilirse yalnızca o dizin taranır.
    """
    if mode == "fixture":
        fixture = PROJECT_ROOT / "test_vuln.py"
        if not fixture.is_file():
            fail("test_vuln.py bulunamadı.")
        return {str(fixture): fixture.read_text(encoding="utf-8")}

    from app.services.parser import get_code_files_from_repo

    if scan_path is not None:
        target = scan_path.expanduser().resolve()
        if not target.is_dir():
            fail(f"Tarama yolu bir dizin değil veya bulunamadı: {scan_path}")
        source_files = get_code_files_from_repo(str(target))
        return source_files

    source_files = get_code_files_from_repo(str(PROJECT_ROOT / "app"))
    scan_py = PROJECT_ROOT / "scan.py"
    try:
        source_files[str(scan_py)] = scan_py.read_text(encoding="utf-8")
    except OSError as error:
        print(f"Uyarı: {scan_py} okunamadı: {error}", flush=True)

    return source_files


def is_sql_injection(finding: dict) -> bool:
    """Fixture işi yalnızca SQL Injection etiketli bir bulguyu başarı sayar."""
    parts = [
        finding.get("name"),
        finding.get("zafiyet_adi"),
        finding.get("recommendation"),
        finding.get("cozum_onerisi"),
    ]
    text = " ".join(str(part) for part in parts if part).lower()
    if "sqli" in text:
        return True
    has_sql = "sql" in text
    has_injection = "inject" in text or "enjeksiyon" in text
    return has_sql and has_injection


def filter_by_level(findings: list[dict], level: str) -> list[dict]:
    """`--level critical` yalnızca kritik bulguları bırakır."""
    if level == "high":
        return findings
    kept: list[dict] = []
    for finding in findings:
        severity = str(
            finding.get("severity") or finding.get("seviye") or "high"
        ).strip().lower()
        if severity == "critical":
            kept.append(finding)
    return kept


def contents_by_relative(source_files: dict[str, str], root: Path) -> dict[str, str]:
    return {
        relative_name(file_path, root): content
        for file_path, content in source_files.items()
    }


async def run_scan(
    mode: str,
    scan_path: Path | None,
    apply_ignore: bool,
) -> tuple[list[dict], list[str], dict[str, str], int]:
    """Kaynak dosyaları parçalayıp Groq analizörüne gönderir."""
    from app.services.analyzer import analyze_code_chunk_async
    from app.services.ignore import IgnoreRules, filter_findings, filter_source_files
    from app.services.parser import chunk_code

    source_files = collect_source_files(mode, scan_path)
    if apply_ignore:
        rules = IgnoreRules.load([PROJECT_ROOT])
        source_files, skipped = filter_source_files(source_files, rules)
        if skipped:
            print(
                f"Ignore: {len(skipped)} dosya atlandı (.devsecopsignore)",
                flush=True,
            )
    else:
        rules = IgnoreRules.none(PROJECT_ROOT)

    if not source_files:
        fail("Taranacak kaynak kod dosyası bulunamadı.")

    label = "fixture (test_vuln.py)" if mode == "fixture" else "uygulama kodu"
    if scan_path is not None and mode != "fixture":
        label = relative_name(str(scan_path.resolve()))
    print(f"Tarama modu: {label}", flush=True)
    print(f"Taranacak dosya sayısı: {len(source_files)}", flush=True)

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    relative_root = rules.root if rules.enabled else PROJECT_ROOT
    relative_contents = contents_by_relative(source_files, relative_root)

    async def analyze_with_semaphore(chunk: str, file_name: str) -> list:
        async with semaphore:
            await asyncio.sleep(REQUEST_DELAY_SECONDS)
            return await analyze_code_chunk_async(chunk, file_name)

    tasks = []
    for file_path, file_content in source_files.items():
        file_name = relative_name(file_path, relative_root)
        print(f"  - {file_name}", flush=True)
        for code_part in chunk_code(file_content):
            tasks.append(analyze_with_semaphore(code_part, file_name))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[dict] = []
    errors: list[str] = []
    for item in results:
        if isinstance(item, BaseException):
            errors.append(str(item))
        else:
            findings.extend(item)

    findings = filter_findings(findings, rules, relative_contents)
    return findings, errors, relative_contents, len(source_files)


def print_report(findings: list[dict], *, annotate_errors: bool) -> None:
    """Bulguları konsola ve istenirse GitHub PR arayüzüne yazar."""
    in_github_actions = os.getenv("GITHUB_ACTIONS") == "true"

    print("\n========== GÜVENLİK TARAMA RAPORU ==========", flush=True)
    if not findings:
        print("Kritik veya yüksek seviyeli zafiyet bulunamadı.", flush=True)
        return

    print(f"Bulunan zafiyet sayısı: {len(findings)}\n", flush=True)

    for index, finding in enumerate(findings, start=1):
        file_name = finding.get("file_name") or finding.get("dosya_adi") or "Bilinmeyen"
        line_number = (
            finding.get("line_number") or finding.get("satir_numarasi") or "Bilinmeyen"
        )
        name = finding.get("name") or finding.get("zafiyet_adi") or "Bilinmeyen"
        suggestion = (
            finding.get("recommendation")
            or finding.get("cozum_onerisi")
            or "Manuel inceleme yapın."
        )
        severity = finding.get("severity") or finding.get("seviye") or "high"

        print(f"{index}. {name} [{severity}]", flush=True)
        print(f"   Dosya : {file_name}", flush=True)
        print(f"   Satır : {line_number}", flush=True)
        print(f"   Çözüm : {suggestion}\n", flush=True)

        # PR'de ilgili dosya/satır üzerinde kırmızı açıklama gösterir.
        # Fixture işinde bulgu beklenen sonuçtur; orada ::error basılmaz.
        if in_github_actions and annotate_errors:
            print(
                f"::error file={file_name},line={github_line(line_number)}::{name} — {suggestion}",
                flush=True,
            )


def export_json(path: Path, findings: list[dict], scanned_file_count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "taranan_dosya_sayisi": scanned_file_count,
        "bulgular": findings,
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"JSON yazıldı: {path}", flush=True)


def finish(mode: str, findings: list[dict], errors: list[str]) -> None:
    """Moda göre çıkış kodunu seçer. API hatası hiçbir modda başarı sayılmaz."""
    if errors:
        print(
            f"Pipeline başarısız: {len(errors)} analiz çağrısı tamamlanamadı.",
            flush=True,
        )
        for message in errors:
            print(f"  - {message}", flush=True)
            if os.getenv("GITHUB_ACTIONS") == "true":
                print(f"::error::{message}", flush=True)
        raise SystemExit(2)

    if mode == "fixture":
        if any(is_sql_injection(finding) for finding in findings):
            print("Fixture doğrulandı: SQL Injection tespit edildi.", flush=True)
            if os.getenv("GITHUB_ACTIONS") == "true":
                print(
                    "::notice file=test_vuln.py::SQL Injection tespit edildi.",
                    flush=True,
                )
            return

        print(
            "Fixture başarısız: SQL Injection tespit edilemedi.",
            flush=True,
        )
        if os.getenv("GITHUB_ACTIONS") == "true":
            print(
                "::error file=test_vuln.py::SQL Injection tespit edilemedi.",
                flush=True,
            )
        raise SystemExit(1)

    if findings:
        print(
            f"Pipeline başarısız: {len(findings)} kritik/yüksek zafiyet bulundu.",
            flush=True,
        )
        raise SystemExit(1)

    print("Pipeline başarılı: güvenlik taraması temiz.", flush=True)


def main(
    path: Optional[Path] = typer.Option(
        None,
        "--path",
        help="Taranacak dizin. Varsayılan: app/ ve scan.py.",
    ),
    level: str = typer.Option(
        "high",
        "--level",
        help="critical veya high. high, her iki seviyeyi de içerir.",
    ),
    export_json_path: Optional[Path] = typer.Option(
        None,
        "--export-json",
        help="Bulguları JSON dosyasına yaz.",
    ),
    export_sarif_path: Optional[Path] = typer.Option(
        None,
        "--export-sarif",
        help="Bulguları SARIF 2.1.0 dosyasına yaz.",
    ),
    fixture: bool = typer.Option(
        False,
        "--fixture",
        help="Yalnızca test_vuln.py dosyasını tara.",
    ),
    comment_pr: bool = typer.Option(
        False,
        "--comment-pr",
        help="Pull request varsa GitHub yorumu yaz veya güncelle.",
    ),
) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    if fixture and path is not None:
        fail("--path ve --fixture birlikte kullanılamaz.")

    if path is not None and not path.expanduser().is_dir():
        fail(f"Tarama yolu bir dizin değil veya bulunamadı: {path}")

    normalized_level = level.strip().lower()
    if normalized_level not in VALID_LEVELS:
        fail(f"--level {level!r} geçersiz. Kullanım: critical veya high.")

    if not os.getenv("GROQ_API_KEY"):
        fail(
            "GROQ_API_KEY ortam değişkeni yok. "
            "Yerelde .env dosyasını, GitHub'da ise repository secret'ını kontrol edin."
        )

    mode = "fixture" if fixture else "app"
    findings, errors, _contents, scanned_file_count = asyncio.run(
        run_scan(mode, path, apply_ignore=(mode != "fixture"))
    )
    if mode != "fixture":
        findings = filter_by_level(findings, normalized_level)

    if export_json_path is not None:
        export_json(export_json_path, findings, scanned_file_count)
    if export_sarif_path is not None:
        from app.services.sarif import write_sarif

        write_sarif(export_sarif_path, findings)
        print(f"SARIF yazıldı: {export_sarif_path}", flush=True)
    if comment_pr and mode != "fixture":
        from app.services.pr_comment import maybe_comment_on_pull_request

        maybe_comment_on_pull_request(findings, scanned_file_count)

    print_report(findings, annotate_errors=(mode != "fixture"))
    finish(mode, findings, errors)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    typer.run(main)
