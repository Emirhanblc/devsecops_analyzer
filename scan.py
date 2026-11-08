"""
CI/CD güvenlik taraması.

GitHub Actions içindeki `python scan.py` adımı (veya yerel çalıştırma)
bu dosyayı başlatır. Mevcut depodaki uygulama kodunu Groq ile tarar;
kritik veya yüksek seviyeli zafiyet bulunursa süreç 1 koduyla çıkar
ve pipeline kırmızıya düşer.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

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


def fail(message: str, code: int = 2) -> None:
    """Yapılandırma hatasında pipeline'ı net bir mesajla durdurur."""
    print(f"Hata: {message}", file=sys.stderr, flush=True)
    raise SystemExit(code)


def collect_source_files() -> dict[str, str]:
    """
    Taranacak kaynak dosyalarını toplar.

    temp_repos içindeki üçüncü parti klonlar taranmaz; yalnızca uygulama
    kodu (app/) ve kök dizindeki Python dosyaları (scan.py dahil) alınır.
    """
    from app.services.parser import get_code_files_from_repo

    source_files = get_code_files_from_repo(str(PROJECT_ROOT / "app"))

    for py_file in PROJECT_ROOT.glob("*.py"):
        try:
            source_files[str(py_file)] = py_file.read_text(encoding="utf-8")
        except OSError as error:
            print(f"Uyarı: {py_file} okunamadı: {error}", flush=True)

    return source_files


def relative_name(file_path: str) -> str:
    """Mutlak yolu raporlarda görünen göreli yola çevirir."""
    return Path(file_path).resolve().relative_to(PROJECT_ROOT).as_posix()


def github_line(value: object) -> str:
    """GitHub Actions açıklaması için satır numarasının ilk rakamlarını alır."""
    digits = ""
    for character in str(value):
        if character.isdigit():
            digits += character
        elif digits:
            break
    return digits or "1"


async def run_scan() -> tuple[list[dict], list[str]]:
    """Kaynak dosyaları parçalayıp Groq analizörüne gönderir."""
    from app.services.analyzer import analyze_code_chunk_async
    from app.services.parser import chunk_code

    source_files = collect_source_files()
    if not source_files:
        fail("Taranacak kaynak kod dosyası bulunamadı.")

    print(f"Taranacak dosya sayısı: {len(source_files)}", flush=True)

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    async def analyze_with_semaphore(chunk: str, file_name: str) -> list:
        async with semaphore:
            await asyncio.sleep(REQUEST_DELAY_SECONDS)
            return await analyze_code_chunk_async(chunk, file_name)

    tasks = []
    for file_path, file_content in source_files.items():
        file_name = relative_name(file_path)
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
    return findings, errors


def print_report(findings: list[dict]) -> None:
    """Bulguları konsola ve varsa GitHub PR arayüzüne yazar."""
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

        print(f"{index}. {name}", flush=True)
        print(f"   Dosya : {file_name}", flush=True)
        print(f"   Satır : {line_number}", flush=True)
        print(f"   Çözüm : {suggestion}\n", flush=True)

        # PR'de ilgili dosya/satır üzerinde kırmızı açıklama gösterir.
        if in_github_actions:
            print(
                f"::error file={file_name},line={github_line(line_number)}::{name} — {suggestion}",
                flush=True,
            )


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    if not os.getenv("GROQ_API_KEY"):
        fail(
            "GROQ_API_KEY ortam değişkeni yok. "
            "Yerelde .env dosyasını, GitHub'da ise repository secret'ını kontrol edin."
        )

    findings, errors = asyncio.run(run_scan())
    print_report(findings)

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

    if findings:
        print(
            f"Pipeline başarısız: {len(findings)} kritik/yüksek zafiyet bulundu.",
            flush=True,
        )
        raise SystemExit(1)

    print("Pipeline başarılı: güvenlik taraması temiz.", flush=True)


if __name__ == "__main__":
    main()
