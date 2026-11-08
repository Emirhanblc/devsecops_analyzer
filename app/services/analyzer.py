import asyncio
import json
import os

from dotenv import load_dotenv
from openai import AsyncOpenAI


# Proje kökündeki .env dosyasını yükler. Böylece GROQ_API_KEY hem yerel
# çalıştırmada hem de Docker ortamında okunabilir.
load_dotenv()

# Groq hesabına ait API anahtarını ortam değişkeninden alıyoruz.
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Anahtar yoksa burada çökertmiyoruz. Asıl çağrı AnalysisError yükseltir;
# böylece başarısız bir istek temiz tarama gibi görünmez.
if not GROQ_API_KEY:
    print("Uyarı: GROQ_API_KEY bulunamadı. Lütfen .env dosyasını kontrol edin.")

# Groq, OpenAI uyumlu bir uç nokta sunduğu için AsyncOpenAI istemcisini
# Groq'un kendi adresiyle yapılandırıyoruz.
client = AsyncOpenAI(
    api_key=GROQ_API_KEY,
    base_url="https://api.groq.com/openai/v1",
)

# llama-3.1-8b-instant bu Groq hesabında 404 döndürüyor. JSON modunda
# çalışan ve SQL Injection örneğini yakalayan model varsayılandır.
# İstenirse GROQ_MODEL ortam değişkeniyle değiştirilebilir.
DEFAULT_MODEL = "qwen/qwen3.8-27b"
MODEL_NAME = os.getenv("GROQ_MODEL", DEFAULT_MODEL)


class AnalysisError(RuntimeError):
    """Groq çağrısı bulgu üretemedi. Bu, temiz tarama anlamına gelmez."""


# Modele "yalnızca JSON dön" kuralını sistem mesajında net biçimde veriyoruz.
SYSTEM_PROMPT = """
Sen kıdemli bir DevSecOps ve uygulama güvenliği uzmanısın.
Verilen kaynak kodu OWASP Top 10 kapsamında incele ve yalnızca kritik veya
yüksek seviyeli güvenlik açıklarını bildir.
Dosyanın test, örnek veya kasıtlı olarak zafiyetli olduğu yazılmış olsa bile
kodda bulunan açığı bildir. Yorum satırı zafiyeti ortadan kaldırmaz.

KESİNLİKLE yalnızca aşağıdaki JSON formatında yanıt ver. JSON dışında
açıklama, markdown veya ek metin yazma:

{"bulgular": [{"zafiyet_adi": "...", "dosya_adi": "...", "satir_numarasi": "...", "cozum_onerisi": "..."}]}

Eğer zafiyet yoksa tam olarak şunu döndür:
{"bulgular": []}
""".strip()


async def _request_findings(code_chunk: str, file_name: str) -> list:
    """Tek bir Groq çağrısı yapar. Hata olursa AnalysisError yükseltir."""
    user_prompt = f"""
Dosya adı: {file_name}

Bu kodu güvenlik açıkları açısından incele:

--- KOD BAŞLANGICI ---
{code_chunk}
--- KOD SONU ---
""".strip()

    try:
        # Groq'un OpenAI uyumlu sohbet uç noktasını asenkron olarak çağırıyoruz.
        response = await client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            # Yanıtın geçerli bir JSON nesnesi olmasını zorunlu kılar.
            response_format={"type": "json_object"},
            # Düşük sıcaklık, daha tutarlı ve teknik güvenlik sonuçları üretir.
            temperature=0.2,
        )
    except Exception as error:
        raise AnalysisError(f"Groq API/ağ hatası ({file_name}): {error}") from error

    # Model yanıtının metin içeriğini alıyoruz.
    raw_content = response.choices[0].message.content
    if not raw_content:
        raise AnalysisError(f"Groq boş yanıt döndürdü ({file_name}).")

    try:
        parsed_response = json.loads(raw_content)
    except json.JSONDecodeError as error:
        raise AnalysisError(
            f"Groq yanıtı geçerli JSON değil ({file_name}): {error}"
        ) from error

    findings = parsed_response.get("bulgular", [])
    if not isinstance(findings, list):
        raise AnalysisError(
            f"Groq yanıtındaki 'bulgular' alanı liste değil ({file_name})."
        )

    return findings


async def analyze_code_chunk_async(code_chunk: str, file_name: str) -> list:
    """
    Tek bir kod parçasını Groq API'sine gönderir.

    Başarılı olursa modelin ürettiği "bulgular" listesini döndürür.
    API veya JSON hatası AnalysisError olarak yükselir; boş liste yalnızca
    gerçekten bulgu olmayan başarılı bir tarama anlamına gelir.
    """
    # Boş parçaları API'ye göndermeye gerek yok; doğrudan zafiyet yok kabul ederiz.
    if not code_chunk or not code_chunk.strip():
        return []

    findings = None
    for attempt in range(3):
        try:
            findings = await _request_findings(code_chunk, file_name)
            break
        except AnalysisError as error:
            if attempt == 2:
                raise
            message = str(error).lower()
            # Dakikalık token limiti dolunca Groq 429 döner. Kısa bir bekleme
            # yetmez; limit penceresi kapanmadan aynı çağrı yine düşer.
            if "429" in message or "rate_limit" in message or "rate limit" in message:
                await asyncio.sleep(16)
            else:
                await asyncio.sleep(1)

    if findings is None:
        raise AnalysisError(f"Groq analizi tamamlanamadı ({file_name}).")

    # Model Türkçe anahtarlar üretir. Dashboard ve mevcut veritabanı
    # kayıt döngüsü İngilizce anahtarları da okuduğu için her iki adı
    # da dolduruyoruz. Böylece db.add() döngüsüne dokunmamız gerekmez.
    normalized_findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        zafiyet_adi = finding.get("zafiyet_adi") or finding.get("name") or "Bilinmeyen"
        dosya_adi = finding.get("dosya_adi") or finding.get("file_name") or file_name
        satir_numarasi = finding.get("satir_numarasi") or finding.get("line_number") or "Bilinmeyen"
        cozum_onerisi = (
            finding.get("cozum_onerisi")
            or finding.get("recommendation")
            or "Manuel inceleme yapın."
        )

        normalized_findings.append(
            {
                "zafiyet_adi": zafiyet_adi,
                "dosya_adi": dosya_adi,
                "satir_numarasi": satir_numarasi,
                "cozum_onerisi": cozum_onerisi,
                "name": zafiyet_adi,
                "file_name": dosya_adi,
                "line_number": satir_numarasi,
                "recommendation": cozum_onerisi,
            }
        )

    return normalized_findings
