import json
import os

from dotenv import load_dotenv
from openai import AsyncOpenAI


# Proje kökündeki .env dosyasını yükler. Böylece GROQ_API_KEY hem yerel
# çalıştırmada hem de Docker ortamında okunabilir.
load_dotenv()

# Groq hesabına ait API anahtarını ortam değişkeninden alıyoruz.
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Anahtar yoksa uygulamayı çökertmiyoruz; yalnızca konsola uyarı yazıyoruz.
# Analiz isteği geldiğinde try-except bloğu boş liste döndürecektir.
if not GROQ_API_KEY:
    print("Uyarı: GROQ_API_KEY bulunamadı. Lütfen .env dosyasını kontrol edin.")

# Groq, OpenAI uyumlu bir uç nokta sunduğu için AsyncOpenAI istemcisini
# Groq'un kendi adresiyle yapılandırıyoruz.
client = AsyncOpenAI(
    api_key=GROQ_API_KEY,
    base_url="https://api.groq.com/openai/v1",
)

# Groq, eski llama3-8b-8192 modelini kaldırdı. Aynı sınıftaki güncel ve hızlı
# üretim modeli llama-3.1-8b-instant'tır.
MODEL_NAME = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

# Modele "yalnızca JSON dön" kuralını sistem mesajında net biçimde veriyoruz.
SYSTEM_PROMPT = """
Sen kıdemli bir DevSecOps ve uygulama güvenliği uzmanısın.
Verilen kaynak kodu OWASP Top 10 kapsamında incele ve yalnızca kritik veya
yüksek seviyeli güvenlik açıklarını bildir.

KESİNLİKLE yalnızca aşağıdaki JSON formatında yanıt ver. JSON dışında
açıklama, markdown veya ek metin yazma:

{"bulgular": [{"zafiyet_adi": "...", "dosya_adi": "...", "satir_numarasi": "...", "cozum_onerisi": "..."}]}

Eğer zafiyet yoksa tam olarak şunu döndür:
{"bulgular": []}
""".strip()


async def analyze_code_chunk_async(code_chunk: str, file_name: str) -> list:
    """
    Tek bir kod parçasını Groq (LLaMA 3.1) API'sine gönderir.

    Başarılı olursa modelin ürettiği "bulgular" listesini döndürür.
    JSON ayrıştırma veya ağ hatasında uygulamanın çökmemesi için boş liste döner.
    """
    # Boş parçaları API'ye göndermeye gerek yok; doğrudan zafiyet yok kabul ederiz.
    if not code_chunk or not code_chunk.strip():
        return []

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

        # Model yanıtının metin içeriğini alıyoruz.
        raw_content = response.choices[0].message.content
        if not raw_content:
            print(f"Uyarı: Groq boş yanıt döndürdü ({file_name}).")
            return []

        # Gelen metni Python sözlüğüne çeviriyoruz.
        parsed_response = json.loads(raw_content)
        findings = parsed_response.get("bulgular", [])

        # Beklenmeyen bir tip gelirse çökmek yerine boş liste döneriz.
        if not isinstance(findings, list):
            print(f"Uyarı: Groq yanıtındaki 'bulgular' alanı liste değil ({file_name}).")
            return []

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

    except json.JSONDecodeError as error:
        # Model bazen bozuk JSON üretebilir; analizi durdurmak yerine atlarız.
        print(f"Uyarı: Groq yanıtı geçerli JSON değil ({file_name}): {error}")
        return []
    except Exception as error:
        # API, ağ veya zaman aşımı hatalarında uygulamayı ayakta tutuyoruz.
        print(f"Uyarı: Groq API/ağ hatası ({file_name}): {error}")
        return []
