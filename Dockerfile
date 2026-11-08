# Groq OpenAI uyumlu istemcisinin desteklediği güncel Python sürümünü kullanıyoruz.
FROM python:3.11-slim

# Python loglarını anında gösterir ve gereksiz .pyc dosyalarını engeller.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Konteyner içindeki çalışma dizinini ayarlıyoruz
WORKDIR /app

# Gereksinim dosyasını konteynere kopyalıyoruz
COPY requirements.txt .

# Önce yalnızca bağımlılık katmanını oluşturarak Docker önbelleğini verimli kullanıyoruz.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# openai 1.12.0, httpx 0.28 ile kırılır: AsyncClient 'proxies' parametresini kaldırdı.
RUN pip install --no-cache-dir "httpx==0.27.2"

# Uygulama kodlarını kopyalıyoruz
COPY ./app ./app

# FastAPI servisinin dinlediği portu belgeliyoruz.
EXPOSE 8000

# FastAPI'yi başlatmak için uvicorn komutunu çalıştırıyoruz
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]