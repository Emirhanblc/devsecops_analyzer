# LLM Tabanlı DevSecOps Analizörü

![Güvenlik Taraması Durumu](https://github.com/Emirhanblc/devsecops_analyzer/actions/workflows/security-scan.yml/badge.svg)

Bu proje, kaynak kodu Groq API üzerindeki bir sohbet modeliyle tarayarak OWASP Top 10 kapsamındaki kritik ve yüksek seviye zafiyetleri otomatik olarak tespit eder. Groq hesabında LLaMA 3 sohbet modelleri kalktığı için varsayılan model `qwen/qwen3.8-27b`dir; `GROQ_MODEL` ortam değişkeniyle değiştirilebilir. GitHub Actions iş akışı (`security-scan.yml`) her `push` ve `pull_request` olayında `scan.py` scriptini çalıştırır. Model SQL Injection gibi yüksek riskli bir açık bildirirse veya Groq çağrısı başarısız olursa pipeline kırmızıya düşer.

Kök dizindeki `test_vuln.py` dosyası üretim kodu değildir. CI/CD taramasının SQL Injection gibi bilinen bir OWASP açığını gerçekten yakaladığını doğrulamak için kasıtlı olarak zafiyetli bırakılmıştır.
