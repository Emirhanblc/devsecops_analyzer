# LLM Tabanlı DevSecOps Analizörü

![Güvenlik Taraması Durumu](https://github.com/Emirhanblc/devsecops_analyzer/actions/workflows/security-scan.yml/badge.svg)

Bu proje, kaynak kodu **Groq API** üzerindeki **LLaMA 3** ailesi modelleriyle tarayarak OWASP Top 10 kapsamındaki kritik ve yüksek seviye zafiyetleri otomatik olarak tespit eder. GitHub Actions iş akışı (`security-scan.yml`) her `push` ve `pull_request` olayında `scan.py` scriptini çalıştırır; model SQL Injection, XSS ve benzeri yüksek riskli açıkları raporlar. En az bir kritik veya yüksek bulgu varsa pipeline başarısız olur ve birleştirme durdurulur.

Kök dizindeki `test_vuln.py` dosyası üretim kodu değildir. CI/CD taramasının SQL Injection gibi bilinen bir OWASP açığını gerçekten yakaladığını doğrulamak için kasıtlı olarak zafiyetli bırakılmıştır.
