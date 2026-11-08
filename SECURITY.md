# Güvenlik

`test_vuln.py` kasıtlı olarak zafiyetlidir. Üretim kodu değildir. İçindeki SQL Injection, tarayıcının bilinen bir açığı gördüğünü doğrulamak için durur. Bu dosyada bulgu çıkması beklenen davranıştır.

## Reporting a vulnerability

If you believe the application itself has a security issue, report it privately. Anything in `test_vuln.py` is out of scope.

Use **Security → Report a vulnerability** on this GitHub repository.

Do not open a public issue for an unpublished vulnerability. Do not paste API keys, the database password, or a working exploit.

The scanner’s findings are model output. They are not a promise that a repository is safe, and they are not a substitute for review.

The same model output is written as SARIF and shown under **Security → Code scanning**. Treat those alerts as hints, not as a CodeQL-class proof.

`.devsecopsignore` and `# devsecops:ignore` tell this tool not to report a file or line. They do not fix the issue and they do not transfer responsibility. Do not use them to hide an open vulnerability in production code.
