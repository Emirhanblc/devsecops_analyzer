# Hacker News

Show HN başlığı ve gövde. Başlığa ünlem, “launch”, veya “AI-powered” eklemeyin. Gövde tek paragraftır; yoruma “I built this” diye ayrıca yazmayın, başlık onu söylüyor.

## Başlık

```
Show HN: DevSecOps Analyzer – scan a public repo for critical OWASP issues
```

## Gövde

```
DevSecOps Analyzer downloads a public GitHub repo’s default branch, splits source files into 8,000-character chunks, and asks Groq for critical and high OWASP findings as JSON (file, line, and a short fix), which a FastAPI dashboard stores in Postgres. GitHub Actions then runs two jobs in sequence: python scan.py fails the build if app/ or scan.py has a finding or if the API call fails, and python scan.py --fixture passes only when the model reports the intentional SQL injection in test_vuln.py. It does not replace Semgrep or CodeQL, does not scan private repos, and a quiet result is not evidence that the code is safe. https://github.com/Emirhanblc/devsecops_analyzer
```
