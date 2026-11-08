# Reddit

Aynı metni aynı gün üç subreddit’e yapıştırmayın. Birini seçin, yorumlara cevap verin, bir gün sonra gerekirse diğerine geçin. r/netsec tanıtım yazılarını daha çabuk siler; orada gövdeyi kısaltıp sınırları üste alın.

Başlığı subreddit’e göre değiştirin. Gövde aynı kalabilir. Satış cümlesi eklemeyin.

## Başlıklar

- r/devsecops: `I built a small LLM scanner that fails CI when it finds a critical OWASP issue`
- r/Python: `FastAPI app that scans a public GitHub repo with Groq and stores the findings`
- r/netsec: `LLM repo scanner with a CI job that must catch an intentional SQL injection`

## Gövde

```
I built DevSecOps Analyzer because I wanted the “did we just merge an obvious injection?” check to run before review, not during it.

It downloads a public GitHub repo’s default branch as a zipball (no token, no private repos), keeps common source extensions, and skips vendor trees, tests, docs, minified files, and anything over 500 KB. Each file is split into 8,000-character chunks. Groq (default model qwen/qwen3.8-27b, override with GROQ_MODEL) has to answer with JSON. The FastAPI dashboard shows the finding name, file, line, and a short fix, and stores the rows in Postgres.

GitHub Actions runs two jobs, the second only after the first, so they don’t share Groq’s per-minute token budget. `python scan.py` scans this repo’s app/ and scan.py. A finding or a failed API call fails the job. An API error is not treated as a clean scan. `python scan.py --fixture` scans only test_vuln.py, which is an intentional SQL injection, and the job passes only when the model reports that injection.

Limits, so this doesn’t sound like more than it is:

- Findings are model output. Line numbers are the model’s, on a sliced chunk.
- It asks only for critical and high issues. Silence is not a proof the repo is safe.
- It is not a stand-in for Semgrep or CodeQL.
- The dashboard allows 5 Groq calls at once; CI allows 2, with a 2-second gap, and retries HTTP 429 three times after a 16-second wait.
- Fork PRs don’t get the GROQ_API_KEY secret, so CI can’t call Groq there.

https://github.com/Emirhanblc/devsecops_analyzer

Happy to hear where the fixture check or the chunking would fall over.
```
