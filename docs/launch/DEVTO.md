# Dev.to

Yazıyı Dev.to editörüne yapıştırın. En üstteki `published: false` satırını `true` yapmadan önce önizlemeyi okuyun. Kapak görseli olarak `docs/images/social-preview.png` yükleyin. `cover_image` boş kalsın; Dev.to kapağı yüklenen dosyadan alır.

````markdown
---
title: A CI job that fails when the scanner goes blind
published: false
tags: devsecops, python, security, cicd
---

Most “we added AI security” demos stop at a prompt that returns a list of bugs. The list can be empty because the code is fine, or because the request never landed. Those two outcomes look the same if the pipeline is green either way.

DevSecOps Analyzer is a small FastAPI app that scans a public GitHub repository for critical and high OWASP issues, then uses GitHub Actions to separate those two outcomes.

## What actually runs

You paste a public repository URL. The app downloads the default branch as a zipball. There is no GitHub token, so private repositories are out of scope.

A walker keeps `.py`, `.js`, `.ts`, `.java`, `.c`, `.cpp`, `.go`, `.html`, `.php`, and `.cs`. It skips virtualenvs, `node_modules`, `tests`, `docs`, `examples`, minified files, and files larger than 500 KB. Each remaining file is cut into 8,000-character chunks.

Each chunk goes to Groq’s OpenAI-compatible API. The default model is `qwen/qwen3.8-27b`. `GROQ_MODEL` overrides it. Temperature is 0.2, and the response has to be a JSON object. The prompt asks for critical and high issues only, and it tells the model not to ignore a bug just because a comment says the file is a sample.

The dashboard (Turkish UI) renders the finding name, file, line, and a short fix. The same rows are stored in PostgreSQL. The dashboard allows five calls at once. CI allows two, with two seconds between them, because five parallel calls were enough to hit Groq’s per-minute token limit. HTTP 429 waits 16 seconds and retries, up to three attempts.

## Two CI jobs, on purpose

`test_vuln.py` in the repository root builds a SQL string with an f-string. It is not application code. It exists so the scanner has a bug it must see.

If that file is part of the main scan, the default branch is red forever. A red badge then means “the fixture is still there,” which is true and useless. Visitors read it as “the project is broken.”

The workflow splits the question:

| Job | Command | Green when |
| --- | --- | --- |
| Application scan | `python scan.py` | `app/` and `scan.py` have no critical or high finding, and every Groq call succeeded |
| Fixture | `python scan.py --fixture` | The model reports SQL injection in `test_vuln.py` |

The fixture job waits until the application scan finishes. Running both at once is an easy way to spend the token budget and fail on 429. An API error exits 2 in both modes. It is never reported as a clean repository, and it is never reported as a successful detection.

The fixture passes only when the finding text looks like SQL injection (`SQL Injection`, `SQL Enjeksiyonu`, `SQLi`). Any other finding is a miss.

## What this will get wrong

The model will flag safe code and miss real bugs. Line numbers refer to a character slice, then to whatever the model prints. A chunk boundary can cut a function in half.

A scan that returns no findings is not a clearance. The prompt never asked for medium or low issues, and the walker never opened the files it skipped.

This does not replace a rule-based SAST tool. Semgrep and CodeQL are deterministic on the patterns they encode. This one is a model reading a chunk and returning JSON. Use the finding as a pointer, then read the line.

## Run it

```bash
cp .env.example .env
# set GROQ_API_KEY
docker compose up --build
```

The UI is at `http://localhost:8080`. The Postgres password in Compose (`secpass123`) is a local demo credential. Don’t reuse it anywhere else.

Source and the workflow: https://github.com/Emirhanblc/devsecops_analyzer
````
