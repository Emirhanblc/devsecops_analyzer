# DevSecOps Analyzer

[![Security scan](https://github.com/Emirhanblc/devsecops_analyzer/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Emirhanblc/devsecops_analyzer/actions/workflows/security-scan.yml)
[![Python 3.11](https://img.shields.io/badge/python-3.11-3776AB)](https://www.python.org/downloads/release/python-3110/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

![DevSecOps Analyzer](docs/images/social-preview.png)

> GitHub deposunu Groq üzerindeki bir sohbet modeliyle tarar. OWASP Top 10 kapsamındaki kritik ve yüksek açıkları dosya, satır ve düzeltme önerisiyle panele yazar. Her push ve pull request’te aynı tarama CI’da çalışır. Uygulama kodunda bulgu varsa pipeline kırmızıya düşer.

An LLM scanner for public GitHub repositories. Paste a repo URL, get critical and high OWASP findings with file, line, and a short fix. The same check runs in GitHub Actions: application code must stay clean, and a separate job must still catch the intentional SQL injection sample.

## Dashboard

![Dashboard: paste a GitHub URL and start an analysis](docs/images/dashboard.png)

## What it does

- Downloads the default branch of a **public** GitHub repository as a zipball. No token, no private repos.
- Reads source files (`.py`, `.js`, `.ts`, `.java`, `.c`, `.cpp`, `.go`, `.html`, `.php`, `.cs`). Skips `node_modules`, virtualenvs, `tests`, `docs`, `examples`, minified files, and anything over 500 KB.
- Splits each file into 8,000-character chunks and asks Groq for JSON findings. Default model is `qwen/qwen3.8-27b`. Override it with `GROQ_MODEL`.
- Keeps only what the model reports as critical or high, with a `severity` field. Shows name, file, line, and a fix in the dashboard.
- Honors a [`.devsecopsignore`](.devsecopsignore) in the scanned repo (CLI and dashboard). Fixture mode does not.
- Stores each finding in PostgreSQL. **Geçmiş Taramaları Gör** reads `GET /api/history`.
- In CI, `python scan.py --export-sarif results.sarif --comment-pr` scans `app/` and `scan.py`. A finding or a failed Groq call fails the job. SARIF is uploaded to the Security tab; pull requests get a summary comment.
- `python scan.py --fixture` scans only [`test_vuln.py`](test_vuln.py). The job passes when the model reports SQL injection, and fails when it does not.

`test_vuln.py` is not production code. The SQL injection in it is deliberate, so the second CI job can prove the scanner still sees a known bug.

## How a scan moves

```mermaid
flowchart LR
  repo[GitHubRepo] --> fetch[download_repo]
  fetch --> ignore[devsecopsignore]
  ignore --> chunk[chunk_code]
  chunk --> groq[Groq_OWASP]
  groq --> ui[Dashboard]
  groq --> db[Postgres]
  scan[scan.py] --> ignore
  scan --> groq
  scan --> sarif[SARIF]
  scan --> pr[PRComment]
  sarif --> ghas[CodeScanning]
  scan --> ci[GitHubActions]
```

The dashboard sends at most five Groq calls at once, with one second between them. CI uses two calls at once and a two-second delay. On HTTP 429 the client waits 16 seconds and retries, up to three attempts. Temperature is 0.2, and the response must be a JSON object.

## Run it

You need Docker, and a Groq API key.

```bash
cp .env.example .env
```

Set `GROQ_API_KEY` in `.env`. Optionally set `GROQ_MODEL`.

```bash
docker compose up --build
```

Open [http://localhost:8080](http://localhost:8080).

Compose starts PostgreSQL 15 and the FastAPI app. These database credentials are for this local demo only. Do not reuse them on a shared machine.

- User: `secuser`
- Password: `secpass123`
- Database: `secdb`
- Host inside Compose: `db`
- Host from your machine: `localhost:5432`

To run the app on the host and keep Postgres in Docker:

```bash
docker compose up -d db
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open [http://localhost:8000](http://localhost:8000). Outside a container, [`app/database.py`](app/database.py) connects to `localhost` unless `DATABASE_URL` or `DB_HOST` is set.

Scan this repo from the project root (`.env` is loaded automatically):

```bash
python scan.py
python scan.py --fixture
python scan.py --path ./app --level critical
python scan.py --export-json results.json --export-sarif results.sarif
```

The image built from the [`Dockerfile`](Dockerfile) is the dashboard only. CI runs `scan.py` on the GitHub runner, not inside that image.

## CLI

`scan.py` is a Typer command. `python scan.py --help` lists flags. `python scan.py` and `python scan.py --fixture` stay the default CI entry points.

| Flag | Effect |
| --- | --- |
| *(none)* | Scan `app/` and `scan.py` |
| `--fixture` | Scan only `test_vuln.py` |
| `--path DIR` | Scan that directory only |
| `--level critical\|high` | Default `high` keeps critical and high. `critical` drops high |
| `--export-json FILE` | Write findings as JSON |
| `--export-sarif FILE` | Write SARIF 2.1.0 (empty `results` if the scan is clean) |
| `--comment-pr` | On a GitHub Actions `pull_request` job, upsert a summary comment |

`--path` and `--fixture` together exit `2`. Ignore rules apply to every mode except `--fixture`.

## Ignore list

Put a [`.devsecopsignore`](.devsecopsignore) at the repo root (gitignore-style paths, plus line ranges). The dashboard uses the ignore file inside the downloaded repository, not this analyzer’s own file.

```
# skip the whole file (not sent to Groq)
test_vuln.py
*.generated.py
vendor/

# drop findings on one line or a range
app/legacy.py:42
app/auth.py:100-120
```

A source line that contains `# devsecops:ignore` is also dropped after the model returns. Skipping a finding is not a fix.

## Tests

Parser skips the `tests/` directory during security scans. From the project root:

```bash
python -m unittest discover -s tests
```

## API

`POST /analyze-repo`

```bash
curl -X POST http://localhost:8080/analyze-repo \
  -H "Content-Type: application/json" \
  -d "{\"github_url\":\"https://github.com/owner/repo\"}"
```

The JSON below shows the response shape. It is not a finding from this repository. There is no `app/db.py` here.

```json
{
  "taranan_dosya_sayisi": 12,
  "bulgular": [
        {
            "name": "SQL Injection",
            "file_name": "app/db.py",
            "line_number": "40",
            "severity": "high",
            "recommendation": "Use a parameterized query."
        }
  ]
}
```

Turkish keys (`zafiyet_adi`, `dosya_adi`, `satir_numarasi`, `seviye`, `cozum_onerisi`) are included on each finding as well.

`GET /api/history` returns saved rows, newest first: `repo_url`, `file_name`, `vulnerability_name`, `line_number`, `suggestion`, `created_at`.

`POST /fetch-repo` only downloads and extracts. It does not scan.

## CI

[`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml) runs on every push and pull request. Both jobs need the `GROQ_API_KEY` repository secret. The second job waits for the first so the two scans do not share Groq’s per-minute token budget. The workflow token needs `security-events: write` (SARIF) and `pull-requests: write` (PR comment).

| Job | Command | Passes when |
| --- | --- | --- |
| Uygulama kodu taraması | `python scan.py --export-sarif results.sarif --comment-pr` | `app/` and `scan.py` have no critical or high finding, and every Groq call succeeds |
| SQL Injection örneği yakalanıyor | `python scan.py --fixture` | The model reports SQL injection in `test_vuln.py` |

Exit codes for both commands: `0` pass, `1` the security expectation failed, `2` configuration or API failure. An API error is never treated as a clean scan.

On a failing application scan, findings are written as GitHub Actions `::error` annotations and as SARIF. `upload-sarif` still runs after exit `1`, so the Security tab and the pull request show the same issues. The fixture job does not upload SARIF and does not comment on the PR.

On a pull request the scanner upserts one comment marked `<!-- devsecops-analyzer -->`. Later pushes update that comment instead of stacking new ones.

## Limits

- Findings are model output, including the Security tab SARIF upload. Read them before you change production code. The scanner is not Semgrep or CodeQL.
- `.devsecopsignore` only hides files or lines from this tool. It does not mean the code is safe.
- Only critical and high issues are requested. A quiet report is not a proof that the repo is safe.
- Line numbers are the model’s, on a character-sliced chunk. Treat them as a hint.
- Public default-branch zipballs only. Private repos and non-default branches are out of scope.
- Large repositories can take minutes and can hit Groq rate limits even with retries.
- Fork pull requests do not receive repository secrets, so the workflow cannot call Groq there.

## Layout

```
app/                  FastAPI app, dashboard, Groq client, GitHub download
app/services/         Parser, Groq client, ignore, SARIF, PR comment
scan.py               Typer CLI / CI entry point
tests/                Unit tests for ignore, SARIF, and PR comment text
test_vuln.py          Intentional SQL injection fixture
.devsecopsignore      Skip list (CLI + dashboard)
.github/workflows/    Application scan, SARIF upload, then fixture detection
```

## License

[MIT](LICENSE) © Emirhanblc
