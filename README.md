# CHRONO-LEAK

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Use: Educational](https://img.shields.io/badge/use-research%20%26%20education-red.svg)](#responsible-use)
[![OSINT](https://img.shields.io/badge/OSINT-self--audit-00e5ff.svg)](#)

> A personal OSINT self-audit tool that surfaces signals an observer may be able to derive from **public data alone** — account presence, public identity clues, approximate temporal patterns, breach exposure, and a project-specific exposure score, with an optional AI-generated analysis brief.

CHRONO-LEAK is built for **defensive self-assessment**: see your own
digital footprint the way a stranger would, then close the gaps it finds.

---

## How it works

Give it a GitHub username and the launcher runs a five-stage pipeline,
saving an HTML dashboard for each stage to `reports/`:

| # | Stage | What it does |
|---|-------|--------------|
| 1 | **GitHub scraper** | Collects public activity timestamps (repos, commits, events) — metadata only, never file contents |
| 2 | **Temporal analyzer** | Finds low-activity windows and estimates timezone + behavioral patterns from activity timing |
| 3 | **Identity scanner** | Validates username results across 30+ platforms, then extracts public profile clues and correlates them as probabilistic evidence |
| 4 | **Exposure scorer** | Fuses everything into a single exposure score out of 100 across five categories |
| 5 | **AI analyst (Grok)** | Writes a human-readable defensive exposure brief (falls back to an offline template if no API key) |

### The identity scanner is self-validating

Naive username checkers trust "HTTP 200 = account exists", which produces
piles of false positives (login walls, SPA shells, soft-404 pages). Before
trusting any platform, CHRONO-LEAK probes it with random garbage usernames;
if the platform claims the garbage account "exists", that platform is
marked **unreliable** and its result is thrown away. Results that pass the validation checks are treated as higher-confidence account signals, but platform behavior can still produce false positives or false negatives.

### Exposure score

Five categories, 20 points each, fused into a `/100` **project-specific exposure heuristic**. It is not a probability of compromise, a standardized risk rating, or a security certification:

`Identity · Temporal · Network · Location · Security`

| Score | Project label |
|-------|---------------|
| 0–20  | LOW |
| 21–40 | MODERATE |
| 41–60 | HIGH |
| 61–80 | CRITICAL |
| 81–100| SEVERE |

These labels are intended for comparing findings within CHRONO-LEAK, not as externally validated risk levels.

---

## Setup

```bash
# 1. Clone
git clone https://github.com/Pyhroff/chrono-leak
cd chrono-leak

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) add your API keys
cp .env.example .env        # then edit .env

# 4. Run
python main.py <username>
```

```bash
# Example — analyze GitHub's mascot account
python main.py octocat
```

Open the generated dashboards in any browser:

```
reports/<username>_report.html            # timezone + behavioral profile
reports/<username>_identity_report.html   # confirmed accounts + identity map
reports/<username>_exposure.html          # exposure score
reports/<username>_brief.txt              # forensic brief
```

### Configuration

All keys are read from your environment first, then from `.env` (see
`.env.example`). Nothing is required to get started:

| Variable | Used by | Effect if unset |
|----------|---------|-----------------|
| `GROK_API_KEY`  | AI analyst | Falls back to an offline template brief |
| `GITHUB_TOKEN`  | GitHub scraper, identity scanner | GitHub API stays capped at 60 req/hour (vs 5000 with a token) |
| `HIBP_API_KEY`  | Breach checker (standalone) | Email breach check is skipped (password check still works) |

Get a Grok key at <https://console.x.ai> (model `grok-2-latest`, served on
xAI's OpenAI-compatible endpoint `https://api.x.ai/v1`). A GitHub token
needs **no scopes** — generate one at <https://github.com/settings/tokens>.

---

## Standalone modules

Two extra modules ship with CHRONO-LEAK but run on their own rather than as
part of the main pipeline:

```bash
python modules/breach_checker.py      # check an email/password against HaveIBeenPwned
python modules/instagram_scraper.py   # pull timing/location metadata from a public IG profile
```

The breach checker uses HIBP's **k-anonymity** model for passwords — only
the first five characters of the SHA-1 hash leave your machine, so the
password itself and full hash are not transmitted. Email hash-range searches
similarly use the first six SHA-1 characters when the configured HIBP plan
supports that endpoint.

---

## Project structure

```
chrono-leak/
├── main.py                      # launcher — runs the 5-stage pipeline
├── modules/
│   ├── env_config.py            # shared env/.env key loader
│   ├── github_scraper.py        # stage 1: public timestamp collection
│   ├── analyzer.py              # stage 2: timezone + behavioral inference
│   ├── identity_scanner.py      # stage 3: self-validating account search
│   ├── exposure_scorer.py       # stage 4: /100 exposure score
│   ├── ai_analyst.py            # stage 5: Grok forensic brief
│   ├── breach_checker.py        # standalone: HIBP breach/password check
│   ├── instagram_scraper.py     # standalone: public IG metadata
│   └── run_scan.py              # dev helper for the identity scanner
├── .env.example
├── requirements.txt
└── reports/                     # generated output (gitignored)
```

---

## Limitations & interpretation

CHRONO-LEAK is an OSINT self-audit prototype, not a definitive identity, location, sleep, or threat-attribution system. Results depend on public platform behavior, API availability, rate limits, username collisions, incomplete breach datasets, and the amount and diversity of activity available for analysis.

- A timezone result is an estimate from activity timing; it does not establish where a person lives or is physically located.
- A "dead zone" is a low-activity pattern, not proof that someone was asleep.
- Identity correlation is heuristic evidence. Shared names/usernames can belong to different people, and the same person can use different names.
- "Confirmed" platform results mean they passed this project's validation checks; they are not independently verified ownership.
- Exposure scores are project-specific heuristics and should not be interpreted as probabilities, compliance ratings, or evidence that an account is compromised.
- AI-generated briefs are summaries of supplied signals, not authoritative forensic conclusions.
- Breach databases are incomplete and may omit sensitive, retired, or otherwise unavailable records.

## Privacy & external services

CHRONO-LEAK is designed around a local-first analysis boundary:

- GitHub and platform collection uses public metadata only.
- The AI analyst redacts common API tokens and private-key material before sending analysis context to the configured xAI endpoint. External analysis is opt-in and disabled by default unless `ALLOW_EXTERNAL_ANALYSIS=true` is set.
- Password checks use HIBP's k-anonymous range API: only the first five SHA-1 characters are sent, never the password or full hash. HIBP documents this as its privacy-preserving password-search model. 
- Email breach checks use HIBP's six-character k-anonymous email range API when an API key and eligible HIBP subscription are configured, so the raw email address is not sent to the breach-search endpoint. HIBP documents this as a paid feature whose returned unrelated suffixes must be discarded immediately.
- Unrelated HIBP hash-range results are discarded locally rather than stored.
- Reports are written locally under `reports/`; that directory should remain gitignored.

These safeguards reduce unnecessary disclosure, but they do not make external analysis risk-free. Review the data you are authorized to process before enabling the AI analyst or breach integrations.

## Responsible use

CHRONO-LEAK is for **research, education, and authorized self-assessment**. Only point it at:

- **yourself**, or
- an account you **own** or have **explicit written permission** to assess.

It reads only data that is already public and stores results locally. It is
**not** a tool for stalking, harassment, or profiling other people without
consent — doing so may be illegal in your jurisdiction. You are responsible
for how you use it.

## License

[MIT](LICENSE)
