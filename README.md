# CHRONO-LEAK

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Use: Educational](https://img.shields.io/badge/use-research%20%26%20education-red.svg)](#responsible-use)
[![OSINT](https://img.shields.io/badge/OSINT-self--audit-00e5ff.svg)](#)

> A personal OSINT self-audit tool. Point it at a username and it shows you
> exactly what an attacker can learn about you from **public data alone** —
> confirmed accounts, recovered identity, behavioral timezone, breach
> exposure, and an overall exposure score, capped off with an AI-written
> forensic brief.

CHRONO-LEAK is built for **defensive self-assessment**: see your own
digital footprint the way a stranger would, then close the gaps it finds.

---

## How it works

Give it a GitHub username and the launcher runs a five-stage pipeline,
saving an HTML dashboard for each stage to `reports/`:

| # | Stage | What it does |
|---|-------|--------------|
| 1 | **GitHub scraper** | Collects public activity timestamps (repos, commits, events) — metadata only, never file contents |
| 2 | **Temporal analyzer** | Finds the daily "dead zone" (sleep window) and infers timezone + behavioral routine from activity timing |
| 3 | **Identity scanner** | Self-validating username search across 30+ platforms, then extracts real name / bio / location from confirmed accounts and correlates them |
| 4 | **Exposure scorer** | Fuses everything into a single exposure score out of 100 across five categories |
| 5 | **AI analyst (Grok)** | Writes a human-readable forensic threat brief (falls back to an offline template if no API key) |

### The identity scanner is self-validating

Naive username checkers trust "HTTP 200 = account exists", which produces
piles of false positives (login walls, SPA shells, soft-404 pages). Before
trusting any platform, CHRONO-LEAK probes it with random garbage usernames;
if the platform claims the garbage account "exists", that platform is
marked **unreliable** and its result is thrown away. What's left is only
genuinely confirmed accounts.

### Exposure score

Five categories, 20 points each, fused into a `/100` score:

`Identity · Temporal · Network · Location · Security`

| Score | Risk level |
|-------|------------|
| 0–20  | LOW |
| 21–40 | MODERATE |
| 41–60 | HIGH |
| 61–80 | CRITICAL |
| 81–100| SEVERE |

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
the first five characters of the SHA-1 hash ever leave your machine, so the
password itself is never transmitted.

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

## Responsible use

CHRONO-LEAK is for **research and education**, and for auditing your own
footprint. Only point it at:

- **yourself**, or
- an account you **own** or have **explicit written permission** to assess.

It reads only data that is already public and stores results locally. It is
**not** a tool for stalking, harassment, or profiling other people without
consent — doing so may be illegal in your jurisdiction. You are responsible
for how you use it.

## License

[MIT](LICENSE)
