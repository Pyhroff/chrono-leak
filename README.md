# CHRONO-LEAK

**Defensive OSINT self-audit: measure how much of your public digital footprint can be correlated.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Use](https://img.shields.io/badge/use-research%20%26%20education-red.svg)](#responsible-use) [![OSINT](https://img.shields.io/badge/OSINT-self--audit-00e5ff.svg)](#)

> Give it a username you control. CHRONO-LEAK collects public signals, correlates confirmed accounts, infers behavioral timing, scores exposure, and produces a local forensic brief.

**Design goal:** show you what a stranger could reasonably infer from public data, so you can reduce the exposure.

## Pipeline

```text
Username
   │
   ▼
Public activity ──► Temporal inference ──► Identity correlation
                                             │
                                             ▼
                                  Exposure score /100
                                             │
                                             ▼
                                  Local forensic brief
                                             │
                                             └──► Optional external AI analysis
```

| Stage | Purpose |
|---|---|
| GitHub scraper | Collect public activity timestamps and metadata |
| Temporal analyzer | Estimate recurring activity windows and likely timezone |
| Identity scanner | Confirm username matches before correlating profile data |
| Exposure scorer | Combine identity, temporal, network, location, and security signals |
| AI analyst | Produce a concise defensive brief; offline fallback is available |

### Why the identity scanner validates results

A simple HTTP-200 account check creates false positives because login walls, SPA shells, and soft-404 pages can look like real profiles.

CHRONO-LEAK probes candidate platforms with randomized usernames first. Platforms that cannot distinguish nonexistent accounts are treated as unreliable rather than trusted blindly.

## Exposure score

Five categories contribute up to 20 points each:

**Identity · Temporal · Network · Location · Security**

| Score | Level |
|---:|---|
| 0–20 | LOW |
| 21–40 | MODERATE |
| 41–60 | HIGH |
| 61–80 | CRITICAL |
| 81–100 | SEVERE |

The score is a **heuristic self-audit indicator**, not a probability of compromise.

## Quick start

```bash
git clone https://github.com/Pyhroff/chrono-leak
cd chrono-leak
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python main.py octocat
```

Generated artifacts are written locally under reports/:

```text
reports/<username>_report.html
reports/<username>_identity_report.html
reports/<username>_exposure.html
reports/<username>_brief.txt
```

The main pipeline can run without an external AI key because the analyst has an offline template fallback.

## Optional integrations

| Variable | Purpose | If unset |
|---|---|---|
| GITHUB_TOKEN | Higher GitHub API rate limit | Uses unauthenticated API limits |
| GROK_API_KEY | Optional external AI brief | Offline brief |
| ALLOW_EXTERNAL_ANALYSIS | Explicit opt-in for external AI analysis | External analysis disabled |
| HIBP_API_KEY | Optional breach/paste checks | Those checks are skipped |

External analysis is deliberately **opt-in**. Review the privacy boundary before enabling it.

### Password checks

The standalone password checker uses Have I Been Pwned's k-anonymity range method: the password is hashed locally and only a short hash prefix is sent for the lookup. The full password and full hash are not transmitted.

## Privacy boundary

CHRONO-LEAK is designed to minimize unnecessary disclosure:
- Collection focuses on publicly available metadata.
- Reports are written locally.
- Generated reports should remain outside version control.
- The AI analyst sanitizes analysis context before an external request.
- External AI analysis is disabled unless explicitly enabled.
- Password range checks use a privacy-preserving hash-prefix lookup.
- Review the data you are authorized to process before enabling any external integration.

These controls reduce disclosure; they do not make third-party processing risk-free.

## Responsible use

CHRONO-LEAK is for **research, education, and defensive self-auditing**.

Only analyze yourself, accounts you own, or accounts for which you have explicit authorization.

Do not use it for stalking, harassment, doxxing, or profiling people without consent. Public availability does not remove ethical or legal constraints.

## Scope and limitations

The output is based on public signals and heuristic correlation.
- A confirmed username does not prove two accounts belong to the same person.
- Timezone inference is probabilistic and can be distorted by travel, scheduled jobs, bots, or irregular activity.
- Exposure scores depend on the selected signals and weighting.
- Platform behavior changes can invalidate account-existence checks.
- External AI analysis can introduce model error; the offline fallback is deterministic and easier to audit.

Treat every correlation as a lead to review, not as identity proof.

## License

MIT — see [LICENSE](LICENSE).