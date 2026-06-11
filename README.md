# CHRONO-LEAK

A personal OSINT self-audit tool. Point it at a username and it shows you
exactly what an attacker can learn about you from public data alone —
confirmed accounts, recovered identity, behavioral timezone, and an overall
exposure score, capped off with an AI-written forensic brief.

> For research and educational use only. Run it on yourself or on accounts
> you have permission to investigate.

## Features

| Module | What it does |
|--------|--------------|
| GitHub scraper      | Collects public activity timestamps |
| Temporal analyzer   | Predicts timezone + behavioral routine from timing |
| Identity scanner    | Self-validating search across 30+ platforms (no false positives) |
| Profile extractor   | Recovers real name, bio, location from confirmed accounts |
| Breach checker      | Checks email/password against known breaches |
| Exposure scorer     | Scores total exposure out of 100 |
| **AI Analyst (Grok)** | Writes a human-readable forensic threat brief |

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/Pyhroff/darkdecoder
cd darkdecoder

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add your API key (Grok / xAI)
echo "GROK_API_KEY=your_key_here" > .env

# 4. Run
python main.py <username>
```

Get a Grok API key at <https://console.x.ai>. The AI Analyst layer is
optional — without a key, CHRONO-LEAK falls back to an offline template
brief so everything still works.

## Example

```bash
python main.py octocat
```

Outputs HTML dashboards and a forensic brief to the `reports/` folder.

## Notes on Grok

The AI Analyst uses Grok (by xAI), which exposes an OpenAI-compatible API:

- Endpoint: `https://api.x.ai/v1`
- Model: `grok-2-latest`
- Auth: `GROK_API_KEY` in your `.env`
