"""
CHRONO-LEAK | AI Analyst Layer (powered by Grok / xAI)
========================================================
Takes the structured output from all other modules and asks
Grok to write a human-readable forensic "threat brief" — the
kind of narrative a real OSINT analyst would hand to a client.

Grok (by xAI) exposes an OpenAI-COMPATIBLE API, so we use the
standard `openai` client pointed at xAI's endpoint:
    base_url = https://api.x.ai/v1
    model    = grok-2-latest

SETUP:
  1. Get a key at https://console.x.ai
  2. Put it in a .env file in the project root:
        GROK_API_KEY=your_key_here
  3. pip install -r requirements.txt

If no key is set, this module FALLS BACK to a built-in template
generator so the tool still produces a brief offline.
"""

import os
from env_config import get_key
from privacy import sanitize_for_external_analysis

# ── LOAD API KEY (environment or .env, via shared helper) ─────────────────────
GROK_API_KEY  = get_key("GROK_API_KEY")
GROK_BASE_URL = "https://api.x.ai/v1"
GROK_MODEL    = "grok-2-latest"
ALLOW_EXTERNAL_ANALYSIS = get_key("ALLOW_EXTERNAL_ANALYSIS", "false").strip().lower() in {"1", "true", "yes"}


# ── PROMPT BUILDER ────────────────────────────────────────────────────────────
def _build_prompt(username, found, profiles, correlation, tz_results, exposure):
    """Turn the raw module outputs into a clean prompt for Grok."""
    safe = sanitize_for_external_analysis({
        "username": username, "found": found, "profiles": profiles,
        "correlation": correlation, "tz_results": tz_results, "exposure": exposure,
    })
    username = safe["username"]
    found = safe["found"]
    profiles = safe["profiles"]
    correlation = safe["correlation"]
    tz_results = safe["tz_results"]
    exposure = safe["exposure"]
    lines = [f"OSINT target username: {username}", ""]

    lines.append("CONFIRMED ACCOUNTS:")
    for a in found:
        lines.append(f"  - {a['platform']}: {a['url']}")

    lines.append("\nEXTRACTED PROFILE DATA:")
    for p in profiles:
        bits = [f"{k}={v}" for k, v in p.items() if v and k != "platform"]
        lines.append(f"  - {p['platform']}: {', '.join(bits)}")

    if correlation:
        lines.append(f"\nIDENTITY CORRELATION: {correlation.get('verdict','N/A')} "
                     f"({correlation.get('confidence',0)}% confidence)")

    if tz_results:
        top = tz_results[0]
        lines.append(f"\nTIMEZONE ESTIMATE: {top['timezone']} ({top['confidence']}% confidence)")

    if exposure:
        lines.append(f"\nEXPOSURE SCORE: {exposure.get('total_score','?')}/100 "
                     f"({exposure.get('risk_level','?')} risk)")

    return "\n".join(lines)


SYSTEM_PROMPT = (
    "You are a senior OSINT analyst writing a concise, factual threat brief. "
    "Use ONLY the data provided — never invent details. Write 2-3 short paragraphs: "
    "(1) who this person appears to be and how confident we are, "
    "(2) what an attacker could do with this exposure, "
    "(3) the top 3 concrete steps to reduce the exposure. "
    "Keep it professional and direct. This is a defensive self-audit."
)


# ── GROK CALL ─────────────────────────────────────────────────────────────────
def generate_brief(username, found, profiles, correlation,
                   tz_results=None, exposure=None):
    """
    Generate the forensic brief.
    Uses Grok if a key is available, otherwise a template fallback.
    """
    prompt = _build_prompt(username, found, profiles, correlation, tz_results, exposure)

    if not GROK_API_KEY or not ALLOW_EXTERNAL_ANALYSIS:
        if GROK_API_KEY and not ALLOW_EXTERNAL_ANALYSIS:
            print("  [i] External AI analysis is disabled — using offline template brief.")
            print("      Set ALLOW_EXTERNAL_ANALYSIS=true only after reviewing the data-sharing boundary.")
        else:
            print("  [i] No GROK_API_KEY found — using offline template brief.")
        print("      Add GROK_API_KEY to .env for AI-generated analysis.")
        return _fallback_brief(username, found, profiles, correlation, tz_results, exposure)

    try:
        # xAI is OpenAI-compatible, so we reuse the openai client
        from openai import OpenAI

        client = OpenAI(api_key=GROK_API_KEY, base_url=GROK_BASE_URL)
        print(f"  [*] Asking Grok ({GROK_MODEL}) to write the forensic brief...")

        response = client.chat.completions.create(
            model=GROK_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.4,
            max_tokens=600,
        )
        brief = response.choices[0].message.content.strip()
        print("  [+] Grok brief generated.")
        return brief

    except ImportError:
        print("  [!] 'openai' package not installed. Run: pip install -r requirements.txt")
        return _fallback_brief(username, found, profiles, correlation, tz_results, exposure)
    except Exception as e:
        print(f"  [!] Grok API error: {e}")
        print("      Falling back to offline template brief.")
        return _fallback_brief(username, found, profiles, correlation, tz_results, exposure)


# ── OFFLINE FALLBACK ──────────────────────────────────────────────────────────
def _fallback_brief(username, found, profiles, correlation, tz_results, exposure):
    """A decent template brief generated locally with no API needed."""
    real_name = next((p.get("real_name") for p in profiles if p.get("real_name")), None)
    location  = next((p.get("location")  for p in profiles if p.get("location")),  None)
    platforms = ", ".join(a["platform"] for a in found) or "no platforms"

    p1 = (f"The username '{username}' resolves to confirmed accounts on {platforms}. "
          + (f"Public data identifies the subject as '{real_name}'. " if real_name else "")
          + (f"Location signals point to {location}. " if location else "")
          + (f"Cross-platform name correlation is {correlation.get('verdict','inconclusive')} "
             f"at {correlation.get('confidence',0)}% confidence." if correlation else ""))

    tz_line = ""
    if tz_results:
        tz_line = (f" Behavioral timing suggests {tz_results[0]['timezone']} "
                   f"({tz_results[0]['confidence']}% confidence).")

    p2 = ("An attacker could combine these public footprints to build a profile for "
          "social-engineering, credential-stuffing against the linked accounts, or "
          "physical/temporal targeting." + tz_line)

    p3 = ("Top actions: (1) use distinct usernames per platform to break correlation; "
          "(2) remove real name / location / employer from public bios; "
          "(3) audit and delete dormant accounts and enable 2FA everywhere.")

    score_line = ""
    if exposure:
        score_line = f"\n\nExposure score: {exposure.get('total_score','?')}/100 ({exposure.get('risk_level','?')} risk)."

    return f"{p1}\n\n{p2}\n\n{p3}{score_line}"


# ── SAVE ──────────────────────────────────────────────────────────────────────
def save_brief(username, brief):
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, f"{username}_brief.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"CHRONO-LEAK FORENSIC BRIEF — @{username}\n")
        f.write("=" * 55 + "\n\n")
        f.write(brief + "\n")
    print(f"  [+] Brief saved: {path}")
    return path


# ── STANDALONE TEST ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys, json
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    username = sys.argv[1] if len(sys.argv) > 1 else "octocat"
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    id_file  = os.path.join(base_dir, "reports", f"{username}_identity.json")

    if not os.path.exists(id_file):
        print(f"[!] Run the scanner first to produce {id_file}")
        sys.exit(1)

    with open(id_file, encoding="utf-8") as f:
        data = json.load(f)

    brief = generate_brief(
        username    = username,
        found       = data.get("found", []),
        profiles    = data.get("profiles", []),
        correlation = data.get("correlation", {}),
    )

    print("\n" + "=" * 55)
    print("  FORENSIC BRIEF")
    print("=" * 55 + "\n")
    print(brief)
    save_brief(username, brief)
