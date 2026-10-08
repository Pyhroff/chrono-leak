"""
CHRONO-LEAK | Module 10: Exposure Scorer
==========================================
Takes outputs from all other modules and calculates
an overall EXPOSURE SCORE out of 100.

Broken into 5 categories (20 points each):
  1. Identity Exposure   - how many platforms you're findable on
  2. Temporal Exposure   - how accurately your timezone/routine was predicted
  3. Network Exposure    - how many public connections/repos/activity visible
  4. Location Exposure   - geographic clues left in public data
  5. Security Exposure   - risky platforms, forgotten accounts, breach risk

Higher score = more exposed to an attacker doing OSINT on you.
The report also gives actionable steps to REDUCE each score.
"""

import json
import os
from datetime import datetime


# ── SCORING RUBRICS ───────────────────────────────────────────────────────────

def score_identity(found_accounts):
    """
    Score: How many platforms is this person findable on?
    More accounts found = higher exposure.

    0-3   accounts = low     (0-5 pts)
    4-7   accounts = medium  (6-12 pts)
    8-14  accounts = high    (13-17 pts)
    15+   accounts = critical(18-20 pts)
    """
    count = len(found_accounts) if found_accounts else 0

    if count == 0:
        score = 0
    elif count <= 3:
        score = count * 2                    # 2 pts each
    elif count <= 7:
        score = 6 + (count - 3) * 2         # up to 12
    elif count <= 14:
        score = 14 + (count - 7)            # up to 17
    else:
        score = min(20, 17 + (count - 14))  # caps at 20

    # What platforms are highest risk
    high_risk_platforms = ["Instagram", "LinkedIn", "Twitter/X", "Facebook",
                           "TikTok", "Snapchat", "Reddit"]
    risky_found = [a["platform"] for a in (found_accounts or [])
                   if a["platform"] in high_risk_platforms]

    findings = []
    if count == 0:
        findings.append("No accounts found — good username hygiene")
    else:
        findings.append(f"Found on {count} platforms")
    if risky_found:
        findings.append(f"High-risk social platforms: {', '.join(risky_found)}")

    recommendations = []
    if count > 5:
        recommendations.append("Audit and delete unused accounts")
    if "Snapchat" in [a["platform"] for a in (found_accounts or [])]:
        recommendations.append("Snapchat presence detectable even without content")
    if count > 10:
        recommendations.append("Use different usernames across platforms to prevent correlation")

    return {
        "score":           min(20, score),
        "max":             20,
        "category":        "Identity Exposure",
        "accounts_found":  count,
        "findings":        findings,
        "recommendations": recommendations
    }


def score_temporal(tz_results, profile):
    """
    Score: How much does your activity reveal about your routine?
    High confidence timezone prediction = higher exposure.

    Low confidence (<40%)  = 0-5 pts
    Medium confidence (40-70%) = 6-12 pts
    High confidence (>70%)    = 13-20 pts
    """
    if not tz_results:
        return {
            "score": 0, "max": 20,
            "category": "Temporal Exposure",
            "findings": ["Insufficient data for temporal analysis"],
            "recommendations": []
        }

    top_confidence = tz_results[0]["confidence"] if tz_results else 0
    evidence_status = tz_results[0].get("status", "candidate") if tz_results else "insufficient_evidence"
    behavioral_type = profile.get("behavioral_type", "") if profile else ""

    # Score based on confidence
    if top_confidence < 40:
        score = int(top_confidence / 8)          # 0-5
    elif top_confidence < 70:
        score = 6 + int((top_confidence - 40) / 5)  # 6-12
    else:
        score = 13 + int((top_confidence - 70) / 10) # 13-20

    findings = [
        f"Timezone candidate confidence: {top_confidence}%",
        f"Top candidate: {tz_results[0]['timezone']}",
        f'Evidence status: {evidence_status.replace("_", " ")}',
    ]
    if behavioral_type:
        findings.append(f"Behavioral pattern detected: {behavioral_type}")

    recommendations = []
    if evidence_status == "candidate" and top_confidence > 60:
        recommendations.append("Spread activity across different times of day to obscure patterns")
    if evidence_status == "candidate" and top_confidence > 80:
        recommendations.append("Your routine is highly predictable — vary your online schedule")
    recommendations.append("Using a VPN does NOT hide behavioral timing patterns")

    return {
        "score":           min(20, score),
        "max":             20,
        "category":        "Temporal Exposure",
        "tz_confidence":   top_confidence,
        "findings":        findings,
        "recommendations": recommendations
    }


def score_network(github_data):
    """
    Score: How much public technical/network activity is visible?
    More commits, repos, public work = higher exposure.
    """
    if not github_data:
        return {
            "score": 0, "max": 20,
            "category": "Network Exposure",
            "findings": ["No GitHub activity found"],
            "recommendations": []
        }

    total_points    = len(github_data)
    repo_count      = sum(1 for d in github_data if d.get("source") == "github_repo_created")
    commit_count    = sum(1 for d in github_data if d.get("source") == "github_commit")
    event_count     = sum(1 for d in github_data if d.get("source") == "github_event")

    # Unique repos touched
    repos_touched   = len(set(d.get("repo_name","") for d in github_data))

    # Score
    if total_points < 10:
        score = 2
    elif total_points < 30:
        score = 5 + int(total_points / 6)
    elif total_points < 100:
        score = 10 + int((total_points - 30) / 14)
    else:
        score = 18 + min(2, int((total_points - 100) / 50))

    findings = [
        f"{repo_count} public repositories visible",
        f"{commit_count} commits publicly accessible",
        f"Activity spans {len(set(d.get('date','') for d in github_data))} unique days",
    ]

    recommendations = []
    if repo_count > 5:
        recommendations.append("Review public repos — ensure no sensitive files are committed")
    if commit_count > 20:
        recommendations.append("Git commit history reveals your work schedule in detail")
        recommendations.append("Check git log for accidentally committed emails or credentials")

    return {
        "score":        min(20, score),
        "max":          20,
        "category":     "Network Exposure",
        "data_points":  total_points,
        "findings":     findings,
        "recommendations": recommendations
    }


def score_location(github_data, found_accounts):
    """
    Score: How many geographic clues exist in public data?
    Timezone accuracy, location-tagged platforms = higher score.
    """
    score    = 0
    findings = []
    recs     = []

    # Instagram found = potential location tags
    has_instagram = any(
        a.get("platform") == "Instagram"
        for a in (found_accounts or [])
    )
    if has_instagram:
        score += 8
        findings.append("Instagram account found — location tags may reveal frequent places")
        recs.append("Disable location tagging on Instagram posts")
        recs.append("Remove location data from past posts via Instagram settings")

    # Timezone was determinable from GitHub alone
    if github_data and len(github_data) > 5:
        score += 5
        findings.append("GitHub activity alone reveals approximate timezone")

    # Snapchat = snap map risk
    has_snapchat = any(
        a.get("platform") == "Snapchat"
        for a in (found_accounts or [])
    )
    if has_snapchat:
        score += 5
        findings.append("Snapchat account found — Snap Map can expose real-time location")
        recs.append("Disable Snap Map or set to Ghost Mode in Snapchat settings")

    if not findings:
        findings.append("No direct location exposure detected in public data")

    return {
        "score":           min(20, score),
        "max":             20,
        "category":        "Location Exposure",
        "findings":        findings,
        "recommendations": recs
    }


def score_security(found_accounts, github_data):
    """
    Score: How many security risks exist in public presence?
    Forgotten accounts, developer platforms with potential leaks, etc.
    """
    score    = 0
    findings = []
    recs     = []

    count = len(found_accounts) if found_accounts else 0

    # Old forgotten accounts = security risk (stale passwords, old data)
    forgotten_platforms = ["Bandcamp", "500px", "Gravatar", "About.me",
                           "Keybase", "Pastebin", "WordPress", "Blogger"]
    forgotten_found = [
        a["platform"] for a in (found_accounts or [])
        if a["platform"] in forgotten_platforms
    ]

    if forgotten_found:
        score += len(forgotten_found) * 2
        findings.append(f"Potentially forgotten accounts: {', '.join(forgotten_found)}")
        recs.append(f"Delete or secure these old accounts — they use old passwords and have stale data")

    # Developer platforms = code exposure risk
    dev_platforms = ["GitHub", "GitLab", "Replit", "CodePen", "Bitbucket"]
    dev_found = [
        a["platform"] for a in (found_accounts or [])
        if a["platform"] in dev_platforms
    ]
    if dev_found:
        score += 3
        findings.append(f"Developer platforms found: {', '.join(dev_found)}")
        recs.append("Scan public repos for accidentally committed API keys or passwords")
        recs.append("Run: git log --all --full-history -- '*.env'")

    # Gaming platforms = username correlation risk
    gaming_platforms = ["Steam", "Roblox", "Chess.com", "Twitch", "Lichess"]
    gaming_found = [
        a["platform"] for a in (found_accounts or [])
        if a["platform"] in gaming_platforms
    ]
    if gaming_found:
        score += 2
        findings.append(f"Gaming accounts found: {', '.join(gaming_found)}")
        recs.append("Gaming accounts often use real names or persistent usernames — easy to correlate")

    if not findings:
        findings.append("No major security risks detected in public presence")
        recs.append("Run Module 8 (breach checker) to check email/password exposure")

    return {
        "score":           min(20, score),
        "max":             20,
        "category":        "Security Exposure",
        "findings":        findings,
        "recommendations": recs
    }


# ── RISK LEVEL LABELER ────────────────────────────────────────────────────────

def get_risk_level(total_score):
    if total_score <= 20:
        return "LOW",      "#69f0ae", "Your public footprint is minimal. Good OPSEC."
    elif total_score <= 40:
        return "MODERATE", "#fff176", "Some exposure. Review recommendations below."
    elif total_score <= 60:
        return "HIGH",     "#ffa726", "Significant exposure. Take action on key areas."
    elif total_score <= 80:
        return "CRITICAL", "#ef5350", "Highly exposed. An attacker can build a detailed profile."
    else:
        return "SEVERE",   "#b71c1c", "Extreme exposure. Immediate action recommended."


# ── HTML REPORT ───────────────────────────────────────────────────────────────

def save_exposure_report(username, scores, total_score, risk_level, risk_color, risk_desc):
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    safe_username = html_escape(username)

    # Build category cards
    category_cards = ""
    for s in scores:
        pct   = int((s["score"] / s["max"]) * 100)
        color = "#69f0ae" if pct < 40 else "#ffa726" if pct < 70 else "#ef5350"

        findings_html = "".join(
            f'<li style="margin:4px 0; color:#ccc">{html_escape(f)}</li>'
            for f in s["findings"]
        )
        recs_html = "".join(
            f'<li style="margin:4px 0; color:#aaa">{html_escape(r)}</li>'
            for r in s["recommendations"]
        )

        category_cards += f"""
        <div class="card">
          <div style="display:flex; justify-content:space-between; align-items:center">
            <h2 style="margin:0">{html_escape(s['category'].upper())}</h2>
            <div style="font-size:28px; font-weight:bold; color:{color}">
              {s['score']}/{s['max']}
            </div>
          </div>

          <div style="background:#0a1628; border-radius:6px; height:8px; margin:12px 0">
            <div style="background:{color}; width:{pct}%; height:100%; border-radius:6px"></div>
          </div>

          <div style="margin-top:12px">
            <div style="color:#888; font-size:12px; margin-bottom:6px">FINDINGS</div>
            <ul style="margin:0; padding-left:18px; font-size:13px">{findings_html}</ul>
          </div>

          {"<div style='margin-top:12px'><div style='color:#888; font-size:12px; margin-bottom:6px'>RECOMMENDATIONS</div><ul style='margin:0; padding-left:18px; font-size:13px'>" + recs_html + "</ul></div>" if recs_html else ""}
        </div>"""

    # Gauge visual (simple CSS arc)
    gauge_pct = total_score

    html = f"""<!DOCTYPE html>
<html>
<head>
  <title>CHRONO-LEAK Exposure Score: {safe_username}</title>
  <style>
    body  {{ font-family:'Segoe UI',sans-serif; background:#1a1a2e; color:#eee; margin:0; padding:20px; }}
    h1    {{ color:#00e5ff; letter-spacing:2px; margin-bottom:4px; }}
    h2    {{ color:#00e5ff; font-size:14px; border-bottom:1px solid #2a2a4a; padding-bottom:6px; margin-top:0; }}
    .card {{ background:#16213e; border-radius:10px; padding:20px; margin:14px 0; }}
    .hero {{ text-align:center; padding:30px; }}
    .score-circle {{
      width:160px; height:160px; border-radius:50%; margin:0 auto 16px;
      background: conic-gradient({risk_color} {gauge_pct * 3.6}deg, #0a1628 0deg);
      display:flex; align-items:center; justify-content:center;
      position:relative;
    }}
    .score-inner {{
      width:130px; height:130px; border-radius:50%;
      background:#16213e;
      display:flex; flex-direction:column;
      align-items:center; justify-content:center;
    }}
    .score-num  {{ font-size:42px; font-weight:bold; color:{risk_color}; line-height:1; }}
    .score-max  {{ font-size:14px; color:#555; }}
    .risk-badge {{
      display:inline-block; background:{risk_color}22;
      color:{risk_color}; padding:6px 20px;
      border-radius:20px; font-weight:bold; letter-spacing:2px;
      margin-bottom:10px;
    }}
  </style>
</head>
<body>
  <h1>CHRONO-LEAK</h1>
  <p style="color:#888; margin-top:-10px">Personal Exposure Score Report</p>

  <div class="card hero">
    <div class="score-circle">
      <div class="score-inner">
        <div class="score-num">{total_score}</div>
        <div class="score-max">/ 100</div>
      </div>
    </div>
    <div class="risk-badge">{risk_level} RISK</div>
    <div style="color:#aaa; font-size:14px; max-width:400px; margin:0 auto">
      {risk_desc}
    </div>
    <div style="color:#555; font-size:12px; margin-top:12px">
      Target: @{safe_username} &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')}
    </div>
  </div>

  <div class="card">
    <h2>SCORE BREAKDOWN</h2>
    <table style="width:100%; border-collapse:collapse">
      {"".join(f'''<tr>
        <td style="padding:10px 0; color:#ccc">{s['category']}</td>
        <td style="padding:10px 0; width:200px">
          <div style="background:#0a1628; border-radius:4px; height:6px">
            <div style="background:{'#69f0ae' if s['score']/s['max'] < 0.4 else '#ffa726' if s['score']/s['max'] < 0.7 else '#ef5350'};
                        width:{int(s['score']/s['max']*100)}%; height:100%; border-radius:4px"></div>
          </div>
        </td>
        <td style="padding:10px 0 10px 12px; font-weight:bold; color:{'#69f0ae' if s['score']/s['max'] < 0.4 else '#ffa726' if s['score']/s['max'] < 0.7 else '#ef5350'}">
          {s['score']}/{s['max']}
        </td>
      </tr>''' for s in scores)}
    </table>
  </div>

  {category_cards}

  <div style="color:#333; font-size:12px; text-align:center; margin-top:20px">
    CHRONO-LEAK | For research and educational use only
  </div>
</body>
</html>"""

    html_path = os.path.join(reports_dir, f"{username}_exposure.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] Exposure report saved: {html_path}")
    return html_path


# ── MAIN SCORER ───────────────────────────────────────────────────────────────

def calculate_exposure_score(username, github_data=None, tz_results=None,
                              found_accounts=None, profile=None):
    """
    Main function — runs all 5 scoring categories and returns final score.
    Called by main.py after all other modules have run.
    """
    print(f"\n[*] Calculating exposure score for @{username}...")

    # Run all 5 category scorers
    scores = [
        score_identity(found_accounts),
        score_temporal(tz_results, profile),
        score_network(github_data),
        score_location(github_data, found_accounts),
        score_security(found_accounts, github_data),
    ]

    total_score = sum(s["score"] for s in scores)
    risk_level, risk_color, risk_desc = get_risk_level(total_score)

    # Print terminal summary
    print("\n" + "=" * 55)
    print("  EXPOSURE SCORE RESULTS")
    print("=" * 55)

    print(f"\n  {'Category':<25} {'Score':>6}  {'Bar'}")
    print(f"  {'-'*50}")

    for s in scores:
        bar_len = int((s["score"] / s["max"]) * 20)
        bar     = "#" * bar_len + "-" * (20 - bar_len)
        print(f"  {s['category']:<25} {s['score']:>3}/{s['max']}  [{bar}]")

    print(f"  {'-'*50}")
    print(f"  {'TOTAL EXPOSURE SCORE':<25} {total_score:>3}/100")
    print(f"\n  RISK LEVEL: {risk_level}")
    print(f"  {risk_desc}")

    # Top recommendations
    all_recs = []
    for s in scores:
        all_recs.extend(s.get("recommendations", []))

    if all_recs:
        print(f"\n  TOP RECOMMENDATIONS:")
        for i, rec in enumerate(all_recs[:5], 1):
            print(f"    {i}. {rec}")

    # Save HTML report
    save_exposure_report(username, scores, total_score, risk_level, risk_color, risk_desc)

    return {
        "total_score": total_score,
        "risk_level":  risk_level,
        "scores":      scores
    }


# ── RUN DIRECTLY ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(__file__))

    # Load previously saved data if running standalone
    username = input("  Username to score: ").strip() or "octocat"

    # Try to load existing identity scan results
    base_dir   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    id_file    = os.path.join(base_dir, "reports", f"{username}_identity.json")
    gh_file    = os.path.join(base_dir, "reports", f"{username}_github_raw.json")

    found_accounts = []
    github_data    = []

    if os.path.exists(id_file):
        with open(id_file) as f:
            id_data = json.load(f)
            found_accounts = id_data.get("found", [])
        print(f"[+] Loaded identity data: {len(found_accounts)} accounts found")

    if os.path.exists(gh_file):
        with open(gh_file) as f:
            github_data = json.load(f)
        print(f"[+] Loaded GitHub data: {len(github_data)} data points")

    calculate_exposure_score(
        username       = username,
        github_data    = github_data,
        found_accounts = found_accounts,
        tz_results     = None,
        profile        = None
    )
