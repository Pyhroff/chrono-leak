"""
CHRONO-LEAK | Main Launcher
=============================
Run this file to start CHRONO-LEAK.
It will ask you for a username and run all modules.

Usage:
  python main.py
"""

import sys
import os

# Force UTF-8 console so scraped names (emojis, accents, Hindi) print safely
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Add modules folder to path so we can import from it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules"))

from github_scraper    import scrape_github, save_raw_data
from analyzer          import build_hourly_heatmap, build_weekly_heatmap, find_dead_zone, predict_timezone, build_behavioral_profile, save_html_report, print_heatmap_ascii
from identity_scanner  import scan_identity, save_results
from exposure_scorer   import calculate_exposure_score
from ai_analyst        import generate_brief, save_brief

def print_banner():
    print("""
  ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗
 ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔═══██╗
 ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║   ██║
 ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║
 ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝
       LEAK  -- Temporal De-Anonymization Tool
    """)

def get_target():
    # Allow: python main.py <username>
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        print("=" * 60)
        print("  TARGET SELECTION")
        print("=" * 60)
        username = input("\n  Enter GitHub username to investigate: ")

    # Strip whitespace AND a stray UTF-8 BOM (﻿) that Windows pipes add
    username = username.strip().lstrip("﻿").strip()

    if not username:
        print("  [!] No username entered. Exiting.")
        sys.exit(0)
    return username

def run_github_module(username):
    print("\n" + "=" * 60)
    print("  [1/5] GITHUB SCRAPER")
    print("=" * 60)
    result = scrape_github(username)
    if not result:
        print(f"  [!] Could not find GitHub user: {username}")
        return []
    data, user_info = result
    save_raw_data(data, username)
    return data

def run_analyzer_module(username, data):
    print("\n" + "=" * 60)
    print("  [2/5] TEMPORAL ANALYZER")
    print("=" * 60)
    if not data:
        print("  [!] No data to analyze.")
        return {}, {}

    heatmap    = build_hourly_heatmap(data)
    weekly_map = build_weekly_heatmap(data)
    _, _, dead_center = find_dead_zone(heatmap)
    tz_results = predict_timezone(heatmap, dead_center)
    top_tz     = tz_results[0] if tz_results else {"timezone": "Unknown", "confidence": 0, "offset": 0}
    profile    = build_behavioral_profile(data, heatmap, weekly_map, top_tz)

    print(f"\n  Timezone prediction: {top_tz['timezone']} ({top_tz['confidence']}% confidence)")
    print(f"  Behavioral type:     {profile.get('behavioral_type', 'Unknown')}")

    print_heatmap_ascii(heatmap, tz_offset=top_tz["offset"],
                        label=top_tz["timezone"].split("(")[-1].replace(")", ""))
    save_html_report(username, heatmap, weekly_map, tz_results, profile, data)
    return tz_results, profile

def run_identity_module(username):
    print("\n" + "=" * 60)
    print("  [3/5] IDENTITY SCANNER (self-validating v2)")
    print("=" * 60)
    results = scan_identity(username)
    save_results(username, results)

    # Show the intelligence we recovered
    corr = results["correlation"]
    print(f"\n  Confirmed accounts: {len(results['found'])}")
    print(f"  Identity link:      {corr['verdict']} ({corr['confidence']}%)")
    for p in results["profiles"]:
        if p.get("real_name"):
            extra = f" | {p['location']}" if p.get("location") else ""
            print(f"    [{p['platform']}] {p['real_name']}{extra}")

    return results

def main():
    print_banner()
    username = get_target()

    print(f"\n  Target locked: @{username}")
    print(f"  Running full CHRONO-LEAK analysis...\n")

    # Run all modules
    github_data          = run_github_module(username)
    tz_results, profile  = run_analyzer_module(username, github_data)
    identity             = run_identity_module(username)
    found_accounts       = identity["found"]

    # Run exposure scorer
    print("\n" + "=" * 60)
    print("  [4/5] EXPOSURE SCORER")
    print("=" * 60)
    score_data = calculate_exposure_score(
        username     = username,
        github_data  = github_data,
        tz_results   = tz_results,
        found_accounts = found_accounts,
        profile      = profile
    )

    # Run AI analyst (Grok)
    print("\n" + "=" * 60)
    print("  [5/5] AI ANALYST (Grok)")
    print("=" * 60)
    brief = generate_brief(
        username    = username,
        found       = found_accounts,
        profiles    = identity["profiles"],
        correlation = identity["correlation"],
        tz_results  = tz_results,
        exposure    = score_data,
    )
    print("\n  --- FORENSIC BRIEF ---\n")
    print("  " + brief.replace("\n", "\n  "))
    save_brief(username, brief)

    # Final summary
    print("\n" + "=" * 60)
    print("  CHRONO-LEAK COMPLETE")
    print("=" * 60)
    print(f"\n  Target:          @{username}")
    print(f"  Exposure Score:  {score_data['total_score']}/100")
    print(f"  Risk Level:      {score_data['risk_level']}")
    print(f"\n  Reports saved to: reports/")
    print(f"  Open reports/{username}_report.html for full dashboard")
    print(f"  Open reports/{username}_identity_report.html for identity map")
    print(f"  Open reports/{username}_exposure.html for exposure score")
    print(f"  Open reports/{username}_brief.txt for the Grok forensic brief\n")

if __name__ == "__main__":
    main()
