"""
CHRONO-LEAK | Module 2: Analysis Engine
=========================================
Takes raw timestamps from Module 1 and produces:
  - Activity heatmap (what hours/days are they active)
  - Dead zone detection (when are they sleeping)
  - Timezone prediction with confidence score
  - Behavioral profile (student? developer? night owl?)
  - HTML visual report saved to /reports/
"""

import json
import os
from datetime import datetime, timezone
from collections import Counter
import math
from report_utils import html_escape

# ── TIMEZONE DATABASE ─────────────────────────────────────────────────────────
# Common timezones with their UTC offset in hours
# We'll match the target's sleep pattern against these

TIMEZONES = {
    "UTC-8  (Los Angeles / PST)":      -8,
    "UTC-7  (Denver / MST)":           -7,
    "UTC-6  (Chicago / CST)":          -6,
    "UTC-5  (New York / EST)":         -5,
    "UTC-4  (Atlantic / AST)":         -4,
    "UTC-3  (Buenos Aires / BRT)":     -3,
    "UTC+0  (London / GMT)":            0,
    "UTC+1  (Paris / CET)":             1,
    "UTC+2  (Cairo / EET)":             2,
    "UTC+3  (Moscow / MSK)":            3,
    "UTC+4  (Dubai / GST)":             4,
    "UTC+5  (Karachi / PKT)":           5,
    "UTC+5:30 (India / IST)":           5.5,
    "UTC+6  (Dhaka / BST)":             6,
    "UTC+7  (Bangkok / ICT)":           7,
    "UTC+8  (Singapore / SGT)":         8,
    "UTC+9  (Tokyo / JST)":             9,
    "UTC+10 (Sydney / AEST)":          10,
    "UTC+12 (Auckland / NZST)":        12,
}

# ── LOAD DATA ─────────────────────────────────────────────────────────────────

def load_data(username):
    """
    Load the raw JSON data saved by Module 1.
    Returns a list of data points with parsed timestamps.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    filepath = os.path.join(base_dir, "reports", f"{username}_github_raw.json")

    if not os.path.exists(filepath):
        print(f"[!] No data found for '{username}'.")
        print(f"    Run github_scraper.py first to collect data.")
        return None

    with open(filepath, "r") as f:
        raw_data = json.load(f)

    # Re-parse the timestamps back into datetime objects
    for entry in raw_data:
        dt = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
        entry["datetime_utc"] = dt
        entry["hour_utc"]     = dt.hour
        entry["minute_utc"]   = dt.minute
        entry["day_of_week"]  = dt.strftime("%A")

    print(f"[+] Loaded {len(raw_data)} data points for {username}")
    return raw_data

# ── HEATMAP BUILDER ───────────────────────────────────────────────────────────

def build_hourly_heatmap(data):
    """
    Build a 24-hour activity map.
    Shows which hours of the day (UTC) had the most activity.
    This is the foundation of timezone detection.
    """
    # Count activity per hour (0-23 UTC)
    hour_counts = Counter()
    for entry in data:
        hour_counts[entry["hour_utc"]] += 1

    # Fill in zeros for hours with no activity
    heatmap = {hour: hour_counts.get(hour, 0) for hour in range(24)}
    return heatmap

def build_weekly_heatmap(data):
    """
    Build activity map by day of week.
    Weekday vs weekend patterns reveal work/school schedules.
    """
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    day_counts = Counter(entry["day_of_week"] for entry in data)
    return {day: day_counts.get(day, 0) for day in days}

# ── DEAD ZONE DETECTION ───────────────────────────────────────────────────────

def find_dead_zone(heatmap):
    """
    Find the longest consecutive stretch of zero/low activity.
    That stretch = when they're sleeping.
    The CENTER of that stretch = their local ~3am (deepest sleep).

    This is the core timezone detection trick.
    """
    hours = list(range(24))
    counts = [heatmap[h] for h in hours]

    # Find all hours with zero activity
    zero_hours = [h for h in hours if counts[h] == 0]

    if not zero_hours:
        # If no complete dead hours, use the lowest activity hours instead
        avg = sum(counts) / 24
        zero_hours = [h for h in hours if counts[h] <= avg * 0.2]

    if not zero_hours:
        return None, None, []

    # Find the longest consecutive run of dead hours
    # We double the list to handle wraparound (e.g., 22, 23, 0, 1, 2)
    doubled = zero_hours + [h + 24 for h in zero_hours]

    longest_run = []
    current_run = [doubled[0]]

    for i in range(1, len(doubled)):
        if doubled[i] == doubled[i-1] + 1:
            current_run.append(doubled[i])
        else:
            if len(current_run) > len(longest_run):
                longest_run = current_run
            current_run = [doubled[i]]

    if len(current_run) > len(longest_run):
        longest_run = current_run

    # Normalize back to 0-23
    longest_run = [h % 24 for h in longest_run]

    # Dead zone start and end
    dead_start = longest_run[0]
    dead_end   = longest_run[-1]

    # Center of dead zone = their local ~3am
    center_idx = len(longest_run) // 2
    dead_center_utc = longest_run[center_idx]

    return dead_start, dead_end, dead_center_utc

# ── TIMEZONE PREDICTOR ────────────────────────────────────────────────────────

def predict_timezone(heatmap, dead_center_utc, sample_count=None):
    """Rank timezone candidates without overstating sparse-timestamp evidence."""
    if dead_center_utc is None:
        return []

    total_activity = sum(heatmap.values())
    sample_count = sample_count if sample_count is not None else total_activity
    if total_activity == 0:
        return []

    estimated_offset = dead_center_utc - 3
    if estimated_offset > 14:
        estimated_offset -= 24
    if estimated_offset < -12:
        estimated_offset += 24

    # Evidence quality: sample volume and concentration matter.
    coverage = min(1.0, total_activity / 96.0)
    active_hours = sum(1 for count in heatmap.values() if count > 0)
    diversity = min(1.0, active_hours / 12.0)

    results = []
    for tz_name, tz_offset in TIMEZONES.items():
        distance = abs(tz_offset - estimated_offset)
        distance_score = max(0.0, 100.0 - (distance * 20.0))

        local_activity_score = 0.0
        for utc_hour, count in heatmap.items():
            local_hour = (utc_hour + tz_offset) % 24
            if 7 <= local_hour <= 23:
                local_activity_score += count
            else:
                local_activity_score -= count * 0.5

        fit_score = max(0.0, (local_activity_score / total_activity) * 100.0)

        raw_confidence = (distance_score * 0.55) + (fit_score * 0.45)
        evidence_factor = 0.35 + (0.65 * ((coverage + diversity) / 2.0))
        confidence = raw_confidence * evidence_factor

        results.append({
            "timezone": tz_name,
            "offset": tz_offset,
            "confidence": round(confidence, 1),
            "raw_confidence": round(raw_confidence, 1),
            "evidence_quality": round(evidence_factor * 100, 1),
            "sample_count": sample_count,
            "active_hours": active_hours,
            "distance": distance,
            "fit_score": round(fit_score, 1),
        })

    results.sort(key=lambda x: x["confidence"], reverse=True)

    # Never present a weak result as a strong attribution.
    if results and (sample_count < 12 or active_hours < 4):
        for result in results:
            result["confidence"] = min(result["confidence"], 39.9)
            result["status"] = "insufficient_evidence"
    else:
        for result in results:
            result["status"] = "candidate"

    return results[:5]

# ── BEHAVIORAL PROFILER ───────────────────────────────────────────────────────

def build_behavioral_profile(data, heatmap, weekly_map, top_timezone):
    """
    Build a human-readable behavioral profile from the patterns.
    Answers: Who is this person? What kind of schedule do they have?
    """
    profile = {}
    tz_offset = top_timezone["offset"] if top_timezone else 0

    # Convert activity hours to local time
    local_hours = [(h + tz_offset) % 24 for entry in data for h in [entry["hour_utc"]]]

    if not local_hours:
        return {"error": "Not enough data"}

    avg_local_hour = sum(local_hours) / len(local_hours)
    profile["average_active_hour_local"] = f"{int(avg_local_hour):02d}:00"

    # Morning (6-12), Afternoon (12-18), Evening (18-24), Night (0-6)
    time_buckets = {
        "morning (6am-12pm)":   sum(1 for h in local_hours if 6  <= h < 12),
        "afternoon (12pm-6pm)": sum(1 for h in local_hours if 12 <= h < 18),
        "evening (6pm-12am)":   sum(1 for h in local_hours if 18 <= h < 24),
        "night (12am-6am)":     sum(1 for h in local_hours if 0  <= h < 6),
    }
    peak_time = max(time_buckets, key=time_buckets.get)
    profile["peak_activity_window"] = peak_time

    # Weekday vs Weekend activity
    weekday_activity = sum(weekly_map[d] for d in ["Monday","Tuesday","Wednesday","Thursday","Friday"])
    weekend_activity = sum(weekly_map[d] for d in ["Saturday","Sunday"])

    total_days_activity = weekday_activity + weekend_activity
    if total_days_activity > 0:
        weekday_pct = round((weekday_activity / total_days_activity) * 100)
        profile["weekday_vs_weekend"] = f"{weekday_pct}% weekday / {100 - weekday_pct}% weekend"

    # Classify the person
    if time_buckets["night (12am-6am)"] > len(local_hours) * 0.3:
        profile["behavioral_type"] = "Night Owl Coder - active late at night"
    elif time_buckets["morning (6am-12pm)"] > len(local_hours) * 0.4:
        profile["behavioral_type"] = "Early Bird - codes in the morning"
    elif time_buckets["afternoon (12pm-6pm)"] > len(local_hours) * 0.4:
        profile["behavioral_type"] = "Afternoon Coder - likely student schedule"
    elif time_buckets["evening (6pm-12am)"] > len(local_hours) * 0.4:
        profile["behavioral_type"] = "Evening Coder - likely has day job/classes"
    else:
        profile["behavioral_type"] = "Mixed schedule - no clear pattern"

    return profile

# ── HEATMAP VISUALIZER ────────────────────────────────────────────────────────

def print_heatmap_ascii(heatmap, tz_offset=0, label="UTC"):
    """
    Print a clean ASCII heatmap in the terminal.
    Shows activity intensity per hour as a bar chart.
    """
    max_count = max(heatmap.values()) if heatmap.values() else 1
    if max_count == 0:
        max_count = 1

    print(f"\n  ACTIVITY HEATMAP (shown in {label} time)")
    print("  " + "-" * 45)

    for utc_hour in range(24):
        local_hour = int((utc_hour + tz_offset) % 24)
        count      = heatmap[utc_hour]

        # Scale bar to max 30 chars wide
        bar_len  = int((count / max_count) * 30)
        bar      = "#" * bar_len

        # AM/PM label
        ampm = "am" if local_hour < 12 else "pm"
        display_hour = local_hour if local_hour <= 12 else local_hour - 12
        if display_hour == 0:
            display_hour = 12

        print(f"  {display_hour:2d}{ampm} ({utc_hour:02d}UTC) | {bar:<30} {count}")

    print("  " + "-" * 45)

# ── SAVE HTML REPORT ──────────────────────────────────────────────────────────

def save_html_report(username, heatmap, weekly_map, tz_results, profile, data):
    """
    Save a clean HTML report with all findings.
    Open it in any browser to see a visual dashboard.
    """
    top_tz = tz_results[0] if tz_results else {"timezone": "Unknown", "confidence": 0, "offset": 0}
    safe_username = html_escape(username)

    # Build heatmap rows for HTML
    max_count = max(heatmap.values()) if heatmap.values() else 1
    heatmap_rows = ""
    for hour in range(24):
        count    = heatmap[hour]
        pct      = int((count / max_count) * 100) if max_count > 0 else 0
        local_h  = int((hour + top_tz["offset"]) % 24)
        ampm     = "am" if local_h < 12 else "pm"
        disp     = local_h if local_h != 0 else 12
        disp     = disp if disp <= 12 else disp - 12

        color = f"hsl({120 - pct}, 80%, {70 - pct//3}%)" if count > 0 else "#f0f0f0"

        heatmap_rows += f"""
        <tr>
          <td style="padding:3px 10px; font-size:12px; color:#666">
            {disp}{ampm} (UTC {hour:02d}:00)
          </td>
          <td style="padding:3px">
            <div style="background:{color}; width:{max(pct,2)}%; height:18px;
                        border-radius:3px; min-width:4px"></div>
          </td>
          <td style="padding:3px 8px; font-size:12px">{count}</td>
        </tr>"""

    # Build timezone candidates table
    tz_rows = ""
    for i, tz in enumerate(tz_results):
        bg = "#e8f5e9" if i == 0 else "white"
        tz_rows += f"""
        <tr style="background:{bg}">
          <td style="padding:8px 12px">{html_escape(tz['timezone'])}</td>
          <td style="padding:8px 12px; font-weight:bold; color:#2e7d32">
            {tz['confidence']}%
          </td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
  <title>CHRONO-LEAK Report: {safe_username}</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    h1 {{ color: #00e5ff; font-size: 28px; letter-spacing: 2px; }}
    h2 {{ color: #00e5ff; font-size: 16px; border-bottom: 1px solid #333; padding-bottom: 8px; }}
    .card {{ background: #16213e; border-radius: 10px; padding: 20px; margin: 16px 0; }}
    .verdict {{ background: #0f3460; border-left: 4px solid #00e5ff; padding: 16px; border-radius: 6px; }}
    .verdict .tz {{ font-size: 24px; font-weight: bold; color: #00e5ff; }}
    .verdict .conf {{ font-size: 14px; color: #aaa; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ border-bottom: 1px solid #222; }}
    .profile-item {{ display: flex; justify-content: space-between; padding: 8px 0;
                     border-bottom: 1px solid #2a2a4a; font-size: 14px; }}
    .profile-label {{ color: #888; }}
    .profile-value {{ color: #00e5ff; font-weight: bold; }}
    .tag {{ display: inline-block; background: #0f3460; padding: 4px 10px;
            border-radius: 20px; font-size: 12px; margin: 2px; }}
  </style>
</head>
<body>
<div class="container">
  <h1>CHRONO-LEAK</h1>
  <p style="color:#888; margin-top:-10px">Temporal De-Anonymization Report</p>

  <div class="card">
    <h2>TARGET</h2>
    <div style="font-size:20px; color:white">@{username}</div>
    <div style="color:#888; margin-top:4px">
      {len(data)} data points analyzed &nbsp;|&nbsp;
      {len(set(e['date'] for e in data))} active days
    </div>
  </div>

  <div class="card">
    <h2>TIMEZONE VERDICT</h2>
    <div class="verdict">
      <div class="tz">{top_tz['timezone']}</div>
      <div class="conf">Confidence: {top_tz['confidence']}% &mdash; {top_tz.get('status', 'candidate').replace('_', ' ')}</div>
    </div>
    <br>
    <h2>ALL CANDIDATES</h2>
    <table>{tz_rows}</table>
  </div>

  <div class="card">
    <h2>BEHAVIORAL PROFILE</h2>
    {"".join(f'<div class="profile-item"><span class="profile-label">{html_escape(k.replace("_"," ").upper())}</span><span class="profile-value">{html_escape(v)}</span></div>' for k, v in profile.items() if k != "error")}
  </div>

  <div class="card">
    <h2>ACTIVITY HEATMAP (24h)</h2>
    <table>{heatmap_rows}</table>
  </div>

  <div style="color:#444; font-size:12px; text-align:center; margin-top:20px">
    CHRONO-LEAK | For research and educational use only
  </div>
</div>
</body>
</html>"""

    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filepath = os.path.join(reports_dir, f"{username}_report.html")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] HTML report saved: {filepath}")
    return filepath

# ── MAIN ──────────────────────────────────────────────────────────────────────

def analyze(username):
    """
    Full analysis pipeline.
    Load data -> build heatmaps -> detect dead zone ->
    predict timezone -> behavioral profile -> save report
    """
    print("=" * 55)
    print("  CHRONO-LEAK | Analysis Engine")
    print("=" * 55)

    # Step 1: Load scraped data
    data = load_data(username)
    if not data:
        return

    # Step 2: Build activity heatmaps
    print("\n[*] Building activity heatmaps...")
    heatmap     = build_hourly_heatmap(data)
    weekly_map  = build_weekly_heatmap(data)

    # Step 3: Detect dead zone (sleep window)
    print("[*] Detecting sleep/dead zone...")
    dead_start, dead_end, dead_center = find_dead_zone(heatmap)

    if dead_center is not None:
        print(f"[+] Dead zone (UTC): {dead_start:02d}:00 to {dead_end:02d}:00")
        print(f"[+] Sleep center (UTC): ~{dead_center:02d}:00")
    else:
        print("[!] Could not determine dead zone (not enough data)")

    # Step 4: Predict timezone
    print("[*] Predicting timezone...")
    tz_results  = predict_timezone(heatmap, dead_center, sample_count=len(data))
    top_tz      = tz_results[0] if tz_results else {"timezone": "Unknown", "confidence": 0, "offset": 0, "status": "insufficient_evidence"}

    # Step 5: Build behavioral profile
    print("[*] Building behavioral profile...")
    profile     = build_behavioral_profile(data, heatmap, weekly_map, top_tz)

    # ── PRINT RESULTS ─────────────────────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  CHRONO-LEAK ANALYSIS RESULTS")
    print("=" * 55)

    print(f"\n  TARGET:     @{username}")
    print(f"  DATA PTS:   {len(data)} timestamps")
    print(f"  DATE RANGE: {min(e['date'] for e in data)} to {max(e['date'] for e in data)}")

    print(f"\n  TIMEZONE PREDICTION:")
    for i, tz in enumerate(tz_results):
        marker = "  >>>" if i == 0 else "     "
        print(f"  {marker} {tz['timezone']:<35} {tz['confidence']}% confidence")

    print(f"\n  BEHAVIORAL PROFILE:")
    for k, v in profile.items():
        if k != "error":
            label = k.replace("_", " ").upper()
            print(f"       {label:<35} {v}")

    # Print ASCII heatmap
    print_heatmap_ascii(heatmap, tz_offset=top_tz["offset"],
                        label=top_tz["timezone"].split("(")[-1].replace(")", ""))

    # Step 6: Save HTML report
    save_html_report(username, heatmap, weekly_map, tz_results, profile, data)

    print("\n[OK] Analysis complete!")
    print(f"     Open reports/{username}_report.html in your browser to see the visual report.")


if __name__ == "__main__":
    TARGET = "octocat"
    analyze(TARGET)
