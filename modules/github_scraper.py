"""
CHRONO-LEAK | Module 1: GitHub Scraper
========================================
This module collects all public timestamps from a GitHub user's activity.
It gathers commits, repo creations, and events — without reading any content.
Pure metadata. Pure timestamps.
"""

import requests
import json
import os
from datetime import datetime, timezone

# ── CONFIG ────────────────────────────────────────────────────────────────────
# GitHub allows 60 requests/hour without a token.
# Set GITHUB_TOKEN in your environment or .env for 5000 requests/hour.
# Get one at: github.com/settings/tokens (no special permissions needed)
from env_config import get_key
GITHUB_TOKEN = get_key("GITHUB_TOKEN", "")

HEADERS = {
    "User-Agent": "CHRONO-LEAK-Research-Tool",
    "Accept": "application/vnd.github+json"
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# ── FUNCTIONS ─────────────────────────────────────────────────────────────────

def get_user_info(username):
    """
    Step 1: Check if the user exists and grab basic profile info.
    Returns a dict with their profile or None if not found.
    """
    print(f"\n[*] Looking up GitHub user: {username}")

    url = f"https://api.github.com/users/{username}"
    response = requests.get(url, headers=HEADERS)

    # 404 means the user doesn't exist
    if response.status_code == 404:
        print(f"[!] User '{username}' not found on GitHub.")
        return None

    # 403 means we hit the rate limit
    if response.status_code == 403:
        print("[!] Rate limit hit. Add a GitHub token to GITHUB_TOKEN variable above.")
        return None

    data = response.json()

    print(f"[+] Found: {data.get('name', 'No name')} (@{data['login']})")
    print(f"    Account created: {data['created_at']}")
    print(f"    Public repos:    {data['public_repos']}")
    print(f"    Followers:       {data['followers']}")

    return data


def get_all_repos(username):
    """
    Step 2: Get all public repositories and their timestamps.
    Each repo creation/update time is a data point for our analysis.
    """
    print(f"\n[*] Fetching repositories for {username}...")

    all_repos = []
    page = 1

    # GitHub paginates results (max 100 per page), so we loop through all pages
    while True:
        url = f"https://api.github.com/users/{username}/repos?per_page=100&page={page}"
        response = requests.get(url, headers=HEADERS)

        if response.status_code != 200:
            break

        repos = response.json()

        # If the page is empty, we've got everything
        if not repos:
            break

        for repo in repos:
            all_repos.append({
                "source":     "github_repo_created",
                "repo_name":  repo["name"],
                "timestamp":  repo["created_at"],
                "language":   repo.get("language", "Unknown")
            })

        page += 1

    print(f"[+] Found {len(all_repos)} repositories")
    return all_repos


def get_commit_timestamps(username, repos):
    """
    Step 3: Dig into each repo and pull every commit timestamp.
    This is the richest source of data — commits happen constantly.
    We only look at commits where they are the author.
    """
    print(f"\n[*] Scraping commit timestamps from {len(repos)} repos...")

    all_commits = []

    for repo_data in repos:
        repo_name = repo_data["repo_name"]
        url = f"https://api.github.com/repos/{username}/{repo_name}/commits?author={username}&per_page=100"

        response = requests.get(url, headers=HEADERS)

        # Some repos might be empty or have restricted access
        if response.status_code != 200:
            continue

        commits = response.json()

        # Sometimes GitHub returns a dict (error message) instead of a list
        if not isinstance(commits, list):
            continue

        for commit in commits:
            # Navigate the nested JSON to find the timestamp
            try:
                timestamp = commit["commit"]["author"]["date"]
                all_commits.append({
                    "source":    "github_commit",
                    "repo_name": repo_name,
                    "timestamp": timestamp,
                    "language":  repo_data["language"]
                })
            except (KeyError, TypeError):
                continue  # Skip malformed commit data

        print(f"    [{repo_name}] -> {len(commits)} commits scraped")

    print(f"[+] Total commits collected: {len(all_commits)}")
    return all_commits


def get_public_events(username):
    """
    Step 4: Get recent public events (last ~90 days, max 300).
    This includes PRs, issues, stars, forks — everything the user did.
    """
    print(f"\n[*] Fetching public events for {username}...")

    all_events = []
    page = 1

    while page <= 3:  # GitHub caps events at 3 pages (300 events max)
        url = f"https://api.github.com/users/{username}/events/public?per_page=100&page={page}"
        response = requests.get(url, headers=HEADERS)

        if response.status_code != 200:
            break

        events = response.json()

        if not events:
            break

        for event in events:
            all_events.append({
                "source":     "github_event",
                "repo_name":  event.get("repo", {}).get("name", "unknown"),
                "timestamp":  event["created_at"],
                "event_type": event["type"]
            })

        page += 1

    print(f"[+] Found {len(all_events)} recent events")
    return all_events


def scrape_github(username):
    """
    MAIN FUNCTION — runs all scrapers and combines the results.
    Call this from other modules.
    Returns a list of timestamp data points ready for analysis.
    """
    print("=" * 55)
    print("  CHRONO-LEAK | GitHub Scraper")
    print("=" * 55)

    # Step 1: Check user exists
    user_info = get_user_info(username)
    if not user_info:
        return []

    # Step 2: Get repos
    repos = get_all_repos(username)

    # Step 3: Get commits (needs repo list first)
    commits = get_commit_timestamps(username, repos)

    # Step 4: Get events
    events = get_public_events(username)

    # Combine everything into one clean list
    all_data = repos + commits + events

    # Add a parsed datetime object to each entry (makes analysis easier)
    for entry in all_data:
        dt = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
        entry["datetime_utc"] = dt
        entry["hour_utc"]     = dt.hour
        entry["minute_utc"]   = dt.minute
        entry["day_of_week"]  = dt.strftime("%A")  # e.g. "Monday"
        entry["date"]         = dt.strftime("%Y-%m-%d")

    print(f"\n[+] TOTAL DATA POINTS COLLECTED: {len(all_data)}")
    print(f"    Date range: {min(e['date'] for e in all_data)} to {max(e['date'] for e in all_data)}")

    return all_data, user_info


def save_raw_data(data, username):
    """
    Save the raw scraped data to a JSON file.
    This lets us re-run analysis without re-scraping.
    """
    # Resolve reports/ at the project root and create it if missing —
    # it's gitignored, so a fresh clone won't have it yet.
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filepath = os.path.join(reports_dir, f"{username}_github_raw.json")

    # Convert datetime objects to strings for JSON serialization
    clean_data = []
    for entry in data:
        clean_entry = {k: v for k, v in entry.items() if k != "datetime_utc"}
        clean_data.append(clean_entry)

    with open(filepath, "w") as f:
        json.dump(clean_data, f, indent=2)

    print(f"\n[+] Raw data saved to: {filepath}")


# ── RUN DIRECTLY ──────────────────────────────────────────────────────────────
# This block only runs when you run THIS file directly
# (not when it's imported by another module)

if __name__ == "__main__":
    # Change this to any GitHub username you want to analyze
    TARGET = "octocat"

    result = scrape_github(TARGET)

    if result:
        data, user_info = result
        save_raw_data(data, TARGET)

        print("\n--- SAMPLE OF COLLECTED DATA ---")
        for entry in data[:5]:
            print(f"  {entry['timestamp']}  |  {entry['source']}  |  {entry.get('repo_name','')}")

        print(f"\n[OK] Module 1 complete. {len(data)} timestamps ready for analysis.")
