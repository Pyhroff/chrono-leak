"""
CHRONO-LEAK | Module 3: Instagram Public Profile Scraper
==========================================================
Scrapes public Instagram profiles for:
  - Post timestamps (when they post = behavioral pattern)
  - Location tags (where they've been)
  - Caption patterns (writing style, hashtag habits)
  - Posting frequency (active vs dormant periods)
  - Top hashtags used

Only works on PUBLIC accounts.
Private accounts = zero data accessible.

Uses the instaloader library — no official API needed.
Instagram may rate-limit after many requests.
Adding a delay between requests helps avoid this.
"""

import instaloader
import json
import os
from datetime import datetime
from collections import Counter
import time
import re

# ── SETUP ─────────────────────────────────────────────────────────────────────

def create_loader():
    """
    Create an instaloader instance with settings that reduce
    the chance of Instagram blocking us.
    """
    loader = instaloader.Instaloader(
        # Don't download actual images — we only want metadata
        download_pictures=False,
        download_videos=False,
        download_video_thumbnails=False,
        download_geotags=True,        # Grab location data if public
        download_comments=False,
        save_metadata=False,
        compress_json=False,
        quiet=True                    # Suppress instaloader's own output
    )
    return loader


# ── PROFILE SCRAPER ───────────────────────────────────────────────────────────

def scrape_instagram(username, max_posts=50):
    """
    Scrape a public Instagram profile.
    Returns profile info + list of post data with timestamps.

    max_posts: how many posts to scrape (default 50)
               More = better analysis but slower + higher block risk
    """
    print("=" * 55)
    print("  CHRONO-LEAK | Instagram Scraper")
    print("=" * 55)
    print(f"\n[*] Target: @{username}")
    print(f"[*] Max posts to scan: {max_posts}")
    print("[*] Connecting to Instagram...")
    print("    (no login needed for public profiles)\n")

    loader  = create_loader()
    posts   = []
    profile = None

    try:
        # Load the profile
        profile = instaloader.Profile.from_username(loader.context, username)

        print(f"[+] Profile found!")
        print(f"    Name:       {profile.full_name}")
        print(f"    Followers:  {profile.followers:,}")
        print(f"    Following:  {profile.followees:,}")
        print(f"    Posts:      {profile.mediacount}")
        print(f"    Private:    {profile.is_private}")
        print(f"    Bio:        {profile.biography[:80]}..." if len(profile.biography) > 80 else f"    Bio:        {profile.biography}")

        if profile.is_private:
            print("\n[!] This account is PRIVATE.")
            print("    Cannot scrape post data without following them.")
            print("    CHRONO-LEAK only works on public accounts.")
            return None, None

        print(f"\n[*] Scraping up to {max_posts} posts...")
        print("    (adding 1.5s delay between requests to avoid rate limiting)")

        count = 0
        for post in profile.get_posts():
            if count >= max_posts:
                break

            # Extract all useful data from the post
            post_data = {
                # Core timestamp data (what we need for CHRONO-LEAK)
                "timestamp":  post.date_utc.isoformat() + "Z",
                "hour_utc":   post.date_utc.hour,
                "minute_utc": post.date_utc.minute,
                "day_of_week":post.date_utc.strftime("%A"),
                "date":       post.date_utc.strftime("%Y-%m-%d"),
                "source":     "instagram_post",

                # Extra intel
                "likes":       post.likes,
                "comments":    post.comments,
                "is_video":    post.is_video,
                "hashtags":    list(post.caption_hashtags) if post.caption_hashtags else [],
                "mentions":    list(post.caption_mentions) if post.caption_mentions else [],
                "has_location":post.location is not None,
                "location":    str(post.location.name) if post.location else None,
                "caption_len": len(post.caption) if post.caption else 0,
            }

            posts.append(post_data)
            count += 1

            # Show progress every 10 posts
            if count % 10 == 0:
                print(f"    Scraped {count}/{max_posts} posts...")

            # Polite delay — reduces Instagram rate limiting
            time.sleep(1.5)

        print(f"\n[+] Successfully scraped {len(posts)} posts")

    except instaloader.exceptions.ProfileNotExistsException:
        print(f"[!] Profile @{username} does not exist on Instagram.")
        return None, None

    except instaloader.exceptions.PrivateProfileNotFollowedException:
        print(f"[!] @{username} is a private account. Cannot access posts.")
        return None, None

    except instaloader.exceptions.ConnectionException as e:
        print(f"[!] Instagram connection error: {e}")
        print("    Instagram may be rate-limiting us. Try again in a few minutes.")
        return None, None

    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None, None

    return posts, profile


# ── ANALYSIS ──────────────────────────────────────────────────────────────────

def analyze_instagram_data(posts, username):
    """
    Analyze scraped Instagram data and extract behavioral patterns.
    """
    if not posts:
        print("[!] No posts to analyze.")
        return {}

    print(f"\n[*] Analyzing {len(posts)} posts...")

    # ── Temporal patterns ─────────────────────────────────────────────────────
    hours       = [p["hour_utc"] for p in posts]
    days        = [p["day_of_week"] for p in posts]
    dates       = sorted([p["date"] for p in posts])

    hour_counts = Counter(hours)
    day_counts  = Counter(days)

    # Most active hour (UTC)
    peak_hour_utc = hour_counts.most_common(1)[0][0] if hour_counts else 0

    # Posting frequency
    if len(dates) >= 2:
        first_date = datetime.strptime(dates[0], "%Y-%m-%d")
        last_date  = datetime.strptime(dates[-1], "%Y-%m-%d")
        day_span   = (last_date - first_date).days or 1
        posts_per_week = round((len(posts) / day_span) * 7, 1)
    else:
        posts_per_week = 0

    # ── Content patterns ──────────────────────────────────────────────────────
    all_hashtags = []
    all_locations = []
    for p in posts:
        all_hashtags.extend(p.get("hashtags", []))
        if p.get("location"):
            all_locations.append(p["location"])

    top_hashtags  = Counter(all_hashtags).most_common(10)
    top_locations = Counter(all_locations).most_common(5)

    # ── Engagement patterns ───────────────────────────────────────────────────
    likes_list = [p["likes"] for p in posts if p.get("likes", 0) > 0]
    avg_likes  = round(sum(likes_list) / len(likes_list)) if likes_list else 0

    analysis = {
        "total_posts_scraped": len(posts),
        "date_range":          f"{dates[0]} to {dates[-1]}" if dates else "N/A",
        "posts_per_week":      posts_per_week,
        "peak_posting_hour_utc": peak_hour_utc,
        "most_active_day":     day_counts.most_common(1)[0][0] if day_counts else "N/A",
        "top_hashtags":        top_hashtags,
        "top_locations":       top_locations,
        "avg_likes":           avg_likes,
        "has_location_posts":  sum(1 for p in posts if p["has_location"]),
        "hour_distribution":   dict(hour_counts),
        "day_distribution":    dict(day_counts),
    }

    # ── Print summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  INSTAGRAM ANALYSIS RESULTS")
    print("=" * 55)

    print(f"\n  Posts scraped:       {analysis['total_posts_scraped']}")
    print(f"  Date range:          {analysis['date_range']}")
    print(f"  Posts per week:      {analysis['posts_per_week']}")
    print(f"  Most active day:     {analysis['most_active_day']}")
    print(f"  Peak hour (UTC):     {analysis['peak_posting_hour_utc']:02d}:00 UTC")
    print(f"  Avg likes per post:  {analysis['avg_likes']}")
    print(f"  Posts with location: {analysis['has_location_posts']}")

    if top_hashtags:
        print(f"\n  Top hashtags:")
        for tag, count in top_hashtags[:5]:
            print(f"    #{tag:<25} ({count} uses)")

    if top_locations:
        print(f"\n  Top locations tagged:")
        for loc, count in top_locations:
            print(f"    {loc:<30} ({count} posts)")

    return analysis


# ── SAVE DATA ─────────────────────────────────────────────────────────────────

def save_instagram_data(username, posts, analysis, profile):
    """
    Save scraped posts and analysis to JSON for use by the analyzer module.
    """
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    # Save raw posts (compatible with analyzer.py format)
    output = {
        "username":  username,
        "scraped_at": datetime.now().isoformat(),
        "profile": {
            "full_name":  profile.full_name if profile else "",
            "followers":  profile.followers if profile else 0,
            "post_count": profile.mediacount if profile else 0,
            "bio":        profile.biography if profile else "",
        },
        "posts":    posts,
        "analysis": {
            k: v for k, v in analysis.items()
            if k not in ("hour_distribution", "day_distribution")
        }
    }

    json_path = os.path.join(reports_dir, f"{username}_instagram_raw.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n[+] Instagram data saved: {json_path}")
    print(f"    Feed this into analyzer.py for timezone prediction!")

    return json_path


# ── MAIN ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    TARGET    = input("\n  Enter Instagram username to scrape: ").strip()
    MAX_POSTS = input("  How many posts to scan? (default 30): ").strip()
    MAX_POSTS = int(MAX_POSTS) if MAX_POSTS.isdigit() else 30

    if not TARGET:
        TARGET = "octocat"

    posts, profile = scrape_instagram(TARGET, max_posts=MAX_POSTS)

    if posts:
        analysis = analyze_instagram_data(posts, TARGET)
        save_instagram_data(TARGET, posts, analysis, profile)
        print(f"\n[OK] Instagram scrape complete — {len(posts)} posts collected.")
    else:
        print("\n[!] No data collected. Account may be private or username incorrect.")
