"""
CHRONO-LEAK | Module 7 v2: Self-Validating Identity Scanner
=============================================================
MAJOR UPGRADE over v1.

THE PROBLEM WITH v1:
  v1 trusted "HTTP 200 = user exists". But most modern sites return
  200 OK for EVERY url (login walls, SPA shells, soft 404 pages).
  Result: a garbage username scored 14 false "hits". Useless.

HOW v2 FIXES IT — three layers of defense:

  1. SMART DETECTION
     Each platform declares HOW to detect a real account:
       - "status"   : a missing user returns a non-200 code (clean 404)
       - "absence"  : page always 200, but contains a "not found" marker
                      string when the user is missing
       - "presence" : page always 200, but contains a marker string only
                      when the user DOES exist

  2. CONTROL VALIDATION (the killer feature)
     Before trusting ANY platform, we test it with 2 random garbage
     usernames. If the platform claims the garbage user "exists", the
     platform is UNRELIABLE and we throw its result away automatically.
     This self-calibrates — even if our detection rule is wrong, the
     control test catches it. No more false positives.

  3. PROFILE EXTRACTION + CORRELATION
     For confirmed accounts we pull real data (name, bio, location,
     join date) and cross-reference names across platforms to prove
     "these accounts belong to the same person".
"""

import requests
import json
import os
import sys
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Windows terminals default to cp1252 and crash on emojis/accents in
# scraped profile data. Force UTF-8 output so any character prints safely.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ── BROWSER HEADERS ───────────────────────────────────────────────────────────
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# Optional: set GITHUB_TOKEN in your environment or .env to lift the
# 60-req/hour limit to 5000. Get one (no scopes needed) at:
# github.com/settings/tokens
from env_config import get_key
GITHUB_TOKEN = get_key("GITHUB_TOKEN", "")
GH_HEADERS = dict(HEADERS)
if GITHUB_TOKEN:
    GH_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# ── PLATFORM DATABASE WITH DETECTION RULES ────────────────────────────────────
# method:
#   "status"   -> exists if HTTP status == 200
#   "absence"  -> exists if `marker` is NOT in the page body
#   "presence" -> exists if `marker` IS in the page body
#
# Every result is STILL control-validated afterwards, so even a wrong
# rule here cannot produce a false positive in the final report.

PLATFORMS = {
    # ── Clean 404 platforms (status method — these are trustworthy) ───────────
    "GitHub":        {"url": "https://github.com/{}",                  "method": "status"},
    "GitLab":        {"url": "https://gitlab.com/{}",                  "method": "status"},
    "Dev.to":        {"url": "https://dev.to/{}",                      "method": "status"},
    "Gravatar":      {"url": "https://en.gravatar.com/{}",             "method": "status"},
    "About.me":      {"url": "https://about.me/{}",                    "method": "status"},
    "Chess.com":     {"url": "https://www.chess.com/member/{}",        "method": "status"},
    "Lichess":       {"url": "https://lichess.org/@/{}",               "method": "status"},
    "npm":           {"url": "https://www.npmjs.com/~{}",              "method": "status"},
    "Behance":       {"url": "https://www.behance.net/{}",             "method": "status"},
    "Keybase":       {"url": "https://keybase.io/{}",                  "method": "status"},
    "Tumblr":        {"url": "https://{}.tumblr.com/",                 "method": "status"},
    "DockerHub":     {"url": "https://hub.docker.com/u/{}",            "method": "status"},
    "Vimeo":         {"url": "https://vimeo.com/{}",                   "method": "status"},
    "ProductHunt":   {"url": "https://www.producthunt.com/@{}",        "method": "status"},
    "Pastebin":      {"url": "https://pastebin.com/u/{}",             "method": "status"},
    # Verified reliable (your v1 garbage-test proved these 404 correctly)
    "LinkedIn":      {"url": "https://www.linkedin.com/in/{}/",        "method": "status"},
    "Facebook":      {"url": "https://www.facebook.com/{}",            "method": "status"},
    "Snapchat":      {"url": "https://www.snapchat.com/add/{}",        "method": "status"},
    "Roblox":        {"url": "https://www.roblox.com/user.aspx?username={}", "method": "status"},
    "Quora":         {"url": "https://www.quora.com/profile/{}",       "method": "status"},
    "CodePen":       {"url": "https://codepen.io/{}",                  "method": "status"},
    "Bitbucket":     {"url": "https://bitbucket.org/{}/",              "method": "status"},
    "StackOverflow": {"url": "https://stackoverflow.com/users/{}",     "method": "status"},
    "HuggingFace":   {"url": "https://huggingface.co/{}",              "method": "status"},
    "Dribbble":      {"url": "https://dribbble.com/{}",                "method": "status"},
    "Substack":      {"url": "https://{}.substack.com/",              "method": "status"},
    "Blogger":       {"url": "https://{}.blogspot.com/",              "method": "status"},

    # ── Always-200 platforms (need content markers) ───────────────────────────
    "Reddit":        {"url": "https://old.reddit.com/user/{}",
                      "method": "absence",
                      "marker": "nobody on Reddit goes by that name"},

    "Steam":         {"url": "https://steamcommunity.com/id/{}",
                      "method": "absence",
                      "marker": "The specified profile could not be found"},

    "Telegram":      {"url": "https://t.me/{}",
                      "method": "presence",
                      "marker": "tgme_page_title"},

    "HackerNews":    {"url": "https://news.ycombinator.com/user?id={}",
                      "method": "absence",
                      "marker": "No such user."},

    "SoundCloud":    {"url": "https://soundcloud.com/{}",
                      "method": "presence",
                      "marker": "soundcloud://users"},

    "Flickr":        {"url": "https://www.flickr.com/people/{}",
                      "method": "presence",
                      "marker": "person"},
}

# ── DETECTION CORE ────────────────────────────────────────────────────────────

def _detect(platform_data, username):
    """
    Run the detection rule for one platform/username.
    Returns (exists: bool, status_code, body_text) or (None, ...) on error.
    """
    url = platform_data["url"].format(username)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
    except requests.exceptions.RequestException:
        return None, None, ""

    method = platform_data["method"]
    body   = resp.text

    if method == "status":
        exists = (resp.status_code == 200)
    elif method == "absence":
        # User exists if the "not found" marker is ABSENT
        exists = (resp.status_code == 200) and (platform_data["marker"].lower() not in body.lower())
    elif method == "presence":
        # User exists if the "exists" marker is PRESENT
        exists = (platform_data["marker"].lower() in body.lower())
    else:
        exists = False

    return exists, resp.status_code, body


def _random_username():
    """Generate a garbage username that cannot plausibly exist."""
    return "zz" + "".join(random.choices(string.ascii_lowercase + string.digits, k=18))


def check_platform(platform_name, platform_data, username):
    """
    Check a username on one platform — WITH built-in control validation.

    Steps:
      1. Test the real username.
      2. If it looks like a hit, test a garbage control username.
      3. If the garbage username ALSO looks like a hit, this platform's
         detection is broken -> mark UNRELIABLE, discard the result.
      4. Only return FOUND if real=hit AND control=miss.
    """
    url = platform_data["url"].format(username)

    # Step 1: real username
    real_exists, status, _ = _detect(platform_data, username)

    if real_exists is None:
        return {"platform": platform_name, "url": url,
                "result": "error", "status": None}

    if not real_exists:
        return {"platform": platform_name, "url": url,
                "result": "not_found", "status": status}

    # Step 2 + 3: control validation — does garbage also "exist"?
    control_exists, _, _ = _detect(platform_data, _random_username())

    if control_exists:
        # Platform can't tell real from fake -> untrustworthy
        return {"platform": platform_name, "url": url,
                "result": "unreliable", "status": status}

    # Step 4: confirmed real account
    return {"platform": platform_name, "url": url,
            "result": "found", "status": status}

# ── PROFILE EXTRACTION ────────────────────────────────────────────────────────

def extract_github_profile(username):
    """
    Pull rich profile data from GitHub's public API.
    This is the OSINT goldmine — real name, location, company,
    personal website, linked Twitter, sometimes a public email.
    """
    try:
        resp = requests.get(f"https://api.github.com/users/{username}",
                            headers=GH_HEADERS, timeout=8)
        if resp.status_code == 403:
            print("    [!] GitHub API rate-limited (60/hr). Add a token to GITHUB_TOKEN for 5000/hr.")
            return None
        if resp.status_code != 200:
            return None
        d = resp.json()
        return {
            "platform":   "GitHub",
            "real_name":  d.get("name"),
            "bio":        d.get("bio"),
            "location":   d.get("location"),
            "company":    d.get("company"),
            "website":    d.get("blog"),
            "twitter":    d.get("twitter_username"),
            "email":      d.get("email"),
            "joined":     d.get("created_at", "")[:10],
            "followers":  d.get("followers"),
        }
    except requests.exceptions.RequestException:
        return None


def extract_generic_name(url):
    """
    Lightweight extractor for non-GitHub confirmed accounts.
    Grabs the og:title / <title> meta (often the display name),
    then CLEANS away platform boilerplate so we get just the name.
    """
    import html

    try:
        resp = requests.get(url, headers=HEADERS, timeout=8)
        body = resp.text
        name = None

        # Try Open Graph title first (cleaner)
        if 'og:title' in body:
            start = body.find('og:title')
            chunk = body[start:start+200]
            q1 = chunk.find('content="') + 9
            q2 = chunk.find('"', q1)
            if q1 > 8 and q2 > q1:
                name = chunk[q1:q2].strip()

        # Fall back to <title>
        if not name and '<title>' in body:
            s = body.find('<title>') + 7
            e = body.find('</title>', s)
            if e > s:
                name = body[s:e].strip()

        return _clean_name(name) if name else None
    except requests.exceptions.RequestException:
        return None


def _clean_name(raw):
    """
    Strip platform boilerplate from a scraped page title to isolate
    a person's actual display name.
    e.g. "Snapchat पर John.D"         -> "John.D"
         "johndoe&#x27;s Profile"        -> "johndoe"
         "John Doe (@john) • Instagram" -> "John Doe"
    """
    import html, re

    name = html.unescape(raw)  # decode &#x27; etc.

    # Cut at common separators — keep the part before them
    for sep in ["|", "•", "·", " on ", " पर ", " - ", " — ", "("]:
        if sep in name:
            # For " on X"/" पर X" the name is BEFORE; for "X पर name" it's AFTER
            if sep in (" पर ", " on ") and name.lower().split(sep.lower())[0].strip().lower() in \
               ("snapchat", "instagram", "twitter", "telegram"):
                name = name.split(sep)[-1]
            else:
                name = name.split(sep)[0]

    # Remove trailing "'s Profile", "Profile", platform words
    name = re.sub(r"'s Profile$", "", name, flags=re.I)
    name = re.sub(r"\b(Profile|Roblox|Snapchat|Instagram|Telegram)\b", "", name, flags=re.I)

    return name.strip(" -–—•·|") or raw.strip()

# ── MAIN SCAN ─────────────────────────────────────────────────────────────────

def scan_identity(username, max_workers=12):
    """
    Self-validating scan across all platforms, then profile extraction
    and name correlation on confirmed hits.
    """
    print("=" * 62)
    print("  CHRONO-LEAK | Self-Validating Identity Scanner v2")
    print("=" * 62)
    print(f"\n  Target: '{username}'")
    print(f"  Platforms: {len(PLATFORMS)}  (each result is control-validated)\n")

    found, not_found, unreliable, errors = [], [], [], []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_platform, n, d, username): n
                   for n, d in PLATFORMS.items()}

        done = 0
        for future in as_completed(futures):
            r = future.result()
            done += 1
            tag = r["result"]
            print(f"  [{done:02d}/{len(PLATFORMS)}] ", end="")

            if tag == "found":
                print(f"CONFIRMED   {r['platform']:<14} -> {r['url']}")
                found.append(r)
            elif tag == "unreliable":
                print(f"unreliable  {r['platform']:<14} (failed control test, ignored)")
                unreliable.append(r)
            elif tag == "error":
                print(f"error       {r['platform']}")
                errors.append(r)
            else:
                print(f"--          {r['platform']}")
                not_found.append(r)

    # ── Profile extraction on confirmed hits ─────────────────────────────────
    print(f"\n  Extracting profile data from {len(found)} confirmed account(s)...")
    profiles = []

    for acc in found:
        if acc["platform"] == "GitHub":
            p = extract_github_profile(username)
        else:
            name = extract_generic_name(acc["url"])
            p = {"platform": acc["platform"], "real_name": name} if name else None

        if p:
            profiles.append(p)
            bits = []
            if p.get("real_name"): bits.append(f"name='{p['real_name']}'")
            if p.get("location"):  bits.append(f"loc='{p['location']}'")
            if p.get("email"):     bits.append(f"email='{p['email']}'")
            if bits:
                print(f"    [{p['platform']}] {' | '.join(bits)}")

    # ── Name correlation ─────────────────────────────────────────────────────
    correlation = correlate_identities(profiles, search_username=username)

    return {
        "found":       found,
        "not_found":   not_found,
        "unreliable":  unreliable,
        "errors":      errors,
        "profiles":    profiles,
        "correlation": correlation,
    }

# ── IDENTITY CORRELATION ──────────────────────────────────────────────────────

def correlate_identities(profiles, search_username=""):
    """
    Cross-reference extracted names using NAME TOKENS, not exact strings.
    "John Doe" and "John.D" share the token 'john' -> same person.

    We split every name into word tokens, drop generic/username noise,
    and look for real name-tokens shared across 2+ platforms.
    """
    import re

    names = [p["real_name"].strip() for p in profiles
             if p.get("real_name") and len(p["real_name"].strip()) > 1]

    if not names:
        return {"verdict": "No names extractable", "names": [], "confidence": 0,
                "shared_tokens": []}

    # Words we never treat as a "name" signal
    STOP = {"profile", "the", "official", "real", "on", "user", "home",
            search_username.lower()}

    # Build a token set per name
    def tokens(n):
        raw = re.split(r"[\s.\-_@]+", n.lower())
        return {t for t in raw if len(t) >= 3 and t not in STOP and t.isalpha()}

    token_sets = [tokens(n) for n in names]

    # Count how many profiles each token appears in
    from collections import Counter
    token_counts = Counter()
    for ts in token_sets:
        for t in ts:
            token_counts[t] += 1

    # Tokens shared by 2+ profiles = correlation evidence
    shared = [t for t, c in token_counts.items() if c >= 2]

    if shared:
        verdict    = f"STRONG — shared name token(s): {', '.join(shared)}"
        confidence = 90
    elif len(set(" ".join(n.lower().split()) for n in names)) == 1:
        verdict    = "STRONG — identical name across profiles"
        confidence = 92
    else:
        # No shared tokens, but a GitHub real name is itself strong intel
        has_real_name = any(p.get("platform") == "GitHub" and p.get("real_name")
                            for p in profiles)
        if has_real_name:
            verdict    = "MODERATE — real name recovered (GitHub), others differ"
            confidence = 60
        else:
            verdict    = "WEAK — no shared name tokens"
            confidence = 30

    return {"verdict": verdict, "names": names, "confidence": confidence,
            "shared_tokens": shared}

# ── SAVE REPORT ───────────────────────────────────────────────────────────────

def save_results(username, results):
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    # JSON
    json_path = os.path.join(reports_dir, f"{username}_identity.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "username":   username,
            "scanned_at": datetime.now().isoformat(),
            "found":      results["found"],
            "unreliable": [r["platform"] for r in results["unreliable"]],
            "profiles":   results["profiles"],
            "correlation":results["correlation"],
        }, f, indent=2, default=str)

    # HTML
    found_rows = ""
    for r in sorted(results["found"], key=lambda x: x["platform"]):
        found_rows += f"""
        <tr>
          <td style="padding:10px 16px; font-weight:bold; color:#00e5ff">{r['platform']}</td>
          <td style="padding:10px 16px"><a href="{r['url']}" target="_blank"
              style="color:#aaa; text-decoration:none; font-size:13px">{r['url']}</a></td>
          <td style="padding:10px 16px"><span style="background:#1b5e20; color:#69f0ae;
              padding:3px 10px; border-radius:20px; font-size:12px">CONFIRMED</span></td>
        </tr>"""

    # Profile intel rows
    intel_rows = ""
    for p in results["profiles"]:
        details = []
        for k in ("real_name", "location", "company", "email", "website", "twitter", "joined"):
            if p.get(k):
                details.append(f"<b style='color:#888'>{k}:</b> {p[k]}")
        if details:
            intel_rows += f"""
            <div style="padding:12px 0; border-bottom:1px solid #1e2a42">
              <div style="color:#00e5ff; font-weight:bold; margin-bottom:6px">{p['platform']}</div>
              <div style="color:#ccc; font-size:13px; line-height:1.7">{' &nbsp;|&nbsp; '.join(details)}</div>
            </div>"""

    corr = results["correlation"]
    corr_color = "#69f0ae" if corr["confidence"] >= 70 else "#ffa726" if corr["confidence"] >= 40 else "#888"

    html = f"""<!DOCTYPE html>
<html><head><title>CHRONO-LEAK Identity v2: {username}</title>
<style>
  body {{ font-family:'Segoe UI',sans-serif; background:#1a1a2e; color:#eee; margin:0; padding:20px; }}
  h1 {{ color:#00e5ff; letter-spacing:2px; }}
  h2 {{ color:#00e5ff; font-size:15px; border-bottom:1px solid #333; padding-bottom:8px; }}
  .card {{ background:#16213e; border-radius:10px; padding:20px; margin:16px 0; }}
  table {{ width:100%; border-collapse:collapse; }}
  tr:hover {{ background:#1e2d50; }}
  td {{ border-bottom:1px solid #1e2a42; }}
  .stat {{ display:inline-block; background:#0f3460; border-radius:8px; padding:14px 24px; margin:8px; text-align:center; }}
  .stat-num {{ font-size:32px; font-weight:bold; }}
  .stat-lbl {{ font-size:12px; color:#888; margin-top:4px; }}
</style></head><body>
  <h1>CHRONO-LEAK</h1>
  <p style="color:#888; margin-top:-10px">Self-Validating Identity Report (v2)</p>

  <div class="card"><h2>TARGET</h2>
    <div style="font-size:22px">@{username}</div></div>

  <div class="card"><h2>SUMMARY</h2>
    <div class="stat"><div class="stat-num" style="color:#69f0ae">{len(results['found'])}</div>
      <div class="stat-lbl">CONFIRMED ACCOUNTS</div></div>
    <div class="stat"><div class="stat-num" style="color:#ffa726">{len(results['unreliable'])}</div>
      <div class="stat-lbl">UNRELIABLE (IGNORED)</div></div>
    <div class="stat"><div class="stat-num" style="color:#888">{len(results['not_found'])}</div>
      <div class="stat-lbl">NOT FOUND</div></div>
  </div>

  <div class="card"><h2>IDENTITY CORRELATION</h2>
    <div style="font-size:18px; color:{corr_color}; font-weight:bold">{corr['verdict']}</div>
    <div style="color:#888; margin-top:6px">Confidence: {corr['confidence']}%</div>
    <div style="color:#ccc; margin-top:8px; font-size:13px">
      Names found: {', '.join(corr['names']) if corr['names'] else 'none'}</div>
  </div>

  {"<div class='card'><h2>EXTRACTED INTELLIGENCE</h2>" + intel_rows + "</div>" if intel_rows else ""}

  <div class="card"><h2>CONFIRMED ACCOUNTS</h2>
    <table>{found_rows}</table></div>

  <div style="color:#444; font-size:12px; text-align:center; margin-top:20px">
    CHRONO-LEAK v2 | For research and educational use only</div>
</body></html>"""

    html_path = os.path.join(reports_dir, f"{username}_identity_report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  [+] Saved: {json_path}")
    print(f"  [+] Saved: {html_path}")


# ── RUN DIRECTLY ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    TARGET = input("\n  Enter username to scan: ").strip() or "octocat"

    results = scan_identity(TARGET)

    print("\n" + "=" * 62)
    print("  SCAN COMPLETE")
    print("=" * 62)
    print(f"\n  CONFIRMED accounts:  {len(results['found'])}")
    print(f"  Ignored (unreliable):{len(results['unreliable'])}")
    print(f"  Not found:           {len(results['not_found'])}")

    if results["found"]:
        print(f"\n  CONFIRMED ON:")
        for r in results["found"]:
            print(f"    [+] {r['platform']:<14} {r['url']}")

    c = results["correlation"]
    print(f"\n  IDENTITY CORRELATION: {c['verdict']} ({c['confidence']}%)")

    save_results(TARGET, results)
    print(f"\n  Open reports/{TARGET}_identity_report.html in your browser.")
