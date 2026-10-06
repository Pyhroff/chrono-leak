"""
CHRONO-LEAK | Module 8: Breach & Leak Checker
===============================================
Checks if an email address or password has appeared in
known data breaches and leaks.

Two checks:
  1. EMAIL  → HaveIBeenPwned API (free API key needed)
             Shows every breach your email appeared in
             with details: what data was exposed, when, how many victims

  2. PASSWORD → HaveIBeenPwned Pwned Passwords (100% free, no key needed)
               Uses k-anonymity — your password is NEVER sent over the network
               Only first 5 chars of its SHA1 hash are sent
               If it's in a breach database, you'll know instantly

How to get a FREE HIBP API key:
  1. Go to https://haveibeenpwned.com/API/Key
  2. Sign up (it's free for personal use)
  3. Paste your key below in HIBP_API_KEY
"""

import requests
import hashlib
import json
import os
import time
from datetime import datetime
from urllib.parse import quote
from report_utils import html_escape

# ── CONFIG ────────────────────────────────────────────────────────────────────
# Get your free key at: https://haveibeenpwned.com/API/Key
# Set HIBP_API_KEY in your environment or .env to enable the email breach
# check. Leave it unset to skip that step (the password check still works).
from env_config import get_key
HIBP_API_KEY = get_key("HIBP_API_KEY", "")

HIBP_HEADERS = {
    "User-Agent":    "CHRONO-LEAK-Personal-Security-Audit",
    "hibp-api-key":  HIBP_API_KEY
}

# ── EMAIL BREACH CHECK ────────────────────────────────────────────────────────

def check_email_breaches(email):
    """
    Check if an email has appeared in known data breaches.
    Returns a list of breach objects with details.

    Requires HIBP API key (free at haveibeenpwned.com/API/Key)
    """
    if not HIBP_API_KEY:
        print("\n[!] No HIBP API key set.")
        print("    Get a free key at: https://haveibeenpwned.com/API/Key")
        print("    Then paste it into breach_checker.py in the HIBP_API_KEY variable.")
        print("    Skipping email breach check...\n")
        return None

    print(f"\n[*] Checking email: {email}")
    print("    (checking HaveIBeenPwned database...)")

    # Privacy-preserving email lookup: hash locally and send only the first 6 SHA-1 chars.\n    # HIBP requires an API key for this k-anonymity email endpoint.\n    digest = hashlib.sha1(email.strip().lower().encode("utf-8")).hexdigest().upper()\n    prefix, suffix = digest[:6], digest[6:]\n    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/range/{prefix}"

    try:
        response = requests.get(url, headers=HIBP_HEADERS, timeout=10)

        # 404 = good news, email not found in any breach
        if response.status_code == 404:
            print(f"\n[+] GOOD NEWS: {email} was NOT found in any known breach!")
            return []

        # 401 = invalid or missing API key
        if response.status_code == 401:
            print("[!] Invalid API key. Check your HIBP_API_KEY value.")
            return None

        # 429 = rate limited, wait and retry
        if response.status_code == 429:
            retry_after = min(int(response.headers.get("Retry-After", 5)), 30)
            print(f"[!] Rate limited. Waiting {retry_after} seconds (single retry)...")
            time.sleep(retry_after + 1)
            response = requests.get(url, headers=HIBP_HEADERS, timeout=10)
            if response.status_code == 200:
                return response.json()
            print(f"[!] HIBP retry failed (status {response.status_code}).")
            return None

        if response.status_code == 200:
            breaches = response.json()
            print(f"\n[!] ALERT: {email} found in {len(breaches)} breach(es)!")
            return breaches

    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")
        return None

    return None


def display_breach_details(breaches):
    """
    Display breach details in a readable format.
    Shows what data was exposed in each breach.
    """
    if not breaches:
        return

    # Sort by date (most recent first)
    breaches_sorted = sorted(
        breaches,
        key=lambda x: x.get("BreachDate", "0000-00-00"),
        reverse=True
    )

    print("\n" + "=" * 55)
    print("  BREACH DETAILS")
    print("=" * 55)

    for i, breach in enumerate(breaches_sorted, 1):
        name        = breach.get("Name", "Unknown")
        domain      = breach.get("Domain", "Unknown")
        date        = breach.get("BreachDate", "Unknown")
        pwn_count   = breach.get("PwnCount", 0)
        description = breach.get("Description", "")
        data_classes= breach.get("DataClasses", [])
        is_verified = breach.get("IsVerified", False)
        is_sensitive= breach.get("IsSensitive", False)

        # Format the victim count nicely
        if pwn_count >= 1_000_000:
            count_str = f"{pwn_count/1_000_000:.1f}M victims"
        elif pwn_count >= 1_000:
            count_str = f"{pwn_count/1_000:.0f}K victims"
        else:
            count_str = f"{pwn_count} victims"

        # Severity based on what data was exposed
        high_risk_data = {"Passwords", "Credit cards", "Bank account numbers",
                          "Social security numbers", "Passport numbers"}
        severity = "HIGH" if any(d in high_risk_data for d in data_classes) else "MEDIUM"
        if is_sensitive:
            severity = "HIGH"

        print(f"\n  [{i}] {name} ({domain})")
        print(f"      Date:      {date}")
        print(f"      Scale:     {count_str}")
        print(f"      Severity:  {severity}")
        print(f"      Verified:  {'Yes' if is_verified else 'No'}")
        print(f"      Exposed:   {', '.join(data_classes[:6])}")

        # Show if password was exposed — this is the most critical info
        if "Passwords" in data_classes:
            print(f"      !! PASSWORD WAS EXPOSED — change it immediately if still using it !!")

# ── PASSWORD BREACH CHECK (FREE, NO KEY NEEDED) ───────────────────────────────

def check_password_breached(password):
    """
    Check if a password has appeared in any known breach.

    Uses k-anonymity model — completely safe:
    1. We hash the password with SHA1
    2. Send only the FIRST 5 CHARACTERS of the hash
    3. Server returns all hashes starting with those 5 chars
    4. We check locally if our full hash is in the list
    5. Your actual password NEVER leaves your computer

    Example:
      password = "hello123"
      sha1     = "8843d7f92416211de9ebb963ff4ce28125932878"
      we send  = "8843d"
      server returns all hashes starting with "8843d"
      we check if our full hash is in that list
    """
    print(f"\n[*] Checking password safety...")
    print("    (using k-anonymity — password never sent over network)")

    # SHA1 hash the password
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix    = sha1_hash[:5]   # First 5 chars sent to server
    suffix    = sha1_hash[5:]   # Rest checked locally

    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            print(f"[!] Error checking password (status {response.status_code})")
            return None

        # Response is a list of "HASH_SUFFIX:COUNT" lines
        # Check if our suffix appears
        hashes = response.text.splitlines()
        for line in hashes:
            parts         = line.split(":")
            hash_suffix   = parts[0]
            breach_count  = int(parts[1]) if len(parts) > 1 else 0

            if hash_suffix == suffix:
                if breach_count >= 1_000_000:
                    count_str = f"{breach_count/1_000_000:.1f}M"
                elif breach_count >= 1_000:
                    count_str = f"{breach_count/1_000:.0f}K"
                else:
                    count_str = str(breach_count)

                print(f"\n  [!!] PASSWORD FOUND IN BREACH DATABASE!")
                print(f"       Seen {count_str} times in known breaches.")
                print(f"       This password is COMPROMISED — change it everywhere you use it!")
                return breach_count

        print(f"\n  [+] Password NOT found in any known breach database.")
        print(f"      (This does not mean it's a strong password — just not leaked yet)")
        return 0

    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")
        return None


# ── USERNAME BREACH CHECK ─────────────────────────────────────────────────────

def check_username_pastes(email):
    """
    Check if an email/username appears in public pastes
    (Pastebin dumps, etc.) — often indicates it was part of a leak.
    Requires HIBP API key.
    """
    if not HIBP_API_KEY:
        return None

    print(f"\n[*] Checking paste sites for: {email}")

    url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"

    try:
        response = requests.get(url, headers=HIBP_HEADERS, timeout=10)

        if response.status_code == 404:
            print("    [+] Not found in any public pastes.")
            return []

        if response.status_code == 200:
            pastes = response.json()
            print(f"    [!] Found in {len(pastes)} public paste(s)!")
            for paste in pastes:
                source = paste.get("Source", "Unknown")
                date   = paste.get("Date", "Unknown date")
                title  = paste.get("Title", "No title")
                print(f"       - {source} | {date} | {title}")
            return pastes

    except Exception:
        pass

    return None


# ── SAVE HTML REPORT ──────────────────────────────────────────────────────────

def save_breach_report(email, breaches, password_count, pastes):
    """
    Save breach check results to an HTML report.
    """
    base_dir    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    safe_email = html_escape(email)

    # Generate breach rows
    breach_rows = ""
    if breaches:
        for b in sorted(breaches, key=lambda x: x.get("BreachDate",""), reverse=True):
            data_classes = b.get("DataClasses", [])
            has_password = "Passwords" in data_classes
            severity_color = "#ef5350" if has_password else "#ffa726"
            severity_label = "HIGH" if has_password else "MEDIUM"

            breach_rows += f"""
            <tr>
              <td style="padding:10px 14px; font-weight:bold">{html_escape(b.get('Name','?'))}</td>
              <td style="padding:10px 14px; color:#888">{html_escape(b.get('BreachDate','?'))}</td>
              <td style="padding:10px 14px; color:#aaa; font-size:12px">
                {html_escape(', '.join(data_classes[:5]))}
              </td>
              <td style="padding:10px 14px">
                <span style="background:{severity_color}22; color:{severity_color};
                             padding:3px 10px; border-radius:20px; font-size:12px">
                  {severity_label}
                </span>
              </td>
            </tr>"""

    # Password status
    if password_count is None:
        pw_status = "Check skipped"
        pw_color  = "#888"
    elif password_count == 0:
        pw_status = "Password NOT found in breaches"
        pw_color  = "#69f0ae"
    else:
        pw_status = f"PASSWORD COMPROMISED ({password_count:,} times seen)"
        pw_color  = "#ef5350"

    breach_count = len(breaches) if breaches else 0
    summary_color = "#ef5350" if breach_count > 0 else "#69f0ae"

    html = f"""<!DOCTYPE html>
<html>
<head>
  <title>CHRONO-LEAK Breach Report: {safe_email}</title>
  <style>
    body  {{ font-family:'Segoe UI',sans-serif; background:#1a1a2e; color:#eee; margin:0; padding:20px; }}
    h1    {{ color:#00e5ff; letter-spacing:2px; }}
    h2    {{ color:#00e5ff; font-size:15px; border-bottom:1px solid #333; padding-bottom:8px; margin-top:28px; }}
    .card {{ background:#16213e; border-radius:10px; padding:20px; margin:16px 0; }}
    table {{ width:100%; border-collapse:collapse; }}
    tr:hover {{ background:#1e2d50; }}
    td    {{ border-bottom:1px solid #1e2a42; }}
    .stat {{ display:inline-block; background:#0f3460; border-radius:8px; padding:14px 24px; margin:8px; text-align:center; }}
    .stat-num {{ font-size:32px; font-weight:bold; }}
    .stat-lbl {{ font-size:12px; color:#888; margin-top:4px; }}
    .alert {{ background:#3e1a1a; border-left:4px solid #ef5350; padding:14px 18px; border-radius:6px; margin:10px 0; }}
    .safe  {{ background:#1a3e1a; border-left:4px solid #69f0ae; padding:14px 18px; border-radius:6px; margin:10px 0; }}
  </style>
</head>
<body>
  <h1>CHRONO-LEAK</h1>
  <p style="color:#888; margin-top:-10px">Breach & Leak Checker Report</p>

  <div class="card">
    <h2>TARGET</h2>
    <div style="font-size:20px" >{safe_email}</div>
  </div>

  <div class="card">
    <h2>SUMMARY</h2>
    <div class="stat">
      <div class="stat-num" style="color:{summary_color}">{breach_count}</div>
      <div class="stat-lbl">BREACHES FOUND</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:{pw_color}; font-size:16px; margin-top:8px">{pw_status}</div>
      <div class="stat-lbl">PASSWORD STATUS</div>
    </div>
  </div>

  {"<div class='card'><h2>BREACH HISTORY</h2><table>" + breach_rows + "</table></div>" if breach_rows else ""}

  <div style="color:#444; font-size:12px; text-align:center; margin-top:20px">
    CHRONO-LEAK | For research and educational use only
  </div>
</body>
</html>"""

    html_path = os.path.join(reports_dir, f"breach_report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] Breach report saved: {html_path}")


# ── MAIN ──────────────────────────────────────────────────────────────────────

def run_breach_check():
    print("=" * 55)
    print("  CHRONO-LEAK | Breach & Leak Checker")
    print("=" * 55)
    print("\n  This module checks if your credentials have been")
    print("  exposed in known data breaches.")
    print("\n  NOTE: All checks are done against public breach databases.")
    print("        Your data is never stored or sent anywhere by this tool.")

    print("\n" + "-" * 55)

    # Email check
    email = input("\n  Enter email to check (or press Enter to skip): ").strip()
    breaches = []
    pastes   = []

    if email:
        breaches = check_email_breaches(email)
        if breaches:
            display_breach_details(breaches)
        pastes = check_username_pastes(email)

    # Password check
    print("\n" + "-" * 55)
    password = input("\n  Enter password to check (or press Enter to skip): ").strip()
    password_count = None

    if password:
        password_count = check_password_breached(password)

    # Summary
    print("\n" + "=" * 55)
    print("  BREACH CHECK COMPLETE")
    print("=" * 55)

    if email and breaches is not None:
        if len(breaches) == 0:
            print(f"\n  [+] {email}: Clean — not found in any breach")
        else:
            print(f"\n  [!] {email}: Found in {len(breaches)} breach(es)")
            high_risk = [b for b in breaches if "Passwords" in b.get("DataClasses",[])]
            if high_risk:
                print(f"      {len(high_risk)} breach(es) included your PASSWORD")
                print(f"      Change your password on these services immediately!")

    if password_count is not None:
        if password_count == 0:
            print(f"\n  [+] Password: Not found in breach databases")
        else:
            print(f"\n  [!] Password: COMPROMISED ({password_count:,} times seen in breaches)")

    # Save report
    if email or password_count is not None:
        save_breach_report(
            email or "anonymous",
            breaches or [],
            password_count,
            pastes or []
        )


if __name__ == "__main__":
    run_breach_check()
