"""Quick test runner for the v2 identity scanner."""
import requests, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Wait for GitHub API rate limit to reset (so profile extraction works)
while True:
    rate = requests.get("https://api.github.com/rate_limit",
                        headers={"User-Agent": "x"}).json()["rate"]
    if rate["remaining"] > 5:
        print(f"[+] GitHub API ready ({rate['remaining']} calls available)\n")
        break
    wait = max(2, int(rate["reset"] - time.time()) + 2)
    print(f"[*] Waiting {min(wait, 75)}s for GitHub API reset...")
    time.sleep(min(wait, 75))

from identity_scanner import scan_identity, save_results

TARGET = sys.argv[1] if len(sys.argv) > 1 else "octocat"
r = scan_identity(TARGET)

print("\n" + "=" * 62)
print("  FINAL RESULT")
print("=" * 62)
print("CONFIRMED  :", [x["platform"] for x in r["found"]])
print("UNRELIABLE :", [x["platform"] for x in r["unreliable"]])
print("PROFILES   :")
for p in r["profiles"]:
    print("   ", {k: v for k, v in p.items() if v})
print("CORRELATION:", r["correlation"]["verdict"], f"({r['correlation']['confidence']}%)")

save_results(TARGET, r)
