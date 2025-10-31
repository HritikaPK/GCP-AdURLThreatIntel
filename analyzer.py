import re
import csv
from datetime import datetime
from collections import Counter
import json


PHISH_KEYWORDS = ["login", "verify", "update", "secure", "account", "payment"]
SUSPICIOUS_TLDS = [".ru", ".xyz", ".biz"]

def score_url(u: str):
    score = 0
    reasons = []
    lower_u = u.lower()

    # Rule 1 – phishing words
    found_phish = [k for k in PHISH_KEYWORDS if k in lower_u]
    if found_phish:
        score += 2
        reasons.append(f"Phishing keywords: {found_phish}")

    # Rule 2 – suspicious domain endings
    if any(lower_u.endswith(tld) or tld in lower_u for tld in SUSPICIOUS_TLDS):
        score += 2
        reasons.append("Suspicious TLD/infrastructure")

    # Rule 3 – encoded characters like %3D or %2F
    if re.search(r"%[0-9a-fA-F]{2}", u):
        score += 2
        reasons.append("Obfuscated / encoded URL")

    # Rule 4 – very long URLs
    if len(u) > 100:
        score += 1
        reasons.append("Unusually long URL")

    return score, reasons


def analyze_file(path_to_csv="urls.csv"):
    results = []
    with open(path_to_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            u = row["url"].strip()
            s, r = score_url(u)
            results.append({
                "url": u,
                "score": s,
                "reasons": r,
                "time": datetime.utcnow().isoformat()
            })
    return results


def summarize(results):
    high_risk = [r for r in results if r["score"] >= 4]
    # Count recurring reasons
    reason_counts = Counter(reason for r in results for reason in r["reasons"])
    summary = {
        "total_urls": len(results),
        "high_risk_count": len(high_risk),
        "common_reasons": list(reason_counts.most_common()),
        "recommendation": "Investigate domains with suspicious TLDs or phishing words."
    }
    return summary


if __name__ == "__main__":
    detections = analyze_file()
    report = summarize(detections)
    print(json.dumps({
        "detections": detections,
        "summary": report
    }, indent=2))
