
import re

SUSPICIOUS_WORDS = [
    "urgent",
    "blocked",
    "suspended",
    "verify your account",
    "password",
    "bank details",
    "click here",
    "immediately",
    "won a prize"
]


def analyze_email(email):

    findings = []
    score = 0

    email = email.lower()

    for word in SUSPICIOUS_WORDS:

        if word in email:
            findings.append("Suspicious phrase detected: " + word)
            score += 10

    score = min(score, 100)

    if score >= 60:
        risk = "HIGH RISK"

    elif score >= 25:
        risk = "SUSPICIOUS"

    else:
        risk = "LOW RISK"

    if not findings:
        findings.append("No suspicious keywords detected.")

    return {
        "score": score,
        "risk": risk,
        "findings": findings
    }
