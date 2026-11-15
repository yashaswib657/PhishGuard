
import re
import ipaddress
from urllib.parse import urlparse
from email.utils import parseaddr


# ---------------- SENDER ANALYSIS ----------------

def analyze_sender(sender):

    score = 0
    findings = []

    if not sender.strip():
        findings.append("Sender address was not provided.")
        return score, findings

    # Extract the actual email address
    display_name, address = parseaddr(sender)

    # Check email format
    email_pattern = r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"

    if not re.match(email_pattern, address):
        score += 25
        findings.append("Sender email address has an invalid format.")

        return score, findings

    # Extract domain
    domain = address.rsplit("@", 1)[1].lower()

    # Check whether domain is an IP address
    try:
        ipaddress.ip_address(domain.strip("[]"))

        score += 30
        findings.append("Sender uses an IP address instead of a normal domain.")

    except ValueError:
        pass

    # Check for Punycode domains
    if any(label.startswith("xn--") for label in domain.split(".")):
        score += 20
        findings.append("Sender domain contains Punycode encoding.")

    if not findings:
        findings.append("No basic sender-format warning signs detected.")

    return score, findings


# ---------------- SUBJECT ANALYSIS ----------------

def analyze_subject(subject):

    score = 0
    findings = []

    subject = subject.lower().strip()

    if not subject:
        findings.append("Email subject was not provided.")
        return score, findings

    # Check for urgency
    urgency_words = [
        "urgent",
        "immediately",
        "action required",
        "final notice",
        "act now",
        "within 24 hours",
        "within 30 minutes"
    ]

    for word in urgency_words:
        if word in subject:
            score += 15
            findings.append(
                f"Urgent language detected in subject: '{word}'."
            )
            break

    # Check for account threats
    threat_words = [
        "account suspended",
        "account blocked",
        "account terminated",
        "account locked",
        "unauthorized transfer",
        "security alert"
    ]

    for word in threat_words:
        if word in subject:
            score += 20
            findings.append(
                f"Possible account threat detected: '{word}'."
            )
            break

    # Check for financial or credential-related requests
    sensitive_words = [
        "verify your account",
        "confirm your identity",
        "password reset",
        "payment failed",
        "bank details",
        "security verification"
    ]

    for word in sensitive_words:
        if word in subject:
            score += 20
            findings.append(
                f"Sensitive information-related wording detected: '{word}'."
            )
            break

    # Check excessive exclamation marks
    if subject.count("!") >= 3:
        score += 10
        findings.append(
            "Excessive exclamation marks detected in subject."
        )

    if not findings:
        findings.append(
            "No basic subject-line warning signs detected."
        )

    return score, findings

# ---------------- BODY ANALYSIS ----------------

def analyze_body(body):

    score = 0
    findings = []

    body = body.lower().strip()

    if not body:
        findings.append("Email body was not provided.")
        return score, findings

    # Check for password and OTP requests
    sensitive_words = [
        "password",
        "otp",
        "one time password",
        "cvv",
        "card number",
        "bank details",
        "login credentials"
    ]

    for word in sensitive_words:
        if word in body:
            score += 20
            findings.append(
                f"Sensitive information request detected: '{word}'."
            )

    # Check for urgency
    urgency_words = [
        "immediately",
        "within 30 minutes",
        "within 24 hours",
        "act now",
        "urgent action"
    ]

    for word in urgency_words:
        if word in body:
            score += 15
            findings.append(
                f"Urgent language detected: '{word}'."
            )
            break

    # Check for threats
    threat_words = [
        "account will be blocked",
        "account will be suspended",
        "permanently disabled",
        "legal action"
    ]

    for word in threat_words:
        if word in body:
            score += 20
            findings.append(
                f"Threatening language detected: '{word}'."
            )
            break

    if not findings:
        findings.append(
            "No basic body-text warning signs detected."
        )

    return score, findings

# ---------------- URL ANALYSIS ----------------

def analyze_urls(body):

    score = 0
    findings = []

    url_pattern = r"https?://[^\s<>\"']+"
    urls = re.findall(url_pattern, body)

    if not urls:
        findings.append("No URLs found in email body.")
        return score, findings

    shortened_domains = [
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "cutt.ly"
    ]

    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname

        if not domain:
            continue

        try:
            ipaddress.ip_address(domain)
            score += 30
            findings.append("URL uses an IP address: " + url)
        except ValueError:
            pass

        if domain.lower() in shortened_domains:
            score += 20
            findings.append("Shortened URL detected: " + url)

        if "@" in url:
            score += 20
            findings.append("Unusual @ symbol in URL: " + url)

    if not findings:
        findings.append("No basic URL warning signs detected.")

    return score, findings


# ---------------- HEADER ANALYSIS ----------------

def analyze_headers(headers, sender):

    score = 0
    findings = []

    if not headers.strip():
        findings.append("Email headers were not provided.")
        return score, findings

    headers_lower = headers.lower()

    checks = {
        "spf=fail": "SPF authentication failed.",
        "dkim=fail": "DKIM authentication failed.",
        "dmarc=fail": "DMARC authentication failed."
    }

    for keyword, message in checks.items():
        if keyword in headers_lower:
            score += 20
            findings.append(message)

    reply_match = re.search(
        r"reply-to:\s*(.+)",
        headers,
        re.IGNORECASE
    )

    if reply_match:
        reply_address = parseaddr(reply_match.group(1))[1]
        sender_address = parseaddr(sender)[1]

        if reply_address and sender_address:
            if reply_address.lower() != sender_address.lower():
                score += 20
                findings.append(
                    "Reply-To address differs from sender address."
                )

    if not findings:
        findings.append("No basic email-header warning signs detected.")

    return score, findings


# ---------------- MAIN EMAIL ANALYSIS ----------------

def analyze_email(email_data):

    findings = []
    score = 0

    # 1. Sender Analysis
    sender = email_data.get("sender", "")
    sender_score, sender_findings = analyze_sender(sender)
    score += sender_score
    findings.extend(sender_findings)

    # 2. Subject Analysis
    subject_score, subject_findings = analyze_subject(
        email_data.get("subject", "")
    )
    score += subject_score
    findings.extend(subject_findings)

    # 3. Body Analysis
    body = email_data.get("body", "")
    body_score, body_findings = analyze_body(body)
    score += body_score
    findings.extend(body_findings)

    # 4. URL Analysis
    url_score, url_findings = analyze_urls(body)
    score += url_score
    findings.extend(url_findings)

    # 5. Header Analysis
    header_score, header_findings = analyze_headers(
        email_data.get("headers", ""),
        sender
    )
    score += header_score
    findings.extend(header_findings)

    # Final score (maximum 100)
    score = min(score, 100)

    # Risk classification
    if score >= 60:
        risk = "HIGH RISK"
    elif score >= 25:
        risk = "SUSPICIOUS"
    else:
        risk = "LOW RISK"

    return {
        "score": score,
        "risk": risk,
        "findings": findings
    }
