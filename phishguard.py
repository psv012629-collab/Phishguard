from urllib.parse import urlparse
import re


def analyze_url(url):
    score = 0
    reasons = []

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    url_lower = url.lower()

    # 1. IP address instead of a domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 25
        reasons.append("URL uses an IP address instead of a domain")

    # 2. Very long URL
    if len(url) > 75:
        score += 15
        reasons.append("URL is unusually long")

    # 3. @ symbol
    if "@" in url:
        score += 20
        reasons.append("URL contains @ symbol")

    # 4. Too many subdomains
    if hostname.count(".") >= 3:
        score += 15
        reasons.append("URL contains many subdomains")

    # 5. Suspicious keywords
    keywords = [
        "login", "signin", "verify", "verification",
        "account", "update", "secure", "password",
        "bank", "wallet", "confirm", "unlock"
    ]

    found_keywords = [
        word for word in keywords
        if word in url_lower
    ]

    if found_keywords:
        score += 10
        reasons.append(
            "Suspicious keyword detected: "
            + ", ".join(found_keywords)
        )

    # 6. HTTP instead of HTTPS
    if parsed.scheme == "http":
        score += 10
        reasons.append("Connection does not use HTTPS")

    # 7. Many hyphens in hostname
    if hostname.count("-") >= 3:
        score += 10
        reasons.append("Hostname contains many hyphens")

    # 8. Encoded characters
    if "%" in url:
        score += 5
        reasons.append("URL contains encoded characters")

    # 9. Suspicious domain patterns
    suspicious_patterns = [
        "secure-login",
        "account-verify",
        "login-verify",
        "bank-login",
        "paypal-login"
    ]

    found_patterns = [
        pattern for pattern in suspicious_patterns
        if pattern in hostname
    ]

    if found_patterns:
        score += 20
        reasons.append(
            "Suspicious domain pattern detected"
        )

    # 10. URL contains a port number
    if parsed.port is not None:
        score += 5
        reasons.append("URL uses a non-standard port")

    score = min(score, 100)

    # Risk classification
    if score >= 60:
        risk = "HIGH RISK"
        recommendation = (
            "Avoid opening this URL and verify the source "
            "through a trusted channel."
        )

    elif score >= 30:
        risk = "MEDIUM RISK"
        recommendation = (
            "Be cautious. Verify the domain and source "
            "before entering any information."
        )

    else:
        risk = "LOW RISK"
        recommendation = (
            "No major warning indicators were detected. "
            "Still verify unfamiliar websites before sharing information."
        )

    return score, risk, reasons, recommendation


if __name__ == "__main__":
    url = input("Enter URL: ")

    score, risk, reasons, recommendation = analyze_url(url)

    print("\n===== PhishGuard =====")
    print(f"Risk Score : {score}/100")
    print(f"Risk Level : {risk}")

    print("\nSecurity Indicators:")

    if reasons:
        for reason in reasons:
            print(f"- {reason}")
    else:
        print("- No obvious suspicious indicators detected.")

    print(f"\nRecommendation: {recommendation}")
