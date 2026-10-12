import re
from urllib.parse import urlparse


# =========================================
# ADVANCED SCAM ANALYSIS
# =========================================

SCAM_PATTERNS = {
    "OTP Scam": [
        "share your otp",
        "verify your otp",
        "otp immediately",
        "otp to claim",
        "send otp"
    ],

    "Bank Account Scam": [
        "bank account blocked",
        "account will be blocked",
        "update your bank details",
        "verify your bank account",
        "bank account suspended"
    ],

    "UPI Payment Scam": [
        "upi pin",
        "scan qr code to receive",
        "receive money",
        "collect request",
        "approve payment request"
    ],

    "Fake Job Scam": [
        "registration fee",
        "pay to get job",
        "job offer guaranteed",
        "work from home earn",
        "pay security deposit"
    ],

    "Lottery Scam": [
        "you won a lottery",
        "claim your prize",
        "lottery winner",
        "prize money",
        "claim your reward"
    ],

    "Investment Scam": [
        "guaranteed returns",
        "double your money",
        "risk free investment",
        "guaranteed profit",
        "invest and earn"
    ],

    "Fake Loan Scam": [
        "instant loan approved",
        "loan processing fee",
        "pay loan fee",
        "guaranteed loan",
        "loan approval fee"
    ],

    "KYC Verification Scam": [
        "kyc expired",
        "update your kyc",
        "kyc verification required",
        "kyc will be blocked"
    ],

    "Password Theft Scam": [
        "share your password",
        "confirm your password",
        "password verification",
        "enter your password"
    ]
}


URGENT_PATTERNS = [
    "immediately",
    "urgent",
    "act now",
    "limited time",
    "account blocked",
    "account suspended",
    "within 24 hours",
    "last warning",
    "final warning"
]


PERSONAL_INFO_PATTERNS = [
    "share your otp",
    "send otp",
    "share your password",
    "enter your password",
    "share your pin",
    "send your pin"
]


PAYMENT_PATTERNS = [
    "pay registration fee",
    "processing fee",
    "send money",
    "pay now",
    "transfer money",
    "pay security deposit",
    "claim fee"
]


def find_urls(message):
    """
    Extract URLs from a message.
    """

    pattern = r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""

    urls = re.findall(pattern, message)

    # Remove common trailing punctuation
    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,!?;:)]}")

        cleaned_urls.append(url)

    return cleaned_urls


def analyze_url(url):
    """
    Identify URL warning signs.
    This does not verify whether a website is malicious.
    """

    findings = []

    normalized_url = url.lower()

    if normalized_url.startswith("www."):
        normalized_url = "http://" + normalized_url

    try:
        parsed = urlparse(normalized_url)

        hostname = parsed.hostname

        if not hostname:
            return ["URL hostname could not be identified"]

        if parsed.scheme != "https":
            findings.append(
                "URL does not use HTTPS"
            )

        if "xn--" in hostname:
            findings.append(
                "Internationalized domain requires careful checking"
            )

        if parsed.username or parsed.password:
            findings.append(
                "URL contains unusual credentials information"
            )

        if re.search(r"\d+\.\d+\.\d+\.\d+", hostname):
            findings.append(
                "URL uses an IP address instead of a regular domain name"
            )

        if hostname.count(".") >= 4:
            findings.append(
                "URL has an unusually deep subdomain structure"
            )

    except ValueError:
        findings.append(
            "URL could not be parsed normally"
        )

    return findings


def analyze_message(message, predicted_label, predicted_category=None):
    """
    Combine model prediction with rule-based warning signs.

    Risk score is a heuristic indicator, not a probability
    that the message is fraudulent.
    """

    message_lower = message.lower()

    suspicious_words = []
    matched_categories = []
    recommendations = []

    risk_score = 0

    # -------------------------------------
    # 1. Scam/Safe prediction
    # -------------------------------------

    label = str(predicted_label).strip().lower()

    if label == "scam":
        risk_score += 40

        recommendations.append(
            "Treat this message cautiously and verify it independently."
        )

    elif label == "safe":
        recommendations.append(
            "Still verify unexpected requests before taking action."
        )

    else:
        recommendations.append(
            "The model returned an unfamiliar label. Verify manually."
        )

    # -------------------------------------
    # 2. Detect suspicious phrases
    # -------------------------------------

    for category, patterns in SCAM_PATTERNS.items():

        matches = [
            phrase
            for phrase in patterns
            if phrase in message_lower
        ]

        if matches:

            matched_categories.append(category)

            suspicious_words.extend(matches)

            risk_score += 12

    # -------------------------------------
    # 3. Urgency detection
    # -------------------------------------

    urgency_matches = [
        phrase
        for phrase in URGENT_PATTERNS
        if phrase in message_lower
    ]

    if urgency_matches:

        suspicious_words.extend(urgency_matches)

        risk_score += 10

        recommendations.append(
            "Do not rush. Verify urgent warnings using official channels."
        )

    # -------------------------------------
    # 4. Personal information requests
    # -------------------------------------

    personal_matches = [
        phrase
        for phrase in PERSONAL_INFO_PATTERNS
        if phrase in message_lower
    ]

    if personal_matches:

        suspicious_words.extend(personal_matches)

        risk_score += 20

        recommendations.append(
            "Never share OTPs, passwords or PINs with anyone."
        )

    # -------------------------------------
    # 5. Payment requests
    # -------------------------------------

    payment_matches = [
        phrase
        for phrase in PAYMENT_PATTERNS
        if phrase in message_lower
    ]

    if payment_matches:

        suspicious_words.extend(payment_matches)

        risk_score += 15

        recommendations.append(
            "Verify payment requests independently before sending money."
        )

    # -------------------------------------
    # 6. URL analysis
    # -------------------------------------

    urls = find_urls(message)

    url_findings = []

    for url in urls:

        findings = analyze_url(url)

        if findings:

            url_findings.append({
                "url": url,
                "warnings": findings
            })

            risk_score += 10

    if url_findings:

        recommendations.append(
            "Avoid opening suspicious links. Check the domain carefully."
        )

    # -------------------------------------
    # 7. Category result
    # -------------------------------------

    if predicted_category:
        category = str(predicted_category)

    elif matched_categories:
        category = matched_categories[0]

    else:
        category = "General Message"

    # -------------------------------------
    # 8. Final risk score
    # -------------------------------------

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "High"

    elif risk_score >= 35:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    # -------------------------------------
    # 9. Remove duplicate findings
    # -------------------------------------

    suspicious_words = list(
        dict.fromkeys(suspicious_words)
    )

    recommendations = list(
        dict.fromkeys(recommendations)
    )

    if not suspicious_words:
        suspicious_words = [
            "No configured suspicious phrase was detected."
        ]

    if not recommendations:
        recommendations = [
            "Check the sender and verify important claims independently."
        ]

    # -------------------------------------
    # 10. Return results
    # -------------------------------------

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "category": category,
        "suspicious_words": suspicious_words,
        "matched_categories": matched_categories,
        "urls": urls,
        "url_findings": url_findings,
        "recommendations": recommendations
    }