from flask import Flask, render_template, request
import joblib
from db import get_connection

app = Flask(__name__)

# =========================================================
# Load Machine Learning Model
# =========================================================

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# =========================================================
# Find Suspicious Reasons
# =========================================================

def find_scam_reasons(message):

    reasons = []

    text = message.lower()

    keywords = {
        "otp": "The message asks for an OTP.",
        "password": "The message mentions a password.",
        "urgent": "The message creates urgency.",
        "click": "The message asks you to click a link.",
        "prize": "The message mentions a prize.",
        "winner": "The message claims that you have won something.",
        "reward": "The message mentions a reward.",
        "kyc": "The message mentions KYC verification.",
        "verify": "The message asks you to verify information.",
        "bank": "The message mentions banking information."
    }

    for word, reason in keywords.items():

        if word in text:
            reasons.append(reason)

    return reasons


# =========================================================
# Safety Recommendations
# =========================================================

def get_safety_tips(message):

    tips = []

    text = message.lower()

    if "otp" in text:
        tips.append("Never share your OTP with anyone.")

    if "password" in text:
        tips.append("Never share your password.")

    if "click" in text:
        tips.append(
            "Avoid clicking unknown or suspicious links."
        )

    if "bank" in text:
        tips.append(
            "Do not share banking details with unknown people."
        )

    if "kyc" in text or "verify" in text:
        tips.append(
            "Verify KYC requests through the official bank or service."
        )

    if "prize" in text or "reward" in text or "winner" in text:
        tips.append(
            "Do not pay money to claim an unexpected prize or reward."
        )

    if not tips:
        tips.append(
            "Stay alert and verify the message through an official source."
        )

    return tips


# =========================================================
# Home Page
# =========================================================

@app.route("/")
def home():

    return render_template("index.html")


# =========================================================
# Scan Message
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    # Get message from HTML form
    message = request.form["message"]

    # -----------------------------------------------------
    # Convert message into TF-IDF vector
    # -----------------------------------------------------

    message_vector = vectorizer.transform([message])

    # -----------------------------------------------------
    # ML Prediction
    # -----------------------------------------------------

    prediction = model.predict(message_vector)[0]

    # -----------------------------------------------------
    # Calculate Scam Risk
    # -----------------------------------------------------

    probabilities = model.predict_proba(message_vector)[0]

    classes = model.classes_

    scam_index = list(classes).index("scam")

    risk = round(
        probabilities[scam_index] * 100,
        2
    )

    # -----------------------------------------------------
    # Risk Level
    # -----------------------------------------------------

    if risk <= 30:

        risk_level = "LOW RISK"

    elif risk <= 70:

        risk_level = "MEDIUM RISK"

    else:

        risk_level = "HIGH RISK"

    # -----------------------------------------------------
    # Find Suspicious Reasons
    # -----------------------------------------------------

    reasons = find_scam_reasons(message)

    # -----------------------------------------------------
    # Get Safety Tips
    # -----------------------------------------------------

    tips = get_safety_tips(message)

    # =====================================================
    # Save Scan in SQLite Database
    # =====================================================

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans
        (message, prediction, risk, reasons)
        VALUES (?, ?, ?, ?)
    """, (
        message,
        prediction,
        risk,
        ", ".join(reasons)
    ))

    connection.commit()

    connection.close()

    # =====================================================
    # Show Result Page
    # =====================================================

    return render_template(
        "result.html",
        message=message,
        result=prediction,
        risk=risk,
        risk_level=risk_level,
        reasons=reasons,
        tips=tips
    )


# =========================================================
# Scan History
# =========================================================

@app.route("/history")
def history():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY scan_date DESC
    """)

    scans = cursor.fetchall()

    connection.close()

    return render_template(
        "history.html",
        scans=scans
    )
# Dashboard
@app.route("/dashboard")
def dashboard():

    connection = get_connection()
    cursor = connection.cursor()

    # Total scans
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    # Scam detected
    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE prediction = 'scam'"
    )
    scam_detected = cursor.fetchone()[0]

    # Safe messages
    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE prediction = 'safe'"
    )
    safe_messages = cursor.fetchone()[0]

    # High risk
    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE risk > 70"
    )
    high_risk = cursor.fetchone()[0]

    # Medium risk
    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE risk > 30 AND risk <= 70"
    )
    medium_risk = cursor.fetchone()[0]

    # Low risk
    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE risk <= 30"
    )
    low_risk = cursor.fetchone()[0]

    # Recent 5 scans
    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY scan_date DESC
        LIMIT 5
    """)

    recent_scans = cursor.fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        scam_detected=scam_detected,
        safe_messages=safe_messages,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk,
        recent_scans=recent_scans
    )

# =========================================================
# Run Flask Application
# =========================================================

if __name__ == "__main__":

    app.run(debug=True)