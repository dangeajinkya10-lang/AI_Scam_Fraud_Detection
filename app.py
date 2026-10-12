import os
import sqlite3
import joblib

from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for


# ==================================================
# 1. FLASK APPLICATION
# ==================================================

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATABASE_DIR = BASE_DIR / "database"
DATABASE_PATH = DATABASE_DIR / "scans.db"

DATABASE_DIR.mkdir(parents=True, exist_ok=True)


# ==================================================
# 2. LOAD MACHINE LEARNING MODELS
# ==================================================

def load_model_file(filename):
    """
    Load a saved machine learning model.
    Return None if the file is missing or cannot be loaded.
    """

    file_path = BASE_DIR / filename

    if not file_path.exists():
        print(f"WARNING: {filename} not found.")
        return None

    try:
        return joblib.load(file_path)

    except Exception as error:
        print(f"ERROR loading {filename}: {error}")
        return None


model = load_model_file("model.pkl")
vectorizer = load_model_file("vectorizer.pkl")

category_model = load_model_file("category_model.pkl")
category_vectorizer = load_model_file("category_vectorizer.pkl")


# ==================================================
# 3. DATABASE CONNECTION
# ==================================================

def get_db_connection():

    connection = sqlite3.connect(str(DATABASE_PATH))

    connection.row_factory = sqlite3.Row

    return connection


# ==================================================
# 4. INITIALIZE DATABASE
# ==================================================

def init_db():

    connection = get_db_connection()

    try:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                message TEXT NOT NULL,

                prediction TEXT NOT NULL,

                risk REAL NOT NULL,

                reasons TEXT,

                category TEXT,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

            )
        """)

        # Support databases created by earlier app versions.

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scans)"
            ).fetchall()
        }

        if "category" not in columns:

            connection.execute("""
                ALTER TABLE scans
                ADD COLUMN category TEXT
            """)

        if "created_at" not in columns:

            connection.execute("""
                ALTER TABLE scans
                ADD COLUMN created_at TIMESTAMP
            """)

        connection.commit()

    finally:

        connection.close()


# ==================================================
# 5. SAVE SCAN HISTORY
# ==================================================

def save_scan(message, prediction, risk, reasons, category):

    connection = get_db_connection()

    try:

        connection.execute("""
            INSERT INTO scans
            (
                message,
                prediction,
                risk,
                reasons,
                category
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            message,
            prediction,
            float(risk),
            ", ".join(reasons) if isinstance(reasons, list)
            else str(reasons),
            category
        ))

        connection.commit()

    finally:

        connection.close()


# ==================================================
# 6. DETECT SCAM CATEGORY
# ==================================================

def detect_category(message):

    text = message.lower()

    # Use the trained category model when available.

    if category_model is not None and category_vectorizer is not None:

        try:

            features = category_vectorizer.transform([message])

            category_prediction = category_model.predict(features)[0]

            category_prediction = str(
                category_prediction
            ).strip()

            if category_prediction.lower() not in (
                "safe",
                "unknown",
                "none",
                ""
            ):

                return category_prediction

        except Exception as error:

            print("Category prediction warning:", error)

    # Keyword-based fallback if category model is unavailable.

    category_keywords = {

        "OTP Scam": [
            "otp",
            "one time password",
            "verification code"
        ],

        "Banking Scam": [
            "bank account",
            "banking",
            "debit card",
            "credit card",
            "account blocked",
            "bank account blocked",
            "upi pin"
        ],

        "KYC Scam": [
            "kyc",
            "update kyc",
            "kyc expired",
            "verify your kyc"
        ],

        "Lottery Scam": [
            "lottery",
            "lucky draw",
            "lottery winner"
        ],

        "Prize Scam": [
            "you won a prize",
            "claim your prize",
            "won a prize",
            "free gift",
            "congratulations winner"
        ],

        "Credential Scam": [
            "password",
            "login credentials",
            "account credentials",
            "reset your password"
        ],

        "Phishing": [
            "click here",
            "suspicious link",
            "verify your account",
            "account suspended",
            "http://",
            "https://"
        ]

    }

    for category_name, keywords in category_keywords.items():

        if any(keyword in text for keyword in keywords):

            return category_name

    return "General Message"


# ==================================================
# 7. PREDICT MESSAGE RISK
# ==================================================

# ==========================================
# PREDICT MESSAGE - CORRECTED VERSION
# ==========================================

def predict_message(message):

    if model is None or vectorizer is None:
        raise RuntimeError(
            "Model files missing. Check model.pkl and vectorizer.pkl."
        )

    features = vectorizer.transform([message])

    # Get prediction from trained model
    predicted_label = str(
        model.predict(features)[0]
    ).strip().lower()

    # Get scam probability
    risk = 0.0

    if hasattr(model, "predict_proba"):

        probabilities = model.predict_proba(features)[0]

        classes = [
            str(label).strip().lower()
            for label in model.classes_
        ]

        scam_labels = [
            "scam",
            "fraud",
            "spam",
            "phishing",
            "unsafe",
            "malicious"
        ]

        scam_indices = [
            i for i, label in enumerate(classes)
            if label in scam_labels
        ]

        if scam_indices:
            risk = max(
                float(probabilities[i]) * 100
                for i in scam_indices
            )

    # Normalize prediction label
    scam_labels = [
        "scam",
        "fraud",
        "spam",
        "phishing",
        "unsafe",
        "malicious"
    ]

    safe_labels = [
        "safe",
        "ham",
        "legitimate",
        "genuine",
        "not scam",
        "not_scam"
    ]

    if predicted_label in scam_labels:
        result = "Scam"

    elif predicted_label in safe_labels:
        result = "Likely Safe"

    else:
        result = "Unknown"

    risk = round(max(0.0, min(risk, 100.0)), 2)

    print("\n--- MODEL DEBUG ---")
    print("Message:", message)
    print("Model classes:", model.classes_)
    print("Predicted label:", predicted_label)
    print("Scam probability:", risk)
    print("Final model result:", result)
    print("-------------------\n")

    return result, risk

# ==================================================
# 8. GET CATEGORY FOR A MESSAGE
# ==================================================

def get_category(message):

    return detect_category(message)


# ==================================================
# 9. FIND SCAM REASONS
# ==================================================

def find_scam_reasons(message, result=None, category=None):

    text = message.lower()

    reasons = []

    keyword_reasons = {

        "OTP": [
            "otp",
            "one time password",
            "verification code"
        ],

        "Banking details": [
            "bank account",
            "banking",
            "upi pin",
            "debit card",
            "credit card"
        ],

        "KYC verification": [
            "kyc",
            "update kyc",
            "kyc expired"
        ],

        "Suspicious links": [
            "click here",
            "http://",
            "https://",
            "click this link"
        ],

        "Urgent action": [
            "urgent",
            "immediately",
            "act now",
            "within 24 hours"
        ],

        "Prize or lottery claim": [
            "lottery",
            "winner",
            "won a prize",
            "claim your prize",
            "free gift"
        ],

        "Password or credentials": [
            "password",
            "login credentials",
            "account credentials"
        ],

        "Account verification": [
            "verify your account",
            "account suspended",
            "account blocked"
        ],

        "Money request": [
            "send money",
            "transfer money",
            "pay now",
            "claim reward"
        ]

    }

    for reason, keywords in keyword_reasons.items():

        if any(keyword in text for keyword in keywords):

            reasons.append(reason)

    if category and category != "General Message":

        category_reason = f"Possible category: {category}"

        if category_reason not in reasons:

            reasons.append(category_reason)

    if not reasons:

        reasons.append(
            "No common scam warning keywords were identified."
        )

    return reasons


# ==================================================
# 10. DETERMINE RISK LEVEL
# ==================================================

def get_risk_level(risk):

    if risk >= 70:

        return "High"

    elif risk >= 40:

        return "Medium"

    else:

        return "Low"


# ==================================================
# 11. HOME PAGE
# ==================================================

@app.route("/")
def home():

    return render_template("index.html")


# ==================================================
# 12. SCAN MESSAGE
# ==================================================

@app.route("/scan", methods=["GET", "POST"])
def scan():

    if request.method == "GET":

        return redirect(url_for("home"))

    message = request.form.get("message", "").strip()

    if not message:

        return render_template(
            "result.html",
            message="",
            result="Invalid Message",
            prediction="Invalid Message",
            risk=0,
            risk_score=0,
            risk_level="Low",
            category="Unknown",
            reasons=["Please enter a message to scan."],
            tips=[
                "Enter a message before scanning."
            ]
        )

    try:

        # Step 1: ML prediction

        predicted_label, model_risk = predict_message(message)

        # Step 2: Detect message category

        category = get_category(message)

        # Step 3: Calculate final risk

        risk = model_risk

        # Step 4: Determine final result

        scam_keywords = [
            "lottery",
            "won a prize",
            "claim your reward",
            "claim your prize",
            "lucky draw",
            "you are winner",
            "congratulations winner",
            "share your otp",
            "send your otp",
            "account will be blocked",
            "update kyc",
            "upi pin"
        ]

        message_lower = message.lower()

        category_lower = category.lower()

        scam_category = any(
            name in category_lower
            for name in [
                "lottery",
                "banking scam",
                "otp scam",
                "kyc scam",
                "prize scam",
                "credential scam",
                "phishing"
            ]
        )

        scam_keyword_found = any(
            keyword in message_lower
            for keyword in scam_keywords
        )

        if risk >= 70 or (
            scam_category and scam_keyword_found
        ):
            result = "Scam"

        elif risk >= 40 or scam_keyword_found:
            result = "Suspicious Message"

        else:
            result = "Likely Safe"

        # Step 5: Determine risk level

        risk_level = get_risk_level(risk)

        if result == "Scam" and risk_level == "Low":
            risk_level = "High"

        # Step 6: Find warning reasons

        reasons = find_scam_reasons(
            message,
            result,
            category
        )

        # Step 7: Safety tips

        tips = [
            "Never share your OTP, PIN, password, or banking details.",
            "Avoid opening suspicious links.",
            "Verify the sender using official contact details.",
            "Do not send money to unknown people.",
            "Contact your bank through its official website or number if needed."
        ]

        # Step 8: Save scan in database

        save_scan(
            message,
            result,
            risk,
            reasons,
            category
        )
        print("MESSAGE:", message)
        print("CATEGORY:", category)
        print("RISK:", risk)
        print("FINAL RESULT:", result)
        # Step 9: Show result page

        return render_template(
            "result.html",
            message=message,
            result=result,
            prediction=result,
            risk=risk,
            risk_score=risk,
            risk_level=risk_level,
            category=category,
            reasons=reasons,
            tips=tips
        )

    except Exception as error:

        app.logger.exception(
            "Message scanning failed"
        )

        return (
            "Message scanning failed. "
            "Please check the terminal for the error details."
        ), 500


# ==================================================
# 13. SCAN HISTORY
# ==================================================

@app.route("/history")
def history():

    connection = get_db_connection()

    try:

        scans = connection.execute("""
            SELECT *
            FROM scans
            ORDER BY id DESC
        """).fetchall()

        return render_template(
            "history.html",
            scans=scans,
            history=scans
        )

    finally:

        connection.close()


# ==================================================
# 14. DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():

    connection = get_db_connection()

    try:

        total_scans = connection.execute("""
            SELECT COUNT(*) AS total
            FROM scans
        """).fetchone()["total"]

        scam_count = connection.execute("""
            SELECT COUNT(*) AS total
            FROM scans
            WHERE prediction = 'Scam'
        """).fetchone()["total"]

        safe_count = connection.execute("""
            SELECT COUNT(*) AS total
            FROM scans
            WHERE prediction = 'Likely Safe'
        """).fetchone()["total"]

        suspicious_count = connection.execute("""
            SELECT COUNT(*) AS total
            FROM scans
            WHERE prediction = 'Suspicious Message'
        """).fetchone()["total"]

        high_risk = connection.execute("""
            SELECT COUNT(*) AS total
            FROM scans
            WHERE risk >= 70
        """).fetchone()["total"]

        medium_risk = connection.execute("""
            SELECT COUNT(*) AS total
            FROM scans
            WHERE risk >= 40 AND risk < 70
        """).fetchone()["total"]

        low_risk = connection.execute("""
            SELECT COUNT(*) AS total
            FROM scans
            WHERE risk < 40
        """).fetchone()["total"]

        recent_scans = connection.execute("""
            SELECT *
            FROM scans
            ORDER BY id DESC
            LIMIT 10
        """).fetchall()

        return render_template(
            "dashboard.html",
            total_scans=total_scans,
            scam_count=scam_count,
            safe_count=safe_count,
            suspicious_count=suspicious_count,
            high_risk=high_risk,
            medium_risk=medium_risk,
            low_risk=low_risk,
            recent_scans=recent_scans
        )

    finally:

        connection.close()


# ==================================================
# 15. APPLICATION START
# ==================================================

if __name__ == "__main__":

    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )