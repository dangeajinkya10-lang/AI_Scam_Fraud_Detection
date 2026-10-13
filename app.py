import sqlite3
import joblib

from pathlib import Path
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify
)

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
    file_path = BASE_DIR / filename

    if not file_path.exists():
        app.logger.warning("%s not found.", filename)
        return None

    try:
        return joblib.load(file_path)

    except Exception:
        app.logger.exception("Error loading %s", filename)
        return None


model = load_model_file("model.pkl")
vectorizer = load_model_file("vectorizer.pkl")

category_model = load_model_file("category_model.pkl")
category_vectorizer = load_model_file(
    "category_vectorizer.pkl"
)


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

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scans)"
            ).fetchall()
        }

        if "category" not in columns:
            connection.execute("""
                ALTER TABLE scans ADD COLUMN category TEXT
            """)

        if "created_at" not in columns:
            connection.execute("""
                ALTER TABLE scans ADD COLUMN created_at TIMESTAMP
            """)

        connection.commit()

    finally:
        connection.close()


# Initialize database for both the website and API.
init_db()


# ==================================================
# 5. SAVE SCAN HISTORY
# ==================================================

def save_scan(message, prediction, risk, reasons, category):
    connection = get_db_connection()

    try:
        if isinstance(reasons, list):
            reasons_text = ", ".join(reasons)
        else:
            reasons_text = str(reasons)

        connection.execute("""
            INSERT INTO scans (
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
            reasons_text,
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

    if (
        category_model is not None
        and category_vectorizer is not None
    ):
        try:
            features = category_vectorizer.transform([message])

            category_prediction = (
                category_model.predict(features)[0]
            )

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

        except Exception:
            app.logger.exception(
                "Category prediction warning"
            )

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


def get_category(message):
    return detect_category(message)


# ==================================================
# 7. PREDICT MESSAGE
# ==================================================

def predict_message(message):
    if model is None or vectorizer is None:
        raise RuntimeError(
            "Model files missing. Check model.pkl and vectorizer.pkl."
        )

    features = vectorizer.transform([message])

    predicted_label = str(
        model.predict(features)[0]
    ).strip().lower()

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
            index
            for index, label in enumerate(classes)
            if label in scam_labels
        ]

        if scam_indices:
            risk = max(
                float(probabilities[index]) * 100
                for index in scam_indices
            )

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

    app.logger.info(
        "ML prediction=%s, risk=%s",
        result,
        risk
    )

    return result, risk


# ==================================================
# 8. FIND SCAM REASONS
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
        reasons.append(f"Possible category: {category}")

    if not reasons:
        reasons.append(
            "No common scam warning keywords were identified."
        )

    return reasons


# ==================================================
# 9. DETERMINE RISK LEVEL
# ==================================================

def get_risk_level(risk):
    if risk >= 70:
        return "High"

    elif risk >= 40:
        return "Medium"

    return "Low"


# ==================================================
# 10. SHARED SCANNING LOGIC
# ==================================================

def analyze_message(message):
    if model is None or vectorizer is None:
        raise RuntimeError(
            "Machine learning model files are unavailable."
        )

    predicted_label, model_risk = predict_message(message)

    category = get_category(message)
    risk = model_risk

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

    elif predicted_label == "Likely Safe":
        result = "Likely Safe"

    elif predicted_label == "Scam":
        result = "Scam"

    else:
        result = "Suspicious Message"

    risk_level = get_risk_level(risk)

    if result == "Scam" and risk_level == "Low":
        risk_level = "High"

    reasons = find_scam_reasons(
        message,
        result,
        category
    )

    tips = [
        "Never share your OTP, PIN, password, or banking details.",
        "Avoid opening suspicious links.",
        "Verify the sender using official contact details.",
        "Do not send money to unknown people.",
        "Contact your bank through its official website or number if needed."
    ]

    return {
        "message": message,
        "result": result,
        "risk": risk,
        "risk_level": risk_level,
        "category": category,
        "reasons": reasons,
        "tips": tips
    }


# ==================================================
# 11. ANDROID APP API
# ==================================================

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Please send a valid JSON request."
        }), 400

    message = data.get("message", "")

    if not isinstance(message, str):
        return jsonify({
            "success": False,
            "error": "Message must be text."
        }), 400

    message = message.strip()

    if not message:
        return jsonify({
            "success": False,
            "error": "Please enter a message."
        }), 400

    if len(message) > 10000:
        return jsonify({
            "success": False,
            "error": "Message is too long. Maximum 10000 characters."
        }), 400

    try:
        analysis = analyze_message(message)

        save_scan(
            analysis["message"],
            analysis["result"],
            analysis["risk"],
            analysis["reasons"],
            analysis["category"]
        )

        return jsonify({
            "success": True,
            **analysis
        }), 200

    except Exception:
        app.logger.exception("Android API scan failed")

        return jsonify({
            "success": False,
            "error": "Scanning failed. Please try again."
        }), 500


# ==================================================
# 12. HOME PAGE
# ==================================================

@app.route("/")
def home():
    return render_template("index.html")


# ==================================================
# 13. WEBSITE SCAN
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
            tips=["Enter a message before scanning."]
        )

    try:
        analysis = analyze_message(message)

        save_scan(
            analysis["message"],
            analysis["result"],
            analysis["risk"],
            analysis["reasons"],
            analysis["category"]
        )

        return render_template(
            "result.html",
            message=analysis["message"],
            result=analysis["result"],
            prediction=analysis["result"],
            risk=analysis["risk"],
            risk_score=analysis["risk"],
            risk_level=analysis["risk_level"],
            category=analysis["category"],
            reasons=analysis["reasons"],
            tips=analysis["tips"]
        )

    except Exception:
        app.logger.exception("Website scanning failed")

        return (
            "Message scanning failed. "
            "Please check the application logs."
        ), 500


# ==================================================
# 14. SCAN HISTORY
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
# 15. DASHBOARD
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
# 16. HEALTH CHECK
# ==================================================

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "success": True,
        "status": "online",
        "service": "Scam Detection API",
        "model_loaded": model is not None,
        "vectorizer_loaded": vectorizer is not None
    }), 200


# ==================================================
# 17. START APPLICATION
# ==================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )