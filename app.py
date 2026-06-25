from datetime import datetime
import os
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4
import re
from xml.sax.saxutils import escape

import pandas as pd
from flask import Flask, jsonify, render_template, request, send_from_directory, url_for
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset.csv"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "password",
    "login",
    "bank",
    "click here",
    "account suspended",
    "payment",
    "update account",
    "security alert",
]

URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>'\"()]+", re.IGNORECASE)
IP_ADDRESS_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
LONG_URL_THRESHOLD = 90


def load_training_data():
    """Read the sample dataset and validate the columns needed for training."""
    if not DATASET_PATH.exists():
        raise FileNotFoundError("dataset.csv was not found in the project folder.")

    data = pd.read_csv(DATASET_PATH)
    required_columns = {"email", "label"}
    if not required_columns.issubset(data.columns):
        raise ValueError("dataset.csv must contain 'email' and 'label' columns.")

    data = data.dropna(subset=["email", "label"])
    data["label"] = data["label"].str.lower().str.strip()
    return data


def train_model():
    """Train a TF-IDF + Multinomial Naive Bayes pipeline at application startup."""
    training_data = load_training_data()
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    ngram_range=(1, 2),
                    max_features=5000,
                ),
            ),
            ("classifier", MultinomialNB()),
        ]
    )
    pipeline.fit(training_data["email"], training_data["label"])
    return pipeline


MODEL = train_model()


def find_suspicious_keywords(email_text):
    """Find configured phishing keywords and phrases in the email body."""
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        pattern = rf"(?<!\w){re.escape(keyword)}(?!\w)"
        if re.search(pattern, email_text, re.IGNORECASE):
            found_keywords.append(keyword)
    return found_keywords


def extract_urls(email_text):
    """Extract URLs and remove common trailing punctuation from copied email text."""
    urls = []
    for match in URL_PATTERN.findall(email_text):
        cleaned = match.rstrip(".,;:!?)]}")
        if cleaned not in urls:
            urls.append(cleaned)
    return urls


def is_ip_host(hostname):
    """Return True when a URL hostname is an IPv4 address."""
    if not hostname or not IP_ADDRESS_PATTERN.match(hostname):
        return False
    return all(0 <= int(part) <= 255 for part in hostname.split("."))


def analyze_urls(urls):
    """Score suspicious URL traits such as HTTP, IP hosts, and excessive length."""
    details = []
    score = 0

    for url in urls:
        normalized_url = url if re.match(r"^https?://", url, re.IGNORECASE) else f"http://{url}"
        parsed_url = urlparse(normalized_url)
        hostname = parsed_url.hostname or ""

        reasons = []
        is_http = parsed_url.scheme.lower() == "http"
        is_long = len(url) > LONG_URL_THRESHOLD
        is_ip_based = is_ip_host(hostname)

        if is_http:
            reasons.append("HTTP link")
            score += 10
        if is_long:
            reasons.append("Excessively long URL")
            score += 8
        if is_ip_based:
            reasons.append("IP-based URL")
            score += 12

        details.append(
            {
                "url": url,
                "is_http": is_http,
                "is_long": is_long,
                "is_ip_based": is_ip_based,
                "reasons": reasons or ["No suspicious URL trait detected"],
            }
        )

    if len(urls) > 2:
        score += min((len(urls) - 2) * 3, 10)

    return details, min(score, 35)


def get_phishing_probability(email_text):
    """Return the model's phishing probability and raw model label."""
    probabilities = MODEL.predict_proba([email_text])[0]
    classes = list(MODEL.classes_)

    phishing_index = classes.index("phishing")
    phishing_probability = float(probabilities[phishing_index])
    model_prediction = MODEL.predict([email_text])[0]

    return phishing_probability, model_prediction


def risk_level_from_score(score):
    """Map a 0-100 score into the requested risk bands."""
    if score <= 30:
        return "Low"
    if score <= 70:
        return "Medium"
    return "High"


def build_email_statistics(email_text, urls, keywords):
    """Create simple statistics shown in the dashboard."""
    words = re.findall(r"\b[\w'-]+\b", email_text)
    return {
        "characters": len(email_text),
        "words": len(words),
        "lines": len(email_text.splitlines()) or 1,
        "urls": len(urls),
        "keywords": len(keywords),
    }


def analyze_email(email_text):
    """Combine machine learning, keyword matching, and URL analysis into one result."""
    phishing_probability, model_prediction = get_phishing_probability(email_text)
    keywords_found = find_suspicious_keywords(email_text)
    urls_found = extract_urls(email_text)
    url_details, url_score = analyze_urls(urls_found)

    ml_score = round(phishing_probability * 50)
    keyword_score = min(len(keywords_found) * 7, 35)
    risk_score = min(100, ml_score + keyword_score + url_score)
    risk_level = risk_level_from_score(risk_score)
    prediction = "Phishing" if risk_score >= 55 or phishing_probability >= 0.65 else "Safe"

    if prediction == "Phishing":
        confidence = round(max(phishing_probability * 100, risk_score), 1)
    else:
        confidence = round(max((1 - phishing_probability) * 100, 100 - risk_score), 1)

    return {
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "prediction": prediction,
        "model_prediction": model_prediction.title(),
        "confidence": min(confidence, 100),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "keywords_found": keywords_found,
        "urls_found": urls_found,
        "url_details": url_details,
        "statistics": build_email_statistics(email_text, urls_found, keywords_found),
    }


def paragraph_list(items, empty_text):
    """Create PDF-safe paragraph content for comma separated or line separated values."""
    if not items:
        return Paragraph(escape(empty_text), getSampleStyleSheet()["BodyText"])
    value = "<br/>".join(escape(str(item)) for item in items)
    return Paragraph(value, getSampleStyleSheet()["BodyText"])


def generate_pdf_report(result):
    """Generate a PDF report for a completed scan and return the filename."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"phishing_scan_{timestamp}_{uuid4().hex[:8]}.pdf"
    report_path = REPORTS_DIR / filename

    doc = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        rightMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            textColor=colors.HexColor("#102a43"),
            fontSize=20,
            leading=24,
            spaceAfter=16,
        )
    )

    summary_data = [
        ["Scan Date", result["scan_date"]],
        ["Prediction", result["prediction"]],
        ["Risk Score", f"{result['risk_score']}%"],
        ["Risk Level", result["risk_level"]],
        ["Confidence", f"{result['confidence']}%"],
    ]

    summary_table = Table(summary_data, colWidths=[1.7 * inch, 4.8 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8f1f7")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#102a43")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bcccdc")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    findings_data = [
        ["Suspicious Keywords Found", paragraph_list(result["keywords_found"], "None")],
        ["URLs Found", paragraph_list(result["urls_found"], "None")],
    ]

    findings_table = Table(findings_data, colWidths=[2.2 * inch, 4.3 * inch])
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bcccdc")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    elements = [
        Paragraph("Phishing Email Detection Report", styles["ReportTitle"]),
        Paragraph("Scan Summary", styles["Heading2"]),
        summary_table,
        Spacer(1, 16),
        Paragraph("Detected Indicators", styles["Heading2"]),
        findings_table,
    ]

    doc.build(elements)
    return filename


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan_email():
    """Accept email content, run analysis, and return JSON for the dashboard."""
    payload = request.get_json(silent=True) or request.form
    email_text = (payload.get("email_content") or "").strip()

    if not email_text:
        return jsonify({"error": "Please paste email content before scanning."}), 400

    try:
        result = analyze_email(email_text)
        report_filename = generate_pdf_report(result)
        result["report_url"] = url_for("download_report", filename=report_filename)
        return jsonify(result)
    except Exception:
        app.logger.exception("Email scan failed")
        return jsonify({"error": "The scan could not be completed. Please try again."}), 500


@app.route("/report/<path:filename>", methods=["GET"])
def download_report(filename):
    """Download a generated PDF report from the reports directory."""
    report_path = REPORTS_DIR / filename
    if not report_path.exists() or report_path.suffix.lower() != ".pdf":
        return jsonify({"error": "Report not found."}), 404
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
