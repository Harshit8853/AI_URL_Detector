from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    flash,
    jsonify,
    send_file,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash

import os
import sys
import io
import math
import pickle
from datetime import datetime

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors

# ---------------- PATH FIX FOR feature_extractor ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # changed
SRC_PATH = os.path.join(BASE_DIR, "src")

if SRC_PATH not in sys.path:
    sys.path.append(SRC_PATH)

from feature_extractor import extract_features, get_osint_details  # noqa: E402

# ---------------- FLASK + DB CONFIG ----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key-change-this"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    BASE_DIR, "threatscan.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# ---------------- DATABASE MODELS ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    url = db.Column(db.String(500))
    result = db.Column(db.String(32))

    domain = db.Column(db.String(255))
    https = db.Column(db.Integer)
    ssl_valid = db.Column(db.Integer)
    domain_age_days = db.Column(db.Integer)
    redirects = db.Column(db.Integer)
    suspicious_keywords = db.Column(db.Integer)
    subdomain_count = db.Column(db.Integer)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="scans")


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()


# ---------------- LOAD MODEL + SCALER ----------------
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "random_forest_model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "minmax_scaler.pkl")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

with open(SCALER_PATH, "rb") as f:
    scaler = pickle.load(f)


# ---------------- HELPER: USER STATS ----------------
def get_user_stats(user_id: int):
    total = Scan.query.filter_by(user_id=user_id).count()
    phish = Scan.query.filter_by(user_id=user_id, result="Phishing").count()
    legit = Scan.query.filter_by(user_id=user_id, result="Legitimate").count()
    last_scan_obj = (
        Scan.query.filter_by(user_id=user_id)
        .order_by(Scan.created_at.desc())
        .first()
    )
    phish_rate = int((phish / total) * 100) if total else 0

    return {
        "total": total,
        "phish": phish,
        "legit": legit,
        "phish_rate": phish_rate,
        "last_scan": last_scan_obj.created_at.strftime("%Y-%m-%d %H:%M")
        if last_scan_obj
        else None,
    }


# ---------------- AUTH ROUTES ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("User already exists.", "error")
            return redirect(url_for("login"))

        user = User(email=email, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("login.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("dashboard"))

    return render_template("login.html", mode="login")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ---------------- MAIN PAGES ----------------
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    history = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )
    stats = get_user_stats(current_user.id)
    return render_template(
        "index.html",
        url="",
        result=None,
        osint=None,
        history=history,
        user=current_user,
        stats=stats,
    )


@app.route("/predict", methods=["POST"])
@login_required
def predict():
    url = (request.form.get("url") or "").strip()

    features = extract_features(url)
    scaled = scaler.transform([features])
    pred = model.predict(scaled)[0]
    result = "Legitimate" if pred == 1 else "Phishing"

    osint = get_osint_details(url)

    # simple hybrid tweaks
    if osint["https"] == 1 and osint["ssl_valid"] == 1 and osint["suspicious_keywords"] == 0:
        result = "Legitimate"
    if osint["https"] == 0 and osint["ssl_valid"] == 0 and osint["suspicious_keywords"] >= 2:
        result = "Phishing"

    scan = Scan(
        user_id=current_user.id,
        url=url,
        result=result,
        domain=osint["domain"],
        https=osint["https"],
        ssl_valid=osint["ssl_valid"],
        domain_age_days=osint["domain_age_days"],
        redirects=osint["redirects"],
        suspicious_keywords=osint["suspicious_keywords"],
        subdomain_count=osint["subdomain_count"],
    )
    db.session.add(scan)
    db.session.commit()

    history = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )
    stats = get_user_stats(current_user.id)

    return render_template(
        "index.html",
        url=url,
        result=result,
        osint=osint,
        history=history,
        user=current_user,
        stats=stats,
    )


# ---------------- PUBLIC JSON API ----------------
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "url field is required"}), 400

    feats = extract_features(url)
    scaled = scaler.transform([feats])
    pred = model.predict(scaled)[0]
    result = "Legitimate" if pred == 1 else "Phishing"
    osint = get_osint_details(url)

    return jsonify({"url": url, "result": result, "osint": osint})


# ---------------- ADVANCED PDF REPORT ----------------
@app.route("/report/<int:scan_id>/pdf")
@login_required
def download_report(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()

    buffer = io.BytesIO()
    WIDTH, HEIGHT = A4
    p = canvas.Canvas(buffer, pagesize=A4)
    p.setTitle("AI Financial Threat Scanner – Report")

    # palette
    BLUE = colors.HexColor("#2563eb")
    GREEN = colors.HexColor("#16a34a")
    RED = colors.HexColor("#dc2626")
    ORANGE = colors.HexColor("#f97316")
    GRAY = colors.HexColor("#6b7280")
    LIGHT = colors.HexColor("#e5e7eb")
    BG = colors.HexColor("#f9fafb")

    # -------- PAGE 1: SUMMARY + OSINT TABLE --------
    y = HEIGHT

    # header band
    p.setFillColor(BLUE)
    p.rect(0, y - 70, WIDTH, 70, fill=1, stroke=0)
    p.setFillColor(colors.white)
    p.setFont("Helvetica-Bold", 18)
    p.drawString(40, y - 45, "AI Financial Threat Scanner")
    p.setFont("Helvetica", 10)
    p.drawString(40, y - 60, "Machine-learning + OSINT based URL risk report")
    y -= 90

    # user info
    p.setFont("Helvetica", 10)
    p.setFillColor(GRAY)
    p.drawString(40, y, f"User: {current_user.email}")
    y -= 14
    p.drawString(40, y, f"Scan time: {scan.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 24

    # summary box
    p.setFillColor(BG)
    p.roundRect(30, y - 90, WIDTH - 60, 90, 10, fill=1, stroke=0)

    p.setFillColor(GRAY)
    p.setFont("Helvetica-Bold", 10)
    p.drawString(40, y - 18, "Scanned URL")
    p.setFillColor(colors.black)
    p.setFont("Helvetica", 10)
    p.drawString(40, y - 32, (scan.url or "")[:110])

    verdict_color = GREEN if scan.result == "Legitimate" else RED
    badge_w, badge_h = 150, 24
    badge_x = WIDTH - badge_w - 40
    badge_y = y - 34
    p.setFillColor(verdict_color)
    p.roundRect(badge_x, badge_y, badge_w, badge_h, 12, fill=1, stroke=0)
    p.setFillColor(colors.white)
    p.setFont("Helvetica-Bold", 11)
    p.drawCentredString(badge_x + badge_w / 2, badge_y + 7, f"Verdict: {scan.result}")

    # risk meter
    meter_x = 40
    meter_w = WIDTH - 120
    meter_y = y - 70
    p.setFillColor(LIGHT)
    p.roundRect(meter_x, meter_y, meter_w, 10, 5, fill=1, stroke=0)

    overall_risk = 20 if scan.result == "Legitimate" else 80
    p.setFillColor(GREEN if overall_risk <= 30 else ORANGE if overall_risk <= 60 else RED)
    p.roundRect(meter_x, meter_y, meter_w * (overall_risk / 100.0), 10, 5, fill=1, stroke=0)

    p.setFont("Helvetica", 9)
    p.setFillColor(GRAY)
    p.drawString(
        meter_x,
        meter_y - 10,
        "Risk meter (0 = very safe, 100 = very risky overall score)",
    )

    y -= 120

    # OSINT table
    rows = [
        ("Domain", scan.domain or "-"),
        ("HTTPS", "Yes" if scan.https else "No"),
        ("Valid SSL", "Yes" if scan.ssl_valid else "No"),
        ("Domain age (days)", str(scan.domain_age_days)),
        ("Redirect count", str(scan.redirects)),
        ("Suspicious keywords", str(scan.suspicious_keywords)),
        ("Subdomain count", str(scan.subdomain_count)),
    ]

    p.setFont("Helvetica-Bold", 12)
    p.setFillColor(colors.black)
    p.drawString(40, y, "OSINT details")
    y -= 20

    p.setFillColor(LIGHT)
    p.rect(40, y - 14, WIDTH - 80, 16, fill=1, stroke=0)
    p.setFillColor(colors.black)
    p.setFont("Helvetica-Bold", 10)
    p.drawString(45, y - 4, "Field")
    p.drawString(220, y - 4, "Value")
    y -= 24

    p.setFont("Helvetica", 10)
    for label, val in rows:
        p.setFillColor(BG)
        p.rect(40, y - 14, WIDTH - 80, 16, fill=1, stroke=0)
        p.setFillColor(colors.black)
        p.drawString(45, y - 4, label)
        p.drawString(220, y - 4, str(val))
        y -= 18

    # footer page 1
    p.setFont("Helvetica", 8)
    p.setFillColor(GRAY)
    p.drawString(40, 30, "Page 1 / 2 – Summary & OSINT details")

    # -------- PAGE 2: VISUAL RISK SUMMARY --------
    p.showPage()
    y = HEIGHT - 60
    p.setFont("Helvetica-Bold", 16)
    p.setFillColor(colors.black)
    p.drawString(40, y, "Visual Risk Summary")
    y -= 12
    p.setFont("Helvetica", 10)
    p.setFillColor(GRAY)
    p.drawString(
        40,
        y,
        "Charts and badges summarise risk across age, redirects, keywords and overall behaviour.",
    )
    y -= 28

    # Severity legend
    p.setFont("Helvetica-Bold", 11)
    p.setFillColor(colors.black)
    p.drawString(40, y, "Severity legend")
    y -= 18

    legend_items = [
        ("Low risk (0–30)", GREEN, "Passed"),
        ("Medium risk (31–60)", ORANGE, "Monitor"),
        ("High risk (61–100)", RED, "Failed"),
    ]
    p.setFont("Helvetica", 9)
    lx = 40
    for text, color_val, badge in legend_items:
        p.setFillColor(color_val)
        p.circle(lx + 6, y + 3, 5, fill=1, stroke=0)

        p.setFillColor(colors.black)
        p.drawString(lx + 16, y, text)

        p.setFillColor(color_val)
        p.roundRect(lx + 160, y - 2, 60, 14, 7, fill=1, stroke=0)
        p.setFillColor(colors.white)
        p.drawCentredString(lx + 160 + 30, y + 2, badge)

        y -= 20

    y -= 8

    # risk scores
    age_risk = max(
        0.0,
        100.0 - min(float(scan.domain_age_days or 0), 365.0) / 365.0 * 100.0,
    )
    redirects_risk = min(float(scan.redirects or 0) * 25.0, 100.0)
    keyword_risk = min(float(scan.suspicious_keywords or 0) * 30.0, 100.0)

    chart_items = [
        (
            "Domain Age Risk",
            age_risk,
            "New domains are more likely to be used for short-lived phishing campaigns.",
        ),
        (
            "Redirects Risk",
            redirects_risk,
            "Multiple redirects can be used to hide the final malicious destination.",
        ),
        (
            "Keyword Risk",
            keyword_risk,
            "Presence of words like 'login', 'verify' or 'payment' may indicate phishing intent.",
        ),
        (
            "Overall Risk",
            overall_risk,
            "Combined signal from ML model and OSINT heuristics.",
        ),
    ]

    # ----- Feature risk profile (fixed layout) -----
    p.setFont("Helvetica-Bold", 13)
    p.setFillColor(colors.black)
    p.drawString(40, y, "Feature risk profile")
    y -= 24

    bar_x = 60
    bar_height = 14
    bar_width_max = WIDTH - 180
    line_spacing = 40

    p.setFont("Helvetica", 10)
    current_y = y

    for label, score, explanation in chart_items:
        if current_y < 180:
            p.showPage()
            current_y = HEIGHT - 80
            p.setFont("Helvetica-Bold", 13)
            p.setFillColor(colors.black)
            p.drawString(40, current_y, "Feature risk profile (cont.)")
            current_y -= 24
            p.setFont("Helvetica", 10)

        # severity colour
        if score <= 30:
            sev_color = GREEN
        elif score <= 60:
            sev_color = ORANGE
        else:
            sev_color = RED

        # icon
        icon_x = bar_x - 12
        icon_y = current_y + 3
        p.setFillColor(sev_color)
        p.circle(icon_x, icon_y, 4.5, fill=1, stroke=0)

        # label
        p.setFillColor(colors.black)
        p.drawString(bar_x, current_y, label)

        # bar (under label)
        bar_top_y = current_y - 8
        p.setFillColor(LIGHT)
        p.roundRect(bar_x, bar_top_y, bar_width_max, bar_height, 6, fill=1, stroke=0)
        p.setFillColor(colors.HexColor("#d4d4d8"))
        p.roundRect(
            bar_x, bar_top_y, bar_width_max * 0.5, bar_height, 6, fill=1, stroke=0
        )

        fill_w = bar_width_max * (score / 100.0)
        p.setFillColor(sev_color)
        p.roundRect(bar_x, bar_top_y, fill_w, bar_height, 6, fill=1, stroke=0)

        # numeric value
        p.setFillColor(colors.black)
        p.drawString(bar_x + bar_width_max + 10, current_y, f"{int(score)}")

        # explanation below bar
        exp_y = bar_top_y - 14
        p.setFillColor(GRAY)
        p.setFont("Helvetica", 8)
        p.drawString(bar_x, exp_y, explanation[:110])
        p.setFont("Helvetica", 10)

        current_y = exp_y - (line_spacing - 20)

    bar_y = current_y  # for next sections

    # ----- PIE CHART (safe for total=0) -----
    if bar_y < 220:
        p.showPage()
        y = HEIGHT - 60
    else:
        y = bar_y - 10

    p.setFont("Helvetica-Bold", 13)
    p.setFillColor(colors.black)
    p.drawString(40, y, "Risk composition (pie chart)")
    y -= 22

    total = age_risk + redirects_risk + keyword_risk
    pie_x1, pie_y1 = 60, y - 120
    pie_x2, pie_y2 = 180, y

    pie_segments = [
        ("Age", age_risk, GREEN),
        ("Redirects", redirects_risk, ORANGE),
        ("Keywords", keyword_risk, RED),
    ]

    if total <= 0:
        # no risk at all
        p.setFillColor(LIGHT)
        cx = (pie_x1 + pie_x2) / 2
        cy = (pie_y1 + pie_y2) / 2
        p.circle(cx, cy, 40, fill=1, stroke=0)
        p.setFillColor(colors.black)
        p.setFont("Helvetica", 9)
        p.drawCentredString(cx, cy - 3, "No risk")
        p.drawCentredString(cx, pie_y1 - 12, "All feature risks are zero")
    else:
        start_angle = 0
        for name, score, color_val in pie_segments:
            if score <= 0:
                continue
            extent = 360.0 * (score / total)
            p.setFillColor(color_val)
            p.wedge(pie_x1, pie_y1, pie_x2, pie_y2, start_angle, extent)
            start_angle += extent

        # legend
        legend_x = 190
        legend_y = y - 10
        p.setFont("Helvetica", 9)
        for name, score, color_val in pie_segments:
            p.setFillColor(color_val)
            p.rect(legend_x, legend_y, 10, 10, fill=1, stroke=0)
            p.setFillColor(colors.black)
            p.drawString(legend_x + 16, legend_y + 2, f"{name} ({int(score)})")
            legend_y -= 14

    # ----- RADAR / SPIDER CHART -----
    radar_center_x = WIDTH - 170
    radar_center_y = y - 55
    radar_radius = 55

    norms = [
        age_risk / 100.0,
        redirects_risk / 100.0,
        keyword_risk / 100.0,
        overall_risk / 100.0,
    ]
    labels = ["Age", "Redirects", "Keywords", "Overall"]

    p.setFont("Helvetica-Bold", 13)
    p.setFillColor(colors.black)
    p.drawString(radar_center_x - 40, radar_center_y + radar_radius + 30, "Radar chart")

    # rings
    p.setStrokeColor(LIGHT)
    for level in [0.25, 0.5, 0.75, 1.0]:
        coords = []
        for i in range(4):
            angle = 2 * math.pi * i / 4 - math.pi / 2
            x = radar_center_x + radar_radius * level * math.cos(angle)
            y_line = radar_center_y + radar_radius * level * math.sin(angle)
            coords.append((x, y_line))
        coords.append(coords[0])
        p.lines(
            [
                (coords[j][0], coords[j][1], coords[j + 1][0], coords[j + 1][1])
                for j in range(4)
            ]
        )

    # axes + labels
    p.setStrokeColor(GRAY)
    for i, label in enumerate(labels):
        angle = 2 * math.pi * i / 4 - math.pi / 2
        x = radar_center_x + radar_radius * math.cos(angle)
        y_axis = radar_center_y + radar_radius * math.sin(angle)
        p.line(radar_center_x, radar_center_y, x, y_axis)

        lx = radar_center_x + (radar_radius + 12) * math.cos(angle)
        ly = radar_center_y + (radar_radius + 12) * math.sin(angle)
        p.setFont("Helvetica", 8)
        p.setFillColor(colors.black)
        p.drawCentredString(lx, ly, label)

    # polygon
    p.setFillColor(colors.HexColor("#60a5fa"))
    p.setStrokeColor(BLUE)
    coords = []
    for i, norm in enumerate(norms):
        angle = 2 * math.pi * i / 4 - math.pi / 2
        x = radar_center_x + radar_radius * norm * math.cos(angle)
        y_poly = radar_center_y + radar_radius * norm * math.sin(angle)
        coords.append((x, y_poly))
    coords.append(coords[0])

    p.setLineWidth(1)
    p.lines(
        [
            (coords[j][0], coords[j][1], coords[j + 1][0], coords[j + 1][1])
            for j in range(4)
        ]
    )

    path = p.beginPath()
    path.moveTo(coords[0][0], coords[0][1])
    for pt in coords[1:]:
        path.lineTo(pt[0], pt[1])
    path.close()
    p.setFillColor(colors.Color(0.37, 0.62, 0.95, alpha=0.25))
    p.drawPath(path, fill=1, stroke=0)

    # footer page 2
    p.setFont("Helvetica", 8)
    p.setFillColor(GRAY)
    p.drawString(40, 30, "Page 2 / 2 – Visual risk summary & charts")
    p.drawRightString(WIDTH - 40, 30, f"Report ID: {scan.id}")

    p.showPage()
    p.save()
    buffer.seek(0)

    filename = f"threatscan_report_{scan.id}.pdf"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


# ---------------- RUN SERVER ----------------
if __name__ == "__main__":
    app.run(debug=True)
