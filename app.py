import calendar
import csv
import hashlib
import io
import os
import re
import secrets
import smtplib
import sys
import time
from datetime import date, datetime, time as dtime, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from email.message import EmailMessage
from functools import wraps

import mysql.connector
from dotenv import load_dotenv
from flask import (Flask, Response, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

# ----------------------------------------------------------------------------
# App & configuration
# ----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-only-change-me")
csrf = CSRFProtect(app)

REMEMBER_ME_DAYS = int(os.getenv("REMEMBER_ME_DAYS", 30))
SESSION_IDLE_MINUTES = int(os.getenv("SESSION_IDLE_MINUTES", 30))
RESET_TOKEN_MINUTES = int(os.getenv("RESET_TOKEN_MINUTES", 30))
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=REMEMBER_ME_DAYS),
    ADMIN_CONTACT_EMAIL=os.getenv("ADMIN_CONTACT_EMAIL", "johnbrightc123@gmail.com"),
    ADMIN_CONTACT_PHONE=os.getenv("ADMIN_CONTACT_PHONE", ""),
)


# ----------------------------------------------------------------------------
# Database (MySQL) - one connection per request, closed automatically
# ----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME", "interrival"),
            autocommit=True,
        )
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_one(sql, args=()):
    cur = get_db().cursor(dictionary=True, buffered=True)
    cur.execute(sql, args)
    row = cur.fetchone()
    cur.close()
    return row


def execute(sql, args=()):
    cur = get_db().cursor()
    cur.execute(sql, args)
    last_id = cur.lastrowid
    cur.close()
    return last_id


# ----------------------------------------------------------------------------
# Settings: values an admin can change at runtime (Admin > Settings, stored in app_settings).
# cfg("late_after") etc. fall back to the defaults below when nothing has been saved.
# ----------------------------------------------------------------------------
SETTINGS_TTL = 20  # seconds - other server processes pick up a change within this time
SETTING_SPECS = {
    # Office timings: Mon-Fri 09:30 - 18:30, Saturday 09:00 - 18:00 (Sunday is the weekly off).
    "late_after": dict(kind="time", default="09:30", lo="06:00", hi="14:00", label="Mon-Fri start time (late after)"),
    "work_end": dict(kind="time", default="18:30", lo="12:00", hi="23:00", label="Mon-Fri end time"),
    "sat_late_after": dict(kind="time", default="09:00", lo="06:00", hi="14:00", label="Saturday start time (late after)"),
    "sat_work_end": dict(kind="time", default="18:00", lo="12:00", hi="23:00", label="Saturday end time"),
    "monthly_leave_limit": dict(kind="int", default="5", lo=1, hi=31, label="Monthly leave limit"),
    "session_idle_minutes": dict(kind="int", default=str(SESSION_IDLE_MINUTES), lo=5, hi=480, label="Session timeout"),
    "max_failed_attempts": dict(kind="int", default=str(MAX_FAILED_ATTEMPTS), lo=3, hi=10, label="Failed login attempts"),
    "lockout_minutes": dict(kind="int", default=str(LOCKOUT_MINUTES), lo=5, hi=240, label="Lockout duration"),
    "reset_token_minutes": dict(kind="int", default=str(RESET_TOKEN_MINUTES), lo=10, hi=180, label="Reset link validity"),
    "departments": dict(kind="list", default="IT\nHR\nFinance\nOperations\nMarketing\nSales", label="Departments"),
    "contact_email": dict(kind="email", default=app.config["ADMIN_CONTACT_EMAIL"], label="Contact email"),
    "contact_phone": dict(kind="phone", default=app.config["ADMIN_CONTACT_PHONE"], label="Contact phone"),
}
_SETTINGS_CACHE = {"at": 0.0, "raw": {}}


def load_settings(force=False):
    c = _SETTINGS_CACHE
    if force or time.time() - c["at"] > SETTINGS_TTL:
        try:
            c["raw"] = {r["name"]: r["val"] for r in query_all("SELECT name, val FROM app_settings")}
        except Exception as exc:  # e.g. table not created yet - the app keeps working on defaults
            app.logger.warning("Settings unavailable, using defaults: %s", exc)
            c["raw"] = {}
        c["at"] = time.time()
    return c["raw"]


def clean_departments(raw, strict=True):
    seen, out = set(), []
    for line in re.split(r"[\r\n]+", raw):
        d = " ".join(line.split())
        if not d or d.lower() in seen:
            continue
        if strict and (len(d) > 50 or not re.fullmatch(r"[A-Za-z0-9 &/.\-]+", d)):
            raise ValueError(f"\u201c{d[:30]}\u201d isn't a valid department name (letters, numbers, spaces and & / . - only, max 50).")
        seen.add(d.lower())
        out.append(d)
    if strict and not 1 <= len(out) <= 30:
        raise ValueError("Add between 1 and 30 departments, one per line.")
    return out


def _convert(name, raw, strict=True):
    """Text -> typed value. Raises ValueError with a readable message when strict and the value is not acceptable."""
    spec = SETTING_SPECS[name]
    kind, label, raw = spec["kind"], spec["label"], str(raw).strip()
    if kind == "int":
        try:
            n = int(raw)
        except ValueError:
            raise ValueError(f"{label} must be a whole number.") from None
        if strict and not spec["lo"] <= n <= spec["hi"]:
            raise ValueError(f"{label} must be between {spec['lo']} and {spec['hi']}.")
        return n
    if kind == "time":
        try:
            t = datetime.strptime(raw[:5], "%H:%M").time()
        except ValueError:
            raise ValueError(f"Enter a valid time for {label.lower()}.") from None
        if strict and not dtime.fromisoformat(spec["lo"]) <= t <= dtime.fromisoformat(spec["hi"]):
            raise ValueError(f"{label} must be between {spec['lo']} and {spec['hi']}.")
        return t
    if kind == "list":
        return clean_departments(raw, strict)
    if kind == "email":
        raw = raw.lower()
        if strict and not valid_email(raw):
            raise ValueError("Enter a valid contact email address.")
        return raw
    if strict and not re.fullmatch(r"[0-9+()\-\s]{0,30}", raw):  # phone
        raise ValueError("Phone can contain digits, spaces and + ( ) - only (max 30 characters).")
    return " ".join(raw.split())


def cfg(name):
    raw = load_settings().get(name)
    if raw is not None:
        try:
            return _convert(name, raw)
        except ValueError:
            app.logger.warning("Ignoring invalid saved setting %s", name)
    return _convert(name, SETTING_SPECS[name]["default"], strict=False)


def late_after_for(d):
    """Check-ins after this time on day d are Late: Saturday has its own start time, Mon-Fri share one."""
    return cfg("sat_late_after") if d.weekday() == 5 else cfg("late_after")


def clock12(t):
    """09:30 -> '9:30 AM'"""
    return t.strftime("%I:%M %p").lstrip("0")


def setting_text(value):
    if isinstance(value, dtime):
        return value.strftime("%H:%M")
    return "\n".join(value) if isinstance(value, list) else str(value)


# ----------------------------------------------------------------------------
# Helpers: validation, redirects, access control
# ----------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DUMMY_HASH = generate_password_hash("not-a-real-password")  # constant-time-ish misses


def now():
    return datetime.utcnow()


def valid_email(value):
    return bool(value) and len(value) <= 190 and EMAIL_RE.match(value) is not None


def password_errors(pw):
    rules = [
        (len(pw) >= 8, "At least 8 characters"),
        (re.search(r"[A-Z]", pw), "One uppercase letter"),
        (re.search(r"[a-z]", pw), "One lowercase letter"),
        (re.search(r"\d", pw), "One number"),
        (re.search(r"[^A-Za-z0-9]", pw), "One special character"),
    ]
    return [msg for ok, msg in rules if not ok]


def dashboard_for(role):
    return url_for("admin_dashboard" if role == "admin" else "employee_dashboard")


def safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        idle = cfg("session_idle_minutes") * 60
        if not session.get("remember") and time.time() - session.get("last_active", 0) > idle:
            session.clear()
            return redirect(url_for("login", expired=1))
        u = query_one("SELECT is_active FROM users WHERE id=%s", (session["user_id"],))
        if not u or not u["is_active"]:
            session.clear()
            flash("Your account is deactivated. Please contact the administrator.", "danger")
            return redirect(url_for("login"))
        session["last_active"] = time.time()
        return view(*args, **kwargs)
    return wrapped


def role_required(role):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.context_processor
def inject_office_hours():
    """Office timings for templates, e.g. {{ office.weekday }} -> '9:30 AM - 6:30 PM'."""
    return {"office": dict(
        weekday=f"{clock12(cfg('late_after'))} - {clock12(cfg('work_end'))}",
        saturday=f"{clock12(cfg('sat_late_after'))} - {clock12(cfg('sat_work_end'))}",
        weekday_late=clock12(cfg("late_after")), saturday_late=clock12(cfg("sat_late_after")))}


@app.context_processor
def inject_year():
    return {"now_year": now().year}


@app.context_processor
def inject_unread():
    if session.get("role") != "employee" or "user_id" not in session:
        return {}
    try:
        n = query_one("SELECT COUNT(*) AS n FROM notifications WHERE user_id=%s AND is_read=0", (session["user_id"],))["n"]
    except Exception:  # e.g. notifications table not created yet - never break the page
        n = 0
    return {"unread_count": int(n)}


@app.template_filter("ago")
def ago(dt):
    secs = max(int((datetime.now() - dt).total_seconds()), 0)
    if secs < 60:
        return "Just now"
    mins = secs // 60
    if mins < 60:
        return f"{mins} min{'' if mins == 1 else 's'} ago"
    hours = mins // 60
    if hours < 24:
        return f"{hours} hour{'' if hours == 1 else 's'} ago"
    days = hours // 24
    if days < 7:
        return f"{days} day{'' if days == 1 else 's'} ago"
    return dt.strftime("%d %b %Y")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if not resp.direct_passthrough and "text/html" in (resp.content_type or ""):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, message="You don't have access to this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="Page not found."), 404


# ----------------------------------------------------------------------------
# Routes: authentication
# ----------------------------------------------------------------------------
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(dashboard_for(session["role"]))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(dashboard_for(session["role"]))
    if request.args.get("expired"):
        flash("Your session expired. Please sign in again.", "warning")

    email = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        errors = []
        if not email:
            errors.append("Email address is required.")
        elif not valid_email(email):
            errors.append("Enter a valid email address.")
        if not password:
            errors.append("Password is required.")

        if errors:
            for msg in errors:
                flash(msg, "danger")
        else:
            user = query_one("SELECT * FROM users WHERE email=%s", (email,))
            if user and user["locked_until"] and user["locked_until"] > now():
                flash(f"Too many failed attempts. Try again in {cfg('lockout_minutes')} minutes.", "danger")
            else:
                ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
                if user and ok and user["is_active"]:
                    execute("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login_at=%s WHERE id=%s",
                            (now(), user["id"]))
                    session.clear()  # prevents session fixation
                    session.update(user_id=user["id"], role=user["role"], name=user["full_name"], designation=user["designation"],
                                   remember=bool(request.form.get("remember")), last_active=time.time())
                    session.permanent = session["remember"]
                    return redirect(safe_next(request.args.get("next")) or dashboard_for(user["role"]))
                if user and ok:
                    flash("Your account is deactivated. Please contact the administrator.", "danger")
                else:
                    if user:
                        attempts = user["failed_attempts"] + 1
                        lock = now() + timedelta(minutes=cfg("lockout_minutes")) if attempts >= cfg("max_failed_attempts") else None
                        execute("UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s",
                                (0 if lock else attempts, lock, user["id"]))
                    flash("Invalid email or password.", "danger")
    return render_template("login.html", email=email)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


def send_mail(to, subject, body):
    """Send a plain-text email using the MAIL_* values in .env. Raises an error that says what went wrong."""
    server = os.getenv("MAIL_SERVER", "").strip()
    if not server:
        raise RuntimeError("MAIL_SERVER is empty in .env, so no email can be sent.")
    port = int(os.getenv("MAIL_PORT", "587").strip() or 587)
    user = os.getenv("MAIL_USERNAME", "").strip()
    password = os.getenv("MAIL_PASSWORD", "").strip()
    if "gmail" in server.lower():
        password = password.replace(" ", "")  # Google shows app passwords in groups of four with spaces
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.getenv("MAIL_SENDER", "").strip() or user or "no-reply@interrival.com"
    msg["To"] = to
    msg.set_content(body)
    smtp_class = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP  # 465 = SSL from the start, 587 = STARTTLS
    with smtp_class(server, port, timeout=15) as smtp:
        if port != 465:
            smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)


def send_reset_email(to, link):
    body = (f"Hello,\n\nUse the link below to reset your Interrival password. It expires in "
            f"{cfg('reset_token_minutes')} minutes and can be used once.\n\n{link}\n\n"
            "If you didn't request this, you can ignore this email.")
    if not os.getenv("MAIL_SERVER", "").strip():  # development mode
        print(f"\n[DEV] MAIL_SERVER is empty, so no email was sent. Password reset link for {to}: {link}\n", flush=True)
        return
    send_mail(to, "Reset your Interrival password", body)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    sent, email = False, ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not valid_email(email):
            flash("Enter a valid email address.", "danger")
        else:
            user = query_one("SELECT id FROM users WHERE email=%s AND is_active=1", (email,))
            if user:
                token = secrets.token_urlsafe(32)
                execute("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s,%s,%s)",
                        (user["id"], hashlib.sha256(token.encode()).hexdigest(),
                         now() + timedelta(minutes=cfg("reset_token_minutes"))))
                try:
                    send_reset_email(email, url_for("reset_password", token=token, _external=True))
                except Exception as exc:  # never reveal delivery problems to the requester
                    app.logger.error("Reset email failed: %s", exc)
            sent = True  # identical response whether or not the account exists
    return render_template("forgot_password.html", sent=sent, email=email)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    record = query_one(
        "SELECT * FROM password_resets WHERE token_hash=%s AND used_at IS NULL AND expires_at>%s",
        (hashlib.sha256(token.encode()).hexdigest(), now()))
    if not record:
        return render_template("reset_password.html", state="invalid")

    if request.method == "POST":
        pw, confirm = request.form.get("password", ""), request.form.get("confirm", "")
        missing = password_errors(pw)
        if missing:
            flash("Password must include: " + ", ".join(m.lower() for m in missing) + ".", "danger")
        elif pw != confirm:
            flash("Passwords do not match.", "danger")
        else:
            execute("UPDATE users SET password_hash=%s, failed_attempts=0, locked_until=NULL WHERE id=%s",
                    (generate_password_hash(pw), record["user_id"]))
            execute("UPDATE password_resets SET used_at=%s WHERE user_id=%s AND used_at IS NULL",
                    (now(), record["user_id"]))
            return render_template("reset_password.html", state="success")
    return render_template("reset_password.html", state="form")


@app.route("/contact-admin")
def contact_admin():
    return render_template("contact_admin.html", contact_email=cfg("contact_email"), contact_phone=cfg("contact_phone"))


# ----------------------------------------------------------------------------
# Admin dashboard
# ----------------------------------------------------------------------------
AVATAR_COLORS = ("#1e5cf0", "#12a26a", "#f59e0b", "#8b5cf6", "#ef4455", "#0ea5e9")


def initials(name):
    p = name.split()
    return (p[0][0] + (p[-1][0] if len(p) > 1 else "")).upper()


@app.route("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    today = date.today()
    emp = query_one("SELECT COUNT(*) AS total, COALESCE(SUM(created_at>=%s),0) AS joined FROM users "
                    "WHERE role='employee' AND is_active=1", (today.replace(day=1),))
    total_emp, joined = int(emp["total"]), int(emp["joined"])
    present = int(query_one("SELECT COUNT(*) AS n FROM attendance a JOIN users u ON u.id=a.user_id "
                            "WHERE a.work_date=%s AND u.role='employee' AND u.is_active=1", (today,))["n"])
    on_leave = int(query_one("SELECT COUNT(DISTINCT l.user_id) AS n FROM leaves l JOIN users u ON u.id=l.user_id "
                             "WHERE l.status='Approved' AND l.from_date<=%s AND l.to_date>=%s "
                             "AND u.role='employee' AND u.is_active=1", (today, today))["n"])
    t = query_one("SELECT COUNT(*) AS total, COALESCE(SUM(t.status='Completed'),0) AS done, "
                  "COALESCE(SUM(t.status='In Progress'),0) AS prog, COALESCE(SUM(t.status='Pending'),0) AS pend "
                  "FROM tasks t JOIN users u ON u.id=t.user_id WHERE u.is_active=1")
    task_total, done, prog, pend = (int(t[k]) for k in ("total", "done", "prog", "pend"))
    ap = query_one("SELECT (SELECT COUNT(*) FROM timesheets WHERE status='Pending') AS ts, "
                   "(SELECT COUNT(*) FROM leaves WHERE status='Pending') AS lv")
    pct = lambda n, d: round(n * 100 / d) if d else 0

    # task overview donut (pure CSS conic-gradient)
    segs = [("Completed", done, "#12a26a"), ("In Progress", prog, "#1e5cf0"), ("Pending", pend, "#f59e0b")]
    acc, parts = 0.0, []
    for _label, n, color in segs:
        start, acc = acc, acc + (n * 100 / task_total if task_total else 0)
        parts.append(f"{color} {start:.2f}% {acc:.2f}%")
    donut = f"conic-gradient({', '.join(parts)})" if task_total else "conic-gradient(#e3e9f5 0 100%)"
    legend = [dict(label=l, n=n, pct=pct(n, task_total), color=c) for l, n, c in segs]

    projects = [dict(name=r["project"], total=r["total"], pct=pct(int(r["done"]), r["total"]),
                     color=AVATAR_COLORS[i % len(AVATAR_COLORS)]) for i, r in enumerate(query_all(
        "SELECT t.project, COUNT(*) AS total, SUM(t.status='Completed') AS done FROM tasks t "
        "JOIN users u ON u.id=t.user_id WHERE u.is_active=1 AND t.project IS NOT NULL AND t.project<>'' "
        "GROUP BY t.project ORDER BY total DESC LIMIT 5"))]

    people = []
    for r in query_all(
            "SELECT u.id, u.full_name, u.department, a.check_in, a.check_out, "
            "EXISTS(SELECT 1 FROM leaves l WHERE l.user_id=u.id AND l.status='Approved' "
            "AND l.from_date<=%s AND l.to_date>=%s) AS on_leave "
            "FROM users u LEFT JOIN attendance a ON a.user_id=u.id AND a.work_date=%s "
            "WHERE u.role='employee' AND u.is_active=1 ORDER BY (a.check_in IS NULL), a.check_in, u.full_name LIMIT 8",
            (today, today, today)):
        if r["check_in"]:
            status = "Late" if r["check_in"].time() > late_after_for(r["check_in"].date()) else "Present"
        else:
            status = "On Leave" if r["on_leave"] else "Not checked in"
        people.append(dict(name=r["full_name"], initials=initials(r["full_name"]), dept=r["department"] or "—",
                           color=AVATAR_COLORS[r["id"] % len(AVATAR_COLORS)], status=status,
                           check_in=fmt_time(r["check_in"]) if r["check_in"] else "—",
                           check_out=fmt_time(r["check_out"]) if r["check_out"] else "—"))

    return render_template(
        "admin_dashboard.html", today_label=today.strftime("%A, %d %B %Y"),
        total_emp=total_emp, joined=joined, present=present, attendance_pct=pct(present, total_emp),
        on_leave=on_leave, task_total=task_total, completed_pct=pct(done, task_total),
        pending_ts=int(ap["ts"]), pending_lv=int(ap["lv"]), donut=donut, legend=legend,
        projects=projects, people=people)


# ----------------------------------------------------------------------------
# Admin: employee management
# ----------------------------------------------------------------------------
EMP_PER_PAGE = 10


def next_employee_code():
    row = query_one("SELECT employee_code FROM users WHERE employee_code REGEXP '^IRV[0-9]+$' "
                    "ORDER BY CAST(SUBSTRING(employee_code, 4) AS UNSIGNED) DESC LIMIT 1")
    n = int(row["employee_code"][3:]) + 1 if row else 1
    return f"IRV{n:03d}"


@app.route("/admin/employees")
@role_required("admin")
def admin_employees():
    q = request.args.get("q", "").strip()[:100]
    dept = request.args.get("department", "").strip()
    status = request.args.get("status", "")
    status = status if status in ("Active", "Inactive") else ""
    page = max(request.args.get("page", 1, type=int), 1)

    where, args = ["role='employee'"], []
    if q:
        where.append("(full_name LIKE %s OR email LIKE %s OR employee_code LIKE %s)")
        args += [f"%{q}%"] * 3
    if dept:
        where.append("department=%s")
        args.append(dept)
    if status:
        where.append("is_active=%s")
        args.append(1 if status == "Active" else 0)
    clause = " AND ".join(where)

    total = query_one(f"SELECT COUNT(*) AS n FROM users WHERE {clause}", args)["n"]
    pages = max((total + EMP_PER_PAGE - 1) // EMP_PER_PAGE, 1)
    page = min(page, pages)
    rows = query_all(
        "SELECT id, employee_code, full_name, email, department, designation, is_active, locked_until "
        f"FROM users WHERE {clause} ORDER BY employee_code, id LIMIT %s OFFSET %s",
        args + [EMP_PER_PAGE, (page - 1) * EMP_PER_PAGE])
    employees = [dict(r, initials=initials(r["full_name"]), color=AVATAR_COLORS[r["id"] % len(AVATAR_COLORS)],
                      locked=bool(r["locked_until"] and r["locked_until"] > now())) for r in rows]

    c = query_one("SELECT COUNT(*) AS total, COALESCE(SUM(is_active=1),0) AS active, COALESCE(SUM(is_active=0),0) AS inactive, "
                  "COUNT(DISTINCT NULLIF(department,'')) AS depts FROM users WHERE role='employee'")
    existing = [r["department"] for r in query_all(
        "SELECT DISTINCT department FROM users WHERE role='employee' AND department IS NOT NULL AND department<>'' "
        "ORDER BY department")]
    departments = sorted(set(existing) | set(cfg("departments")))
    return render_template("admin_employees.html", employees=employees, q=q, dept=dept, status=status,
                           page=page, pages=pages, total=total, existing_depts=existing, departments=departments,
                           stats={k: int(c[k]) for k in ("total", "active", "inactive", "depts")},
                           next_code=next_employee_code(),
                           args={k: v for k, v in (("q", q), ("department", dept), ("status", status)) if v})


@app.route("/admin/employees/save", methods=["POST"])
@role_required("admin")
def admin_employee_save():
    f = request.form
    emp_id = f.get("emp_id", type=int)
    code = f.get("employee_code", "").strip().upper()
    name = " ".join(f.get("full_name", "").split())
    email = f.get("email", "").strip().lower()
    dept, desig = f.get("department", "").strip(), f.get("designation", "").strip()
    pw = f.get("password", "")

    error = None
    if not 2 <= len(name) <= 120:
        error = "Enter the employee's full name (2 to 120 characters)."
    elif not valid_email(email):
        error = "Enter a valid email address."
    elif len(dept) > 80 or len(desig) > 120:
        error = "Department or designation is too long."
    elif not emp_id and not re.fullmatch(r"[A-Z0-9\-]{3,20}", code):
        error = "Employee ID must be 3 to 20 letters, numbers or dashes."
    elif (pw or not emp_id) and password_errors(pw):
        error = "Password must include: " + ", ".join(m.lower() for m in password_errors(pw)) + "."
    elif query_one("SELECT id FROM users WHERE email=%s AND id<>%s", (email, emp_id or 0)):
        error = "Another account already uses this email address."
    elif not emp_id and query_one("SELECT id FROM users WHERE employee_code=%s", (code,)):
        error = f"Employee ID {code} already exists."
    elif emp_id and not query_one("SELECT id FROM users WHERE id=%s AND role='employee'", (emp_id,)):
        abort(404)

    if error:
        flash(error, "danger")
        return redirect(url_for("admin_employees"))
    try:
        if emp_id:
            execute("UPDATE users SET full_name=%s, email=%s, department=%s, designation=%s WHERE id=%s",
                    (name, email, dept or None, desig or None, emp_id))
            if pw:
                execute("UPDATE users SET password_hash=%s, failed_attempts=0, locked_until=NULL WHERE id=%s",
                        (generate_password_hash(pw), emp_id))
            flash(f"{name} updated" + (" and password reset." if pw else "."), "success")
        else:
            new_id = execute("INSERT INTO users (employee_code, full_name, email, password_hash, role, designation, department) "
                             "VALUES (%s,%s,%s,%s,'employee',%s,%s)",
                             (code, name, email, generate_password_hash(pw), desig or None, dept or None))
            notify(new_id, "system", "Welcome to Interrival Technology",
                   "Your account is ready. Track your tasks, timesheets and attendance here.", url_for("employee_dashboard"))
            flash(f"{name} added with ID {code}. Share the password with them securely.", "success")
    except mysql.connector.IntegrityError:
        flash("That email or employee ID is already in use.", "danger")
    return redirect(url_for("admin_employees"))


@app.route("/admin/employees/<int:emp_id>/toggle", methods=["POST"])
@role_required("admin")
def admin_employee_toggle(emp_id):
    row = query_one("SELECT full_name, is_active FROM users WHERE id=%s AND role='employee'", (emp_id,))
    if not row:
        abort(404)
    new = 0 if row["is_active"] else 1
    execute("UPDATE users SET is_active=%s WHERE id=%s", (new, emp_id))
    flash(f"{row['full_name']} {'activated' if new else 'deactivated'}.", "success")
    return redirect(request.referrer or url_for("admin_employees"))


@app.route("/admin/employees/<int:emp_id>/unlock", methods=["POST"])
@role_required("admin")
def admin_employee_unlock(emp_id):
    if not query_one("SELECT id FROM users WHERE id=%s AND role='employee'", (emp_id,)):
        abort(404)
    execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=%s", (emp_id,))
    flash("Account unlocked.", "success")
    return redirect(request.referrer or url_for("admin_employees"))


# ----------------------------------------------------------------------------
# Admin: attendance management
# ----------------------------------------------------------------------------
ATT_STATUSES = ("Present", "Late", "On Leave", "Absent", "Not checked in", "Weekend")
ATT_PER_PAGE = 10


def csv_safe(v):
    """Stop spreadsheet formula injection in exported text."""
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v


def build_attendance(d, dept="", q=""):
    """One row per active employee for day d, with a derived status."""
    today = date.today()
    where = ["u.role='employee'", "u.is_active=1", "DATE(u.created_at)<=%s"]
    args = [d, d, d, d]
    if dept:
        where.append("u.department=%s")
        args.append(dept)
    if q:
        where.append("(u.full_name LIKE %s OR u.employee_code LIKE %s)")
        args += [f"%{q}%"] * 2
    rows = query_all(
        "SELECT u.id, u.employee_code, u.full_name, u.department, a.check_in, a.check_out, "
        "EXISTS(SELECT 1 FROM leaves l WHERE l.user_id=u.id AND l.status='Approved' "
        "AND l.from_date<=%s AND l.to_date>=%s) AS on_leave "
        "FROM users u LEFT JOIN attendance a ON a.user_id=u.id AND a.work_date=%s "
        "WHERE " + " AND ".join(where) + " ORDER BY u.employee_code, u.id", args)

    people = []
    for r in rows:
        ci, co = r["check_in"], r["check_out"]
        if ci:
            status = "Late" if ci.time() > late_after_for(d) else "Present"
        elif d.weekday() >= 6:
            status = "Weekend"
        elif r["on_leave"]:
            status = "On Leave"
        elif d == today:
            status = "Not checked in"
        else:
            status = "Absent"
        end = co or (datetime.now() if ci and d == today else None)
        mins = max(int((end - ci).total_seconds() // 60), 0) if ci and end else 0
        people.append(dict(
            id=r["id"], code=r["employee_code"] or "—", name=r["full_name"], initials=initials(r["full_name"]),
            color=AVATAR_COLORS[r["id"] % len(AVATAR_COLORS)], dept=r["department"] or "—", status=status,
            check_in=fmt_time(ci) if ci else "—", check_out=fmt_time(co) if co else "—",
            ci_raw=hhmm(ci) if ci else "", co_raw=hhmm(co) if co else "",
            hours=fmt_duration(mins) if mins else "—", running=bool(ci and not co and d == today)))
    return people


def attendance_filters():
    today = date.today()
    d = min(parse_date(request.args.get("date"), today), today)
    dept = request.args.get("department", "").strip()
    q = request.args.get("q", "").strip()[:100]
    status = request.args.get("status", "")
    return d, dept, q, status if status in ATT_STATUSES else ""


@app.route("/admin/attendance")
@role_required("admin")
def admin_attendance():
    today = date.today()
    d, dept, q, status = attendance_filters()
    people = build_attendance(d, dept, q)
    count = lambda *names: sum(p["status"] in names for p in people)
    summary = dict(total=len(people), present=count("Present"), late=count("Late"),
                   leave=count("On Leave"), absent=count("Absent", "Not checked in"))
    if status:
        people = [p for p in people if p["status"] == status]

    page = max(request.args.get("page", 1, type=int), 1)
    total = len(people)
    pages = max((total + ATT_PER_PAGE - 1) // ATT_PER_PAGE, 1)
    page = min(page, pages)
    shown = people[(page - 1) * ATT_PER_PAGE: page * ATT_PER_PAGE]

    departments = [r["department"] for r in query_all(
        "SELECT DISTINCT department FROM users WHERE role='employee' AND department IS NOT NULL "
        "AND department<>'' ORDER BY department")]
    args = {"date": d.isoformat(), **{k: v for k, v in (("department", dept), ("status", status), ("q", q)) if v}}
    return render_template(
        "admin_attendance.html", people=shown, summary=summary, d=d, date_iso=d.isoformat(), today_iso=today.isoformat(),
        date_label=d.strftime("%A, %d %B %Y"), short_date=d.strftime("%d %b %Y"), is_today=d == today,
        prev_day=(d - timedelta(days=1)).isoformat(), next_day=None if d == today else (d + timedelta(days=1)).isoformat(),
        dept=dept, status=status, q=q, departments=departments, statuses=ATT_STATUSES,
        page=page, pages=pages, total=total, offset=(page - 1) * ATT_PER_PAGE, args=args)


@app.route("/admin/attendance/export")
@role_required("admin")
def admin_attendance_export():
    d, dept, q, status = attendance_filters()
    people = [p for p in build_attendance(d, dept, q) if not status or p["status"] == status]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Employee ID", "Name", "Department", "Date", "Check In", "Check Out", "Working Hours", "Status"])
    for p in people:
        w.writerow([csv_safe(p["code"]), csv_safe(p["name"]), csv_safe(p["dept"]), d.isoformat(),
                    p["check_in"], p["check_out"], p["hours"], p["status"]])
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=attendance_{d.isoformat()}.csv"})


@app.route("/admin/attendance/save", methods=["POST"])
@role_required("admin")
def admin_attendance_save():
    f, today = request.form, date.today()
    uid = f.get("user_id", type=int)
    d = parse_date(f.get("date"), None)
    back = url_for("admin_attendance", date=(d or today).isoformat())
    emp = query_one("SELECT full_name FROM users WHERE id=%s AND role='employee'", (uid,)) if uid else None
    try:
        ci = datetime.strptime(f.get("check_in", ""), "%H:%M").time()
        co_raw = f.get("check_out", "").strip()
        co = datetime.strptime(co_raw, "%H:%M").time() if co_raw else None
    except ValueError:
        flash("Enter valid check-in and check-out times.", "danger")
        return redirect(back)

    if not emp or d is None:
        flash("Employee or date not found.", "danger")
    elif d > today:
        flash("You can't edit attendance for a future date.", "danger")
    elif co and co <= ci:
        flash("Check-out must be after check-in.", "danger")
    else:
        execute("INSERT INTO attendance (user_id, work_date, check_in, check_out) VALUES (%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE check_in=VALUES(check_in), check_out=VALUES(check_out)",
                (uid, d, datetime.combine(d, ci), datetime.combine(d, co) if co else None))
        notify(uid, "attendance", "Attendance updated",
               f"Your attendance for {d.strftime('%d %b %Y')} was updated by the admin.", url_for("attendance"))
        flash(f"Attendance updated for {emp['full_name']} on {d.strftime('%d %b %Y')}.", "success")
    return redirect(back)


# ----------------------------------------------------------------------------
# Admin: task management (create, assign, track)
# ----------------------------------------------------------------------------
ADMIN_TASKS_PER_PAGE = 10


@app.route("/admin/tasks")
@role_required("admin")
def admin_tasks():
    today = date.today()
    status = request.args.get("status", "")
    priority = request.args.get("priority", "")
    project = request.args.get("project", "").strip()
    assignee = request.args.get("assignee", type=int)
    q = request.args.get("q", "").strip()[:100]
    page = max(request.args.get("page", 1, type=int), 1)

    where, args = ["u.role='employee'"], []
    if status == "Overdue":
        where.append("t.due_date<%s AND t.status<>'Completed'")
        args.append(today)
    elif status in TASK_STATUSES:
        where.append("t.status=%s")
        args.append(status)
    else:
        status = ""
    if priority in TASK_PRIORITIES:
        where.append("t.priority=%s")
        args.append(priority)
    else:
        priority = ""
    if project:
        where.append("t.project=%s")
        args.append(project)
    if assignee:
        where.append("t.user_id=%s")
        args.append(assignee)
    if q:
        where.append("(t.title LIKE %s OR t.project LIKE %s)")
        args += [f"%{q}%"] * 2
    clause = " AND ".join(where)

    total = query_one(f"SELECT COUNT(*) AS n FROM tasks t JOIN users u ON u.id=t.user_id WHERE {clause}", args)["n"]
    pages = max((total + ADMIN_TASKS_PER_PAGE - 1) // ADMIN_TASKS_PER_PAGE, 1)
    page = min(page, pages)
    rows = query_all(
        "SELECT t.id, t.title, t.project, t.priority, t.status, t.due_date, t.user_id, u.full_name, u.employee_code "
        f"FROM tasks t JOIN users u ON u.id=t.user_id WHERE {clause} "
        "ORDER BY (t.status='Completed'), t.due_date, FIELD(t.priority,'High','Medium','Low'), t.id LIMIT %s OFFSET %s",
        args + [ADMIN_TASKS_PER_PAGE, (page - 1) * ADMIN_TASKS_PER_PAGE])
    tasks = [dict(r, initials=initials(r["full_name"]), color=AVATAR_COLORS[r["user_id"] % len(AVATAR_COLORS)],
                  overdue=r["due_date"] < today and r["status"] != "Completed") for r in rows]

    c = query_one(
        "SELECT COUNT(*) AS total, COALESCE(SUM(t.status='Pending'),0) AS pending, "
        "COALESCE(SUM(t.status='In Progress'),0) AS progress, COALESCE(SUM(t.status='Completed'),0) AS done, "
        "COALESCE(SUM(t.due_date<%s AND t.status<>'Completed'),0) AS overdue "
        "FROM tasks t JOIN users u ON u.id=t.user_id WHERE u.role='employee'", (today,))
    n = {k: int(c[k]) for k in ("total", "pending", "progress", "done", "overdue")}
    tabs = [("All", "", n["total"]), ("Pending", "Pending", n["pending"]), ("In Progress", "In Progress", n["progress"]),
            ("Completed", "Completed", n["done"]), ("Overdue", "Overdue", n["overdue"])]
    employees = query_all("SELECT id, full_name, employee_code FROM users WHERE role='employee' AND is_active=1 "
                          "ORDER BY full_name")
    projects = [r["project"] for r in query_all("SELECT DISTINCT project FROM tasks WHERE project IS NOT NULL "
                                                "AND project<>'' ORDER BY project")]
    return render_template(
        "admin_tasks.html", tasks=tasks, tabs=tabs, status=status, priority=priority, project=project,
        assignee=assignee, q=q, page=page, pages=pages, total=total, offset=(page - 1) * ADMIN_TASKS_PER_PAGE,
        employees=employees, projects=projects, statuses=TASK_STATUSES, priorities=TASK_PRIORITIES,
        today_iso=today.isoformat(),
        args={k: v for k, v in (("status", status), ("priority", priority), ("project", project),
                                ("assignee", assignee), ("q", q)) if v},
        args_no_status={k: v for k, v in (("priority", priority), ("project", project),
                                          ("assignee", assignee), ("q", q)) if v})


@app.route("/admin/tasks/save", methods=["POST"])
@role_required("admin")
def admin_task_save():
    f, today = request.form, date.today()
    task_id = f.get("task_id", type=int)
    title, project = f.get("title", "").strip(), f.get("project", "").strip()
    priority, status = f.get("priority", "Medium"), f.get("status", "Pending")
    assignee = f.get("assignee", type=int)
    due = parse_date(f.get("due_date"), None)

    old = query_one("SELECT user_id, due_date FROM tasks WHERE id=%s", (task_id,)) if task_id else None
    if task_id and not old:
        abort(404)
    only_active = "" if (old and assignee == old["user_id"]) else " AND is_active=1"  # keep current assignee even if deactivated
    emp = query_one("SELECT full_name FROM users WHERE id=%s AND role='employee'" + only_active, (assignee,)) if assignee else None

    error = None
    if not 1 <= len(title) <= 200:
        error = "Task title is required (max 200 characters)."
    elif len(project) > 120:
        error = "Project name is too long (max 120 characters)."
    elif priority not in TASK_PRIORITIES:
        error = "Choose a valid priority."
    elif task_id and status not in TASK_STATUSES:
        error = "Choose a valid status."
    elif due is None:
        error = "Choose a valid due date."
    elif not task_id and due < today:
        error = "The due date can't be in the past."
    elif not emp:
        error = "Choose an active employee to assign this task to."

    if error:
        flash(error, "danger")
        return redirect(url_for("admin_tasks"))

    if task_id:
        execute("UPDATE tasks SET title=%s, project=%s, priority=%s, status=%s, due_date=%s, user_id=%s WHERE id=%s",
                (title, project or None, priority, status, due, assignee, task_id))
        if assignee != old["user_id"]:
            notify(assignee, "task", "New task assigned to you", title, url_for("my_tasks"))
        elif due != old["due_date"]:
            notify(assignee, "task", "Task due date changed", f"{title} is now due on {due.strftime('%d %b %Y')}.", url_for("my_tasks"))
        flash("Task updated.", "success")
    else:
        execute("INSERT INTO tasks (user_id, title, project, priority, status, due_date) VALUES (%s,%s,%s,%s,'Pending',%s)",
                (assignee, title, project or None, priority, due))
        notify(assignee, "task", "New task assigned to you", title, url_for("my_tasks"))
        flash(f"Task assigned to {emp['full_name']}.", "success")
    return redirect(url_for("admin_tasks"))


@app.route("/admin/tasks/<int:task_id>/delete", methods=["POST"])
@role_required("admin")
def admin_task_delete(task_id):
    if not query_one("SELECT id FROM tasks WHERE id=%s", (task_id,)):
        abort(404)
    execute("DELETE FROM tasks WHERE id=%s", (task_id,))
    flash("Task deleted.", "success")
    return redirect(request.referrer or url_for("admin_tasks"))


# ----------------------------------------------------------------------------
# Employee dashboard: attendance, tasks, timesheet
# ----------------------------------------------------------------------------
def query_all(sql, args=()):
    cur = get_db().cursor(dictionary=True, buffered=True)
    cur.execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return rows


def fmt_time(t):
    """MySQL TIME arrives as timedelta, DATETIME as datetime -> '09:05 AM'."""
    if isinstance(t, timedelta):
        t = (datetime.min + timedelta(seconds=int(t.total_seconds()))).time()
    return t.strftime("%I:%M %p")


def fmt_duration(minutes):
    return f"{minutes // 60}h {minutes % 60:02d}m"




@app.route("/employee/change-password", methods=["GET", "POST"])
@role_required("employee")
def employee_change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        uid = session["user_id"]
        row = query_one("SELECT password_hash FROM users WHERE id=%s AND role='employee'", (uid,))
        problems = password_errors(new)
        if not row or not check_password_hash(row["password_hash"], current):
            flash("Your current password is incorrect.", "danger")
        elif new != confirm:
            flash("The new passwords don't match.", "danger")
        elif problems:
            flash("Password must include: " + ", ".join(m.lower() for m in problems) + ".", "danger")
        elif check_password_hash(row["password_hash"], new):
            flash("Choose a password you haven't used just now.", "danger")
        else:
            execute("UPDATE users SET password_hash=%s, failed_attempts=0, locked_until=NULL WHERE id=%s AND role='employee'",
                    (generate_password_hash(new), uid))
            flash("Password changed successfully.", "success")
            return redirect(url_for("employee_change_password"))
    return render_template("employee_change_password.html")


@app.route("/employee/dashboard")
@role_required("employee")
def employee_dashboard():
    uid, today = session["user_id"], date.today()
    sync_deadline_reminders(uid)
    att = query_one("SELECT check_in, check_out FROM attendance WHERE user_id=%s AND work_date=%s", (uid, today))
    tasks = query_all(
        "SELECT id, title, project, priority, status FROM tasks WHERE user_id=%s "
        "AND (due_date=%s OR (due_date<%s AND status<>'Completed')) "
        "ORDER BY (status='Completed'), FIELD(priority,'High','Medium','Low'), id", (uid, today, today))
    rows = query_all("SELECT task, start_time, end_time, hours FROM timesheets "
                     "WHERE user_id=%s AND work_date=%s ORDER BY start_time", (uid, today))

    minutes = 0
    if att:
        minutes = int(((att["check_out"] or datetime.now()) - att["check_in"]).total_seconds() // 60)
    entries = [dict(task=r["task"], start=fmt_time(r["start_time"]), end=fmt_time(r["end_time"]),
                    hours=fmt_duration(int(round(float(r["hours"]) * 60)))) for r in rows]
    total = sum(float(r["hours"]) for r in rows)

    return render_template(
        "employee_dashboard.html",
        today_label=today.strftime("%A, %d %B %Y"), today_iso=today.isoformat(),
        check_in=fmt_time(att["check_in"]) if att else None,
        check_out=fmt_time(att["check_out"]) if att and att["check_out"] else None,
        check_in_iso=att["check_in"].isoformat() if att else "",
        running=bool(att and not att["check_out"]),
        worked=fmt_duration(minutes), tasks=tasks,
        done_count=sum(t["status"] == "Completed" for t in tasks),
        entries=entries, total_hours=fmt_duration(int(round(total * 60))))


@app.route("/employee/check-in", methods=["POST"])
@role_required("employee")
def check_in():
    uid, today = session["user_id"], date.today()
    if query_one("SELECT id FROM attendance WHERE user_id=%s AND work_date=%s", (uid, today)):
        flash("You have already checked in today.", "warning")
    else:
        execute("INSERT INTO attendance (user_id, work_date, check_in) VALUES (%s,%s,%s)",
                (uid, today, datetime.now()))
        flash("Checked in successfully. Have a productive day!", "success")
    return redirect(safe_next(request.form.get("next")) or url_for("employee_dashboard"))


@app.route("/employee/check-out", methods=["POST"])
@role_required("employee")
def check_out():
    uid, today = session["user_id"], date.today()
    cur = get_db().cursor()
    cur.execute("UPDATE attendance SET check_out=%s WHERE user_id=%s AND work_date=%s AND check_out IS NULL",
                (datetime.now(), uid, today))
    changed = cur.rowcount
    cur.close()
    flash("Checked out. See you tomorrow!" if changed else "You need to check in first.",
          "success" if changed else "warning")
    return redirect(safe_next(request.form.get("next")) or url_for("employee_dashboard"))


@app.route("/employee/tasks/<int:task_id>/toggle", methods=["POST"])
@role_required("employee")
def toggle_task(task_id):
    task = query_one("SELECT status FROM tasks WHERE id=%s AND user_id=%s", (task_id, session["user_id"]))
    if not task:
        abort(404)
    execute("UPDATE tasks SET status=%s WHERE id=%s",
            ("Pending" if task["status"] == "Completed" else "Completed", task_id))
    return "", 204


@app.route("/employee/timesheet/add", methods=["POST"])
@role_required("employee")
def add_timesheet():
    f = request.form
    task = f.get("task", "").strip()
    try:
        work_date = datetime.strptime(f.get("work_date", ""), "%Y-%m-%d").date()
        start = datetime.strptime(f.get("start_time", ""), "%H:%M")
        end = datetime.strptime(f.get("end_time", ""), "%H:%M")
    except ValueError:
        flash("Enter a valid date and times.", "danger")
        return redirect(url_for("employee_dashboard"))
    mins = int((end - start).total_seconds() // 60)
    if not task or len(task) > 200:
        flash("Task description is required (max 200 characters).", "danger")
    elif work_date > date.today():
        flash("You can't log time for a future date.", "danger")
    elif mins <= 0:
        flash("End time must be after start time.", "danger")
    else:
        execute("INSERT INTO timesheets (user_id, work_date, task, start_time, end_time, hours) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (session["user_id"], work_date, task, start.time(), end.time(), round(mins / 60, 2)))
        flash("Timesheet entry added.", "success")
    return redirect(url_for("employee_dashboard"))


# ----------------------------------------------------------------------------
# My Tasks page
# ----------------------------------------------------------------------------
TASK_STATUSES = ("Pending", "In Progress", "Completed")
TASK_PRIORITIES = ("High", "Medium", "Low")
TASKS_PER_PAGE = 10


@app.route("/employee/tasks")
@role_required("employee")
def my_tasks():
    uid, today = session["user_id"], date.today()
    status = request.args.get("status", "")
    priority = request.args.get("priority", "")
    q = request.args.get("q", "").strip()[:100]
    page = max(request.args.get("page", 1, type=int), 1)

    where, args = ["user_id=%s"], [uid]
    if status == "Overdue":
        where.append("due_date<%s AND status<>'Completed'")
        args.append(today)
    elif status in TASK_STATUSES:
        where.append("status=%s")
        args.append(status)
    else:
        status = ""
    if priority in TASK_PRIORITIES:
        where.append("priority=%s")
        args.append(priority)
    else:
        priority = ""
    if q:
        where.append("(title LIKE %s OR project LIKE %s)")
        args += [f"%{q}%", f"%{q}%"]
    clause = " AND ".join(where)

    total = query_one(f"SELECT COUNT(*) AS n FROM tasks WHERE {clause}", args)["n"]
    pages = max((total + TASKS_PER_PAGE - 1) // TASKS_PER_PAGE, 1)
    page = min(page, pages)
    tasks = query_all(
        f"SELECT id, title, project, priority, status, due_date FROM tasks WHERE {clause} "
        "ORDER BY (status='Completed'), due_date, FIELD(priority,'High','Medium','Low'), id "
        "LIMIT %s OFFSET %s", args + [TASKS_PER_PAGE, (page - 1) * TASKS_PER_PAGE])

    c = query_one(
        "SELECT COUNT(*) AS total, SUM(status='Pending') AS pending, SUM(status='In Progress') AS progress, "
        "SUM(status='Completed') AS done, SUM(due_date<%s AND status<>'Completed') AS overdue "
        "FROM tasks WHERE user_id=%s", (today, uid))
    n = {k: int(c[k] or 0) for k in ("total", "pending", "progress", "done", "overdue")}
    tabs = [("All", "", n["total"]), ("Pending", "Pending", n["pending"]),
            ("In Progress", "In Progress", n["progress"]), ("Completed", "Completed", n["done"]),
            ("Overdue", "Overdue", n["overdue"])]

    return render_template("my_tasks.html", tasks=tasks, tabs=tabs, status=status, priority=priority,
                           q=q, page=page, pages=pages, total=total, today=today, today_iso=today.isoformat(),
                           statuses=TASK_STATUSES, priorities=TASK_PRIORITIES,
                           args={k: v for k, v in (("status", status), ("priority", priority), ("q", q)) if v})


@app.route("/employee/tasks/<int:task_id>/status", methods=["POST"])
@role_required("employee")
def set_task_status(task_id):
    status = request.form.get("status", "")
    if status not in TASK_STATUSES:
        abort(400)
    if not query_one("SELECT id FROM tasks WHERE id=%s AND user_id=%s", (task_id, session["user_id"])):
        abort(404)
    execute("UPDATE tasks SET status=%s WHERE id=%s", (status, task_id))
    return "", 204


@app.route("/employee/tasks/add", methods=["POST"])
@role_required("employee")
def add_task():
    f = request.form
    title, project = f.get("title", "").strip(), f.get("project", "").strip()
    priority = f.get("priority", "Medium")
    try:
        due = datetime.strptime(f.get("due_date", ""), "%Y-%m-%d").date()
    except ValueError:
        due = None
    if not title or len(title) > 200:
        flash("Task title is required (max 200 characters).", "danger")
    elif len(project) > 120:
        flash("Project name is too long (max 120 characters).", "danger")
    elif priority not in TASK_PRIORITIES:
        flash("Choose a valid priority.", "danger")
    elif due is None:
        flash("Choose a valid due date.", "danger")
    else:
        execute("INSERT INTO tasks (user_id, title, project, priority, status, due_date) VALUES (%s,%s,%s,%s,'Pending',%s)",
                (session["user_id"], title, project or None, priority, due))
        flash("Task added.", "success")
    return redirect(url_for("my_tasks"))


# ----------------------------------------------------------------------------
# Timesheet page: list, filter, add / edit / delete entries
# ----------------------------------------------------------------------------
TS_STATUSES = ("Pending", "Approved", "Rejected")
TS_PER_PAGE = 10


def hhmm(t):
    if isinstance(t, timedelta):
        t = (datetime.min + timedelta(seconds=int(t.total_seconds()))).time()
    return t.strftime("%H:%M")


def hours_label(h):
    return fmt_duration(int(round(float(h) * 60)))


def parse_date(value, default):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return default


def month_bounds(d):
    first = d.replace(day=1)
    return first, (first + timedelta(days=32)).replace(day=1) - timedelta(days=1)


@app.route("/employee/timesheet")
@role_required("employee")
def timesheet():
    uid, today = session["user_id"], date.today()
    first, last = month_bounds(today)
    d_from = parse_date(request.args.get("from"), first)
    d_to = parse_date(request.args.get("to"), last)
    if d_from > d_to:
        d_from, d_to = d_to, d_from
    status = request.args.get("status", "")
    status = status if status in TS_STATUSES else ""
    page = max(request.args.get("page", 1, type=int), 1)

    where, args = ["user_id=%s", "work_date BETWEEN %s AND %s"], [uid, d_from, d_to]
    if status:
        where.append("status=%s")
        args.append(status)
    clause = " AND ".join(where)

    agg = query_one(f"SELECT COUNT(*) AS n, COALESCE(SUM(hours),0) AS h FROM timesheets WHERE {clause}", args)
    total = agg["n"]
    pages = max((total + TS_PER_PAGE - 1) // TS_PER_PAGE, 1)
    page = min(page, pages)
    rows = query_all(
        f"SELECT id, work_date, task, start_time, end_time, hours, status FROM timesheets WHERE {clause} "
        "ORDER BY work_date DESC, start_time DESC LIMIT %s OFFSET %s",
        args + [TS_PER_PAGE, (page - 1) * TS_PER_PAGE])
    entries = [dict(id=r["id"], date=r["work_date"], task=r["task"], start=fmt_time(r["start_time"]),
                    end=fmt_time(r["end_time"]), start_raw=hhmm(r["start_time"]), end_raw=hhmm(r["end_time"]),
                    hours=hours_label(r["hours"]), status=r["status"], editable=r["status"] != "Approved")
               for r in rows]

    by = {r["status"]: float(r["h"]) for r in query_all(
        "SELECT status, COALESCE(SUM(hours),0) AS h FROM timesheets "
        "WHERE user_id=%s AND work_date BETWEEN %s AND %s GROUP BY status", (uid, d_from, d_to))}
    summary = dict(total=hours_label(sum(by.values())), approved=hours_label(by.get("Approved", 0)),
                   pending=hours_label(by.get("Pending", 0)), rejected=hours_label(by.get("Rejected", 0)))
    task_options = [r["title"] for r in query_all(
        "SELECT title FROM tasks WHERE user_id=%s AND status<>'Completed' ORDER BY due_date LIMIT 20", (uid,))]

    return render_template("timesheet.html", entries=entries, summary=summary, total=total, page=page, pages=pages,
                           filtered_hours=hours_label(agg["h"]), status=status, statuses=TS_STATUSES,
                           d_from=d_from.isoformat(), d_to=d_to.isoformat(), today_iso=today.isoformat(),
                           task_options=task_options,
                           args={"from": d_from.isoformat(), "to": d_to.isoformat(), **({"status": status} if status else {})})


@app.route("/employee/timesheet/save", methods=["POST"])
@role_required("employee")
def timesheet_save():
    f, uid = request.form, session["user_id"]
    entry_id = f.get("entry_id", type=int)
    task = f.get("task", "").strip()
    try:
        work_date = datetime.strptime(f.get("work_date", ""), "%Y-%m-%d").date()
        start = datetime.strptime(f.get("start_time", ""), "%H:%M")
        end = datetime.strptime(f.get("end_time", ""), "%H:%M")
    except ValueError:
        flash("Enter a valid date and times.", "danger")
        return redirect(url_for("timesheet"))
    mins = int((end - start).total_seconds() // 60)
    m_first, m_last = month_bounds(work_date)
    back = url_for("timesheet", **{"from": m_first.isoformat(), "to": m_last.isoformat()})

    if not task or len(task) > 200:
        flash("Task description is required (max 200 characters).", "danger")
    elif work_date > date.today():
        flash("You can't log time for a future date.", "danger")
    elif mins <= 0:
        flash("End time must be after start time.", "danger")
    elif entry_id:
        row = query_one("SELECT status FROM timesheets WHERE id=%s AND user_id=%s", (entry_id, uid))
        if not row:
            abort(404)
        if row["status"] == "Approved":
            flash("Approved entries can't be edited.", "warning")
        else:
            execute("UPDATE timesheets SET work_date=%s, task=%s, start_time=%s, end_time=%s, hours=%s, "
                    "status='Pending' WHERE id=%s", (work_date, task, start.time(), end.time(), round(mins / 60, 2), entry_id))
            flash("Timesheet entry updated and sent for approval.", "success")
    else:
        execute("INSERT INTO timesheets (user_id, work_date, task, start_time, end_time, hours) VALUES (%s,%s,%s,%s,%s,%s)",
                (uid, work_date, task, start.time(), end.time(), round(mins / 60, 2)))
        flash("Timesheet entry added.", "success")
    return redirect(back)


@app.route("/employee/timesheet/<int:entry_id>/delete", methods=["POST"])
@role_required("employee")
def timesheet_delete(entry_id):
    row = query_one("SELECT status FROM timesheets WHERE id=%s AND user_id=%s", (entry_id, session["user_id"]))
    if not row:
        abort(404)
    if row["status"] == "Approved":
        flash("Approved entries can't be deleted.", "warning")
    else:
        execute("DELETE FROM timesheets WHERE id=%s", (entry_id,))
        flash("Entry deleted.", "success")
    return redirect(request.referrer or url_for("timesheet"))


# ----------------------------------------------------------------------------
# Admin: timesheet approvals (review, approve / reject, bulk actions, export)
# ----------------------------------------------------------------------------
ADMIN_TS_PER_PAGE = 10
ADMIN_TS_MAX_BULK = 200
TS_FROM = "FROM timesheets t JOIN users u ON u.id=t.user_id"


def admin_ts_filters():
    """Filters shared by the page and the CSV export (defaults to the current month)."""
    first, last = month_bounds(date.today())
    d_from = parse_date(request.args.get("from"), first)
    d_to = parse_date(request.args.get("to"), last)
    if d_from > d_to:
        d_from, d_to = d_to, d_from
    status = request.args.get("status", "")
    return dict(d_from=d_from, d_to=d_to, status=status if status in TS_STATUSES else "",
                emp=request.args.get("employee", type=int),
                dept=request.args.get("department", "").strip()[:100],
                q=request.args.get("q", "").strip()[:100])


def admin_ts_where(f, with_status=True):
    where, args = ["u.role='employee'", "t.work_date BETWEEN %s AND %s"], [f["d_from"], f["d_to"]]
    if f["emp"]:
        where.append("t.user_id=%s")
        args.append(f["emp"])
    if f["dept"]:
        where.append("u.department=%s")
        args.append(f["dept"])
    if f["q"]:
        where.append("(u.full_name LIKE %s OR u.employee_code LIKE %s OR t.task LIKE %s)")
        args += [f"%{f['q']}%"] * 3
    if with_status and f["status"]:
        where.append("t.status=%s")
        args.append(f["status"])
    return " AND ".join(where), args


@app.route("/admin/timesheets")
@role_required("admin")
def admin_timesheets():
    today = date.today()
    f = admin_ts_filters()
    page = max(request.args.get("page", 1, type=int), 1)
    clause, args = admin_ts_where(f)
    base, base_args = admin_ts_where(f, with_status=False)  # tab counts ignore the status tab

    total = int(query_one(f"SELECT COUNT(*) AS n {TS_FROM} WHERE {clause}", args)["n"])
    pages = max((total + ADMIN_TS_PER_PAGE - 1) // ADMIN_TS_PER_PAGE, 1)
    page = min(page, pages)
    filtered_hours = query_one(f"SELECT COALESCE(SUM(t.hours),0) AS h {TS_FROM} WHERE {clause}", args)["h"]
    rows = query_all(
        "SELECT t.id, t.user_id, t.work_date, t.task, t.start_time, t.end_time, t.hours, t.status, "
        f"u.full_name, u.employee_code, u.department, u.is_active {TS_FROM} WHERE {clause} "
        "ORDER BY (t.status='Pending') DESC, t.work_date DESC, t.start_time DESC, t.id DESC LIMIT %s OFFSET %s",
        args + [ADMIN_TS_PER_PAGE, (page - 1) * ADMIN_TS_PER_PAGE])
    entries = [dict(id=r["id"], name=r["full_name"], initials=initials(r["full_name"]), code=r["employee_code"] or "—",
                    color=AVATAR_COLORS[r["user_id"] % len(AVATAR_COLORS)], dept=r["department"] or "—",
                    active=bool(r["is_active"]), date=r["work_date"], task=r["task"], start=fmt_time(r["start_time"]),
                    end=fmt_time(r["end_time"]), hours=hours_label(r["hours"]), status=r["status"]) for r in rows]

    by = {r["status"]: (int(r["n"]), float(r["h"])) for r in query_all(
        f"SELECT t.status, COUNT(*) AS n, COALESCE(SUM(t.hours),0) AS h {TS_FROM} WHERE {base} GROUP BY t.status", base_args)}
    cnt = lambda s: by.get(s, (0, 0.0))[0]
    hrs = lambda s: by.get(s, (0, 0.0))[1]
    people = int(query_one(f"SELECT COUNT(DISTINCT t.user_id) AS n {TS_FROM} WHERE {base}", base_args)["n"])
    summary = dict(hours=hours_label(sum(h for _n, h in by.values())), pending=cnt("Pending"),
                   approved=hours_label(hrs("Approved")), rejected=hours_label(hrs("Rejected")), people=people)
    tabs = [("All", "", sum(n for n, _h in by.values()))] + [(s, s, cnt(s)) for s in TS_STATUSES]

    employees = query_all("SELECT id, full_name, employee_code, is_active FROM users WHERE role='employee' "
                          "ORDER BY is_active DESC, full_name")
    departments = [r["department"] for r in query_all(
        "SELECT DISTINCT department FROM users WHERE role='employee' AND department IS NOT NULL "
        "AND department<>'' ORDER BY department")]

    first, last = month_bounds(today)
    keep = (("from", f["d_from"].isoformat()), ("to", f["d_to"].isoformat()), ("employee", f["emp"]),
            ("department", f["dept"]), ("q", f["q"]))
    args_no_status = {k: v for k, v in keep if v}
    return render_template(
        "admin_timesheets.html", entries=entries, summary=summary, tabs=tabs, total=total, page=page, pages=pages,
        offset=(page - 1) * ADMIN_TS_PER_PAGE, filtered_hours=hours_label(filtered_hours), status=f["status"],
        emp=f["emp"], dept=f["dept"], q=f["q"], d_from=f["d_from"].isoformat(), d_to=f["d_to"].isoformat(),
        employees=employees, departments=departments, is_filtered=bool(
            f["status"] or f["emp"] or f["dept"] or f["q"] or (f["d_from"], f["d_to"]) != (first, last)),
        args=dict(args_no_status, **({"status": f["status"]} if f["status"] else {})),
        args_no_status=args_no_status)


@app.route("/admin/timesheets/review", methods=["POST"])
@role_required("admin")
def admin_timesheet_review():
    """Approve or reject one or many entries; each affected employee gets one notification."""
    new_status = {"approve": "Approved", "reject": "Rejected"}.get(request.form.get("decision", ""))
    back = safe_next(request.form.get("next")) or url_for("admin_timesheets")
    ids = sorted(set(request.form.getlist("ids", type=int)))

    if not new_status:
        flash("Choose whether to approve or reject.", "danger")
    elif not ids:
        flash("Select at least one entry first.", "warning")
    elif len(ids) > ADMIN_TS_MAX_BULK:
        flash(f"You can review up to {ADMIN_TS_MAX_BULK} entries at a time.", "danger")
    else:
        marks = ",".join(["%s"] * len(ids))
        rows = query_all(
            f"SELECT t.id, t.user_id, t.work_date, t.hours {TS_FROM} "
            f"WHERE t.id IN ({marks}) AND u.role='employee' AND t.status<>%s", ids + [new_status])
        if not rows:
            flash(f"Nothing to update — the selected entries are already {new_status.lower()}.", "warning")
        else:
            change = [r["id"] for r in rows]
            execute(f"UPDATE timesheets SET status=%s WHERE id IN ({','.join(['%s'] * len(change))})",
                    [new_status] + change)
            by_user, verb = {}, new_status.lower()
            for r in rows:
                by_user.setdefault(r["user_id"], []).append(r)
            for uid, items in by_user.items():
                if len(items) == 1:
                    e = items[0]
                    m_first, m_last = month_bounds(e["work_date"])
                    msg = f"Your entry for {e['work_date'].strftime('%d %b %Y')} ({hours_label(e['hours'])}) was {verb}."
                    link = url_for("timesheet", **{"from": m_first.isoformat(), "to": m_last.isoformat()})
                else:
                    msg = (f"{len(items)} timesheet entries ({hours_label(sum(float(i['hours']) for i in items))}) "
                           f"were {verb}.")
                    link = url_for("timesheet")
                if new_status == "Rejected":
                    msg += " Please review and resubmit."
                notify(uid, "timesheet", f"Timesheet {verb}", msg, link)
            n = len(rows)
            flash(f"{n} timesheet entr{'y' if n == 1 else 'ies'} {verb}.", "success")
    return redirect(back)


@app.route("/admin/timesheets/export")
@role_required("admin")
def admin_timesheets_export():
    f = admin_ts_filters()
    clause, args = admin_ts_where(f)
    rows = query_all(
        "SELECT t.work_date, t.task, t.start_time, t.end_time, t.hours, t.status, u.full_name, u.employee_code, "
        f"u.department {TS_FROM} WHERE {clause} ORDER BY t.work_date, u.employee_code, t.start_time LIMIT 20000", args)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Employee ID", "Name", "Department", "Date", "Task", "Start Time", "End Time", "Hours", "Status"])
    for r in rows:
        w.writerow([csv_safe(r["employee_code"]), csv_safe(r["full_name"]), csv_safe(r["department"]),
                    r["work_date"].isoformat(), csv_safe(r["task"]), fmt_time(r["start_time"]), fmt_time(r["end_time"]),
                    f"{float(r['hours']):.2f}", r["status"]])
    name = f"timesheets_{f['d_from'].isoformat()}_to_{f['d_to'].isoformat()}.csv"
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={name}"})


# ----------------------------------------------------------------------------
# Admin: leave management (review requests, team calendar, export)
# ----------------------------------------------------------------------------
ADMIN_LEAVES_PER_PAGE = 10
LV_FROM = "FROM leaves l JOIN users u ON u.id=l.user_id"


def leave_period(a, b):
    if a == b:
        return a.strftime("%d %b %Y")
    if a.year == b.year:
        return f"{a.strftime('%d %b')} – {b.strftime('%d %b %Y')}"
    return f"{a.strftime('%d %b %Y')} – {b.strftime('%d %b %Y')}"


def admin_leave_filters():
    """Filters shared by the page and the CSV export. The date range is optional (leaves that overlap it)."""
    d_from = parse_date(request.args.get("from"), None)
    d_to = parse_date(request.args.get("to"), None)
    if d_from and d_to and d_from > d_to:
        d_from, d_to = d_to, d_from
    status = request.args.get("status", "")
    return dict(d_from=d_from, d_to=d_to, status=status if status in LEAVE_STATUSES else "",
                emp=request.args.get("employee", type=int),
                dept=request.args.get("department", "").strip()[:100],
                q=request.args.get("q", "").strip()[:100])


def admin_leave_where(f, with_status=True):
    where, args = ["u.role='employee'"], []
    if f["d_to"]:
        where.append("l.from_date<=%s")
        args.append(f["d_to"])
    if f["d_from"]:
        where.append("l.to_date>=%s")
        args.append(f["d_from"])
    if f["emp"]:
        where.append("l.user_id=%s")
        args.append(f["emp"])
    if f["dept"]:
        where.append("u.department=%s")
        args.append(f["dept"])
    if f["q"]:
        where.append("(u.full_name LIKE %s OR u.employee_code LIKE %s OR l.reason LIKE %s)")
        args += [f"%{f['q']}%"] * 3
    if with_status and f["status"]:
        where.append("l.status=%s")
        args.append(f["status"])
    return " AND ".join(where), args


@app.route("/admin/leaves")
@role_required("admin")
def admin_leaves():
    today = date.today()
    tab = "calendar" if request.args.get("tab") == "calendar" else "list"
    f = admin_leave_filters()
    if tab == "calendar":  # the calendar has its own month; ignore any stray date range / status
        f.update(d_from=None, d_to=None, status="")
    base, base_args = admin_leave_where(f, with_status=False)  # tab counts ignore the status tab

    by = {r["status"]: int(r["n"]) for r in query_all(
        f"SELECT l.status, COUNT(*) AS n {LV_FROM} WHERE {base} GROUP BY l.status", base_args)}
    on_leave_today = int(query_one(
        f"SELECT COUNT(DISTINCT l.user_id) AS n {LV_FROM} WHERE l.status='Approved' AND l.from_date<=%s "
        "AND l.to_date>=%s AND u.role='employee' AND u.is_active=1", (today, today))["n"])
    summary = dict(total=sum(by.values()), pending=by.get("Pending", 0), approved=by.get("Approved", 0),
                   rejected=by.get("Rejected", 0), today=on_leave_today)
    tabs = [("All", "", summary["total"])] + [(s, s, by.get(s, 0)) for s in LEAVE_STATUSES]

    employees = query_all("SELECT id, full_name, employee_code, is_active FROM users WHERE role='employee' "
                          "ORDER BY is_active DESC, full_name")
    departments = [r["department"] for r in query_all(
        "SELECT DISTINCT department FROM users WHERE role='employee' AND department IS NOT NULL "
        "AND department<>'' ORDER BY department")]
    keep = (("from", f["d_from"].isoformat() if f["d_from"] else ""), ("to", f["d_to"].isoformat() if f["d_to"] else ""),
            ("employee", f["emp"]), ("department", f["dept"]), ("q", f["q"]))
    args_no_status = {k: v for k, v in keep if v}
    cal_args = {k: v for k, v in keep if v and k not in ("from", "to")}
    ctx = dict(tab=tab, summary=summary, tabs=tabs, employees=employees, departments=departments,
               emp=f["emp"], dept=f["dept"], q=f["q"], status=f["status"],
               d_from=f["d_from"].isoformat() if f["d_from"] else "", d_to=f["d_to"].isoformat() if f["d_to"] else "",
               args_no_status=args_no_status, cal_args=cal_args,
               is_filtered=bool(f["status"] or f["emp"] or f["dept"] or f["q"] or f["d_from"] or f["d_to"]))

    if tab == "list":
        page = max(request.args.get("page", 1, type=int), 1)
        clause, args = admin_leave_where(f)
        total = int(query_one(f"SELECT COUNT(*) AS n {LV_FROM} WHERE {clause}", args)["n"])
        pages = max((total + ADMIN_LEAVES_PER_PAGE - 1) // ADMIN_LEAVES_PER_PAGE, 1)
        page = min(page, pages)
        rows = query_all(
            "SELECT l.id, l.user_id, l.from_date, l.to_date, l.days, l.reason, l.status, l.admin_note, "
            "u.full_name, u.employee_code, u.department, u.is_active, "
            "(SELECT COUNT(DISTINCT l2.user_id) FROM leaves l2 JOIN users u2 ON u2.id=l2.user_id "
            " WHERE l.status='Pending' AND u.department IS NOT NULL AND u.department<>'' AND u2.department=u.department "
            " AND l2.user_id<>l.user_id AND l2.status='Approved' AND u2.is_active=1 "
            " AND l2.from_date<=l.to_date AND l2.to_date>=l.from_date) AS overlap "
            f"{LV_FROM} WHERE {clause} "
            "ORDER BY (l.status='Pending') DESC, CASE WHEN l.status='Pending' THEN l.from_date END ASC, "
            "l.from_date DESC, l.id DESC LIMIT %s OFFSET %s",
            args + [ADMIN_LEAVES_PER_PAGE, (page - 1) * ADMIN_LEAVES_PER_PAGE])

        def when(r):
            if r["status"] not in ("Pending", "Approved"):
                return ""
            if r["to_date"] < today:
                return "Ended"
            if r["from_date"] <= today:
                return "In progress"
            n = (r["from_date"] - today).days
            return "Starts tomorrow" if n == 1 else f"Starts in {n} days"

        leaves = [dict(id=r["id"], name=r["full_name"], initials=initials(r["full_name"]), code=r["employee_code"] or "—",
                       color=AVATAR_COLORS[r["user_id"] % len(AVATAR_COLORS)], dept=r["department"] or "—",
                       active=bool(r["is_active"]), period=leave_period(r["from_date"], r["to_date"]), when=when(r),
                       days=r["days"], reason=r["reason"], note=r["admin_note"], status=r["status"],
                       overlap=int(r["overlap"] or 0),
                       can_revoke=r["status"] == "Approved" and r["to_date"] >= today) for r in rows]
        ctx.update(leaves=leaves, total=total, page=page, pages=pages, offset=(page - 1) * ADMIN_LEAVES_PER_PAGE,
                   args=dict(args_no_status, **({"status": f["status"]} if f["status"] else {})))
    else:
        try:
            first = datetime.strptime(request.args.get("month", "") + "-01", "%Y-%m-%d").date()
        except ValueError:
            first = today.replace(day=1)
        last = month_bounds(first)[1]
        clause, args = admin_leave_where(dict(f, d_from=first, d_to=last))
        marks = {}
        for r in query_all(
                "SELECT l.from_date, l.to_date, l.status, u.full_name "
                f"{LV_FROM} WHERE {clause} AND l.status IN ('Pending','Approved') "
                "ORDER BY (l.status='Approved') DESC, u.full_name", args):
            d, end = max(r["from_date"], first), min(r["to_date"], last)
            while d <= end:
                if d.weekday() < 6:  # Mon-Sat, same working week as the employee side
                    marks.setdefault(d, []).append(dict(name=r["full_name"], short=r["full_name"].split()[0],
                                                        status=r["status"].lower()))
                d += timedelta(days=1)
        weeks = [[dict(date=d, in_month=d.month == first.month, today=d == today, weekend=d.weekday() >= 6,
                       items=marks.get(d, [])[:3], more=max(len(marks.get(d, [])) - 3, 0))
                  for d in w] for w in calendar.Calendar(firstweekday=0).monthdatescalendar(first.year, first.month)]
        ctx.update(weeks=weeks, month=first.strftime("%Y-%m"), month_label=first.strftime("%B %Y"),
                   prev_month=(first - timedelta(days=1)).strftime("%Y-%m"),
                   next_month=(last + timedelta(days=1)).strftime("%Y-%m"),
                   this_month=today.strftime("%Y-%m"))
    return render_template("admin_leaves.html", **ctx)


@app.route("/admin/leaves/review", methods=["POST"])
@role_required("admin")
def admin_leave_review():
    """Approve or reject a pending request, or revoke an approved leave that hasn't ended yet."""
    f, today = request.form, date.today()
    new_status = {"approve": "Approved", "reject": "Rejected"}.get(f.get("decision", ""))
    back = safe_next(f.get("next")) or url_for("admin_leaves")
    leave_id = f.get("leave_id", type=int)
    note = f.get("note", "").strip()
    row = query_one("SELECT l.id, l.user_id, l.from_date, l.to_date, l.status, u.full_name "
                    f"{LV_FROM} WHERE l.id=%s AND u.role='employee'", (leave_id,)) if leave_id else None
    if not row:
        abort(404)

    old = row["status"]
    if not new_status:
        flash("Choose whether to approve or reject.", "danger")
    elif len(note) > 255:
        flash("The note is too long (max 255 characters).", "danger")
    elif new_status == "Rejected" and len(note) < 3:
        flash("Please give a reason (at least 3 characters) when rejecting or revoking a leave.", "danger")
    elif not (old == "Pending" or (old == "Approved" and new_status == "Rejected" and row["to_date"] >= today)):
        flash(f"This request is already {old.lower()} and can't be changed.", "warning")
    else:
        execute("UPDATE leaves SET status=%s, admin_note=%s WHERE id=%s AND status=%s",
                (new_status, note or None, leave_id, old))
        period = leave_period(row["from_date"], row["to_date"])
        if new_status == "Approved":
            verb, title, msg = "approved", "Leave request approved", f"Your leave for {period} was approved."
        elif old == "Approved":
            verb, title, msg = "revoked", "Approved leave revoked", f"Your approved leave for {period} was revoked by the admin."
        else:
            verb, title, msg = "rejected", "Leave request rejected", f"Your leave request for {period} was rejected."
        if note:
            msg += f" Note: {note}"
        notify(row["user_id"], "leave", title, msg, url_for("leaves"))
        flash(f"Leave {verb} for {row['full_name']}.", "success")
    return redirect(back)


@app.route("/admin/leaves/export")
@role_required("admin")
def admin_leaves_export():
    f = admin_leave_filters()
    clause, args = admin_leave_where(f)
    rows = query_all(
        "SELECT l.from_date, l.to_date, l.days, l.reason, l.status, l.admin_note, u.full_name, u.employee_code, "
        f"u.department {LV_FROM} WHERE {clause} ORDER BY l.from_date DESC, u.employee_code LIMIT 20000", args)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Employee ID", "Name", "Department", "From", "To", "Working Days", "Reason", "Status", "Admin Note"])
    for r in rows:
        w.writerow([csv_safe(r["employee_code"]), csv_safe(r["full_name"]), csv_safe(r["department"]),
                    r["from_date"].isoformat(), r["to_date"].isoformat(), r["days"], csv_safe(r["reason"]),
                    r["status"], csv_safe(r["admin_note"])])
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=leaves_{date.today().isoformat()}.csv"})


# ----------------------------------------------------------------------------
# Admin: payroll (salary structure, monthly payroll, mark paid, export)
# ----------------------------------------------------------------------------
PAYROLL_PER_PAGE = 10
PAY_STATUSES = ("Pending", "Paid")
MONEY_MAX = Decimal("9999999.99")
TWO = Decimal("0.01")


@app.template_filter("inr")
def inr(v):
    """12345678.5 -> ₹1,23,45,678.50 (Indian digit grouping)."""
    n = Decimal(str(v if v is not None else 0))
    sign, n = ("-" if n < 0 else ""), abs(n)
    text = f"{n:.0f}" if n == n.to_integral_value() else f"{n:.2f}"
    whole, _, frac = text.partition(".")
    head, tail, groups = whole[:-3], whole[-3:], []
    while len(head) > 2:
        groups.insert(0, head[-2:])
        head = head[:-2]
    if head:
        groups.insert(0, head)
    return f"{sign}₹{','.join(groups + [tail])}" + (f".{frac}" if frac else "")


def money(v):
    """Parse a rupee amount from a form field. Returns None if invalid, negative or too large."""
    try:
        d = Decimal(str(v).replace(",", "").strip())
        if not d.is_finite():  # rejects "nan" / "infinity"
            return None
        d = d.quantize(TWO, rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError):
        return None
    return d if 0 <= d <= MONEY_MAX else None


def payroll_month(value):
    this_month = date.today().replace(day=1)
    try:
        first = datetime.strptime((value or "") + "-01", "%Y-%m-%d").date()
    except ValueError:
        first = this_month
    return min(first, this_month)  # no future months


def payroll_absences(first):
    """{employee_id: loss-of-pay days} for the month. Same idea as the Attendance page: a working day (Mon-Sat)
    with no check-in and no approved leave is an absence. The current month is counted up to yesterday."""
    last = month_bounds(first)[1]
    upto = min(last, date.today() - timedelta(days=1))
    if upto < first:
        return {}
    present, away = {}, {}
    for r in query_all("SELECT user_id, work_date FROM attendance WHERE work_date BETWEEN %s AND %s", (first, upto)):
        present.setdefault(r["user_id"], set()).add(r["work_date"])
    for r in query_all("SELECT user_id, from_date, to_date FROM leaves WHERE status='Approved' "
                       "AND from_date<=%s AND to_date>=%s", (upto, first)):
        d, end = max(r["from_date"], first), min(r["to_date"], upto)
        while d <= end:
            away.setdefault(r["user_id"], set()).add(d)
            d += timedelta(days=1)
    result = {}
    for u in query_all("SELECT id, created_at FROM users WHERE role='employee'"):
        d, n = max(first, u["created_at"].date()), 0  # nothing counts before the person joined
        while d <= upto:
            if d.weekday() < 6 and d not in present.get(u["id"], ()) and d not in away.get(u["id"], ()):
                n += 1
            d += timedelta(days=1)
        result[u["id"]] = n
    return result


def payroll_filters():
    status = request.args.get("status", "")
    return dict(dept=request.args.get("department", "").strip()[:100], q=request.args.get("q", "").strip()[:100],
                status=status if status in PAY_STATUSES else "")


def payroll_where(first, f, with_status=True):
    where, args = ["p.period=%s", "u.role='employee'"], [first]
    if f["dept"]:
        where.append("u.department=%s")
        args.append(f["dept"])
    if f["q"]:
        where.append("(u.full_name LIKE %s OR u.employee_code LIKE %s)")
        args += [f"%{f['q']}%"] * 2
    if with_status and f["status"]:
        where.append("p.status=%s")
        args.append(f["status"])
    return " AND ".join(where), args


PAY_SELECT = ("SELECT p.id, p.user_id, p.basic, p.allowances, p.deductions, p.lop_days, p.lop_amount, p.net_salary, "
              "p.status, p.paid_on, u.full_name, u.employee_code, u.department "
              "FROM payroll p JOIN users u ON u.id=p.user_id WHERE ")


@app.route("/admin/payroll")
@role_required("admin")
def admin_payroll():
    tab = "structure" if request.args.get("tab") == "structure" else "payroll"
    first = payroll_month(request.args.get("month"))
    last = month_bounds(first)[1]
    this_month = date.today().replace(day=1)
    f = payroll_filters()
    page = max(request.args.get("page", 1, type=int), 1)
    departments = [r["department"] for r in query_all(
        "SELECT DISTINCT department FROM users WHERE role='employee' AND department IS NOT NULL AND department<>'' "
        "ORDER BY department")]
    ctx = dict(tab=tab, q=f["q"], dept=f["dept"], status=f["status"], departments=departments, pay_statuses=PAY_STATUSES,
               month_value=first.strftime("%Y-%m"), month_label=first.strftime("%B %Y"), max_month=this_month.strftime("%Y-%m"),
               prev_month=(first - timedelta(days=1)).strftime("%Y-%m"),
               next_month=None if first == this_month else (last + timedelta(days=1)).strftime("%Y-%m"),
               is_current=first == this_month)

    if tab == "payroll":
        base, bargs = payroll_where(first, f, with_status=False)
        by = {r["status"]: (int(r["n"]), Decimal(str(r["amt"]))) for r in query_all(
            "SELECT p.status, COUNT(*) AS n, COALESCE(SUM(p.net_salary),0) AS amt FROM payroll p "
            f"JOIN users u ON u.id=p.user_id WHERE {base} GROUP BY p.status", bargs)}
        cnt = lambda st: by.get(st, (0, Decimal("0")))
        total = cnt(f["status"])[0] if f["status"] else sum(v[0] for v in by.values())
        pages = max((total + PAYROLL_PER_PAGE - 1) // PAYROLL_PER_PAGE, 1)
        page = min(page, pages)
        clause, cargs = payroll_where(first, f)
        rows = query_all(PAY_SELECT + clause + " ORDER BY u.employee_code, u.id LIMIT %s OFFSET %s",
                         cargs + [PAYROLL_PER_PAGE, (page - 1) * PAYROLL_PER_PAGE])
        items = [dict(r, initials=initials(r["full_name"]), color=AVATAR_COLORS[r["user_id"] % len(AVATAR_COLORS)],
                      total_ded=Decimal(str(r["deductions"])) + Decimal(str(r["lop_amount"]))) for r in rows]
        no_struct = query_one("SELECT COUNT(*) AS n FROM users u LEFT JOIN salary_structures s ON s.user_id=u.id "
                              "WHERE u.role='employee' AND u.is_active=1 AND s.user_id IS NULL")["n"]
        not_generated = query_one(
            "SELECT COUNT(*) AS n FROM salary_structures s JOIN users u ON u.id=s.user_id "
            "LEFT JOIN payroll p ON p.user_id=u.id AND p.period=%s WHERE u.role='employee' AND u.is_active=1 "
            "AND DATE(u.created_at)<=%s AND p.id IS NULL", (first, last))["n"]
        summary = dict(records=sum(v[0] for v in by.values()), net=sum((v[1] for v in by.values()), Decimal("0")),
                       paid_n=cnt("Paid")[0], paid=cnt("Paid")[1], pending_n=cnt("Pending")[0], pending=cnt("Pending")[1])
        args = {"month": ctx["month_value"], **{k: v for k, v in (("department", f["dept"]), ("status", f["status"]), ("q", f["q"])) if v}}
        ctx.update(items=items, summary=summary, no_struct=int(no_struct), not_generated=int(not_generated),
                   total=total, page=page, pages=pages, offset=(page - 1) * PAYROLL_PER_PAGE, args=args)
    else:
        where, args_ = ["u.role='employee'", "u.is_active=1"], []
        if f["dept"]:
            where.append("u.department=%s")
            args_.append(f["dept"])
        if f["q"]:
            where.append("(u.full_name LIKE %s OR u.employee_code LIKE %s)")
            args_ += [f"%{f['q']}%"] * 2
        clause = " AND ".join(where)
        agg = query_one("SELECT COUNT(*) AS total, COUNT(s.user_id) AS set_n, "
                        "COALESCE(SUM(s.basic+s.allowances-s.deductions),0) AS est FROM users u "
                        f"LEFT JOIN salary_structures s ON s.user_id=u.id WHERE {clause}", args_)
        total = int(agg["total"])
        pages = max((total + PAYROLL_PER_PAGE - 1) // PAYROLL_PER_PAGE, 1)
        page = min(page, pages)
        rows = query_all(
            "SELECT u.id, u.employee_code, u.full_name, u.department, u.designation, s.basic, s.allowances, s.deductions "
            f"FROM users u LEFT JOIN salary_structures s ON s.user_id=u.id WHERE {clause} "
            "ORDER BY u.employee_code, u.id LIMIT %s OFFSET %s", args_ + [PAYROLL_PER_PAGE, (page - 1) * PAYROLL_PER_PAGE])
        items = []
        for r in rows:
            net = (Decimal(str(r["basic"])) + Decimal(str(r["allowances"])) - Decimal(str(r["deductions"]))) if r["basic"] is not None else None
            items.append(dict(r, initials=initials(r["full_name"]), color=AVATAR_COLORS[r["id"] % len(AVATAR_COLORS)], net=net))
        summary = dict(total=total, set_n=int(agg["set_n"]), not_set=total - int(agg["set_n"]), est=Decimal(str(agg["est"])))
        ctx.update(items=items, summary=summary, total=total, page=page, pages=pages, offset=(page - 1) * PAYROLL_PER_PAGE,
                   args={"tab": "structure", **{k: v for k, v in (("department", f["dept"]), ("q", f["q"])) if v}})
    return render_template("admin_payroll.html", **ctx)


@app.route("/admin/payroll/salary", methods=["POST"])
@role_required("admin")
def admin_salary_save():
    f = request.form
    uid = f.get("user_id", type=int)
    basic, allow, ded = money(f.get("basic")), money(f.get("allowances") or "0"), money(f.get("deductions") or "0")
    back = safe_next(f.get("next")) or url_for("admin_payroll", tab="structure")
    emp = query_one("SELECT full_name FROM users WHERE id=%s AND role='employee'", (uid,)) if uid else None
    if not emp:
        abort(404)
    if basic is None or basic <= 0:
        flash("Enter a basic salary greater than zero.", "danger")
    elif allow is None or ded is None:
        flash("Allowances and deductions must be valid, non-negative amounts.", "danger")
    elif ded > basic + allow:
        flash("Deductions can't be more than basic salary plus allowances.", "danger")
    else:
        execute("INSERT INTO salary_structures (user_id, basic, allowances, deductions) VALUES (%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE basic=VALUES(basic), allowances=VALUES(allowances), deductions=VALUES(deductions)",
                (uid, basic, allow, ded))
        flash(f"Salary saved for {emp['full_name']}. Regenerate pending payroll to apply it to the current month.", "success")
    return redirect(back)


@app.route("/admin/payroll/generate", methods=["POST"])
@role_required("admin")
def admin_payroll_generate():
    first = payroll_month(request.form.get("month"))
    last = month_bounds(first)[1]
    back = url_for("admin_payroll", month=first.strftime("%Y-%m"))
    structs = query_all("SELECT s.user_id, s.basic, s.allowances, s.deductions FROM salary_structures s "
                        "JOIN users u ON u.id=s.user_id WHERE u.role='employee' AND u.is_active=1 AND DATE(u.created_at)<=%s", (last,))
    if not structs:
        flash("Set up salary structures first, then generate payroll.", "warning")
        return redirect(url_for("admin_payroll", tab="structure"))

    absent, work_days = payroll_absences(first), working_days(first, last) or 1
    for s_ in structs:
        basic, allow, ded = (Decimal(str(s_[k])) for k in ("basic", "allowances", "deductions"))
        lop_days = absent.get(s_["user_id"], 0)
        lop = min((basic / work_days * lop_days).quantize(TWO, rounding=ROUND_HALF_UP), basic)
        net = max(basic + allow - ded - lop, Decimal("0")).quantize(TWO)
        # paid records are never touched; pending ones are recalculated
        execute("INSERT INTO payroll (user_id, period, basic, allowances, deductions, lop_days, lop_amount, net_salary, generated_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE "
                "basic=IF(status='Pending',VALUES(basic),basic), allowances=IF(status='Pending',VALUES(allowances),allowances), "
                "deductions=IF(status='Pending',VALUES(deductions),deductions), lop_days=IF(status='Pending',VALUES(lop_days),lop_days), "
                "lop_amount=IF(status='Pending',VALUES(lop_amount),lop_amount), net_salary=IF(status='Pending',VALUES(net_salary),net_salary), "
                "generated_at=IF(status='Pending',VALUES(generated_at),generated_at)",
                (s_["user_id"], first, basic, allow, ded, lop_days, lop, net, datetime.now()))
    paid = query_one("SELECT COUNT(*) AS n FROM payroll WHERE period=%s AND status='Paid'", (first,))["n"]
    flash(f"Payroll for {first.strftime('%B %Y')} generated for {len(structs)} employee(s)."
          + (f" {paid} already-paid record(s) were left unchanged." if paid else ""), "success")
    return redirect(back)


@app.route("/admin/payroll/pay", methods=["POST"])
@role_required("admin")
def admin_payroll_pay():
    new = {"pay": "Paid", "unpay": "Pending"}.get(request.form.get("action", ""))
    ids = [int(x) for x in request.form.getlist("ids") if x.isdigit()][:200]
    back = safe_next(request.form.get("next")) or url_for("admin_payroll")
    if not new or not ids:
        flash("Select at least one payroll record.", "warning")
        return redirect(back)
    ph = ",".join(["%s"] * len(ids))
    rows = query_all("SELECT p.id, p.user_id, p.period, p.net_salary FROM payroll p JOIN users u ON u.id=p.user_id "
                     f"WHERE p.id IN ({ph}) AND u.role='employee' AND p.status<>%s", ids + [new])
    if not rows:
        flash("Nothing to update: those records already have that status.", "warning")
        return redirect(back)
    execute(f"UPDATE payroll SET status=%s, paid_on=%s WHERE id IN ({','.join(['%s'] * len(rows))})",
            [new, date.today() if new == "Paid" else None] + [r["id"] for r in rows])
    if new == "Paid":
        for r in rows:
            notify(r["user_id"], "system", "Salary processed",
                   f"Your salary for {r['period'].strftime('%B %Y')} ({inr(r['net_salary'])}) has been marked as paid.")
    n = len(rows)
    flash(f"{n} payroll record{'' if n == 1 else 's'} marked {'paid' if new == 'Paid' else 'pending'}.", "success")
    return redirect(back)


@app.route("/admin/payroll/export")
@role_required("admin")
def admin_payroll_export():
    first = payroll_month(request.args.get("month"))
    clause, args = payroll_where(first, payroll_filters())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Employee ID", "Name", "Department", "Month", "Basic", "Allowances", "Deductions", "LOP Days", "LOP Amount",
                "Net Salary", "Status", "Paid On"])
    for r in query_all(PAY_SELECT + clause + " ORDER BY u.employee_code, u.id", args):
        w.writerow([csv_safe(r["employee_code"]), csv_safe(r["full_name"]), csv_safe(r["department"]), first.strftime("%Y-%m"),
                    r["basic"], r["allowances"], r["deductions"], r["lop_days"], r["lop_amount"], r["net_salary"],
                    r["status"], r["paid_on"].isoformat() if r["paid_on"] else ""])
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=payroll_{first.strftime('%Y-%m')}.csv"})


# ----------------------------------------------------------------------------
# Admin: project management
# ----------------------------------------------------------------------------
PROJECT_STATUSES = ("Planning", "Active", "On Hold", "Completed", "Cancelled")
OPEN_PROJECT_STATUSES = ("Planning", "Active", "On Hold")
PROJECTS_PER_PAGE = 10


def unregistered_projects():
    """Project names used on tasks that are not in the projects table yet."""
    return int(query_one("SELECT COUNT(DISTINCT t.project) AS n FROM tasks t LEFT JOIN projects p ON p.name=t.project "
                         "WHERE t.project IS NOT NULL AND t.project<>'' AND p.id IS NULL")["n"])


@app.route("/admin/projects")
@role_required("admin")
def admin_projects():
    today = date.today()
    status = request.args.get("status", "")
    status = status if status in PROJECT_STATUSES else ""
    q = request.args.get("q", "").strip()[:100]
    page = max(request.args.get("page", 1, type=int), 1)

    base, bargs = "1=1", []
    if q:
        base, bargs = "(p.name LIKE %s OR p.client LIKE %s)", [f"%{q}%"] * 2
    by = {r["status"]: int(r["n"]) for r in query_all(
        f"SELECT p.status, COUNT(*) AS n FROM projects p WHERE {base} GROUP BY p.status", bargs)}
    overdue = int(query_one(f"SELECT COUNT(*) AS n FROM projects p WHERE {base} AND p.end_date<%s "
                            "AND p.status IN ('Planning','Active','On Hold')", bargs + [today])["n"])
    clause, cargs = base, list(bargs)
    if status:
        clause += " AND p.status=%s"
        cargs.append(status)
    total = by.get(status, 0) if status else sum(by.values())
    pages = max((total + PROJECTS_PER_PAGE - 1) // PROJECTS_PER_PAGE, 1)
    page = min(page, pages)
    rows = query_all(
        "SELECT p.id, p.name, p.client, p.description, p.start_date, p.end_date, p.status, "
        "COALESCE(t.total,0) AS total, COALESCE(t.done,0) AS done FROM projects p "
        "LEFT JOIN (SELECT project, COUNT(*) AS total, SUM(status='Completed') AS done FROM tasks "
        "WHERE project IS NOT NULL GROUP BY project) t ON t.project=p.name "
        f"WHERE {clause} ORDER BY FIELD(p.status,'Active','Planning','On Hold','Completed','Cancelled'), "
        "p.end_date IS NULL, p.end_date, p.name LIMIT %s OFFSET %s",
        cargs + [PROJECTS_PER_PAGE, (page - 1) * PROJECTS_PER_PAGE])
    projects = []
    for r in rows:
        n, done = int(r["total"]), int(r["done"] or 0)
        projects.append(dict(r, total=n, done=done, pct=round(done * 100 / n) if n else 0,
                             late=bool(r["end_date"] and r["end_date"] < today and r["status"] in OPEN_PROJECT_STATUSES)))
    tabs = [("All", "", sum(by.values()))] + [(s_, s_, by.get(s_, 0)) for s_ in PROJECT_STATUSES]
    summary = dict(total=sum(by.values()), active=by.get("Active", 0), hold=by.get("On Hold", 0),
                   done=by.get("Completed", 0), overdue=overdue)
    return render_template(
        "admin_projects.html", projects=projects, tabs=tabs, summary=summary, status=status, q=q, page=page, pages=pages,
        total=total, offset=(page - 1) * PROJECTS_PER_PAGE, statuses=PROJECT_STATUSES, unregistered=unregistered_projects(),
        args={k: v for k, v in (("status", status), ("q", q)) if v}, args_no_status={"q": q} if q else {})


@app.route("/admin/projects/save", methods=["POST"])
@role_required("admin")
def admin_project_save():
    f = request.form
    pid = f.get("project_id", type=int)
    name = " ".join(f.get("name", "").split())
    client, desc = f.get("client", "").strip(), f.get("description", "").strip()
    status = f.get("status", "Active")
    start, end = parse_date(f.get("start_date"), None), parse_date(f.get("end_date"), None)
    old = query_one("SELECT name FROM projects WHERE id=%s", (pid,)) if pid else None
    if pid and not old:
        abort(404)

    error = None
    if not 2 <= len(name) <= 120:
        error = "Enter a project name (2 to 120 characters)."
    elif len(client) > 120:
        error = "Client name is too long (max 120 characters)."
    elif len(desc) > 500:
        error = "Description is too long (max 500 characters)."
    elif status not in PROJECT_STATUSES:
        error = "Choose a valid status."
    elif f.get("start_date") and start is None or f.get("end_date") and end is None:
        error = "Enter valid dates."
    elif start and end and end < start:
        error = "The end date can't be before the start date."
    elif query_one("SELECT id FROM projects WHERE name=%s AND id<>%s", (name, pid or 0)):
        error = f"A project named '{name}' already exists."

    if error:
        flash(error, "danger")
        return redirect(url_for("admin_projects"))
    try:
        if pid:
            execute("UPDATE projects SET name=%s, client=%s, description=%s, start_date=%s, end_date=%s, status=%s WHERE id=%s",
                    (name, client or None, desc or None, start, end, status, pid))
            if old["name"] != name:  # tasks reference the project by name, so keep them in step
                execute("UPDATE tasks SET project=%s WHERE project=%s", (name, old["name"]))
            flash("Project updated.", "success")
        else:
            execute("INSERT INTO projects (name, client, description, start_date, end_date, status) VALUES (%s,%s,%s,%s,%s,%s)",
                    (name, client or None, desc or None, start, end, status))
            flash(f"Project '{name}' created.", "success")
    except mysql.connector.IntegrityError:
        flash("A project with that name already exists.", "danger")
    return redirect(url_for("admin_projects"))


@app.route("/admin/projects/<int:pid>/delete", methods=["POST"])
@role_required("admin")
def admin_project_delete(pid):
    row = query_one("SELECT name FROM projects WHERE id=%s", (pid,))
    if not row:
        abort(404)
    n = int(query_one("SELECT COUNT(*) AS n FROM tasks WHERE project=%s", (row["name"],))["n"])
    if n:
        flash(f"'{row['name']}' has {n} task{'' if n == 1 else 's'}. Mark it Completed or Cancelled instead of deleting.", "warning")
    else:
        execute("DELETE FROM projects WHERE id=%s", (pid,))
        flash("Project deleted.", "success")
    return redirect(request.referrer or url_for("admin_projects"))


@app.route("/admin/projects/import", methods=["POST"])
@role_required("admin")
def admin_projects_import():
    before = unregistered_projects()
    execute("INSERT IGNORE INTO projects (name, status) SELECT DISTINCT t.project, 'Active' FROM tasks t "
            "WHERE t.project IS NOT NULL AND t.project<>''")
    flash(f"Imported {before} project name{'' if before == 1 else 's'} from existing tasks. Add clients and dates by editing them." if before
          else "Nothing to import.", "success" if before else "warning")
    return redirect(url_for("admin_projects"))


# ----------------------------------------------------------------------------
# Attendance page: monthly history, late / absent summary
# ----------------------------------------------------------------------------
# Office timings (Mon-Fri 9:30-6:30, Sat 9:00-6:00) are settings: Admin > Settings > Work & Leave.


@app.route("/employee/attendance")
@role_required("employee")
def attendance():
    uid, today = session["user_id"], date.today()
    this_month = today.replace(day=1)
    try:
        first = datetime.strptime(request.args.get("month", "") + "-01", "%Y-%m-%d").date()
    except ValueError:
        first = this_month
    first = min(first, this_month)  # no future months
    last = month_bounds(first)[1]
    is_current = first == this_month

    records = {r["work_date"]: r for r in query_all(
        "SELECT work_date, check_in, check_out FROM attendance WHERE user_id=%s AND work_date BETWEEN %s AND %s",
        (uid, first, last))}

    leave_days = set()
    for lv in query_all("SELECT from_date, to_date FROM leaves WHERE user_id=%s AND status='Approved' "
                        "AND from_date<=%s AND to_date>=%s", (uid, last, first)):
        x = lv["from_date"]
        while x <= lv["to_date"]:
            leave_days.add(x)
            x += timedelta(days=1)

    days, present, late, absent, total_min = [], 0, 0, 0, 0
    d = min(last, today)
    while d >= first:
        r, weekend = records.get(d), d.weekday() >= 6
        mins = 0
        if r:
            end = r["check_out"] or (datetime.now() if d == today else None)
            mins = int((end - r["check_in"]).total_seconds() // 60) if end else 0
            status = "Late" if r["check_in"].time() > late_after_for(r["check_in"].date()) else "Present"
            present += 1
            late += status == "Late"
            total_min += mins
        elif weekend:
            status = "Weekend"
        elif d in leave_days:
            status = "On Leave"
        elif d == today:
            status = "Not checked in"
        else:
            status, absent = "Absent", absent + 1
        days.append(dict(date=d, status=status, weekend=weekend,
                         check_in=fmt_time(r["check_in"]) if r else "—",
                         check_out=fmt_time(r["check_out"]) if r and r["check_out"] else "—",
                         hours=fmt_duration(mins) if mins else "—"))
        d -= timedelta(days=1)

    tr = records.get(today)
    today_info = dict(
        check_in=fmt_time(tr["check_in"]) if tr else None,
        check_out=fmt_time(tr["check_out"]) if tr and tr["check_out"] else None,
        running=bool(tr and not tr["check_out"]),
        start_iso=tr["check_in"].isoformat() if tr else "",
        worked=fmt_duration(int(((tr["check_out"] or datetime.now()) - tr["check_in"]).total_seconds() // 60)) if tr else "0h 00m")

    prev_month = (first - timedelta(days=1)).replace(day=1)
    return render_template(
        "attendance.html", days=days, is_current=is_current, today_info=today_info,
        month_label=first.strftime("%B %Y"), month_value=first.strftime("%Y-%m"), max_month=this_month.strftime("%Y-%m"),
        prev_month=prev_month.strftime("%Y-%m"), next_month=None if is_current else (last + timedelta(days=1)).strftime("%Y-%m"),
        summary=dict(present=present, late=late, absent=absent, hours=fmt_duration(total_min),
                     avg=fmt_duration(total_min // present) if present else "0h 00m"))


# ----------------------------------------------------------------------------
# Leaves page: monthly allowance, applications, calendar
# ----------------------------------------------------------------------------
# The monthly leave limit is a setting now: Admin > Settings > Work & Leave.
LEAVE_STATUSES = ("Pending", "Approved", "Rejected", "Cancelled")
LEAVES_PER_PAGE = 10


def working_days(d1, d2):
    """Mon-sat days between two dates, inclusive."""
    n, d = 0, d1
    while d <= d2:
        n += d.weekday() < 6
        d += timedelta(days=1)
    return n


def active_leaves(uid, first, last):
    """Pending + approved leave requests that touch the period first..last."""
    return query_all("SELECT from_date, to_date, status FROM leaves WHERE user_id=%s "
                     "AND status IN ('Pending','Approved') AND from_date<=%s AND to_date>=%s", (uid, last, first))


def month_leave_usage(uid, first):
    """(approved_days, pending_days) of leave that fall inside the month starting on `first`."""
    last = month_bounds(first)[1]
    approved = pending = 0
    for r in active_leaves(uid, first, last):
        n = working_days(max(r["from_date"], first), min(r["to_date"], last))
        if r["status"] == "Approved":
            approved += n
        else:
            pending += n
    return approved, pending


@app.route("/employee/leaves")
@role_required("employee")
def leaves():
    uid, today = session["user_id"], date.today()
    tab = "calendar" if request.args.get("tab") == "calendar" else "list"

    this_month = today.replace(day=1)
    balances = []
    for first in (this_month, month_bounds(this_month)[1] + timedelta(days=1)):
        a, p = month_leave_usage(uid, first)
        balances.append(dict(label=first.strftime("%B %Y"), current=first == this_month, used=a, pending=p,
                             left=max(cfg('monthly_leave_limit') - a - p, 0),
                             pct=min(100, round((a + p) * 100 / cfg('monthly_leave_limit')))))

    ctx = dict(tab=tab, balances=balances, limit=cfg('monthly_leave_limit'), today_iso=today.isoformat(),
               statuses=LEAVE_STATUSES)

    if tab == "list":
        status = request.args.get("status", "")
        status = status if status in LEAVE_STATUSES else ""
        page = max(request.args.get("page", 1, type=int), 1)
        clause, args = "user_id=%s", [uid]
        if status:
            clause += " AND status=%s"
            args.append(status)
        total = query_one(f"SELECT COUNT(*) AS n FROM leaves WHERE {clause}", args)["n"]
        pages = max((total + LEAVES_PER_PAGE - 1) // LEAVES_PER_PAGE, 1)
        page = min(page, pages)
        rows = query_all(
            f"SELECT id, from_date, to_date, days, reason, status, admin_note FROM leaves WHERE {clause} "
            "ORDER BY from_date DESC, id DESC LIMIT %s OFFSET %s", args + [LEAVES_PER_PAGE, (page - 1) * LEAVES_PER_PAGE])
        ctx.update(rows=rows, status=status, page=page, pages=pages, total=total,
                   args={"status": status} if status else {})
    else:
        try:
            first = datetime.strptime(request.args.get("month", "") + "-01", "%Y-%m-%d").date()
        except ValueError:
            first = this_month
        last = month_bounds(first)[1]
        marks = {}
        for r in active_leaves(uid, first, last):
            d, end = max(r["from_date"], first), min(r["to_date"], last)
            while d <= end:
                if d.weekday() < 6:
                    marks[d] = r["status"]
                d += timedelta(days=1)
        weeks = [[dict(date=d, in_month=d.month == first.month, today=d == today, weekend=d.weekday() >= 6,
                       mark=marks.get(d)) for d in w]
                 for w in calendar.Calendar(firstweekday=0).monthdatescalendar(first.year, first.month)]
        ctx.update(weeks=weeks, month_label=first.strftime("%B %Y"),
                   prev_month=(first - timedelta(days=1)).strftime("%Y-%m"),
                   next_month=(last + timedelta(days=1)).strftime("%Y-%m"))
    return render_template("leaves.html", **ctx)


@app.route("/employee/leaves/apply", methods=["POST"])
@role_required("employee")
def leave_apply():
    f, uid, today = request.form, session["user_id"], date.today()
    reason = f.get("reason", "").strip()
    try:
        d1 = datetime.strptime(f.get("from_date", ""), "%Y-%m-%d").date()
        d2 = datetime.strptime(f.get("to_date", ""), "%Y-%m-%d").date()
    except ValueError:
        flash("Enter valid from and to dates.", "danger")
        return redirect(url_for("leaves"))

    days, error = working_days(d1, d2), None
    if not 5 <= len(reason) <= 255:
        error = "Please give a reason (5 to 255 characters)."
    elif d2 < d1:
        error = "The to date can't be before the from date."
    elif d1 < today:
        error = "Leave can't start in the past."
    elif (d2 - d1).days > 59:
        error = "A single request can cover at most 60 days."
    elif days == 0:
        error = "The selected dates fall only on weekends."
    elif query_one("SELECT id FROM leaves WHERE user_id=%s AND status IN ('Pending','Approved') "
                   "AND from_date<=%s AND to_date>=%s", (uid, d2, d1)):
        error = "You already have a leave request that overlaps these dates."
    else:  # check the monthly limit for every month the request touches
        m = d1.replace(day=1)
        while m <= d2 and error is None:
            m_first, m_last = month_bounds(m)
            need = working_days(max(d1, m_first), min(d2, m_last))
            if need:
                a, p = month_leave_usage(uid, m_first)
                left = cfg('monthly_leave_limit') - a - p
                if need > left:
                    error = (f"Monthly limit reached for {m_first.strftime('%B %Y')}: you can take "
                             f"{cfg('monthly_leave_limit')} day(s) per month and have {max(left, 0)} left.")
            m = m_last + timedelta(days=1)

    if error:
        flash(error, "danger")
    else:
        execute("INSERT INTO leaves (user_id, from_date, to_date, days, reason) VALUES (%s,%s,%s,%s,%s)",
                (uid, d1, d2, days, reason))
        notify(uid, "leave", "Leave request submitted",
               f"Your leave request starting {d1.strftime('%d %b %Y')} is pending approval.", url_for("leaves"))
        flash(f"Leave request submitted for {days} working day(s). It is now pending approval.", "success")
    return redirect(url_for("leaves"))


@app.route("/employee/leaves/<int:leave_id>/cancel", methods=["POST"])
@role_required("employee")
def leave_cancel(leave_id):
    row = query_one("SELECT status FROM leaves WHERE id=%s AND user_id=%s", (leave_id, session["user_id"]))
    if not row:
        abort(404)
    if row["status"] != "Pending":
        flash("Only pending requests can be cancelled.", "warning")
    else:
        execute("UPDATE leaves SET status='Cancelled' WHERE id=%s", (leave_id,))
        flash("Leave request cancelled.", "success")
    return redirect(request.referrer or url_for("leaves"))


# ----------------------------------------------------------------------------
# Notifications page
# ----------------------------------------------------------------------------
NOTIFS_PER_PAGE = 15


def notify(user_id, kind, title, message, link=None, ref=None):
    """Create a notification. Safe to call from any route (e.g. future admin actions):
       notify(employee_id, "task", "New task assigned to you", task_title, "/employee/tasks")
       kind: task | leave | timesheet | attendance | reminder | system.  ref de-duplicates repeats."""
    try:
        execute("INSERT IGNORE INTO notifications (user_id, type, title, message, link, ref, created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s)", (user_id, kind, title[:150], message[:255], link, ref, datetime.now()))
    except Exception as exc:
        app.logger.warning("Could not create notification: %s", exc)


def sync_deadline_reminders(uid):
    """One reminder per task per stage (due tomorrow / due today / overdue)."""
    today = date.today()
    try:
        tasks = query_all("SELECT id, title, due_date FROM tasks WHERE user_id=%s AND status<>'Completed' "
                          "AND due_date BETWEEN %s AND %s", (uid, today - timedelta(days=7), today + timedelta(days=1)))
    except Exception as exc:
        app.logger.warning("Deadline check skipped: %s", exc)
        return
    for t in tasks:
        if t["due_date"] < today:
            stage, head = "overdue", "Task overdue"
        elif t["due_date"] == today:
            stage, head = "today", "Task due today"
        else:
            stage, head = "tomorrow", "Task due tomorrow"
        notify(uid, "reminder", head, t["title"], url_for("my_tasks"), ref=f"deadline:{t['id']}:{stage}")


@app.route("/employee/notifications")
@role_required("employee")
def notifications():
    uid = session["user_id"]
    sync_deadline_reminders(uid)
    unread_only = request.args.get("filter") == "unread"
    page = max(request.args.get("page", 1, type=int), 1)
    clause = "user_id=%s" + (" AND is_read=0" if unread_only else "")

    c = query_one("SELECT COUNT(*) AS total, SUM(is_read=0) AS unread FROM notifications WHERE user_id=%s", (uid,))
    total_all, unread = int(c["total"] or 0), int(c["unread"] or 0)
    total = unread if unread_only else total_all
    pages = max((total + NOTIFS_PER_PAGE - 1) // NOTIFS_PER_PAGE, 1)
    page = min(page, pages)
    rows = query_all("SELECT id, type, title, message, link, is_read, created_at FROM notifications "
                     f"WHERE {clause} ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s",
                     (uid, NOTIFS_PER_PAGE, (page - 1) * NOTIFS_PER_PAGE))
    items = [dict(r, link=safe_next(r["link"])) for r in rows]
    return render_template("notifications.html", items=items, unread=unread, total_all=total_all,
                           unread_only=unread_only, page=page, pages=pages,
                           args={"filter": "unread"} if unread_only else {})


@app.route("/employee/notifications/<int:nid>/read", methods=["POST"])
@role_required("employee")
def notification_read(nid):
    execute("UPDATE notifications SET is_read=1 WHERE id=%s AND user_id=%s", (nid, session["user_id"]))
    return "", 204


@app.route("/employee/notifications/read-all", methods=["POST"])
@role_required("employee")
def notifications_read_all():
    execute("UPDATE notifications SET is_read=1 WHERE user_id=%s AND is_read=0", (session["user_id"],))
    flash("All notifications marked as read.", "success")
    return redirect(url_for("notifications"))


@app.route("/employee/notifications/<int:nid>/delete", methods=["POST"])
@role_required("employee")
def notification_delete(nid):
    execute("DELETE FROM notifications WHERE id=%s AND user_id=%s", (nid, session["user_id"]))
    return redirect(request.referrer or url_for("notifications"))


# ----------------------------------------------------------------------------
# Admin: notifications (send announcements, delivery log, clean-up)
# ----------------------------------------------------------------------------
ADMIN_NOTIFS_PER_PAGE = 10
NOTIF_TYPES = ("task", "leave", "timesheet", "attendance", "reminder", "system")
ANNOUNCE_PREFIX = "announce:"
CLEANUP_DAYS = (30, 60, 90)


def admin_notif_filters():
    d_from = parse_date(request.args.get("from"), None)
    d_to = parse_date(request.args.get("to"), None)
    if d_from and d_to and d_from > d_to:
        d_from, d_to = d_to, d_from
    kind = request.args.get("type", "")
    return dict(d_from=d_from, d_to=d_to, kind=kind if kind in NOTIF_TYPES else "",
                emp=request.args.get("employee", type=int), q=request.args.get("q", "").strip()[:100])


def admin_notif_where(f, state=""):
    where, args = ["u.role='employee'"], []
    if f["d_from"]:
        where.append("DATE(n.created_at)>=%s")
        args.append(f["d_from"])
    if f["d_to"]:
        where.append("DATE(n.created_at)<=%s")
        args.append(f["d_to"])
    if f["kind"]:
        where.append("n.type=%s")
        args.append(f["kind"])
    if f["emp"]:
        where.append("n.user_id=%s")
        args.append(f["emp"])
    if f["q"]:
        where.append("(n.title LIKE %s OR n.message LIKE %s OR u.full_name LIKE %s OR u.employee_code LIKE %s)")
        args += [f"%{f['q']}%"] * 4
    if state == "unread":
        where.append("n.is_read=0")
    elif state == "read":
        where.append("n.is_read=1")
    return " AND ".join(where), args


@app.route("/admin/notifications")
@role_required("admin")
def admin_notifications():
    today = date.today()
    tab = "announcements" if request.args.get("tab") == "announcements" else "log"
    state = request.args.get("state", "")
    state = state if state in ("unread", "read") else ""
    f = admin_notif_filters()
    page = max(request.args.get("page", 1, type=int), 1)
    NF = "FROM notifications n JOIN users u ON u.id=n.user_id"

    g_ = query_one(f"SELECT COUNT(*) AS total, COALESCE(SUM(n.is_read=0),0) AS unread, "
                   f"COALESCE(SUM(DATE(n.created_at)=%s),0) AS today {NF} WHERE u.role='employee'", (today,))
    total_all, unread_all, sent_today = int(g_["total"]), int(g_["unread"]), int(g_["today"])
    n_ann = int(query_one(f"SELECT COUNT(DISTINCT n.ref) AS n {NF} WHERE n.ref LIKE %s AND u.role='employee'",
                          (ANNOUNCE_PREFIX + "%",))["n"])
    summary = dict(total=total_all, today=sent_today, unread=unread_all, announcements=n_ann,
                   rate=round((total_all - unread_all) * 100 / total_all) if total_all else 0)

    employees = query_all("SELECT id, full_name, employee_code, department, is_active FROM users WHERE role='employee' "
                          "ORDER BY is_active DESC, full_name")
    departments = [r["department"] for r in query_all(
        "SELECT DISTINCT department FROM users WHERE role='employee' AND is_active=1 AND department IS NOT NULL "
        "AND department<>'' ORDER BY department")]
    keep = (("from", f["d_from"].isoformat() if f["d_from"] else ""), ("to", f["d_to"].isoformat() if f["d_to"] else ""),
            ("type", f["kind"]), ("employee", f["emp"]), ("q", f["q"]))
    ctx = dict(tab=tab, summary=summary, employees=employees, departments=departments, state=state, kind=f["kind"],
               emp=f["emp"], q=f["q"], d_from=keep[0][1], d_to=keep[1][1], types=NOTIF_TYPES,
               is_filtered=bool(f["kind"] or f["emp"] or f["q"] or f["d_from"] or f["d_to"] or state))

    if tab == "log":
        base, bargs = admin_notif_where(f)
        c = query_one(f"SELECT COUNT(*) AS total, COALESCE(SUM(n.is_read=0),0) AS unread {NF} WHERE {base}", bargs)
        n_all, n_unread = int(c["total"]), int(c["unread"])
        counts = {"": n_all, "unread": n_unread, "read": n_all - n_unread}
        clause, args = admin_notif_where(f, state)
        total = counts[state]
        pages = max((total + ADMIN_NOTIFS_PER_PAGE - 1) // ADMIN_NOTIFS_PER_PAGE, 1)
        page = min(page, pages)
        rows = query_all(
            "SELECT n.id, n.type, n.title, n.message, n.is_read, n.created_at, n.user_id, "
            f"u.full_name, u.employee_code, u.is_active {NF} WHERE {clause} "
            "ORDER BY n.created_at DESC, n.id DESC LIMIT %s OFFSET %s",
            args + [ADMIN_NOTIFS_PER_PAGE, (page - 1) * ADMIN_NOTIFS_PER_PAGE])
        items = [dict(id=r["id"], kind=r["type"], title=r["title"], message=r["message"], read=bool(r["is_read"]),
                      sent=r["created_at"], name=r["full_name"], initials=initials(r["full_name"]),
                      code=r["employee_code"] or "—", color=AVATAR_COLORS[r["user_id"] % len(AVATAR_COLORS)],
                      active=bool(r["is_active"])) for r in rows]
        args_ns = {k: v for k, v in keep if v}
        ctx.update(items=items, counts=counts, total=total, page=page, pages=pages,
                   offset=(page - 1) * ADMIN_NOTIFS_PER_PAGE, args_ns=args_ns,
                   args=dict(args_ns, **({"state": state} if state else {})))
    else:
        where, wargs = "n.ref LIKE %s AND u.role='employee'", [ANNOUNCE_PREFIX + "%"]
        if f["q"]:
            where += " AND (n.title LIKE %s OR n.message LIKE %s)"
            wargs += [f"%{f['q']}%"] * 2
        total = int(query_one(f"SELECT COUNT(DISTINCT n.ref) AS n {NF} WHERE {where}", wargs)["n"])
        pages = max((total + ADMIN_NOTIFS_PER_PAGE - 1) // ADMIN_NOTIFS_PER_PAGE, 1)
        page = min(page, pages)
        rows = query_all(
            "SELECT n.ref, MIN(n.title) AS title, MIN(n.message) AS message, MAX(n.created_at) AS sent, "
            f"COUNT(*) AS audience, COALESCE(SUM(n.is_read=1),0) AS read_count {NF} WHERE {where} "
            "GROUP BY n.ref ORDER BY sent DESC LIMIT %s OFFSET %s",
            wargs + [ADMIN_NOTIFS_PER_PAGE, (page - 1) * ADMIN_NOTIFS_PER_PAGE])
        anns = [dict(ref=r["ref"], title=r["title"], message=r["message"], sent=r["sent"], audience=int(r["audience"]),
                     reads=int(r["read_count"]), pct=round(int(r["read_count"]) * 100 / int(r["audience"]))) for r in rows]
        ctx.update(anns=anns, total=total, page=page, pages=pages, offset=(page - 1) * ADMIN_NOTIFS_PER_PAGE,
                   args={"tab": "announcements", **({"q": f["q"]} if f["q"] else {})}, args_ns={}, counts={})
    return render_template("admin_notifications.html", **ctx)


@app.route("/admin/notifications/send", methods=["POST"])
@role_required("admin")
def admin_notification_send():
    f = request.form
    title, message, audience = f.get("title", "").strip(), f.get("message", "").strip(), f.get("audience", "all")
    back = safe_next(f.get("next")) or url_for("admin_notifications", tab="announcements")
    if not 3 <= len(title) <= 150:
        flash("The title must be 3 to 150 characters.", "danger")
        return redirect(back)
    if not 3 <= len(message) <= 255:
        flash("The message must be 3 to 255 characters.", "danger")
        return redirect(back)
    base = "SELECT id FROM users WHERE role='employee' AND is_active=1"
    if audience == "department":
        dept = f.get("department", "").strip()
        rows = query_all(base + " AND department=%s", (dept,)) if dept else []
    elif audience == "employees":
        ids = sorted(set(f.getlist("employee_ids", type=int)))[:500]
        rows = query_all(base + f" AND id IN ({','.join(['%s'] * len(ids))})", ids) if ids else []
    else:
        rows = query_all(base)
    if not rows:
        flash("No active employees match that audience. Choose who should receive it.", "warning")
        return redirect(back)
    ref = ANNOUNCE_PREFIX + secrets.token_hex(6)
    for r in rows:
        notify(r["id"], "system", title, message, None, ref)
    flash(f"Announcement sent to {len(rows)} employee{'' if len(rows) == 1 else 's'}.", "success")
    return redirect(back)


@app.route("/admin/notifications/<int:nid>/delete", methods=["POST"])
@role_required("admin")
def admin_notification_delete(nid):
    execute("DELETE n FROM notifications n JOIN users u ON u.id=n.user_id WHERE n.id=%s AND u.role='employee'", (nid,))
    flash("Notification deleted.", "success")
    return redirect(safe_next(request.form.get("next")) or url_for("admin_notifications"))


@app.route("/admin/notifications/announcement/delete", methods=["POST"])
@role_required("admin")
def admin_announcement_delete():
    ref = request.form.get("ref", "")
    back = safe_next(request.form.get("next")) or url_for("admin_notifications", tab="announcements")
    if not ref.startswith(ANNOUNCE_PREFIX) or len(ref) > 60:
        abort(400)
    n = int(query_one("SELECT COUNT(*) AS n FROM notifications WHERE ref=%s", (ref,))["n"])
    execute("DELETE FROM notifications WHERE ref=%s", (ref,))
    flash(f"Announcement removed from {n} inbox{'' if n == 1 else 'es'}.", "success")
    return redirect(back)


@app.route("/admin/notifications/cleanup", methods=["POST"])
@role_required("admin")
def admin_notifications_cleanup():
    days = request.form.get("days", type=int)
    back = safe_next(request.form.get("next")) or url_for("admin_notifications")
    if days not in CLEANUP_DAYS:
        flash("Choose how old the notifications should be.", "danger")
        return redirect(back)
    cutoff = datetime.now() - timedelta(days=days)
    n = int(query_one("SELECT COUNT(*) AS n FROM notifications WHERE is_read=1 AND created_at<%s", (cutoff,))["n"])
    if n:
        execute("DELETE FROM notifications WHERE is_read=1 AND created_at<%s", (cutoff,))
        flash(f"Deleted {n} read notification{'' if n == 1 else 's'} older than {days} days.", "success")
    else:
        flash(f"No read notifications older than {days} days.", "warning")
    return redirect(back)


# ----------------------------------------------------------------------------
# Admin: settings (work & leave rules, security, organization, my account)
# ----------------------------------------------------------------------------
SETTINGS_SECTIONS = {
    "work": ("late_after", "work_end", "sat_late_after", "sat_work_end", "monthly_leave_limit"),
    "security": ("session_idle_minutes", "max_failed_attempts", "lockout_minutes", "reset_token_minutes"),
    "organization": ("departments", "contact_email", "contact_phone"),
}
SETTINGS_TABS = ("work", "security", "organization", "account")


def settings_ready():
    try:
        query_one("SELECT 1 AS ok FROM app_settings LIMIT 1")
        return True
    except mysql.connector.Error as exc:
        if getattr(exc, "errno", None) == 1146:  # table doesn't exist
            return False
        raise


def settings_back(tab):
    return redirect(url_for("admin_settings", tab=tab))


@app.route("/admin/settings")
@role_required("admin")
def admin_settings():
    if not settings_ready():
        flash("The settings table is missing. Run settings_schema.sql in MySQL first.", "danger")
        return redirect(url_for("admin_dashboard"))
    tab = request.args.get("tab", "work")
    tab = tab if tab in SETTINGS_TABS else "work"
    raw = load_settings(force=True)
    values, defaults, custom = {}, {}, set()
    for name in SETTINGS_SECTIONS.get(tab, ()):
        values[name] = setting_text(cfg(name))
        defaults[name] = setting_text(_convert(name, SETTING_SPECS[name]["default"], strict=False))
        if name in raw and values[name] != defaults[name]:
            custom.add(name)
    me = None
    if tab == "account":
        me = query_one("SELECT full_name, email, designation, employee_code, last_login_at FROM users WHERE id=%s",
                       (session["user_id"],))
    return render_template("admin_settings.html", tab=tab, values=values, defaults=defaults, custom=custom, me=me,
                           specs=SETTING_SPECS, tabs=SETTINGS_TABS)


@app.route("/admin/settings/save", methods=["POST"])
@role_required("admin")
def admin_settings_save():
    section = request.form.get("section", "")
    if section not in SETTINGS_SECTIONS:
        abort(400)
    clean, errors = {}, []
    for name in SETTINGS_SECTIONS[section]:
        try:
            clean[name] = setting_text(_convert(name, request.form.get(name, "")))
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        for msg in errors:
            flash(msg, "danger")
        return settings_back(section)
    for name, text in clean.items():
        execute("INSERT INTO app_settings (name, val) VALUES (%s,%s) ON DUPLICATE KEY UPDATE val=VALUES(val)", (name, text))
    load_settings(force=True)
    flash("Settings saved.", "success")
    return settings_back(section)


@app.route("/admin/settings/reset", methods=["POST"])
@role_required("admin")
def admin_settings_reset():
    section = request.form.get("section", "")
    if section not in SETTINGS_SECTIONS:
        abort(400)
    names = SETTINGS_SECTIONS[section]
    execute(f"DELETE FROM app_settings WHERE name IN ({','.join(['%s'] * len(names))})", names)
    load_settings(force=True)
    flash("Restored the default settings for this section.", "success")
    return settings_back(section)


@app.route("/admin/settings/profile", methods=["POST"])
@role_required("admin")
def admin_settings_profile():
    f, uid = request.form, session["user_id"]
    name = " ".join(f.get("full_name", "").split())
    email = f.get("email", "").strip().lower()
    desig = f.get("designation", "").strip()
    if not 2 <= len(name) <= 100:
        flash("Enter your full name (2 to 100 characters).", "danger")
    elif not valid_email(email):
        flash("Enter a valid email address.", "danger")
    elif len(desig) > 100:
        flash("The designation is too long (max 100 characters).", "danger")
    elif query_one("SELECT id FROM users WHERE email=%s AND id<>%s", (email, uid)):
        flash("Another account already uses this email address.", "danger")
    else:
        execute("UPDATE users SET full_name=%s, email=%s, designation=%s WHERE id=%s", (name, email, desig or None, uid))
        session["name"], session["designation"] = name, desig or None
        flash("Profile updated.", "success")
    return settings_back("account")


@app.route("/admin/settings/password", methods=["POST"])
@role_required("admin")
def admin_settings_password():
    f, uid = request.form, session["user_id"]
    current, new, confirm = f.get("current_password", ""), f.get("new_password", ""), f.get("confirm_password", "")
    row = query_one("SELECT password_hash FROM users WHERE id=%s", (uid,))
    problems = password_errors(new)
    if not row or not check_password_hash(row["password_hash"], current):
        flash("Your current password is incorrect.", "danger")
    elif new != confirm:
        flash("The new passwords don't match.", "danger")
    elif problems:
        flash("Password must include: " + ", ".join(m.lower() for m in problems) + ".", "danger")
    elif check_password_hash(row["password_hash"], new):
        flash("Choose a password you haven't used just now.", "danger")
    else:
        execute("UPDATE users SET password_hash=%s WHERE id=%s", (generate_password_hash(new), uid))
        flash("Password changed.", "success")
    return settings_back("account")


# ----------------------------------------------------------------------------
# CLI: create demo users ->  python app.py seed
# ----------------------------------------------------------------------------
def seed_users():
    users = [
        ("IRV000", "Admin User", "admin@interrival.com", "Admin@123", "admin", "HR Manager"),
        ("IRV001", "Rahul Sharma", "rahul@interrival.com", "Employee@123", "employee", "Software Engineer"),
    ]
    with app.app_context():
        for code, name, email, pw, role, desig in users:
            execute("INSERT IGNORE INTO users (employee_code, full_name, email, password_hash, role, designation) "
                    "VALUES (%s,%s,%s,%s,%s,%s)", (code, name, email, generate_password_hash(pw), role, desig))
    print("Seeded:", ", ".join(f"{u[2]} / {u[3]}" for u in users))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seed":
        seed_users()
    elif len(sys.argv) > 2 and sys.argv[1] == "testmail":  # python app.py testmail you@example.com
        try:
            send_mail(sys.argv[2], "Interrival test email", "If you can read this, Interrival can send email.")
            print(f"Test email sent to {sys.argv[2]}. Check the inbox (and the spam folder).")
        except Exception as exc:
            print(f"Could not send: {type(exc).__name__}: {exc}")
    else:
        app.run(debug=True)