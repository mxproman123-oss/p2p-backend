import os
import re
import time
import secrets
import threading
from datetime import datetime
from collections import defaultdict
from functools import wraps

import requests as http
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# ---------- Config (Render > Environment) ----------
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY") or (ADMIN_PASSWORD + "-p2p-secret")
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID", "")

db_url = os.environ.get("DATABASE_URL", "sqlite:///p2p.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config.update(
    SQLALCHEMY_DATABASE_URI=db_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,
)
db = SQLAlchemy(app)
admin_signer = URLSafeTimedSerializer(SECRET_KEY, salt="admin")
user_signer = URLSafeTimedSerializer(SECRET_KEY, salt="user")


# ---------- Models ----------
class Setting(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text, default="")


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60))
    phone = db.Column(db.String(15), unique=True, index=True)
    pw = db.Column(db.String(255))
    contact = db.Column(db.String(80), default="")
    binance_uid = db.Column(db.String(60), default="")
    bybit_uid = db.Column(db.String(60), default="")
    pay_method = db.Column(db.String(30), default="")
    pay_account = db.Column(db.String(80), default="")
    banned = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)


class Order(db.Model):
    id = db.Column(db.String(20), primary_key=True)
    user_id = db.Column(db.Integer, index=True)
    side = db.Column(db.String(4))
    platform = db.Column(db.String(10))
    usd = db.Column(db.Float)
    rate = db.Column(db.Float)
    etb = db.Column(db.Float)
    user_uid = db.Column(db.String(60))
    pay_method = db.Column(db.String(30))
    pay_account = db.Column(db.String(80))
    contact = db.Column(db.String(80))
    proof = db.Column(db.Text)
    status = db.Column(db.String(15), default="pending")
    note = db.Column(db.Text, default="")
    created = db.Column(db.DateTime, default=datetime.utcnow)


DEFAULTS = {
    "buy_rate": "160",
    "sell_rate": "150",
    "min_usd": "5",
    "max_usd": "500",
    "binance_uid": "000000000",
    "bybit_uid": "000000000",
    "telebirr": "09XXXXXXXX (ስም)",
    "cbe": "1000XXXXXXXXX (ስም)",
    "telegram": "https://t.me/your_username",
    "announcement": "",
    "open": "1",
}
STATUSES = ("pending", "paid", "completed", "rejected", "cancelled")


def migrate():
    """ነባሩ orders ሠንጠረዥ ላይ user_id አምድ ይጨምራል (ዳታ አይጠፋም)።"""
    try:
        cols = [c["name"] for c in inspect(db.engine).get_columns("order")]
        if "user_id" not in cols:
            with db.engine.begin() as conn:
                conn.execute(text('ALTER TABLE "order" ADD COLUMN user_id INTEGER'))
    except Exception as e:  # noqa
        print("migrate:", e)


with app.app_context():
    db.create_all()
    migrate()


# ---------- Helpers ----------
hits = defaultdict(list)


def limited(key, limit, window):
    now = time.time()
    hits[key] = [t for t in hits[key] if now - t < window]
    if len(hits[key]) >= limit:
        return True
    hits[key].append(now)
    return False


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def clean(v, n):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(v or "")).strip()[:n]


def norm_phone(p):
    d = re.sub(r"\D", "", str(p or ""))
    if d.startswith("251"):
        d = d[3:]
    if d.startswith("0"):
        d = d[1:]
    if len(d) == 9 and d[0] in "97":
        return "0" + d
    return None


def get_settings():
    s = dict(DEFAULTS)
    for row in Setting.query.all():
        s[row.key] = row.value
    return s


def notify(text_):
    if not BOT_TOKEN or not ADMIN_CHAT_ID:
        return

    def run():
        try:
            http.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": ADMIN_CHAT_ID, "text": text_},
                timeout=8,
            )
        except Exception:
            pass

    threading.Thread(target=run, daemon=True).start()


@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def token_from_request():
    return request.headers.get("Authorization", "").replace("Bearer ", "").strip()


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        try:
            admin_signer.loads(token_from_request(), max_age=60 * 60 * 8)
        except (BadSignature, SignatureExpired):
            return jsonify(error="unauthorized"), 401
        return f(*a, **k)

    return wrapper


def user_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        u = None
        try:
            data = user_signer.loads(token_from_request(), max_age=60 * 60 * 24 * 30)
            u = db.session.get(User, data["uid"])
        except (BadSignature, SignatureExpired, KeyError, TypeError):
            u = None
        if not u:
            return jsonify(error="እባክህ ግባ።"), 401
        if u.banned:
            return jsonify(error="ይህ መለያ ታግዷል። ለድጋፍ አግኙን።"), 403
        g.user = u
        return f(*a, **k)

    return wrapper


def user_dict(u):
    return {
        "id": u.id, "name": u.name, "phone": u.phone, "contact": u.contact or "",
        "binance_uid": u.binance_uid or "", "bybit_uid": u.bybit_uid or "",
        "pay_method": u.pay_method or "", "pay_account": u.pay_account or "",
    }


def public_order(o):
    return {
        "id": o.id, "side": o.side, "platform": o.platform, "usd": o.usd,
        "rate": o.rate, "etb": o.etb, "status": o.status, "note": o.note or "",
        "has_proof": bool(o.proof), "created": o.created.isoformat(),
        "user_uid": o.user_uid, "pay_method": o.pay_method, "pay_account": o.pay_account,
    }


def admin_order(o, users=None):
    d = public_order(o)
    d["contact"] = o.contact
    u = (users or {}).get(o.user_id)
    d["user_name"] = u.name if u else ""
    d["user_phone"] = u.phone if u else ""
    return d


def own_order(oid):
    o = db.session.get(Order, clean(oid, 20).upper())
    if not o or o.user_id != g.user.id:
        return None
    return o


# ---------- Public ----------
@app.get("/")
def home():
    return jsonify(ok=True, service="p2p-api", version=2)


@app.get("/api/config")
def config():
    return jsonify(get_settings())


# ---------- Auth ----------
@app.post("/api/auth/register")
def register():
    if limited("reg:" + client_ip(), 6, 3600):
        return jsonify(error="ብዙ ሙከራ ተደርጓል። ከትንሽ ቆይታ በኋላ ሞክር።"), 429
    d = request.get_json(silent=True) or {}
    name = clean(d.get("name"), 60)
    phone = norm_phone(d.get("phone"))
    pw = str(d.get("password") or "")
    if len(name) < 2:
        return jsonify(error="ሙሉ ስምህን ጻፍ።"), 400
    if not phone:
        return jsonify(error="ትክክለኛ የኢትዮጵያ ስልክ ቁጥር ጻፍ (ለምሳሌ 09XXXXXXXX)።"), 400
    if len(pw) < 6 or len(pw) > 100:
        return jsonify(error="Password ቢያንስ 6 ቁምፊ መሆን አለበት።"), 400
    if User.query.filter_by(phone=phone).first():
        return jsonify(error="ይህ ስልክ ቁጥር ቀድሞ ተመዝግቧል። ግባ።"), 409
    u = User(name=name, phone=phone, pw=generate_password_hash(pw, method="pbkdf2:sha256"))
    db.session.add(u)
    db.session.commit()
    notify(f"👤 አዲስ ተጠቃሚ: {u.name} ({u.phone})")
    return jsonify(token=user_signer.dumps({"uid": u.id}), user=user_dict(u)), 201


@app.post("/api/auth/login")
def login():
    d = request.get_json(silent=True) or {}
    phone = norm_phone(d.get("phone"))
    pw = str(d.get("password") or "")
    if limited("login:" + client_ip(), 20, 600) or limited("loginp:" + str(phone), 8, 600):
        return jsonify(error="ብዙ ሙከራ ተደርጓል። ከ10 ደቂቃ በኋላ ሞክር።"), 429
    u = User.query.filter_by(phone=phone).first() if phone else None
    if not u or not check_password_hash(u.pw, pw):
        return jsonify(error="ስልክ ቁጥር ወይም password ትክክል አይደለም።"), 401
    if u.banned:
        return jsonify(error="ይህ መለያ ታግዷል። ለድጋፍ አግኙን።"), 403
    return jsonify(token=user_signer.dumps({"uid": u.id}), user=user_dict(u))


@app.get("/api/me")
@user_required
def me():
    return jsonify(user_dict(g.user))


@app.post("/api/me")
@user_required
def update_me():
    d = request.get_json(silent=True) or {}
    u = g.user
    limits = {"contact": 80, "binance_uid": 60, "bybit_uid": 60, "pay_method": 30, "pay_account": 80}
    for k, n in limits.items():
        if k in d:
            setattr(u, k, clean(d[k], n))
    if "name" in d and len(clean(d["name"], 60)) >= 2:
        u.name = clean(d["name"], 60)
    db.session.commit()
    return jsonify(user_dict(u))


@app.post("/api/me/password")
@user_required
def change_password():
    if limited("pwch:" + str(g.user.id), 6, 600):
        return jsonify(error="ብዙ ሙከራ።"), 429
    d = request.get_json(silent=True) or {}
    if not check_password_hash(g.user.pw, str(d.get("old") or "")):
        return jsonify(error="የአሁኑ password ትክክል አይደለም።"), 400
    new = str(d.get("new") or "")
    if len(new) < 6 or len(new) > 100:
        return jsonify(error="አዲሱ password ቢያንስ 6 ቁምፊ መሆን አለበት።"), 400
    g.user.pw = generate_password_hash(new, method="pbkdf2:sha256")
    db.session.commit()
    return jsonify(ok=True)


# ---------- Orders (መግባት ያስፈልጋል) ----------
@app.get("/api/me/orders")
@user_required
def my_orders():
    rows = Order.query.filter_by(user_id=g.user.id).order_by(Order.created.desc()).limit(100).all()
    return jsonify(orders=[public_order(o) for o in rows])


@app.post("/api/orders")
@user_required
def create_order():
    if limited("order:" + str(g.user.id), 10, 3600):
        return jsonify(error="ብዙ ትዕዛዝ ተልኳል። ከትንሽ ቆይታ በኋላ ሞክር።"), 429
    open_count = Order.query.filter(Order.user_id == g.user.id, Order.status.in_(("pending", "paid"))).count()
    if open_count >= 5:
        return jsonify(error="ክፍት የሆኑ 5 ትዕዛዞች አሉህ። መጀመሪያ እነሱን ጨርስ ወይም ሰርዝ።"), 400
    s = get_settings()
    if s["open"] != "1":
        return jsonify(error="አገልግሎቱ ለጊዜው ተዘግቷል።"), 400

    d = request.get_json(silent=True) or {}
    side, platform = d.get("side"), d.get("platform")
    if side not in ("buy", "sell") or platform not in ("binance", "bybit"):
        return jsonify(error="የተሳሳተ ምርጫ።"), 400
    try:
        usd = round(float(d.get("usd")), 2)
    except (TypeError, ValueError):
        return jsonify(error="መጠኑን በቁጥር ጻፍ።"), 400
    if usd < float(s["min_usd"]) or usd > float(s["max_usd"]):
        return jsonify(error=f"መጠኑ ከ {s['min_usd']} እስከ {s['max_usd']} USD መሆን አለበት።"), 400

    user_uid = clean(d.get("user_uid"), 60)
    pay_method = clean(d.get("pay_method"), 30)
    pay_account = clean(d.get("pay_account"), 80)
    contact = clean(d.get("contact"), 80) or g.user.phone
    if not (user_uid and pay_account and pay_method):
        return jsonify(error="ሁሉንም መረጃዎች ሙላ።"), 400

    rate = float(s["buy_rate"] if side == "buy" else s["sell_rate"])
    order = Order(
        id="P2P-" + secrets.token_hex(3).upper(), user_id=g.user.id, side=side,
        platform=platform, usd=usd, rate=rate, etb=round(usd * rate, 2),
        user_uid=user_uid, pay_method=pay_method, pay_account=pay_account, contact=contact,
    )
    db.session.add(order)
    db.session.commit()
    notify(
        f"🆕 አዲስ ትዕዛዝ {order.id}\n"
        f"{g.user.name} ({g.user.phone})\n"
        f"{'USD ይገዛል' if side == 'buy' else 'USD ይሸጣል'} • {platform}\n"
        f"{usd} USD = {order.etb} ETB\nUID: {user_uid}"
    )
    return jsonify(public_order(order)), 201


@app.get("/api/orders/<oid>")
@user_required
def get_order(oid):
    o = own_order(oid)
    if not o:
        return jsonify(error="ትዕዛዙ አልተገኘም።"), 404
    return jsonify(public_order(o))


@app.post("/api/orders/<oid>/proof")
@user_required
def upload_proof(oid):
    if limited("proof:" + str(g.user.id), 15, 3600):
        return jsonify(error="ብዙ ጥያቄ።"), 429
    o = own_order(oid)
    if not o:
        return jsonify(error="ትዕዛዙ አልተገኘም።"), 404
    if o.status not in ("pending", "paid"):
        return jsonify(error="ይህ ትዕዛዝ ተዘግቷል።"), 400
    proof = (request.get_json(silent=True) or {}).get("proof", "")
    if not isinstance(proof, str) or not proof.startswith("data:image/") or len(proof) > 3_000_000:
        return jsonify(error="ፎቶው ትክክል አይደለም ወይም በጣም ትልቅ ነው።"), 400
    o.proof = proof
    o.status = "paid"
    db.session.commit()
    notify(f"📎 ማስረጃ ተጫነ — {o.id}\n{g.user.name}: {o.usd} USD / {o.etb} ETB\nአረጋግጠህ ጨርስ (admin)።")
    return jsonify(public_order(o))


@app.post("/api/orders/<oid>/cancel")
@user_required
def cancel_order(oid):
    o = own_order(oid)
    if not o:
        return jsonify(error="ትዕዛዙ አልተገኘም።"), 404
    if o.status != "pending":
        return jsonify(error="ክፍያ ከተላከ በኋላ መሰረዝ አይቻልም። በ Telegram አግኙን።"), 400
    o.status = "cancelled"
    db.session.commit()
    notify(f"🚫 ትዕዛዝ ተሰረዘ — {o.id} ({g.user.name})")
    return jsonify(public_order(o))


# ---------- Admin ----------
@app.post("/api/admin/login")
def admin_login():
    if limited("alogin:" + client_ip(), 6, 600):
        return jsonify(error="ብዙ ሙከራ። ከ10 ደቂቃ በኋላ ሞክር።"), 429
    if not ADMIN_PASSWORD:
        return jsonify(error="ADMIN_PASSWORD በ Render ላይ አልተቀመጠም።"), 500
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if not secrets.compare_digest(str(pw).encode(), ADMIN_PASSWORD.encode()):
        return jsonify(error="የተሳሳተ password።"), 401
    return jsonify(token=admin_signer.dumps({"admin": True}))


@app.get("/api/admin/orders")
@admin_required
def admin_orders():
    rows = Order.query.order_by(Order.created.desc()).limit(300).all()
    ids = {o.user_id for o in rows if o.user_id}
    users = {u.id: u for u in User.query.filter(User.id.in_(ids)).all()} if ids else {}
    done = [o for o in rows if o.status == "completed"]
    stats = {
        "pending": sum(o.status == "pending" for o in rows),
        "paid": sum(o.status == "paid" for o in rows),
        "completed": len(done),
        "volume_usd": round(sum(o.usd for o in done), 2),
        "volume_etb": round(sum(o.etb for o in done), 2),
        "users": User.query.count(),
    }
    return jsonify(orders=[admin_order(o, users) for o in rows], stats=stats)


@app.get("/api/admin/orders/<oid>/proof")
@admin_required
def admin_proof(oid):
    o = db.session.get(Order, oid)
    if not o or not o.proof:
        return jsonify(error="ማስረጃ የለም።"), 404
    return jsonify(proof=o.proof)


@app.post("/api/admin/orders/<oid>")
@admin_required
def admin_update(oid):
    o = db.session.get(Order, oid)
    if not o:
        return jsonify(error="አልተገኘም።"), 404
    d = request.get_json(silent=True) or {}
    if d.get("status") in STATUSES:
        o.status = d["status"]
    if "note" in d:
        o.note = clean(d["note"], 300)
    db.session.commit()
    return jsonify(admin_order(o))


@app.get("/api/admin/users")
@admin_required
def admin_users():
    rows = User.query.order_by(User.created.desc()).limit(500).all()
    counts = dict(db.session.query(Order.user_id, db.func.count(Order.id)).group_by(Order.user_id).all())
    out = []
    for u in rows:
        d = user_dict(u)
        d.update(orders=counts.get(u.id, 0), banned=bool(u.banned), created=u.created.isoformat())
        out.append(d)
    return jsonify(users=out)


@app.post("/api/admin/users/<int:uid>")
@admin_required
def admin_user_update(uid):
    u = db.session.get(User, uid)
    if not u:
        return jsonify(error="አልተገኘም።"), 404
    d = request.get_json(silent=True) or {}
    if "banned" in d:
        u.banned = bool(d["banned"])
    if "password" in d:
        pw = str(d["password"])
        if len(pw) < 6 or len(pw) > 100:
            return jsonify(error="Password ቢያንስ 6 ቁምፊ።"), 400
        u.pw = generate_password_hash(pw, method="pbkdf2:sha256")
    db.session.commit()
    return jsonify(ok=True)


@app.post("/api/admin/settings")
@admin_required
def admin_settings():
    d = request.get_json(silent=True) or {}
    for k, v in d.items():
        if k not in DEFAULTS:
            continue
        v = clean(v, 300)
        if k.endswith("_rate") or k in ("min_usd", "max_usd"):
            try:
                if float(v) <= 0:
                    raise ValueError
            except ValueError:
                return jsonify(error=f"{k} ከ0 በላይ ቁጥር መሆን አለበት።"), 400
        if k == "open":
            v = "1" if v == "1" else "0"
        row = db.session.get(Setting, k)
        if row:
            row.value = v
        else:
            db.session.add(Setting(key=k, value=v))
    db.session.commit()
    return jsonify(get_settings())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
