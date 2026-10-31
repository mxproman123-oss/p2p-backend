import os
import time
import secrets
import threading
from datetime import datetime
from collections import defaultdict
from functools import wraps

import requests as http
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)
CORS(app)

# ---------- Config (Render > Environment ላይ ተቀምጠዋል) ----------
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY") or (ADMIN_PASSWORD + "-p2p-secret")
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")          # አማራጭ: Telegram ማሳወቂያ
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID", "")  # አማራጭ

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
signer = URLSafeTimedSerializer(SECRET_KEY)


# ---------- Models ----------
class Setting(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text, default="")


class Order(db.Model):
    id = db.Column(db.String(20), primary_key=True)
    side = db.Column(db.String(4))          # buy = ደንበኛው USD ይገዛል, sell = USD ይሸጣል
    platform = db.Column(db.String(10))     # binance | bybit
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
    "buy_rate": "160",        # ደንበኛው 1 USD ሲገዛ የሚከፍለው ብር
    "sell_rate": "150",       # ደንበኛው 1 USD ሲሸጥ የሚያገኘው ብር
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

with app.app_context():
    db.create_all()


def get_settings():
    s = dict(DEFAULTS)
    for row in Setting.query.all():
        s[row.key] = row.value
    return s


def clean(v, n):
    return str(v or "").strip()[:n]


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


def notify(text):
    if not BOT_TOKEN or not ADMIN_CHAT_ID:
        return

    def run():
        try:
            http.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": ADMIN_CHAT_ID, "text": text},
                timeout=8,
            )
        except Exception:
            pass

    threading.Thread(target=run, daemon=True).start()


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        try:
            signer.loads(token, max_age=60 * 60 * 12)
        except (BadSignature, SignatureExpired):
            return jsonify(error="unauthorized"), 401
        return f(*a, **k)

    return wrapper


def public_order(o):
    return {
        "id": o.id, "side": o.side, "platform": o.platform, "usd": o.usd,
        "rate": o.rate, "etb": o.etb, "status": o.status, "note": o.note or "",
        "has_proof": bool(o.proof), "created": o.created.isoformat(),
    }


def admin_order(o):
    d = public_order(o)
    d.update(user_uid=o.user_uid, pay_method=o.pay_method,
             pay_account=o.pay_account, contact=o.contact)
    return d


# ---------- Public API ----------
@app.get("/")
def home():
    return jsonify(ok=True, service="p2p-api")


@app.get("/api/config")
def config():
    return jsonify(get_settings())


@app.post("/api/orders")
def create_order():
    if limited("order:" + client_ip(), 8, 3600):
        return jsonify(error="ብዙ ጥያቄ ተልኳል። ከትንሽ ቆይታ በኋላ ሞክር።"), 429
    s = get_settings()
    if s["open"] != "1":
        return jsonify(error="አገልግሎቱ ለጊዜው ተዘግቷል።"), 400

    d = request.get_json(silent=True) or {}
    side, platform = d.get("side"), d.get("platform")
    if side not in ("buy", "sell") or platform not in ("binance", "bybit"):
        return jsonify(error="የተሳሳተ ምርጫ።"), 400
    try:
        usd = float(d.get("usd"))
    except (TypeError, ValueError):
        return jsonify(error="መጠኑን በቁጥር ጻፍ።"), 400
    if usd < float(s["min_usd"]) or usd > float(s["max_usd"]):
        return jsonify(error=f"መጠኑ ከ {s['min_usd']} እስከ {s['max_usd']} USD መሆን አለበት።"), 400

    user_uid = clean(d.get("user_uid"), 60)
    contact = clean(d.get("contact"), 80)
    pay_method = clean(d.get("pay_method"), 30)
    pay_account = clean(d.get("pay_account"), 80)
    if not (user_uid and contact and pay_account):
        return jsonify(error="ሁሉንም መረጃዎች ሙላ።"), 400

    rate = float(s["buy_rate"] if side == "buy" else s["sell_rate"])
    order = Order(
        id="P2P-" + secrets.token_hex(3).upper(), side=side, platform=platform,
        usd=usd, rate=rate, etb=round(usd * rate, 2), user_uid=user_uid,
        pay_method=pay_method, pay_account=pay_account, contact=contact,
    )
    db.session.add(order)
    db.session.commit()

    notify(
        f"🆕 አዲስ ትዕዛዝ {order.id}\n"
        f"{'USD ይገዛል' if side == 'buy' else 'USD ይሸጣል'} • {platform}\n"
        f"{usd} USD = {order.etb} ETB\nUID: {user_uid}\nእውቂያ: {contact}"
    )
    return jsonify(public_order(order)), 201


@app.get("/api/orders/<oid>")
def get_order(oid):
    if limited("get:" + client_ip(), 120, 600):
        return jsonify(error="ብዙ ጥያቄ።"), 429
    o = db.session.get(Order, oid.strip().upper())
    if not o:
        return jsonify(error="ትዕዛዙ አልተገኘም።"), 404
    return jsonify(public_order(o))


@app.post("/api/orders/<oid>/proof")
def upload_proof(oid):
    if limited("proof:" + client_ip(), 15, 3600):
        return jsonify(error="ብዙ ጥያቄ።"), 429
    o = db.session.get(Order, oid.strip().upper())
    if not o:
        return jsonify(error="ትዕዛዙ አልተገኘም።"), 404
    if o.status not in ("pending", "paid"):
        return jsonify(error="ይህ ትዕዛዝ ተዘግቷል።"), 400
    proof = (request.get_json(silent=True) or {}).get("proof", "")
    if not proof.startswith("data:image/") or len(proof) > 3_000_000:
        return jsonify(error="ፎቶው ትክክል አይደለም ወይም በጣም ትልቅ ነው።"), 400
    o.proof = proof
    o.status = "paid"
    db.session.commit()
    notify(f"📎 ማስረጃ ተጫነ — {o.id}\n{o.usd} USD / {o.etb} ETB\nአረጋግጠህ ጨርስ (admin panel)።")
    return jsonify(public_order(o))


# ---------- Admin API ----------
@app.post("/api/admin/login")
def admin_login():
    if limited("login:" + client_ip(), 6, 600):
        return jsonify(error="ብዙ ሙከራ። ከ10 ደቂቃ በኋላ ሞክር።"), 429
    if not ADMIN_PASSWORD:
        return jsonify(error="ADMIN_PASSWORD በ Render ላይ አልተቀመጠም።"), 500
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if not secrets.compare_digest(str(pw), ADMIN_PASSWORD):
        return jsonify(error="የተሳሳተ password።"), 401
    return jsonify(token=signer.dumps({"admin": True}))


@app.get("/api/admin/orders")
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created.desc()).limit(200).all()
    done = [o for o in orders if o.status == "completed"]
    stats = {
        "pending": sum(o.status == "pending" for o in orders),
        "paid": sum(o.status == "paid" for o in orders),
        "completed": len(done),
        "volume_usd": round(sum(o.usd for o in done), 2),
    }
    return jsonify(orders=[admin_order(o) for o in orders], stats=stats)


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
                float(v)
            except ValueError:
                return jsonify(error=f"{k} ቁጥር መሆን አለበት።"), 400
        row = db.session.get(Setting, k)
        if row:
            row.value = v
        else:
            db.session.add(Setting(key=k, value=v))
    db.session.commit()
    return jsonify(get_settings())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
