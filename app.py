"""
CryptoAPI — Key Issuance & Encryption-as-a-Service
====================================================
Changes from original:
  - PostgreSQL support via DATABASE_URL (Neon serverless compatible)
  - SQLite fallback for local development
  - Admin tier with unlimited quota + special admin endpoints
  - Admin account seeded automatically from env vars on first boot
  - Daily quota removed for admin tier
  - Passwords: bcrypt with fallback to sha256
  - All original security fixes retained
  - FIXED: Removed ThreadedConnectionPool — direct per-request connections
    for Neon serverless compatibility (no pool exhaustion)
"""

import os, secrets, hashlib, hmac, time, logging
from datetime import datetime, timezone
from functools import wraps

import requests
from flask import Flask, request, jsonify, g, abort, render_template_string
from flask_cors import CORS

# ── bcrypt ────────────────────────────────────────────────────────────────────
try:
    import bcrypt as _bcrypt
    def hash_password(pw: str) -> str:
        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(12)).decode()
    def check_password(pw: str, hashed: str) -> bool:
        return _bcrypt.checkpw(pw.encode(), hashed.encode())
except ImportError:
    import hashlib as _hl
    def hash_password(pw: str) -> str:
        salt = secrets.token_hex(16)
        h = _hl.sha256((salt + pw).encode()).hexdigest()
        return f"sha256${salt}${h}"
    def check_password(pw: str, hashed: str) -> bool:
        try:
            _, salt, h = hashed.split("$")
            return hmac.compare_digest(_hl.sha256((salt + pw).encode()).hexdigest(), h)
        except Exception:
            return False

# ── Config ────────────────────────────────────────────────────────────────────
RELAY_TOKEN       = os.getenv("RELAY_TOKEN", "7c9a2f1b8e4d0a92b3c4d5e6f7a8b9c0")
ADMIN_SECRET      = os.getenv("ADMIN_SECRET", "change-me-in-production")
DATABASE_URL      = os.getenv("DATABASE_URL", "")
DB_PATH           = os.getenv("DB_PATH", "")
DYNAMIC_RELAY_URL = os.getenv("RELAY_URL", "")

ADMIN_EMAIL       = os.getenv("ADMIN_EMAIL", "admin@admin.com")
ADMIN_PASSWORD    = os.getenv("ADMIN_PASSWORD", "")

FREE_QUOTA_DAY  = 100
PRO_QUOTA_DAY   = 10_000
ADMIN_QUOTA_DAY = 999_999_999
KEY_PREFIX      = "ck_live_"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("CryptoAPI")

app = Flask("CryptoAPI")
CORS(app)

# ── Database abstraction (PostgreSQL or SQLite) ───────────────────────────────
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras

    def _make_conn():
        url = DATABASE_URL
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        return psycopg2.connect(url)

    def get_db():
        if "db" not in g:
            g.db = _make_conn()
            g.db.autocommit = False
        return g.db

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db:
            if exc:
                db.rollback()
            else:
                db.commit()
            db.close()

    def db_execute(sql, params=()):
        """Execute and return cursor (PostgreSQL uses %s placeholders)."""
        sql = sql.replace("?", "%s")
        cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return cur

    def db_lastrowid(cur):
        cur.execute("SELECT lastval()")
        return cur.fetchone()["lastval"]

    def db_commit():
        get_db().commit()

    AUTOINCREMENT = "SERIAL PRIMARY KEY"
    ON_CONFLICT_UPDATE = "ON CONFLICT (key_id, day) DO UPDATE SET count = daily_counts.count + 1"

else:
    import sqlite3

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA journal_mode=WAL")
        return g.db

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db:
            db.close()

    def db_execute(sql, params=()):
        return get_db().execute(sql, params)

    def db_lastrowid(cur):
        return cur.lastrowid

    def db_commit():
        get_db().commit()

    AUTOINCREMENT = "INTEGER PRIMARY KEY AUTOINCREMENT"
    ON_CONFLICT_UPDATE = "ON CONFLICT(key_id, day) DO UPDATE SET count = count + 1"


# ── Schema ────────────────────────────────────────────────────────────────────
def get_schema():
    ai = AUTOINCREMENT
    return f"""
CREATE TABLE IF NOT EXISTS customers (
    id            {ai},
    email         TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    tier          TEXT NOT NULL DEFAULT 'free',
    created_at    TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    password_hash TEXT
);
CREATE TABLE IF NOT EXISTS api_keys (
    id          {ai},
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    key_hash    TEXT UNIQUE NOT NULL,
    key_prefix  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT,
    label       TEXT DEFAULT 'default'
);
CREATE TABLE IF NOT EXISTS usage_log (
    id          {ai},
    key_id      INTEGER NOT NULL REFERENCES api_keys(id),
    endpoint    TEXT NOT NULL,
    ts          TEXT NOT NULL,
    status      INTEGER NOT NULL,
    latency_ms  INTEGER
);
CREATE TABLE IF NOT EXISTS daily_counts (
    key_id  INTEGER NOT NULL REFERENCES api_keys(id),
    day     TEXT NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0,
    {"UNIQUE(key_id, day)" if USE_POSTGRES else "PRIMARY KEY (key_id, day)"}
);
"""


def init_db():
    with app.app_context():
        if USE_POSTGRES:
            url = DATABASE_URL
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            conn = psycopg2.connect(url)
            conn.autocommit = True
            cur = conn.cursor()
            for stmt in get_schema().split(";"):
                stmt = stmt.strip()
                if stmt:
                    try:
                        cur.execute(stmt)
                    except Exception as e:
                        log.warning(f"Schema stmt skipped: {e}")
            try:
                cur.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS password_hash TEXT")
            except Exception:
                pass
            conn.close()
        else:
            db = sqlite3.connect(DB_PATH)
            db.executescript(get_schema())
            try:
                db.execute("ALTER TABLE customers ADD COLUMN password_hash TEXT")
                db.commit()
            except Exception:
                pass
            db.commit()
            db.close()

        _seed_admin()


def _seed_admin():
    """Create the admin account on first boot if ADMIN_PASSWORD is set."""
    if not ADMIN_PASSWORD:
        log.warning("[Init] ADMIN_PASSWORD not set — admin account NOT created. Set it in env vars.")
        return

    try:
        existing = db_execute(
            "SELECT id FROM customers WHERE email = ?", (ADMIN_EMAIL,)
        ).fetchone()

        if existing:
            db_execute(
                "UPDATE customers SET tier = 'admin', password_hash = ? WHERE email = ?",
                (hash_password(ADMIN_PASSWORD), ADMIN_EMAIL)
            )
            db_commit()
            log.info(f"[Init] Admin account refreshed: {ADMIN_EMAIL}")
            return

        pw_hash = hash_password(ADMIN_PASSWORD)
        db_execute(
            "INSERT INTO customers (email, name, tier, created_at, password_hash) VALUES (?, ?, 'admin', ?, ?)",
            (ADMIN_EMAIL, "Admin", now_iso(), pw_hash)
        )
        db_commit()

        cust = db_execute("SELECT id FROM customers WHERE email = ?", (ADMIN_EMAIL,)).fetchone()
        cust_id = cust["id"]

        raw_key, key_hash, prefix = mint_key()
        db_execute(
            "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, 'admin')",
            (cust_id, key_hash, prefix, now_iso())
        )
        db_commit()
        log.info(f"[Init] Admin account created: {ADMIN_EMAIL}")
        log.info(f"[Init] Admin API key: {raw_key}")

    except Exception as e:
        log.error(f"[Init] Failed to seed admin: {e}")


# ── Helpers ───────────────────────────────────────────────────────────────────
def mint_key():
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest(), raw[:16] + "…"

def today():   return datetime.now(timezone.utc).strftime("%Y-%m-%d")
def now_iso(): return datetime.now(timezone.utc).isoformat()

def quota_for_tier(tier: str) -> int:
    return {"free": FREE_QUOTA_DAY, "pro": PRO_QUOTA_DAY, "admin": ADMIN_QUOTA_DAY}.get(tier, FREE_QUOTA_DAY)


# ── Auth middleware ───────────────────────────────────────────────────────────
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing Authorization header"}), 401

        key_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
        row = db_execute(
            "SELECT k.id, k.customer_id, c.tier, c.active, k.revoked_at "
            "FROM api_keys k JOIN customers c ON c.id = k.customer_id "
            "WHERE k.key_hash = ?", (key_hash,)
        ).fetchone()

        if not row:               return jsonify({"error": "Invalid API key"}), 401
        if row["revoked_at"]:     return jsonify({"error": "API key revoked"}), 401
        if not row["active"]:     return jsonify({"error": "Account suspended"}), 403

        if row["tier"] != "admin":
            quota = quota_for_tier(row["tier"])
            cnt = db_execute(
                "SELECT count FROM daily_counts WHERE key_id = ? AND day = ?",
                (row["id"], today())
            ).fetchone()
            if (cnt["count"] if cnt else 0) >= quota:
                return jsonify({"error": "Daily quota exceeded"}), 429

        g.key_id      = row["id"]
        g.customer_id = row["customer_id"]
        g.tier        = row["tier"]
        g.t0          = time.monotonic()
        return f(*args, **kwargs)
    return decorated


def log_usage(endpoint: str, status: int):
    if not hasattr(g, "key_id"):
        return
    try:
        db_execute(
            "INSERT INTO usage_log (key_id, endpoint, ts, status, latency_ms) VALUES (?, ?, ?, ?, ?)",
            (g.key_id, endpoint, now_iso(), status, int((time.monotonic() - g.t0) * 1000))
        )
        upsert_sql = (
            "INSERT INTO daily_counts (key_id, day, count) VALUES (%s, %s, 1) "
            "ON CONFLICT (key_id, day) DO UPDATE SET count = daily_counts.count + 1"
            if USE_POSTGRES else
            "INSERT INTO daily_counts (key_id, day, count) VALUES (?, ?, 1) "
            "ON CONFLICT(key_id, day) DO UPDATE SET count = count + 1"
        )
        db_execute(upsert_sql, (g.key_id, today()))
        db_commit()
    except Exception as e:
        log.warning(f"log_usage failed: {e}")


# ── Relay helper ──────────────────────────────────────────────────────────────
def relay_request(path, method="GET", body=None):
    if not DYNAMIC_RELAY_URL:
        return None, {"error": "Local engine offline — tunnel not connected"}, 503
    try:
        resp = requests.request(
            method, DYNAMIC_RELAY_URL.rstrip("/") + path,
            headers={
                "X-Relay-Token": RELAY_TOKEN,
                "Content-Type": "application/json",
                "ngrok-skip-browser-warning": "true",
            },
            json=body, timeout=20
        )
        return resp, resp.json(), resp.status_code
    except Exception as e:
        return None, {"error": str(e)}, 500


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(400)
def err400(e): return jsonify({"error": "Bad request", "detail": str(e)}), 400
@app.errorhandler(401)
def err401(e): return jsonify({"error": "Unauthorized"}), 401
@app.errorhandler(403)
def err403(e): return jsonify({"error": "Forbidden"}), 403
@app.errorhandler(404)
def err404(e): return jsonify({"error": "Not found"}), 404
@app.errorhandler(429)
def err429(e): return jsonify({"error": "Too many requests"}), 429
@app.errorhandler(500)
def err500(e): return jsonify({"error": "Internal server error", "detail": str(e)}), 500


# ════════════════════════════════════════════════════════════════
#  ADMIN ENDPOINTS  (X-Admin-Secret header required)
# ════════════════════════════════════════════════════════════════

def admin_auth():
    return hmac.compare_digest(
        request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET
    )


@app.route("/admin/set_relay", methods=["POST"])
def set_relay():
    if not admin_auth(): abort(403)
    global DYNAMIC_RELAY_URL
    new_url = (request.get_json(force=True) or {}).get("url")
    if not new_url: return jsonify({"error": "Missing URL"}), 400
    DYNAMIC_RELAY_URL = new_url
    log.info(f"Relay updated to: {DYNAMIC_RELAY_URL}")
    return jsonify({"message": "Relay updated", "url": DYNAMIC_RELAY_URL})


@app.route("/admin/register", methods=["POST"])
def admin_register():
    if not admin_auth(): abort(403)
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    name  = body.get("name", "").strip()
    tier  = body.get("tier", "free")
    pw    = body.get("password", "")
    if not email or not name: return jsonify({"error": "email and name required"}), 400
    if tier not in ("free", "pro", "admin"): return jsonify({"error": "tier must be free, pro, or admin"}), 400
    try:
        pw_hash = hash_password(pw) if pw else None
        db_execute(
            "INSERT INTO customers (email, name, tier, created_at, password_hash) VALUES (?, ?, ?, ?, ?)",
            (email, name, tier, now_iso(), pw_hash)
        )
        db_commit()
        cust = db_execute("SELECT id FROM customers WHERE email = ?", (email,)).fetchone()
        raw_key, key_hash, prefix = mint_key()
        db_execute(
            "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at) VALUES (?, ?, ?, ?)",
            (cust["id"], key_hash, prefix, now_iso())
        )
        db_commit()
        return jsonify({"message": "Customer registered", "api_key": raw_key,
                        "email": email, "name": name, "tier": tier}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 409


@app.route("/admin/customers", methods=["GET"])
def admin_customers():
    if not admin_auth(): abort(403)
    rows = db_execute(
        "SELECT c.id, c.email, c.name, c.tier, c.active, c.created_at, "
        "COUNT(k.id) as key_count FROM customers c "
        "LEFT JOIN api_keys k ON k.customer_id = c.id "
        "GROUP BY c.id ORDER BY c.created_at DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/customers/<int:cid>/tier", methods=["PATCH"])
def admin_set_tier(cid):
    if not admin_auth(): abort(403)
    tier = (request.get_json(force=True) or {}).get("tier")
    if tier not in ("free", "pro", "admin"):
        return jsonify({"error": "tier must be free, pro, or admin"}), 400
    db_execute("UPDATE customers SET tier = ? WHERE id = ?", (tier, cid))
    db_commit()
    return jsonify({"message": f"Customer {cid} set to tier={tier}"})


@app.route("/admin/customers/<int:cid>/suspend", methods=["POST"])
def admin_suspend(cid):
    if not admin_auth(): abort(403)
    db_execute("UPDATE customers SET active = 0 WHERE id = ?", (cid,))
    db_commit()
    return jsonify({"message": f"Customer {cid} suspended"})


@app.route("/admin/customers/<int:cid>/unsuspend", methods=["POST"])
def admin_unsuspend(cid):
    if not admin_auth(): abort(403)
    db_execute("UPDATE customers SET active = 1 WHERE id = ?", (cid,))
    db_commit()
    return jsonify({"message": f"Customer {cid} reinstated"})


@app.route("/admin/customers/<int:cid>/keys", methods=["GET"])
def admin_list_keys(cid):
    if not admin_auth(): abort(403)
    rows = db_execute(
        "SELECT id, key_prefix, created_at, revoked_at, label FROM api_keys WHERE customer_id = ? ORDER BY id DESC",
        (cid,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/stats", methods=["GET"])
def admin_stats():
    if not admin_auth(): abort(403)
    total_req  = db_execute("SELECT COUNT(*) as c FROM usage_log").fetchone()["c"]
    today_req  = db_execute("SELECT SUM(count) as c FROM daily_counts WHERE day = ?", (today(),)).fetchone()["c"]
    total_cust = db_execute("SELECT COUNT(*) as c FROM customers WHERE active = 1").fetchone()["c"]
    tier_breakdown = db_execute(
        "SELECT tier, COUNT(*) as c FROM customers WHERE active = 1 GROUP BY tier"
    ).fetchall()
    top_users = db_execute(
        "SELECT c.email, c.tier, SUM(d.count) as total "
        "FROM daily_counts d JOIN api_keys k ON k.id = d.key_id "
        "JOIN customers c ON c.id = k.customer_id "
        "GROUP BY c.email, c.tier ORDER BY total DESC LIMIT 10"
    ).fetchall()
    return jsonify({
        "total_customers":  total_cust,
        "total_requests":   total_req,
        "today_requests":   today_req or 0,
        "relay_active":     bool(DYNAMIC_RELAY_URL),
        "relay_url":        DYNAMIC_RELAY_URL or None,
        "tier_breakdown":   [dict(r) for r in tier_breakdown],
        "top_users":        [dict(r) for r in top_users],
    })


@app.route("/admin/usage_log", methods=["GET"])
def admin_usage_log():
    if not admin_auth(): abort(403)
    rows = db_execute(
        "SELECT u.id, c.email, u.endpoint, u.ts, u.status, u.latency_ms "
        "FROM usage_log u JOIN api_keys k ON k.id = u.key_id "
        "JOIN customers c ON c.id = k.customer_id "
        "ORDER BY u.id DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ════════════════════════════════════════════════════════════════
#  PUBLIC AUTH ENDPOINTS
# ════════════════════════════════════════════════════════════════

@app.route("/v1/register", methods=["POST"])
def public_register():
    body     = request.get_json(force=True) or {}
    email    = body.get("email", "").strip().lower()
    password = body.get("password", "").strip()
    name     = body.get("name", "").strip() or email.split("@")[0]

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    try:
        pw_hash = hash_password(password)
        db_execute(
            "INSERT INTO customers (email, name, tier, created_at, password_hash) VALUES (?, ?, 'free', ?, ?)",
            (email, name, now_iso(), pw_hash)
        )
        db_commit()
        cust = db_execute("SELECT id FROM customers WHERE email = ?", (email,)).fetchone()
        raw_key, key_hash, prefix = mint_key()
        db_execute(
            "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, 'primary')",
            (cust["id"], key_hash, prefix, now_iso())
        )
        db_commit()
        return jsonify({
            "api_key": raw_key,
            "tier": "free",
            "quota": FREE_QUOTA_DAY,
            "note": "Save this key — it is shown only once.",
        }), 201
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            return jsonify({"error": "Email already registered. Please log in instead."}), 409
        return jsonify({"error": str(e)}), 500


@app.route("/v1/login", methods=["POST"])
def public_login():
    body     = request.get_json(force=True) or {}
    email    = body.get("email", "").strip().lower()
    password = body.get("password", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    cust = db_execute(
        "SELECT id, name, tier, active, password_hash FROM customers WHERE email = ?", (email,)
    ).fetchone()

    if not cust:                     return jsonify({"error": "Invalid email or password"}), 401
    if not cust["active"]:           return jsonify({"error": "Account suspended"}), 403
    if not cust["password_hash"]:    return jsonify({"error": "No password set. Contact support."}), 401
    if not check_password(password, cust["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    key_row = db_execute(
        "SELECT key_hash, key_prefix, created_at FROM api_keys "
        "WHERE customer_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1",
        (cust["id"],)
    ).fetchone()

    if not key_row:
        return jsonify({"error": "No active key found. Use /v1/rotate_key."}), 404

    quota = quota_for_tier(cust["tier"])
    return jsonify({
        "message":    "Login successful",
        "name":       cust["name"],
        "tier":       cust["tier"],
        "quota":      quota,
        "key_prefix": key_row["key_prefix"],
        "key_created": key_row["created_at"],
        "note": "Raw key shown only once at registration. Use /v1/rotate_key if lost.",
    }), 200


@app.route("/v1/rotate_key", methods=["POST"])
def rotate_key():
    body     = request.get_json(force=True) or {}
    email    = body.get("email", "").strip().lower()
    password = body.get("password", "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    cust = db_execute(
        "SELECT id, active, password_hash, tier FROM customers WHERE email = ?", (email,)
    ).fetchone()

    if not cust or not cust["password_hash"] or not check_password(password, cust["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401
    if not cust["active"]:
        return jsonify({"error": "Account suspended"}), 403

    db_execute(
        "UPDATE api_keys SET revoked_at = ? WHERE customer_id = ? AND revoked_at IS NULL",
        (now_iso(), cust["id"])
    )
    raw_key, key_hash, prefix = mint_key()
    db_execute(
        "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, 'primary')",
        (cust["id"], key_hash, prefix, now_iso())
    )
    db_commit()
    return jsonify({
        "api_key": raw_key,
        "tier":    cust["tier"],
        "note":    "Old key revoked. Save this new key — not shown again.",
    }), 201


# ════════════════════════════════════════════════════════════════
#  AUTHENTICATED API ENDPOINTS
# ════════════════════════════════════════════════════════════════

@app.route("/v1/keys", methods=["POST"])
def issue_key():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header"}), 401
    key_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
    row = db_execute(
        "SELECT k.customer_id, k.revoked_at, c.active FROM api_keys k "
        "JOIN customers c ON c.id = k.customer_id WHERE k.key_hash = ?", (key_hash,)
    ).fetchone()
    if not row or row["revoked_at"] or not row["active"]:
        return jsonify({"error": "Invalid or revoked API key"}), 401
    label = (request.get_json(force=True) or {}).get("label", "secondary")
    raw_key, new_hash, prefix = mint_key()
    db_execute(
        "INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, ?)",
        (row["customer_id"], new_hash, prefix, now_iso(), label)
    )
    db_commit()
    return jsonify({"api_key": raw_key, "label": label,
                    "note": "Store this key safely — not shown again."}), 201


@app.route("/v1/usage", methods=["GET"])
@require_api_key
def usage():
    today_count = db_execute(
        "SELECT count FROM daily_counts WHERE key_id = ? AND day = ?", (g.key_id, today())
    ).fetchone()
    quota = quota_for_tier(g.tier)
    recent = db_execute(
        "SELECT endpoint, ts, status, latency_ms FROM usage_log "
        "WHERE key_id = ? ORDER BY id DESC LIMIT 20", (g.key_id,)
    ).fetchall()
    used = today_count["count"] if today_count else 0
    return jsonify({
        "tier":            g.tier,
        "quota_today":     quota if g.tier != "admin" else "unlimited",
        "used_today":      used,
        "remaining_today": max(0, quota - used) if g.tier != "admin" else "unlimited",
        "recent_calls":    [dict(r) for r in recent],
    })


@app.route("/v1/encrypt", methods=["POST"])
@require_api_key
def encrypt():
    body = request.get_json(force=True) or {}
    if "plaintext" not in body:
        return jsonify({"error": "Missing 'plaintext' field"}), 400
    _, data, status = relay_request("/relay/encrypt", "POST", {"plaintext": body.get("plaintext")})
    log_usage("/v1/encrypt", status)
    return jsonify(data), status


@app.route("/v1/decrypt", methods=["POST"])
@require_api_key
def decrypt():
    body = request.get_json(force=True) or {}
    if not {"ciphertext", "nonce", "encryption_key"}.issubset(body):
        return jsonify({"error": "Missing ciphertext, nonce, or encryption_key"}), 400
    _, data, status = relay_request("/relay/decrypt", "POST", {
        "ciphertext":     body.get("ciphertext"),
        "nonce":          body.get("nonce"),
        "encryption_key": body.get("encryption_key"),
    })
    log_usage("/v1/decrypt", status)
    return jsonify(data), status


@app.route("/v1/export_key", methods=["GET"])
@require_api_key
def export_key():
    _, data, status = relay_request("/relay/export_key", "GET")
    log_usage("/v1/export_key", status)
    return jsonify(data), status


@app.route("/v1/status", methods=["GET"])
@require_api_key
def api_status():
    _, data, status = relay_request("/relay/status")
    return jsonify(data), status


# ── Public stats ──────────────────────────────────────────────────────────────
@app.route("/public/stats", methods=["GET"])
def public_stats():
    total = db_execute("SELECT COUNT(*) as c FROM customers WHERE active = 1").fetchone()["c"]
    today_req = db_execute(
        "SELECT SUM(count) as c FROM daily_counts WHERE day = ?", (today(),)
    ).fetchone()["c"]
    return jsonify({"total_customers": total, "today_requests": today_req or 0})


@app.route("/health")
def health():
    return jsonify({
        "status":        "ok",
        "tunnel_active": bool(DYNAMIC_RELAY_URL),
        "db_backend":    "postgresql" if USE_POSTGRES else "sqlite",
    })


# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ChaosKey — Encryption from Physical Entropy</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,300;0,400;0,500;1,400&family=Instrument+Serif:ital@0;1&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--ink:#08090c;--ink2:#0f1117;--ink3:#161b26;--line:#1e2535;--line2:#252d3e;--dust:#384158;--mist:#5a6a8a;--fog:#8898b8;--paper:#c5cede;--white:#eef2fb;--lime:#b8f552;--lime2:#d4ff7a;--lime3:rgba(184,245,82,.12);--teal:#52e5c8;--teal3:rgba(82,229,200,.1);--rose:#ff6b8a;--glow-lime:0 0 40px rgba(184,245,82,.25);--glow-teal:0 0 40px rgba(82,229,200,.2)}
html{scroll-behavior:smooth;-webkit-font-smoothing:antialiased}
body{background:var(--ink);color:var(--paper);font-family:'Outfit',sans-serif;font-weight:400;min-height:100vh;overflow-x:hidden}
::selection{background:var(--lime);color:#000}
#entropy-canvas{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:0;opacity:.45}
.wrap{position:relative;z-index:1;max-width:1080px;margin:0 auto;padding:0 2rem}
nav{display:flex;align-items:center;justify-content:space-between;padding:1.4rem 2.5rem;position:sticky;top:0;z-index:100;background:rgba(8,9,12,.8);backdrop-filter:blur(20px);border-bottom:1px solid var(--line)}
.nav-logo{display:flex;align-items:center;gap:.75rem;font-family:'DM Mono',monospace;font-size:.95rem;color:var(--white);letter-spacing:-.01em;font-weight:500;text-decoration:none}
.logo-hex{width:34px;height:34px;background:linear-gradient(135deg,var(--lime),var(--teal));clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0}
.nav-right{display:flex;align-items:center;gap:.75rem}
.nav-status{display:flex;align-items:center;gap:.5rem;font-family:'DM Mono',monospace;font-size:.72rem;color:var(--mist);padding:.35rem .9rem;border:1px solid var(--line2);border-radius:100px;transition:all .3s}
.nav-status.live{color:var(--lime);border-color:rgba(184,245,82,.3)}
.pulse-dot{width:6px;height:6px;border-radius:50%;background:var(--dust);transition:background .3s,box-shadow .3s}
.pulse-dot.live{background:var(--lime);box-shadow:0 0 8px var(--lime);animation:blink 2s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
.nav-user-btn{font-family:'DM Mono',monospace;font-size:.72rem;color:var(--paper);padding:.35rem .9rem;border:1px solid var(--line2);border-radius:100px;background:none;cursor:pointer;transition:all .2s}
.nav-user-btn:hover{border-color:var(--lime);color:var(--lime)}
.auth-widget{max-width:440px;margin:0 auto 2rem;background:var(--ink2);border:1px solid var(--line2);border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.5);transition:box-shadow .3s}
.auth-widget:focus-within{border-color:rgba(184,245,82,.35);box-shadow:0 20px 60px rgba(0,0,0,.5),var(--glow-lime)}
.aw-tabs{display:flex;border-bottom:1px solid var(--line)}
.aw-tab{flex:1;padding:.85rem;background:none;border:none;border-bottom:2px solid transparent;font-family:'Outfit',sans-serif;font-size:.82rem;font-weight:600;color:var(--mist);cursor:pointer;transition:all .2s;margin-bottom:-1px}
.aw-tab.active{color:var(--lime);border-bottom-color:var(--lime)}
.aw-body{padding:1.4rem 1.75rem 1.6rem;display:flex;flex-direction:column;gap:.75rem}
.aw-input{background:var(--ink3);border:1px solid var(--line2);border-radius:8px;color:var(--white);font-family:'Outfit',sans-serif;font-size:.9rem;padding:.75rem 1rem;outline:none;transition:border-color .2s;width:100%}
.aw-input::placeholder{color:var(--dust)}
.aw-input:focus{border-color:rgba(184,245,82,.4)}
.aw-btn{background:var(--lime);color:#000;border:none;border-radius:8px;font-family:'Outfit',sans-serif;font-weight:700;font-size:.9rem;padding:.8rem 1.5rem;cursor:pointer;transition:background .2s,transform .15s,box-shadow .2s;width:100%}
.aw-btn:hover{background:var(--lime2);transform:translateY(-1px);box-shadow:var(--glow-lime)}
.aw-btn:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}
.aw-msg{font-family:'DM Mono',monospace;font-size:.75rem;min-height:1.2rem;text-align:center;transition:color .2s;color:var(--mist)}
.aw-msg.ok{color:var(--lime)}.aw-msg.err{color:var(--rose)}
.aw-pw-row{position:relative}
.aw-pw-toggle{position:absolute;right:.85rem;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--dust);cursor:pointer;font-size:.8rem;padding:0;transition:color .15s}
.aw-pw-toggle:hover{color:var(--lime)}
.key-result{display:none;max-width:500px;margin:0 auto 1.5rem;background:linear-gradient(135deg,rgba(184,245,82,.06),rgba(82,229,200,.04));border:1px solid rgba(184,245,82,.3);border-radius:16px;padding:1.5rem 1.75rem;animation:fadeSlide .5s ease}
.key-result.show{display:block}
@keyframes fadeSlide{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.kr-label{font-family:'DM Mono',monospace;font-size:.68rem;color:var(--lime);letter-spacing:.1em;text-transform:uppercase;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem}
.kr-label::before{content:'✓';font-size:.9rem}
.kr-key{font-family:'DM Mono',monospace;font-size:.78rem;color:var(--white);word-break:break-all;line-height:1.6;background:var(--ink3);border:1px solid var(--line2);border-radius:8px;padding:.85rem 1rem;margin-bottom:1rem;position:relative;cursor:pointer;transition:border-color .2s}
.kr-key:hover{border-color:rgba(184,245,82,.3)}
.kr-copy-hint{position:absolute;top:.5rem;right:.65rem;font-size:.6rem;color:var(--mist)}
.kr-key:hover .kr-copy-hint{color:var(--lime)}
.kr-note{font-size:.78rem;color:var(--mist);line-height:1.5}
.kr-note strong{color:var(--rose)}
.kr-actions{display:flex;gap:.6rem;margin-top:1rem}
.kr-action-btn{flex:1;padding:.6rem;border-radius:8px;font-family:'Outfit',sans-serif;font-size:.8rem;font-weight:600;cursor:pointer;transition:all .15s;border:none}
.kr-btn-primary{background:var(--lime);color:#000}.kr-btn-primary:hover{background:var(--lime2)}
.kr-btn-ghost{background:var(--ink3);color:var(--paper);border:1px solid var(--line2)}.kr-btn-ghost:hover{border-color:var(--fog);color:var(--white)}
.login-success{display:none;max-width:500px;margin:0 auto 1.5rem;background:rgba(82,229,200,.06);border:1px solid rgba(82,229,200,.3);border-radius:16px;padding:1.4rem 1.75rem;animation:fadeSlide .5s ease}
.login-success.show{display:block}
.ls-title{font-family:'DM Mono',monospace;font-size:.7rem;color:var(--teal);letter-spacing:.1em;text-transform:uppercase;margin-bottom:.6rem}
.ls-body{font-size:.85rem;color:var(--paper);line-height:1.6}
.ls-body span{color:var(--teal);font-family:'DM Mono',monospace;font-size:.75rem}
.ls-note{font-size:.75rem;color:var(--mist);margin-top:.75rem;line-height:1.5}
.ls-actions{display:flex;gap:.6rem;margin-top:1rem;flex-wrap:wrap}
.ls-btn{flex:1;padding:.6rem;border-radius:8px;font-family:'Outfit',sans-serif;font-size:.8rem;font-weight:600;cursor:pointer;transition:all .15s;border:none;min-width:120px}
.ls-btn-primary{background:var(--lime);color:#000}.ls-btn-primary:hover{background:var(--lime2)}
.ls-btn-warn{background:rgba(255,107,138,.12);color:var(--rose);border:1px solid rgba(255,107,138,.2)}.ls-btn-warn:hover{background:rgba(255,107,138,.2)}
.ls-btn-ghost{background:var(--ink3);color:var(--paper);border:1px solid var(--line2)}.ls-btn-ghost:hover{border-color:var(--fog)}
.hero{padding:7rem 0 5rem;text-align:center;position:relative}
.hero-eyebrow{display:inline-flex;align-items:center;gap:.6rem;font-family:'DM Mono',monospace;font-size:.72rem;color:var(--lime);letter-spacing:.12em;text-transform:uppercase;padding:.4rem 1.1rem;border:1px solid rgba(184,245,82,.25);border-radius:100px;background:rgba(184,245,82,.06);margin-bottom:2.5rem}
.hero-eyebrow::before{content:'◈';font-size:.8rem}
h1{font-family:'Instrument Serif',serif;font-size:clamp(3.2rem,7.5vw,6rem);line-height:1.02;letter-spacing:-.03em;color:var(--white);margin-bottom:1.75rem;font-weight:400}
h1 em{font-style:italic;background:linear-gradient(125deg,var(--lime) 0%,var(--teal) 55%,var(--lime2) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero-lead{font-size:1.1rem;line-height:1.75;color:var(--mist);max-width:560px;margin:0 auto 3.5rem;font-weight:300}
.hero-lead strong{color:var(--paper);font-weight:500}
.flow{display:flex;align-items:center;justify-content:center;gap:0;margin:5rem 0;flex-wrap:wrap}
.flow-step{display:flex;flex-direction:column;align-items:center;gap:.75rem;padding:1.5rem 1.25rem;min-width:140px;text-align:center}
.flow-icon{width:52px;height:52px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:1.4rem;border:1px solid var(--line2);background:var(--ink2)}
.flow-icon.active{background:var(--lime3);border-color:rgba(184,245,82,.3);box-shadow:var(--glow-lime)}
.flow-title{font-size:.82rem;font-weight:600;color:var(--paper)}
.flow-sub{font-size:.72rem;color:var(--mist);line-height:1.4}
.flow-arrow{font-size:1.2rem;color:var(--line2);padding:0 .25rem;align-self:center;margin-bottom:1.5rem;flex-shrink:0}
.section{padding:5rem 0}
.section-tag{font-family:'DM Mono',monospace;font-size:.7rem;color:var(--teal);letter-spacing:.12em;text-transform:uppercase;margin-bottom:.75rem}
.section-h{font-family:'Instrument Serif',serif;font-size:clamp(1.8rem,4vw,2.8rem);color:var(--white);letter-spacing:-.02em;margin-bottom:1rem;font-weight:400;line-height:1.1}
.section-sub{font-size:.95rem;color:var(--mist);line-height:1.7;max-width:500px}
.playground{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:16px;overflow:hidden;margin-top:2rem}
.pg-pane{background:var(--ink2);padding:1.5rem;display:flex;flex-direction:column;gap:1rem}
.pg-pane-header{display:flex;align-items:center;justify-content:space-between}
.pg-pane-label{font-family:'DM Mono',monospace;font-size:.7rem;color:var(--mist);letter-spacing:.08em;text-transform:uppercase}
.pg-badge{font-family:'DM Mono',monospace;font-size:.65rem;padding:.15rem .55rem;border-radius:100px}
.pg-badge-enc{background:rgba(184,245,82,.12);color:var(--lime);border:1px solid rgba(184,245,82,.2)}
.pg-badge-dec{background:rgba(82,229,200,.1);color:var(--teal);border:1px solid rgba(82,229,200,.2)}
textarea{width:100%;background:var(--ink3);border:1px solid var(--line2);border-radius:8px;color:var(--paper);font-family:'DM Mono',monospace;font-size:.78rem;padding:.85rem 1rem;resize:none;outline:none;line-height:1.6;transition:border-color .2s;min-height:110px}
textarea:focus{border-color:var(--line)}
textarea.out{color:var(--lime);background:rgba(184,245,82,.03);border-color:rgba(184,245,82,.15);min-height:130px}
textarea.out.teal{color:var(--teal);background:rgba(82,229,200,.03);border-color:rgba(82,229,200,.15)}
textarea.out.err{color:var(--rose);background:rgba(255,107,138,.03);border-color:rgba(255,107,138,.15)}
.pg-key-row{display:flex;align-items:center;gap:.5rem;padding:.6rem .9rem;background:var(--ink3);border:1px solid var(--line2);border-radius:8px;font-family:'DM Mono',monospace;font-size:.72rem}
.pg-key-dot{width:7px;height:7px;border-radius:50%;background:var(--dust);flex-shrink:0;transition:background .3s,box-shadow .3s}
.pg-key-dot.set{background:var(--lime);box-shadow:0 0 6px var(--lime)}
.pg-key-text{flex:1;color:var(--mist);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pg-key-text.set{color:var(--paper)}
.pg-key-clear{background:none;border:none;color:var(--dust);cursor:pointer;font-size:.75rem;padding:0 .2rem;transition:color .15s}
.pg-key-clear:hover{color:var(--rose)}
.pg-action{background:var(--lime);color:#000;border:none;border-radius:8px;font-family:'Outfit',sans-serif;font-weight:700;font-size:.85rem;padding:.75rem;cursor:pointer;transition:background .2s,transform .15s,box-shadow .2s}
.pg-action:hover{background:var(--lime2);transform:translateY(-1px);box-shadow:var(--glow-lime)}
.pg-action:disabled{opacity:.35;cursor:not-allowed;transform:none;box-shadow:none}
.pg-action.teal-btn{background:rgba(82,229,200,.15);color:var(--teal);border:1px solid rgba(82,229,200,.2)}
.pg-action.teal-btn:hover{background:rgba(82,229,200,.25);box-shadow:var(--glow-teal)}
.pg-key-setup{grid-column:1/-1;background:var(--ink2);display:flex;align-items:center;justify-content:center;padding:2rem;gap:1rem;flex-wrap:wrap}
.pg-key-setup.hidden{display:none}
.pg-setup-input{flex:1;min-width:220px;max-width:340px;background:var(--ink3);border:1px solid var(--line2);border-radius:8px;color:var(--white);font-family:'DM Mono',monospace;font-size:.82rem;padding:.7rem 1rem;outline:none;transition:border-color .2s}
.pg-setup-input:focus{border-color:rgba(184,245,82,.4)}
.pg-setup-btn{background:var(--lime);color:#000;border:none;border-radius:8px;font-family:'Outfit',sans-serif;font-weight:700;font-size:.85rem;padding:.7rem 1.4rem;cursor:pointer;transition:background .2s,transform .15s;white-space:nowrap}
.pg-setup-btn:hover{background:var(--lime2);transform:translateY(-1px)}
.pg-setup-hint{font-size:.75rem;color:var(--mist);text-align:center;width:100%}
.pg-setup-hint a{color:var(--lime);cursor:pointer;text-decoration:none}
.pg-setup-hint a:hover{text-decoration:underline}
.docs-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-top:2rem}
.code-card{background:var(--ink2);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.cc-header{display:flex;align-items:center;justify-content:space-between;padding:.75rem 1.1rem;border-bottom:1px solid var(--line);background:rgba(255,255,255,.02)}
.cc-dots{display:flex;gap:5px}.cc-dots span{width:9px;height:9px;border-radius:50%}
.d1{background:#ff5f57}.d2{background:#febc2e}.d3{background:#28c840}
.cc-lang{font-family:'DM Mono',monospace;font-size:.68rem;color:var(--dust);letter-spacing:.06em}
.cc-copy{font-family:'DM Mono',monospace;font-size:.65rem;color:var(--mist);background:none;border:1px solid var(--line2);border-radius:4px;padding:.15rem .55rem;cursor:pointer;transition:color .2s,border-color .2s}
.cc-copy:hover,.cc-copy.ok{color:var(--lime);border-color:rgba(184,245,82,.3)}
pre{padding:1.25rem;font-family:'DM Mono',monospace;font-size:.76rem;line-height:1.7;overflow-x:auto;color:var(--paper)}
.tk{color:var(--teal)}.ts{color:var(--lime)}.tc{color:var(--dust);font-style:italic}.tm{color:#ff9f7f}.tn{color:#c792ea}
.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:16px;overflow:hidden;margin:4rem 0}
.stat-cell{background:var(--ink2);padding:2rem;text-align:center}
.stat-n{font-family:'Instrument Serif',serif;font-size:2.8rem;color:var(--white);line-height:1;margin-bottom:.4rem}
.stat-l{font-size:.75rem;color:var(--mist);text-transform:uppercase;letter-spacing:.08em}
footer{border-top:1px solid var(--line);padding:2.5rem;display:flex;align-items:center;justify-content:space-between;color:var(--dust);font-size:.8rem;flex-wrap:wrap;gap:1rem}
.footer-left{display:flex;align-items:center;gap:.75rem}
.footer-tag{font-family:'DM Mono',monospace;font-size:.65rem;color:var(--line2)}
.sr{opacity:0;transform:translateY(28px);transition:opacity .7s ease,transform .7s ease}
.sr.in{opacity:1;transform:none}
@media(max-width:680px){.playground,.docs-grid,.stats-row{grid-template-columns:1fr}.flow{flex-direction:column;gap:0}.flow-arrow{transform:rotate(90deg);padding:.5rem 0;margin-bottom:0}h1{font-size:2.8rem}nav{padding:1rem 1.25rem}}
</style>
</head>
<body>
<canvas id="entropy-canvas"></canvas>
<nav>
  <a href="/" class="nav-logo"><div class="logo-hex">⬡</div>ChaosKey</a>
  <div class="nav-right">
    <div class="nav-status" id="nav-pill"><div class="pulse-dot" id="nav-dot"></div><span id="nav-txt" style="font-size:.72rem">checking…</span></div>
    <button class="nav-user-btn" id="nav-user-btn" style="display:none" onclick="handleNavUser()"></button>
  </div>
</nav>
<div class="wrap">
  <section class="hero">
    <div class="hero-eyebrow">Physical Entropy · AES-256-GCM · 10s Key Rotation</div>
    <h1>Your encryption key<br>born from <em>real chaos</em></h1>
    <p class="hero-lead">A camera watches a moving pendulum. A microphone listens to the room.<br><strong>That unpredictable motion derives a NEW cryptographic key every 10 seconds</strong> — generated on a local machine, never stored in the cloud.</p>
    <div class="auth-widget" id="auth-widget">
      <div class="aw-tabs">
        <button class="aw-tab active" id="tab-reg" onclick="switchTab('register')">Create account</button>
        <button class="aw-tab" id="tab-log" onclick="switchTab('login')">Log in</button>
      </div>
      <div class="aw-body" id="pane-register">
        <input class="aw-input" type="email" id="reg-email" placeholder="Email address" autocomplete="email">
        <div class="aw-pw-row"><input class="aw-input" type="password" id="reg-pw" placeholder="Password (min 6 chars)" autocomplete="new-password"><button class="aw-pw-toggle" onclick="togglePw('reg-pw',this)">show</button></div>
        <input class="aw-input" type="text" id="reg-name" placeholder="Your name (optional)">
        <button class="aw-btn" id="reg-btn" onclick="doRegister()">Create free account →</button>
        <div class="aw-msg" id="reg-msg">Free · 100 calls/day · No credit card</div>
      </div>
      <div class="aw-body" id="pane-login" style="display:none">
        <input class="aw-input" type="email" id="log-email" placeholder="Email address" autocomplete="email">
        <div class="aw-pw-row"><input class="aw-input" type="password" id="log-pw" placeholder="Password" autocomplete="current-password"><button class="aw-pw-toggle" onclick="togglePw('log-pw',this)">show</button></div>
        <button class="aw-btn" id="log-btn" onclick="doLogin()">Log in →</button>
        <div class="aw-msg" id="log-msg"></div>
      </div>
    </div>
    <div class="key-result" id="key-result">
      <div class="kr-label">Your permanent API key</div>
      <div class="kr-key" id="kr-key-val" onclick="copyKeyResult(this)" title="Click to copy"><span id="kr-key-text">ck_live_…</span><span class="kr-copy-hint">click to copy</span></div>
      <p class="kr-note"><strong>Save this now.</strong> We only store a hash — we cannot recover the raw key. Use "Rotate key" if you ever lose it.</p>
      <div class="kr-actions"><button class="kr-action-btn kr-btn-primary" onclick="useKeyInPlayground()">Try it below ↓</button><button class="kr-action-btn kr-btn-ghost" onclick="copyKeyResult(document.getElementById('kr-key-val'))">Copy key</button></div>
    </div>
    <div class="login-success" id="login-success">
      <div class="ls-title">✓ Logged in</div>
      <div class="ls-body" id="ls-body"></div>
      <div class="ls-actions">
        <button class="ls-btn ls-btn-primary" onclick="scrollToPlayground()">Paste key below ↓</button>
        <button class="ls-btn ls-btn-warn" onclick="doRotate()">Rotate key</button>
        <button class="ls-btn ls-btn-ghost" onclick="doLogout()">Log out</button>
      </div>
    </div>
  </section>
  <div class="flow sr">
    <div class="flow-step"><div class="flow-icon active">🎥</div><div class="flow-title">Physical Chaos</div><div class="flow-sub">Webcam tracks motion &amp; audio captures room noise</div></div>
    <div class="flow-arrow">→</div>
    <div class="flow-step"><div class="flow-icon active">🌀</div><div class="flow-title">10s Rotation</div><div class="flow-sub">Every 10 seconds the pool is sampled for a new key</div></div>
    <div class="flow-arrow">→</div>
    <div class="flow-step"><div class="flow-icon active">🔑</div><div class="flow-title">Key Derivation</div><div class="flow-sub">SHA-512 → Scrypt → HKDF-SHA256 derives 256 bits</div></div>
    <div class="flow-arrow">→</div>
    <div class="flow-step"><div class="flow-icon">🔐</div><div class="flow-title">Your API Call</div><div class="flow-sub">AES-256-GCM encryption with the current 10s key</div></div>
  </div>
  <div class="stats-row sr">
    <div class="stat-cell"><div class="stat-n" id="s-customers">—</div><div class="stat-l">Active users</div></div>
    <div class="stat-cell"><div class="stat-n" id="s-today">—</div><div class="stat-l">Encryptions today</div></div>
    <div class="stat-cell"><div class="stat-n">10s</div><div class="stat-l">Key Rotation Rate</div></div>
  </div>
  <section class="section sr" id="playground-section">
    <div class="section-tag">Playground</div>
    <div class="section-h">Encrypt something right now.</div>
    <p class="section-sub">Paste your key once — it stays for this session. Encrypt, decrypt, verify it works.</p>
    <div class="playground" id="playground">
      <div class="pg-key-setup" id="pg-key-setup">
        <input class="pg-setup-input" type="text" id="pg-key-input" placeholder="Paste your API key (ck_live_…)" autocomplete="off" spellcheck="false" onkeydown="if(event.key==='Enter')activateKey()">
        <button class="pg-setup-btn" onclick="activateKey()">Activate →</button>
        <p class="pg-setup-hint">No key? <a onclick="scrollToTop()">Get one free above ↑</a></p>
      </div>
      <div class="pg-pane" id="pane-enc" style="display:none">
        <div class="pg-pane-header"><span class="pg-pane-label">Plaintext</span><span class="pg-badge pg-badge-enc">ENCRYPT</span></div>
        <div class="pg-key-row"><div class="pg-key-dot set" id="enc-dot"></div><span class="pg-key-text set" id="enc-key-label">ck_live_…</span><button class="pg-key-clear" onclick="clearKey()" title="Change key">✕</button></div>
        <textarea id="enc-input" rows="4" placeholder="Type anything to encrypt…">Hello from ChaosKey!</textarea>
        <button class="pg-action" onclick="doEncrypt()">Encrypt with AES-256-GCM →</button>
        <textarea class="out" id="enc-output" rows="5" readonly placeholder="Encrypted output will appear here…"></textarea>
      </div>
      <div class="pg-pane" id="pane-dec" style="display:none">
        <div class="pg-pane-header"><span class="pg-pane-label">Ciphertext</span><span class="pg-badge pg-badge-dec">DECRYPT</span></div>
        <p style="font-size:.75rem;color:var(--mist);line-height:1.5">Because keys rotate every 10s, you must provide the specific key returned during encryption.</p>
        <textarea id="dec-input" rows="5" placeholder='{"ciphertext":"…","nonce":"…","encryption_key":"…"}'></textarea>
        <button class="pg-action teal-btn" onclick="doDecrypt()">Decrypt →</button>
        <textarea class="out teal" id="dec-output" rows="4" readonly placeholder="Decrypted plaintext will appear here…"></textarea>
      </div>
      <div class="pg-pane" id="pane-export" style="display:none;grid-column:1/-1">
        <div class="pg-pane-header"><span class="pg-pane-label">Master Chaos Key</span><span class="pg-badge" style="background:rgba(255,107,138,.12);color:var(--rose);border:1px solid rgba(255,107,138,.2)">EXPORT</span></div>
        <p style="font-size:.75rem;color:var(--mist);line-height:1.5">Retrieves the currently active 10-second master key from the physical entropy engine.</p>
        <button class="pg-action" style="background:transparent;border:1px solid var(--rose);color:var(--rose)" onclick="exportChaosKey()">Reveal Active Master Key</button>
        <textarea class="out" id="export-output" rows="2" readonly style="display:none;margin-top:1rem"></textarea>
      </div>
    </div>
  </section>
  <section class="section sr">
    <div class="section-tag">Integration</div>
    <div class="section-h">Copy. Paste. Done.</div>
    <p class="section-sub">Three endpoints. Bearer auth. Works with any HTTP client.</p>
    <div class="docs-grid">
      <div class="code-card">
        <div class="cc-header"><div class="cc-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="cc-lang">PYTHON</span><button class="cc-copy" onclick="cpCode(this,'c1')">copy</button></div>
        <pre id="c1"><span class="tc"># pip install requests</span>
<span class="tk">import</span> requests
BASE = <span class="ts">"https://your-app.onrender.com"</span>
r = requests.<span class="tm">post</span>(f<span class="ts">"{BASE}/v1/register"</span>,
        json={<span class="ts">"email"</span>:<span class="ts">"you@ex.com"</span>,<span class="ts">"password"</span>:<span class="ts">"hunter2"</span>})
KEY = r.json()[<span class="ts">"api_key"</span>]
H = {<span class="ts">"Authorization"</span>: <span class="ts">f"Bearer {KEY}"</span>}
enc = requests.<span class="tm">post</span>(f<span class="ts">"{BASE}/v1/encrypt"</span>,
        headers=H, json={<span class="ts">"plaintext"</span>: <span class="ts">"secret"</span>}).json()
print(requests.<span class="tm">post</span>(f<span class="ts">"{BASE}/v1/decrypt"</span>,
        headers=H, json=enc).json()[<span class="ts">"plaintext"</span>])</pre>
      </div>
      <div class="code-card">
        <div class="cc-header"><div class="cc-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="cc-lang">API REFERENCE</span><button class="cc-copy" onclick="cpCode(this,'c4')">copy</button></div>
        <pre id="c4"><span class="tm">POST</span> /v1/register
  body: {<span class="ts">"email"</span>,<span class="ts">"password"</span>,<span class="ts">"name"</span>}
  → {<span class="ts">"api_key"</span>: <span class="ts">"ck_live_…"</span>}  <span class="tc">← save this!</span>

<span class="tm">POST</span> /v1/login
  body: {<span class="ts">"email"</span>,<span class="ts">"password"</span>}
  → {<span class="ts">"key_prefix"</span>, <span class="ts">"tier"</span>, <span class="ts">"quota"</span>}

<span class="tm">POST</span> /v1/rotate_key
  body: {<span class="ts">"email"</span>,<span class="ts">"password"</span>}
  → {<span class="ts">"api_key"</span>: <span class="ts">"ck_live_…"</span>}  <span class="tc">← new key</span>

<span class="tm">POST</span> /v1/encrypt  <span class="tn">[Bearer ck_live_…]</span>
  body: {<span class="ts">"plaintext"</span>: <span class="ts">"…"</span>}
<span class="tm">POST</span> /v1/decrypt  <span class="tn">[Bearer ck_live_…]</span>
  body: {<span class="ts">"ciphertext"</span>,<span class="ts">"nonce"</span>,<span class="ts">"encryption_key"</span>}</pre>
      </div>
    </div>
  </section>
</div>
<footer>
  <div class="footer-left"><div class="logo-hex" style="width:24px;height:24px;font-size:11px">⬡</div><span style="font-family:'DM Mono',monospace;font-size:.75rem;color:var(--dust)">ChaosKey</span></div>
  <div class="footer-tag">Physical entropy. Key never leaves our machine.</div>
</footer>
<script>
(function(){const cv=document.getElementById('entropy-canvas');const cx=cv.getContext('2d');let W,H,particles=[];const N=90,SPEED=.4;function resize(){W=cv.width=innerWidth;H=cv.height=innerHeight}resize();addEventListener('resize',resize);class Particle{constructor(){this.reset(true)}reset(init){this.x=Math.random()*W;this.y=init?Math.random()*H:(Math.random()<.5?-4:H+4);this.vx=(Math.random()-.5)*SPEED;this.vy=(Math.random()*.6+.2)*SPEED*(this.y<0?1:-1);this.r=Math.random()*1.5+.4;this.life=0;this.maxLife=300+Math.random()*400;this.hue=Math.random()<.6?150:175}step(){const t=Date.now()*.0003;const nx=this.x/W*4+t,ny=this.y/H*4+t*.7;const angle=(Math.sin(nx)*Math.cos(ny))*Math.PI*2;this.vx+=Math.cos(angle)*.008;this.vy+=Math.sin(angle)*.008;this.vx*=.98;this.vy*=.98;this.x+=this.vx;this.y+=this.vy;this.life++;if(this.life>this.maxLife||this.x<-10||this.x>W+10||this.y<-10||this.y>H+10)this.reset(false)}draw(){const alpha=Math.min(this.life/60,1)*Math.min((this.maxLife-this.life)/60,1)*.6;cx.beginPath();cx.arc(this.x,this.y,this.r,0,Math.PI*2);cx.fillStyle=`hsla(${this.hue},90%,65%,${alpha})`;cx.fill()}}for(let i=0;i<N;i++)particles.push(new Particle());function draw(){cx.clearRect(0,0,W,H);for(let i=0;i<particles.length;i++){for(let j=i+1;j<particles.length;j++){const dx=particles[i].x-particles[j].x,dy=particles[i].y-particles[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<120){cx.beginPath();cx.moveTo(particles[i].x,particles[i].y);cx.lineTo(particles[j].x,particles[j].y);cx.strokeStyle=`rgba(184,245,82,${(1-d/120)*.07})`;cx.lineWidth=.5;cx.stroke()}}}particles.forEach(p=>{p.step();p.draw()});requestAnimationFrame(draw)}draw()})();
let _key=sessionStorage.getItem('ck_key')||'';
let _session=JSON.parse(sessionStorage.getItem('ck_session')||'null');
function saveSession(s){_session=s;sessionStorage.setItem('ck_session',JSON.stringify(s))}
function clearSession(){_session=null;sessionStorage.removeItem('ck_session')}
async function pollStatus(){try{const d=await(await fetch('/health')).json();const dot=document.getElementById('nav-dot'),txt=document.getElementById('nav-txt'),pill=document.getElementById('nav-pill');if(d.tunnel_active){dot.classList.add('live');pill.classList.add('live');txt.textContent='Engine online'}else{dot.classList.remove('live');pill.classList.remove('live');txt.textContent='Engine offline'}try{const s=await(await fetch('/public/stats')).json();document.getElementById('s-customers').textContent=s.total_customers??'—';document.getElementById('s-today').textContent=s.today_requests??'—'}catch(e){}}catch(e){}}
pollStatus();setInterval(pollStatus,6000);
function switchTab(tab){document.getElementById('tab-reg').classList.toggle('active',tab==='register');document.getElementById('tab-log').classList.toggle('active',tab==='login');document.getElementById('pane-register').style.display=tab==='register'?'flex':'none';document.getElementById('pane-login').style.display=tab==='login'?'flex':'none'}
function togglePw(id,btn){const el=document.getElementById(id);el.type=el.type==='password'?'text':'password';btn.textContent=el.type==='password'?'show':'hide'}
async function doRegister(){const email=document.getElementById('reg-email').value.trim();const pw=document.getElementById('reg-pw').value;const name=document.getElementById('reg-name').value.trim();const msg=document.getElementById('reg-msg'),btn=document.getElementById('reg-btn');if(!email||!email.includes('@')){setMsg(msg,'Enter a valid email','err');return}if(!pw||pw.length<6){setMsg(msg,'Password must be at least 6 characters','err');return}btn.disabled=true;setMsg(msg,'Creating account…','');const{ok,data}=await apiFetch('/v1/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password:pw,name})});if(ok){saveSession({email,name:data.name||name||email.split('@')[0],tier:data.tier,quota:data.quota});showNewKey(data.api_key);updateNavUser();document.getElementById('auth-widget').style.display='none'}else{setMsg(msg,'✗ '+(data.error||'Registration failed'),'err');btn.disabled=false}}
async function doLogin(){const email=document.getElementById('log-email').value.trim();const pw=document.getElementById('log-pw').value;const msg=document.getElementById('log-msg'),btn=document.getElementById('log-btn');if(!email||!pw){setMsg(msg,'Email and password required','err');return}btn.disabled=true;setMsg(msg,'Logging in…','');const{ok,data}=await apiFetch('/v1/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password:pw})});if(ok){saveSession({email,name:data.name,tier:data.tier,quota:data.quota,keyPrefix:data.key_prefix,keyCreated:data.key_created});document.getElementById('auth-widget').style.display='none';showLoginSuccess(data);updateNavUser()}else{setMsg(msg,'✗ '+(data.error||'Login failed'),'err');btn.disabled=false}}
function doLogout(){clearSession();_key='';sessionStorage.removeItem('ck_key');clearKey();document.getElementById('login-success').classList.remove('show');document.getElementById('key-result').classList.remove('show');document.getElementById('auth-widget').style.display='block';document.getElementById('reg-btn').disabled=false;document.getElementById('log-btn').disabled=false;document.getElementById('reg-msg').textContent='Free · 100 calls/day · No credit card';document.getElementById('reg-msg').className='aw-msg';updateNavUser()}
async function doRotate(){if(!_session){alert('You must be logged in.');return}const pw=prompt('Enter your password to confirm key rotation:');if(!pw)return;const{ok,data}=await apiFetch('/v1/rotate_key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:_session.email,password:pw})});if(ok){document.getElementById('login-success').classList.remove('show');showNewKey(data.api_key);_key=data.api_key;sessionStorage.setItem('ck_key',_key)}else{alert('✗ '+(data.error||'Rotation failed'))}}
function updateNavUser(){const btn=document.getElementById('nav-user-btn');if(_session){btn.style.display='block';btn.textContent=_session.email.split('@')[0]}else{btn.style.display='none'}}
function handleNavUser(){if(_session)doLogout()}
function showNewKey(apiKey){document.getElementById('kr-key-text').textContent=apiKey;document.getElementById('key-result').classList.add('show')}
function showLoginSuccess(data){const created=data.key_created?new Date(data.key_created).toLocaleDateString():'unknown date';document.getElementById('ls-body').innerHTML=`Welcome back, <strong>${data.name||'friend'}</strong>.<br>Tier: <span>${data.tier}</span> · Quota: <span>${data.quota==='unlimited'?'unlimited':data.quota+' calls/day'}</span><br>Active key prefix: <span>${data.key_prefix}</span> (created ${created})<br><br><em style="color:var(--mist);font-size:.75rem">Raw API key shown only once. Paste it below, or rotate to get a new one.</em>`;document.getElementById('login-success').classList.add('show')}
function setMsg(el,txt,cls){el.textContent=txt;el.className='aw-msg'+(cls?' '+cls:'')}
function copyKeyResult(el){navigator.clipboard.writeText(document.getElementById('kr-key-text').textContent).then(()=>{const hint=el.querySelector('.kr-copy-hint');if(hint){hint.textContent='copied!';setTimeout(()=>hint.textContent='click to copy',2000)}})}
function useKeyInPlayground(){const k=document.getElementById('kr-key-text').textContent;sessionStorage.setItem('ck_key',k);_key=k;activateKeyValue(k);document.getElementById('playground-section').scrollIntoView({behavior:'smooth',block:'start'})}
function scrollToPlayground(){document.getElementById('playground-section').scrollIntoView({behavior:'smooth',block:'start'})}
function scrollToTop(){document.getElementById('auth-widget').scrollIntoView({behavior:'smooth',block:'center'})}
function activateKey(){const v=document.getElementById('pg-key-input').value.trim();if(!v)return;sessionStorage.setItem('ck_key',v);_key=v;activateKeyValue(v)}
function activateKeyValue(k){document.getElementById('pg-key-setup').classList.add('hidden');['pane-enc','pane-dec'].forEach(id=>{const el=document.getElementById(id);el.style.display='flex';el.style.flexDirection='column'});document.getElementById('pane-export').style.display='block';document.getElementById('enc-key-label').textContent=k.length>22?k.slice(0,22)+'…':k}
function clearKey(){sessionStorage.removeItem('ck_key');_key='';document.getElementById('pg-key-setup').classList.remove('hidden');['pane-enc','pane-dec','pane-export'].forEach(id=>document.getElementById(id).style.display='none');document.getElementById('pg-key-input').value='';document.getElementById('enc-output').value='';document.getElementById('dec-output').value='';document.getElementById('dec-input').value='';document.getElementById('export-output').style.display='none';document.getElementById('export-output').value=''}
if(_key)activateKeyValue(_key);
if(_session)updateNavUser();
document.getElementById('reg-email').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('reg-pw').focus()});
document.getElementById('reg-pw').addEventListener('keydown',e=>{if(e.key==='Enter')doRegister()});
document.getElementById('log-email').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('log-pw').focus()});
document.getElementById('log-pw').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});
async function doEncrypt(){const plain=document.getElementById('enc-input').value.trim(),out=document.getElementById('enc-output');if(!plain){out.value='⚠ Enter some text first.';out.className='out err';return}out.value='Encrypting…';out.className='out';const{ok,data}=await apiFetch('/v1/encrypt',{method:'POST',headers:{'Authorization':'Bearer '+_key,'Content-Type':'application/json'},body:JSON.stringify({plaintext:plain})});if(ok){out.value=JSON.stringify(data,null,2);out.className='out';document.getElementById('dec-input').value=JSON.stringify(data,null,2)}else{out.value='✗ '+(data.error||JSON.stringify(data));out.className='out err'}}
async function doDecrypt(){const raw=document.getElementById('dec-input').value.trim(),out=document.getElementById('dec-output');if(!raw){out.value='⚠ Paste ciphertext JSON first.';out.className='out err';return}let body;try{body=JSON.parse(raw)}catch(e){out.value='✗ Invalid JSON.';out.className='out err';return}if(!body.ciphertext||!body.nonce||!body.encryption_key){out.value='✗ JSON needs "ciphertext", "nonce", and "encryption_key".';out.className='out err';return}out.value='Decrypting…';out.className='out teal';const{ok,data}=await apiFetch('/v1/decrypt',{method:'POST',headers:{'Authorization':'Bearer '+_key,'Content-Type':'application/json'},body:JSON.stringify({ciphertext:body.ciphertext,nonce:body.nonce,encryption_key:body.encryption_key})});if(ok){out.value=data.plaintext??JSON.stringify(data);out.className='out teal'}else{out.value='✗ '+(data.error||JSON.stringify(data));out.className='out err'}}
async function exportChaosKey(){const out=document.getElementById('export-output');out.style.display='block';out.value='Requesting master key...';out.className='out';const{ok,data}=await apiFetch('/v1/export_key',{method:'GET',headers:{'Authorization':'Bearer '+_key}});if(ok){out.value=data.chaos_key??JSON.stringify(data)}else{out.value='✗ '+(data.error||JSON.stringify(data));out.className='out err'}}
async function apiFetch(path,opts){const r=await fetch(path,opts),ct=r.headers.get('Content-Type')||'';let data;if(ct.includes('application/json')){data=await r.json()}else{const t=await r.text();const m=t.match(/<title>([^<]*)<\/title>/i);data={error:m?m[1]:'HTTP '+r.status}}return{ok:r.ok,status:r.status,data}}
function cpCode(btn,id){navigator.clipboard.writeText(document.getElementById(id).innerText).then(()=>{btn.textContent='copied!';btn.classList.add('ok');setTimeout(()=>{btn.textContent='copy';btn.classList.remove('ok')},2000)})}
const sro=new IntersectionObserver(es=>{es.forEach(e=>{if(e.isIntersecting){e.target.classList.add('in');sro.unobserve(e.target)}})},{threshold:.07});
document.querySelectorAll('.sr').forEach(el=>sro.observe(el));
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


try:
    init_db()
except Exception as e:
    log.error(f"CRITICAL: Database initialization failed: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
