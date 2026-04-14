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
RELAY_TOKEN       = os.getenv("RELAY_TOKEN", "")
ADMIN_SECRET      = os.getenv("ADMIN_SECRET", "")
DATABASE_URL      = os.getenv("DATABASE_URL", "")
DB_PATH           = os.getenv("DB_PATH", "chaoskey.db")
DYNAMIC_RELAY_URL = os.getenv("RELAY_URL", "")

ADMIN_EMAIL       = os.getenv("ADMIN_EMAIL", "admin@admin.com")
ADMIN_PASSWORD    = os.getenv("ADMIN_PASSWORD", "")

FREE_QUOTA_DAY  = 100
PRO_QUOTA_DAY   = 10_000
ADMIN_QUOTA_DAY = 999_999_999
KEY_PREFIX      = "ck_live_"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("CryptoAPI")

if not RELAY_TOKEN:
    log.warning("RELAY_TOKEN env var not set — bridge authentication disabled. "
                "Set RELAY_TOKEN on Render to match BRIDGE_SECRET in your local .env.")
if not ADMIN_SECRET:
    log.warning("ADMIN_SECRET env var not set — admin endpoints are unprotected!")

app = Flask("CryptoAPI")
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)

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
        return None, {"error": "Local engine offline — start the launcher on your machine"}, 503
    try:
        resp = requests.request(
            method, DYNAMIC_RELAY_URL.rstrip("/") + path,
            headers={
                "X-Relay-Token": RELAY_TOKEN,
                "Content-Type": "application/json",
            },
            json=body, timeout=20
        )
        try:
            data = resp.json()
        except Exception:
            data = {
                "error": (
                    f"Bridge returned a non-JSON response (HTTP {resp.status_code}). "
                    "The local encryption bridge may be down — check the launcher."
                )
            }

        # 403 from the bridge always means a token mismatch — give a clear message
        if resp.status_code == 403:
            data = {
                "error": (
                    "Bridge rejected the request (token mismatch). "
                    "RELAY_TOKEN on Render must exactly match BRIDGE_SECRET in your local .env. "
                    "Check both values and redeploy if you changed RELAY_TOKEN."
                )
            }

        return resp, data, resp.status_code
    except requests.exceptions.ConnectionError:
        return None, {"error": "Cannot reach the local bridge — is the launcher running and tunnel active?"}, 503
    except requests.exceptions.Timeout:
        return None, {"error": "Bridge timed out — the local machine may be overloaded"}, 504
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
        "relay_url":     DYNAMIC_RELAY_URL or None,
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
async function doRotate(){if(!_session){alert('You must be logged in.');return}const pw=prompt('Enter your password to confirm key rotation:');if(!pw)return;const{ok,data}=await apiFetch('/v1/rotate_key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:_session.email,password:pw})});if(ok){document.getElementById('login-success').classList.remove('show');showNewKey(data.api_key);_key=data.api_key;sessionStorage.setItem('ck_key',_key);activateKeyValue(_key)}else{alert('✗ '+(data.error||'Rotation failed'))}}
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
async function apiFetch(path,opts){const r=await fetch(path,opts),ct=r.headers.get('Content-Type')||'';let data;if(ct.includes('application/json')){data=await r.json()}else{const t=await r.text();const m=t.match(/<title>([^<]*)<\/title>/i);data={error:m?m[1]:'HTTP '+r.status}}
// If key was revoked, clear it and prompt user to get a new one
if(!r.ok&&data&&data.error&&data.error.toLowerCase().includes('revoked')){clearKey();data={error:'Your API key was revoked. Please rotate your key above to get a new one.'}}
return{ok:r.ok,status:r.status,data}}
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
    app.run(host="0.0.0.0", port=8000, debug=True)        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(12)).decode()
    def check_password(pw: str, h: str) -> bool:
        return _bcrypt.checkpw(pw.encode(), h.encode())
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

import sqlite3

# ── Config ────────────────────────────────────────────────────────────────────
CHAOSKEY_URL = os.getenv("CHAOSKEY_URL", "").rstrip("/")
SECRET_KEY   = os.getenv("SECRET_KEY", secrets.token_hex(32))
DATABASE_URL = os.getenv("DATABASE_URL", "")
DB_PATH      = os.getenv("DB_PATH", "burnchat.db")
PORT         = int(os.getenv("PORT", 5000))

USE_POSTGRES = bool(DATABASE_URL)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("BurnChat")

if not CHAOSKEY_URL:
    log.warning("CHAOSKEY_URL not set — server-side encryption will fail.")
log.info(f"Database backend: {'postgresql' if USE_POSTGRES else 'sqlite'}")

app = Flask("BurnChat")
app.secret_key = SECRET_KEY
CORS(app, supports_credentials=True)

# ── Database abstraction ──────────────────────────────────────────────────────
if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    import urllib.parse as up

    def _pg_url():
        url = (DATABASE_URL or "").strip()
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        parsed = up.urlparse(url)
        qs = up.parse_qs(parsed.query)
        qs.pop("channel_binding", None)
        new_query = up.urlencode(qs, doseq=True)
        url = up.urlunparse(parsed._replace(query=new_query))
        return url

    def get_db():
        if "db" not in g:
            g.db = psycopg2.connect(_pg_url())
            g.db.autocommit = False
        return g.db

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db:
            db.rollback() if exc else db.commit()
            db.close()

    def db_exec(sql, params=()):
        sql = sql.replace("?", "%s")
        cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return cur

    def db_commit():
        get_db().commit()

else:
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(exc=None):
        db = g.pop("db", None)
        if db:
            db.close()

    def db_exec(sql, params=()):
        return get_db().execute(sql, params)

    def db_commit():
        get_db().commit()

# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    email            TEXT UNIQUE NOT NULL,
    display_name     TEXT NOT NULL,
    password_hash    TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    avatar_color     TEXT NOT NULL DEFAULT '#ff6b35',
    chaoskey_api_key TEXT,
    public_key       TEXT,
    encrypted_private_key TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender       TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    ciphertext   TEXT NOT NULL,
    nonce        TEXT NOT NULL DEFAULT '',
    enc_key      TEXT NOT NULL DEFAULT '',
    rsa_wrapped  INTEGER NOT NULL DEFAULT 0,
    plaintext    TEXT,
    sent_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(sender, recipient);
"""

SCHEMA_PG_STMTS = [
    """CREATE TABLE IF NOT EXISTS users (
        id               SERIAL PRIMARY KEY,
        email            TEXT UNIQUE NOT NULL,
        display_name     TEXT NOT NULL,
        password_hash    TEXT NOT NULL,
        created_at       TEXT NOT NULL,
        avatar_color     TEXT NOT NULL DEFAULT '#ff6b35',
        chaoskey_api_key TEXT,
        public_key       TEXT,
        encrypted_private_key TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS messages (
        id           SERIAL PRIMARY KEY,
        sender       TEXT NOT NULL,
        recipient    TEXT NOT NULL,
        ciphertext   TEXT NOT NULL,
        nonce        TEXT NOT NULL DEFAULT '',
        enc_key      TEXT NOT NULL DEFAULT '',
        rsa_wrapped  INTEGER NOT NULL DEFAULT 0,
        plaintext    TEXT,
        sent_at      TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(sender, recipient)",
]

PG_MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_color TEXT NOT NULL DEFAULT '#ff6b35'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS chaoskey_api_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_private_key TEXT",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS rsa_wrapped INTEGER NOT NULL DEFAULT 0",
]

def init_db():
    with app.app_context():
        if USE_POSTGRES:
            conn = psycopg2.connect(_pg_url())
            conn.autocommit = True
            cur = conn.cursor()
            for stmt in SCHEMA_PG_STMTS + PG_MIGRATIONS:
                try:
                    cur.execute(stmt)
                except Exception as e:
                    log.warning(f"Migration skipped: {e}")
            conn.close()
        else:
            db = sqlite3.connect(DB_PATH)
            db.executescript(SCHEMA_SQLITE)
            for col, default in [
                ("avatar_color", "'#ff6b35'"),
                ("chaoskey_api_key", "NULL"),
                ("public_key", "NULL"),
                ("encrypted_private_key", "NULL"),
                ("rsa_wrapped", "0"),
            ]:
                try:
                    db.execute(f"ALTER TABLE messages ADD COLUMN {col} TEXT NOT NULL DEFAULT {default}")
                    db.commit()
                except Exception:
                    pass
            db.commit()
            db.close()
    log.info("Database ready.")


# ── Helpers ───────────────────────────────────────────────────────────────────
def now_iso():
    return datetime.now(timezone.utc).isoformat()

AVATAR_COLORS = [
    "#ff6b35", "#f7931e", "#ffcd3c", "#4ecdc4",
    "#45b7d1", "#a29bfe", "#fd79a8", "#00b894"
]

def pick_color(email: str) -> str:
    return AVATAR_COLORS[sum(ord(c) for c in email) % len(AVATAR_COLORS)]

def require_login(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_email" not in session:
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return wrapped


# ── ChaosKey API bridge ───────────────────────────────────────────────────────
def _ck_api_key() -> str:
    return session.get("ck_api_key", "")

def ck_encrypt(plaintext: str):
    api_key = _ck_api_key()
    if not CHAOSKEY_URL:
        return False, {"error": "CHAOSKEY_URL not configured on this server."}
    if not api_key:
        return False, {"error": "No ChaosKey API key in session. Please log out and log back in."}
    try:
        r = requests.post(
            f"{CHAOSKEY_URL}/v1/encrypt",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"plaintext": plaintext},
            timeout=15,
        )
        data = r.json()
        return r.ok, data
    except requests.exceptions.ConnectionError:
        return False, {"error": "Cannot reach ChaosKey — check CHAOSKEY_URL."}
    except requests.exceptions.Timeout:
        return False, {"error": "ChaosKey timed out."}
    except Exception as e:
        return False, {"error": str(e)}

def ck_decrypt(ciphertext: str, nonce: str, enc_key: str):
    api_key = _ck_api_key()
    if not CHAOSKEY_URL:
        return False, {"error": "CHAOSKEY_URL not configured on this server."}
    if not api_key:
        return False, {"error": "No ChaosKey API key in session."}
    try:
        r = requests.post(
            f"{CHAOSKEY_URL}/v1/decrypt",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"ciphertext": ciphertext, "nonce": nonce, "encryption_key": enc_key},
            timeout=15,
        )
        data = r.json()
        return r.ok, data
    except requests.exceptions.ConnectionError:
        return False, {"error": "Cannot reach ChaosKey."}
    except requests.exceptions.Timeout:
        return False, {"error": "ChaosKey timed out."}
    except Exception as e:
        return False, {"error": str(e)}


# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/auth/signup", methods=["POST"])
def signup():
    body       = request.get_json(force=True) or {}
    email      = body.get("email", "").strip().lower()
    pw         = body.get("password", "").strip()
    name       = body.get("name", "").strip() or email.split("@")[0]
    ck_key     = body.get("chaoskey_api_key", "").strip()
    public_key = body.get("public_key", "").strip()
    enc_priv   = body.get("encrypted_private_key", "").strip()

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not pw or len(pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not ck_key or not ck_key.startswith("ck_live_"):
        return jsonify({"error": "Valid ChaosKey API key required (starts with ck_live_)"}), 400

    color = pick_color(email)
    try:
        db_exec(
            "INSERT INTO users (email, display_name, password_hash, created_at, avatar_color, chaoskey_api_key, public_key, encrypted_private_key) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (email, name, hash_password(pw), now_iso(), color, ck_key, public_key, enc_priv)
        )
        db_commit()
    except Exception as e:
        if "unique" in str(e).lower():
            return jsonify({"error": "Email already registered"}), 409
        return jsonify({"error": str(e)}), 500

    session["user_email"] = email
    session["user_name"]  = name
    session["user_color"] = color
    session["ck_api_key"] = ck_key
    key_prefix = ck_key[:16] + "…"
    return jsonify({"ok": True, "email": email, "name": name, "color": color, "key_prefix": key_prefix}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    pw    = body.get("password", "").strip()

    if not email or not pw:
        return jsonify({"error": "Email and password required"}), 400

    user = db_exec(
        "SELECT email, display_name, password_hash, avatar_color, chaoskey_api_key, public_key, encrypted_private_key "
        "FROM users WHERE email = ?", (email,)
    ).fetchone()

    if not user or not check_password(pw, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    ck_key = user["chaoskey_api_key"] or ""
    session["user_email"] = user["email"]
    session["user_name"]  = user["display_name"]
    session["user_color"] = user["avatar_color"]
    session["ck_api_key"] = ck_key
    key_prefix = (ck_key[:16] + "…") if ck_key else None
    return jsonify({
        "ok":          True,
        "email":       user["email"],
        "name":        user["display_name"],
        "color":       user["avatar_color"],
        "key_prefix":  key_prefix,
        "has_ck_key":  bool(ck_key),
        "public_key":  user["public_key"] or "",
        "encrypted_private_key": user["encrypted_private_key"] or "",
    })


@app.route("/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/auth/me", methods=["GET"])
def me():
    if "user_email" not in session:
        return jsonify({"authenticated": False}), 200
    ck_key = session.get("ck_api_key", "")
    return jsonify({
        "authenticated": True,
        "email":       session["user_email"],
        "name":        session["user_name"],
        "color":       session.get("user_color", "#ff6b35"),
        "has_ck_key":  bool(ck_key),
        "key_prefix":  (ck_key[:16] + "…") if ck_key else None,
    })


@app.route("/auth/update_ck_key", methods=["POST"])
@require_login
def update_ck_key():
    body   = request.get_json(force=True) or {}
    ck_key = body.get("chaoskey_api_key", "").strip()
    if not ck_key or not ck_key.startswith("ck_live_"):
        return jsonify({"error": "Valid ChaosKey API key required (starts with ck_live_)"}), 400
    db_exec("UPDATE users SET chaoskey_api_key = ? WHERE email = ?",
            (ck_key, session["user_email"]))
    db_commit()
    session["ck_api_key"] = ck_key
    return jsonify({"ok": True, "key_prefix": ck_key[:16] + "…"})


# ── ChaosKey + RSA hybrid helpers ────────────────────────────────────────────
def ck_encrypt_for_recipient(plaintext: str, recipient_email: str):
    """
    Always encrypt via ChaosKey, then RSA-wrap the returned enc_key with the
    recipient's stored public key so only their browser can unwrap it.
    """
    ok, enc = ck_encrypt(plaintext)
    if not ok:
        return False, enc

    raw_enc_key = enc.get("encryption_key", "")
    ciphertext  = enc.get("ciphertext", "")
    nonce       = enc.get("nonce", "")

    if not raw_enc_key:
        return False, {"error": "ChaosKey returned no encryption_key"}

    row = db_exec("SELECT public_key FROM users WHERE email = ?", (recipient_email,)).fetchone()
    recip_pub_b64 = row["public_key"] if row else None

    if not recip_pub_b64:
        log.warning(f"Recipient {recipient_email} has no RSA public key; enc_key stored unprotected")
        return True, {
            "ciphertext":  ciphertext,
            "nonce":       nonce,
            "rsa_enc_key": raw_enc_key,
            "rsa_wrapped": False,
        }

    try:
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives import hashes, serialization
        import base64

        pub_der  = base64.b64decode(recip_pub_b64)
        pub_key  = serialization.load_der_public_key(pub_der)
        wrapped  = pub_key.encrypt(
            raw_enc_key.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
        rsa_enc_key_b64 = base64.b64encode(wrapped).decode()
        return True, {
            "ciphertext":  ciphertext,
            "nonce":       nonce,
            "rsa_enc_key": rsa_enc_key_b64,
            "rsa_wrapped": True,
        }
    except ImportError:
        log.warning("cryptography package not installed — storing enc_key without RSA wrap. Run: pip install cryptography")
        return True, {
            "ciphertext":  ciphertext,
            "nonce":       nonce,
            "rsa_enc_key": raw_enc_key,
            "rsa_wrapped": False,
        }
    except Exception as e:
        log.warning(f"RSA wrap failed ({e}) — storing enc_key without RSA wrap")
        return True, {
            "ciphertext":  ciphertext,
            "nonce":       nonce,
            "rsa_enc_key": raw_enc_key,
            "rsa_wrapped": False,
        }


@app.route("/user/key", methods=["GET"])
@require_login
def get_user_key():
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "email param required"}), 400
    u = db_exec("SELECT public_key FROM users WHERE email = ?", (email,)).fetchone()
    return jsonify({"key": u["public_key"] if u else None})


@app.route("/user/update_key", methods=["POST"])
@require_login
def update_public_key():
    body = request.get_json(force=True) or {}
    pub  = body.get("public_key", "").strip()
    if not pub:
        return jsonify({"error": "public_key required"}), 400
    db_exec("UPDATE users SET public_key = ? WHERE email = ?",
            (pub, session["user_email"]))
    db_commit()
    return jsonify({"ok": True})


# ── Message routes ────────────────────────────────────────────────────────────
@app.route("/msg/send", methods=["POST"])
@require_login
def send_message():
    body      = request.get_json(force=True) or {}
    recipient = body.get("recipient", "").strip().lower()
    plaintext = body.get("plaintext", "").strip()
    sender    = session["user_email"]

    if not recipient or not plaintext:
        return jsonify({"error": "recipient and plaintext required"}), 400
    if recipient == sender:
        return jsonify({"error": "Cannot message yourself"}), 400

    exists = db_exec("SELECT id FROM users WHERE email = ?", (recipient,)).fetchone()
    if not exists:
        return jsonify({"error": f"User '{recipient}' not found on BurnChat"}), 404

    ok, enc = ck_encrypt_for_recipient(plaintext, recipient)
    if not ok:
        err_msg = enc.get("error", "Encryption failed")
        log.warning(f"ck_encrypt_for_recipient failed for {sender}: {err_msg}")
        return jsonify({"error": f"Encryption failed: {err_msg}"}), 502

    db_exec(
        "INSERT INTO messages (sender, recipient, ciphertext, nonce, enc_key, rsa_wrapped, plaintext, sent_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (sender, recipient,
         enc["ciphertext"],
         enc["nonce"],
         enc["rsa_enc_key"],
         1 if enc.get("rsa_wrapped") else 0,
         None,
         now_iso())
    )
    db_commit()
    rsa_wrapped = enc.get("rsa_wrapped", False)
    return jsonify({
        "ok":      True,
        "sent_at": now_iso(),
        "mode":    "chaoskey+rsa" if rsa_wrapped else "chaoskey",
    }), 201


@app.route("/msg/thread", methods=["GET"])
@require_login
def get_thread():
    contact = request.args.get("with", "").strip().lower()
    me      = session["user_email"]

    if not contact:
        return jsonify({"error": "?with= required"}), 400

    rows = db_exec(
        "SELECT id, sender, ciphertext, nonce, enc_key, rsa_wrapped, sent_at "
        "FROM messages "
        "WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?) "
        "ORDER BY id ASC",
        (me, contact, contact, me)
    ).fetchall()

    result = []
    for r in rows:
        result.append({
            "id":          r["id"],
            "from":        r["sender"],
            "ciphertext":  r["ciphertext"],
            "nonce":       r["nonce"],
            "rsa_enc_key": r["enc_key"],
            "rsa_wrapped": bool(r["rsa_wrapped"]),
            "sent_at":     r["sent_at"],
        })

    return jsonify(result)


@app.route("/msg/decrypt", methods=["POST"])
@require_login
def decrypt_message():
    body       = request.get_json(force=True) or {}
    msg_id     = body.get("msg_id")
    enc_key    = body.get("enc_key", "").strip()
    me         = session["user_email"]

    if not msg_id or not enc_key:
        return jsonify({"error": "msg_id and enc_key required"}), 400

    row = db_exec(
        "SELECT ciphertext, nonce, sender, recipient FROM messages WHERE id = ?", (msg_id,)
    ).fetchone()

    if not row:
        return jsonify({"error": "Message not found"}), 404
    if me not in (row["sender"], row["recipient"]):
        return jsonify({"error": "Not authorised"}), 403

    ok, dec = ck_decrypt(row["ciphertext"], row["nonce"], enc_key)
    if not ok:
        # FIX: log the exact ChaosKey error so it's diagnosable
        log.warning(f"ChaosKey decrypt failed for msg {msg_id} (user={me}): {dec}")
        return jsonify({"error": dec.get("error", "Decryption failed")}), 502

    return jsonify({"ok": True, "plaintext": dec.get("plaintext", "")})


@app.route("/msg/burn", methods=["POST"])
@require_login
def burn_thread():
    body    = request.get_json(force=True) or {}
    contact = body.get("contact", "").strip().lower()
    me      = session["user_email"]

    if not contact:
        return jsonify({"error": "contact required"}), 400

    db_exec(
        "DELETE FROM messages WHERE "
        "(sender=? AND recipient=?) OR (sender=? AND recipient=?)",
        (me, contact, contact, me)
    )
    db_commit()
    return jsonify({"ok": True, "burned": True})


@app.route("/msg/inbox", methods=["GET"])
@require_login
def inbox():
    me = session["user_email"]
    rows = db_exec(
        "SELECT "
        "  CASE WHEN sender=? THEN recipient ELSE sender END as contact, "
        "  MAX(sent_at) as last_at, "
        "  COUNT(*) as total, "
        "  SUM(CASE WHEN sender!=? THEN 1 ELSE 0 END) as received "
        "FROM messages WHERE sender=? OR recipient=? "
        "GROUP BY contact ORDER BY last_at DESC",
        (me, me, me, me)
    ).fetchall()

    contacts_with_info = []
    for r in rows:
        user = db_exec(
            "SELECT display_name, avatar_color FROM users WHERE email=?", (r["contact"],)
        ).fetchone()
        contacts_with_info.append({
            "contact":  r["contact"],
            "name":     user["display_name"] if user else r["contact"].split("@")[0],
            "color":    user["avatar_color"] if user else "#888",
            "last_at":  r["last_at"],
            "total":    r["total"],
        })
    return jsonify(contacts_with_info)


@app.route("/msg/search_user", methods=["GET"])
@require_login
def search_user():
    q = request.args.get("q", "").strip().lower()
    if not q or len(q) < 3:
        return jsonify([])
    rows = db_exec(
        "SELECT email, display_name, avatar_color FROM users "
        "WHERE (email LIKE ? OR display_name LIKE ?) AND email != ? LIMIT 10",
        (f"%{q}%", f"%{q}%", session["user_email"])
    ).fetchall()
    return jsonify([{"email": r["email"], "name": r["display_name"], "color": r["avatar_color"]} for r in rows])


@app.route("/health")
def health():
    return jsonify({
        "status":         "ok",
        "chaoskey_url":   CHAOSKEY_URL or None,
        "db_backend":     "postgresql" if USE_POSTGRES else "sqlite",
        "e2ee":           "ChaosKey AES-256-GCM + RSA-OAEP Key Escrow",
    })


# ════════════════════════════════════════════════════════════════
#  FRONTEND  (single-page app served at /)
# ════════════════════════════════════════════════════════════════

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BurnChat</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700;800&family=Fira+Code:wght@300;400;500&family=Lora:ital,wght@0,400;0,600;1,400&display=swap" rel="stylesheet">
<style>
/* ── Reset & Tokens ──────────────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --void:#060608;
  --coal:#0d0e13;
  --ash:#181a22;
  --cinder:#22252f;
  --smoke:#2e3140;
  --dust:#4a4f61;
  --fog:#6b7182;
  --mist:#9097a8;
  --paper:#c8ccdb;
  --snow:#eef0f6;

  --ember:#ff6b35;
  --flame:#ff8c42;
  --glow:#ffb347;
  --spark:#ffd166;
  --cold:#4ecdc4;
  --ice:#a8e6cf;

  --ember-dim:rgba(255,107,53,.12);
  --ember-mid:rgba(255,107,53,.25);
  --ember-glow:0 0 30px rgba(255,107,53,.3);
  --cold-glow:0 0 20px rgba(78,205,196,.2);

  --r-sm:8px;
  --r-md:14px;
  --r-lg:20px;
  --r-xl:28px;
}
html{-webkit-font-smoothing:antialiased;height:100%}
body{background:var(--void);color:var(--paper);font-family:'Syne',sans-serif;height:100%;overflow:hidden}

/* ── Scrollbar ───────────────────────────────────────────────────────── */
::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--smoke);border-radius:2px}

/* ══════════════════════════════════════════════════════
   AUTH SCREEN
══════════════════════════════════════════════════════ */
#auth{
  position:fixed;inset:0;
  display:flex;align-items:center;justify-content:center;
  background:var(--void);
  z-index:100;
}
#auth.hidden{display:none}

.auth-bg{
  position:absolute;inset:0;
  background:
    radial-gradient(ellipse 80% 60% at 20% 80%, rgba(255,107,53,.07) 0%, transparent 60%),
    radial-gradient(ellipse 60% 50% at 80% 20%, rgba(78,205,196,.05) 0%, transparent 50%);
  pointer-events:none;
}
.auth-noise{
  position:absolute;inset:0;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
  pointer-events:none;opacity:.4;
}

.auth-card{
  position:relative;
  width:100%;max-width:420px;
  padding:3rem 2.5rem;
  background:var(--coal);
  border:1px solid var(--cinder);
  border-radius:var(--r-xl);
  box-shadow:0 40px 80px rgba(0,0,0,.6);
  animation:riseIn .5s cubic-bezier(.22,1,.36,1) both;
}
@keyframes riseIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}

.auth-wordmark{
  display:flex;align-items:center;gap:12px;
  margin-bottom:2.5rem;
}
.burn-icon{
  width:42px;height:42px;
  background:linear-gradient(135deg,var(--ember),var(--glow));
  border-radius:12px;
  display:flex;align-items:center;justify-content:center;
  font-size:1.3rem;
  box-shadow:var(--ember-glow);
  flex-shrink:0;
}
.wordmark-text h1{
  font-size:1.5rem;font-weight:800;
  letter-spacing:-.03em;color:var(--snow);
}
.wordmark-text p{
  font-family:'Fira Code',monospace;
  font-size:.65rem;color:var(--fog);
  letter-spacing:.06em;margin-top:1px;
}

.auth-tabs{
  display:flex;gap:4px;
  background:var(--ash);border-radius:10px;padding:4px;
  margin-bottom:1.75rem;
}
.auth-tab{
  flex:1;padding:.55rem;
  background:none;border:none;
  font-family:'Syne',sans-serif;font-size:.82rem;font-weight:600;
  color:var(--fog);cursor:pointer;
  border-radius:7px;transition:all .2s;
}
.auth-tab.active{background:var(--cinder);color:var(--snow)}

.form-field{margin-bottom:1rem}
.form-field label{
  display:block;
  font-family:'Fira Code',monospace;font-size:.68rem;
  color:var(--fog);letter-spacing:.06em;text-transform:uppercase;
  margin-bottom:.45rem;
}
.form-field input{
  width:100%;padding:.75rem 1rem;
  background:var(--ash);border:1px solid var(--smoke);border-radius:var(--r-sm);
  color:var(--snow);font-family:'Syne',sans-serif;font-size:.92rem;
  outline:none;transition:border-color .2s,box-shadow .2s;
}
.form-field input::placeholder{color:var(--dust)}
.form-field input:focus{border-color:var(--ember);box-shadow:0 0 0 3px rgba(255,107,53,.12)}

.auth-submit{
  width:100%;padding:.85rem;margin-top:.5rem;
  background:linear-gradient(135deg,var(--ember),var(--flame));
  color:#fff;border:none;border-radius:var(--r-sm);
  font-family:'Syne',sans-serif;font-weight:700;font-size:.95rem;
  cursor:pointer;letter-spacing:.01em;
  transition:all .2s;box-shadow:0 4px 20px rgba(255,107,53,.3);
}
.auth-submit:hover{transform:translateY(-1px);box-shadow:0 8px 30px rgba(255,107,53,.4)}
.auth-submit:disabled{opacity:.4;cursor:not-allowed;transform:none}

.auth-err{
  font-family:'Fira Code',monospace;font-size:.75rem;
  color:#ff8fab;text-align:center;min-height:1.2rem;
  margin-top:.75rem;
}

/* ══════════════════════════════════════════════════════
   CHAT SHELL
══════════════════════════════════════════════════════ */
#app{
  display:flex;height:100vh;
}
#app.hidden{display:none}

/* ── Sidebar ─────────────────────────────────────────────────────────── */
.sidebar{
  width:300px;flex-shrink:0;
  background:var(--coal);border-right:1px solid var(--cinder);
  display:flex;flex-direction:column;
  overflow:hidden;
}

.sidebar-top{
  padding:1.25rem 1.25rem 0;
}
.user-row{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:1.25rem;
}
.user-chip{
  display:flex;align-items:center;gap:10px;
}
.avatar{
  width:34px;height:34px;border-radius:10px;
  display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:.85rem;color:#fff;
  flex-shrink:0;
}
.user-meta .uname{
  font-size:.88rem;font-weight:700;color:var(--snow);
}
.user-meta .uemail{
  font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog);
}
.logout-btn{
  background:none;border:none;
  font-family:'Fira Code',monospace;font-size:.68rem;
  color:var(--dust);cursor:pointer;
  padding:.3rem .6rem;border-radius:6px;
  transition:color .2s,background .2s;
}
.logout-btn:hover{color:var(--ember);background:var(--ember-dim)}

.search-wrap{
  position:relative;margin-bottom:1.25rem;
}
.search-wrap input{
  width:100%;padding:.6rem .9rem .6rem 2.4rem;
  background:var(--ash);border:1px solid var(--smoke);border-radius:10px;
  color:var(--snow);font-family:'Syne',sans-serif;font-size:.85rem;
  outline:none;transition:border-color .2s;
}
.search-wrap input:focus{border-color:var(--ember)}
.search-wrap input::placeholder{color:var(--dust)}
.search-icon{
  position:absolute;left:.8rem;top:50%;transform:translateY(-50%);
  font-size:.85rem;pointer-events:none;color:var(--fog);
}
.search-results{
  position:absolute;top:calc(100% + 4px);left:0;right:0;
  background:var(--cinder);border:1px solid var(--smoke);border-radius:10px;
  overflow:hidden;z-index:50;
  box-shadow:0 10px 30px rgba(0,0,0,.5);
  display:none;
}
.search-results.open{display:block}
.search-result-item{
  display:flex;align-items:center;gap:10px;
  padding:.7rem 1rem;cursor:pointer;
  transition:background .15s;
}
.search-result-item:hover{background:var(--smoke)}
.sr-info .sr-name{font-size:.85rem;font-weight:600;color:var(--snow)}
.sr-info .sr-email{font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog)}

.sidebar-label{
  font-family:'Fira Code',monospace;font-size:.65rem;
  color:var(--dust);letter-spacing:.08em;text-transform:uppercase;
  padding:0 1.25rem .5rem;
}

.thread-list{
  flex:1;overflow-y:auto;
  padding:0 .5rem .5rem;
}
.thread-item{
  display:flex;align-items:center;gap:10px;
  padding:.75rem .75rem;border-radius:12px;
  cursor:pointer;transition:background .15s;
  margin-bottom:2px;
}
.thread-item:hover{background:var(--ash)}
.thread-item.active{background:var(--ember-dim);border:1px solid var(--ember-mid)}
.thread-item.active .thread-name{color:var(--glow)}
.thread-info{flex:1;min-width:0}
.thread-name{
  font-size:.9rem;font-weight:600;color:var(--snow);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.thread-email{
  font-family:'Fira Code',monospace;font-size:.62rem;color:var(--fog);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.thread-time{
  font-family:'Fira Code',monospace;font-size:.62rem;color:var(--dust);flex-shrink:0;
}
.no-threads{
  padding:2rem 1rem;text-align:center;
  color:var(--dust);font-size:.82rem;line-height:1.6;
}
.no-threads .nt-icon{font-size:2rem;margin-bottom:.5rem}

/* ── Main panel ──────────────────────────────────────────────────────── */
.main{
  flex:1;display:flex;flex-direction:column;
  background:var(--void);overflow:hidden;
  position:relative;
}

.empty-state{
  flex:1;display:flex;align-items:center;justify-content:center;
  flex-direction:column;gap:.75rem;color:var(--dust);
  text-align:center;padding:2rem;
}
.es-icon{font-size:3rem;margin-bottom:.5rem;opacity:.4}
.es-title{font-size:1.1rem;font-weight:700;color:var(--fog)}
.es-sub{font-family:'Fira Code',monospace;font-size:.75rem;line-height:1.6}

.chat-view{
  display:none;flex-direction:column;height:100%;
}
.chat-view.active{display:flex}

/* Chat header */
.chat-header{
  display:flex;align-items:center;justify-content:space-between;
  padding:1rem 1.5rem;
  background:var(--coal);border-bottom:1px solid var(--cinder);
  flex-shrink:0;
}
.chat-header-left{display:flex;align-items:center;gap:12px}
.contact-info .cname{
  font-size:.95rem;font-weight:700;color:var(--snow);
}
.contact-info .cemail{
  font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog);
  margin-top:1px;
}
.enc-badge{
  display:flex;align-items:center;gap:5px;
  font-family:'Fira Code',monospace;font-size:.65rem;
  color:var(--cold);padding:.2rem .55rem;
  background:rgba(78,205,196,.08);border:1px solid rgba(78,205,196,.2);
  border-radius:100px;
}
.burn-thread-btn{
  display:flex;align-items:center;gap:6px;
  padding:.45rem .9rem;border-radius:8px;
  background:rgba(255,90,90,.1);border:1px solid rgba(255,90,90,.2);
  color:#ff8fab;font-family:'Syne',sans-serif;font-size:.78rem;font-weight:600;
  cursor:pointer;transition:all .2s;
}
.burn-thread-btn:hover{background:rgba(255,90,90,.2);color:#ff6b6b}

/* Messages area */
.messages{
  flex:1;overflow-y:auto;
  padding:1.5rem;display:flex;flex-direction:column;gap:.75rem;
}

.msg-group{display:flex;flex-direction:column;gap:3px;max-width:70%}
.msg-group.mine{align-self:flex-end;align-items:flex-end}
.msg-group.theirs{align-self:flex-start;align-items:flex-start}

.bubble{
  padding:.65rem 1rem;
  font-family:'Lora',serif;font-size:.9rem;line-height:1.6;
  word-break:break-word;
  position:relative;
}
.mine .bubble{
  background:linear-gradient(135deg,var(--ember),var(--flame));
  color:#fff;border-radius:18px 18px 4px 18px;
}
.theirs .bubble{
  background:var(--ash);border:1px solid var(--cinder);
  color:var(--snow);border-radius:18px 18px 18px 4px;
}
.bubble.error-bubble{
  font-family:'Fira Code',monospace;font-size:.78rem;
  color:var(--fog);font-style:italic;
  background:var(--cinder) !important;
  border-color:var(--smoke) !important;
}

.msg-meta{
  font-family:'Fira Code',monospace;font-size:.6rem;
  color:var(--dust);padding:0 .3rem;
}
.e2ee-tag{
  font-family:'Fira Code',monospace;font-size:.55rem;
  color:var(--cold);opacity:.6;padding:0 .3rem;
}

/* Compose */
.compose{
  padding:1rem 1.5rem;
  background:var(--coal);border-top:1px solid var(--cinder);
  display:flex;gap:.75rem;align-items:flex-end;
  flex-shrink:0;
}
.compose-wrap{
  flex:1;background:var(--ash);
  border:1px solid var(--smoke);border-radius:14px;
  overflow:hidden;transition:border-color .2s,box-shadow .2s;
}
.compose-wrap:focus-within{
  border-color:var(--ember);
  box-shadow:0 0 0 3px rgba(255,107,53,.1);
}
.compose-input{
  width:100%;padding:.8rem 1rem;
  background:none;border:none;
  color:var(--snow);font-family:'Lora',serif;font-size:.9rem;
  outline:none;resize:none;
  max-height:120px;line-height:1.5;
}
.compose-input::placeholder{color:var(--dust)}
.send-btn{
  width:44px;height:44px;flex-shrink:0;
  background:linear-gradient(135deg,var(--ember),var(--flame));
  border:none;border-radius:12px;
  color:#fff;font-size:1.1rem;cursor:pointer;
  display:flex;align-items:center;justify-content:center;
  transition:all .2s;
  box-shadow:0 4px 12px rgba(255,107,53,.3);
}
.send-btn:hover{transform:scale(1.05);box-shadow:0 6px 20px rgba(255,107,53,.45)}
.send-btn:disabled{opacity:.35;cursor:not-allowed;transform:none}

/* ── Burn confirmation modal ─────────────────────────────────────────── */
.modal-overlay{
  position:fixed;inset:0;background:rgba(0,0,0,.7);
  display:flex;align-items:center;justify-content:center;
  z-index:200;opacity:0;pointer-events:none;transition:opacity .2s;
}
.modal-overlay.open{opacity:1;pointer-events:all}
.modal{
  background:var(--coal);border:1px solid var(--cinder);border-radius:var(--r-xl);
  padding:2rem 2.25rem;max-width:380px;width:90%;
  box-shadow:0 40px 80px rgba(0,0,0,.6);
  transform:scale(.95);transition:transform .2s;
}
.modal-overlay.open .modal{transform:scale(1)}
.modal-icon{font-size:2.5rem;margin-bottom:1rem}
.modal h2{font-size:1.1rem;font-weight:800;color:var(--snow);margin-bottom:.5rem}
.modal p{font-family:'Fira Code',monospace;font-size:.75rem;color:var(--fog);line-height:1.6;margin-bottom:1.5rem}
.modal-btns{display:flex;gap:.75rem}
.modal-cancel,.modal-confirm{
  flex:1;padding:.7rem;border-radius:10px;border:none;
  font-family:'Syne',sans-serif;font-weight:700;font-size:.88rem;cursor:pointer;
  transition:all .15s;
}
.modal-cancel{background:var(--ash);color:var(--paper);border:1px solid var(--smoke)}
.modal-cancel:hover{border-color:var(--fog)}
.modal-confirm{
  background:linear-gradient(135deg,#ff4444,#ff6b35);
  color:#fff;box-shadow:0 4px 15px rgba(255,60,60,.3);
}
.modal-confirm:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(255,60,60,.4)}

/* ── Toast ───────────────────────────────────────────────────────────── */
.toast{
  position:fixed;bottom:2rem;left:50%;transform:translateX(-50%) translateY(20px);
  background:var(--cinder);color:var(--snow);
  font-family:'Fira Code',monospace;font-size:.78rem;
  padding:.65rem 1.25rem;border-radius:100px;
  border:1px solid var(--smoke);
  opacity:0;transition:opacity .25s,transform .25s;
  pointer-events:none;z-index:300;white-space:nowrap;
}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.ok{border-color:rgba(168,230,207,.3);color:var(--ice)}
.toast.err{border-color:rgba(255,107,53,.3);color:var(--ember)}

/* ── Responsive ──────────────────────────────────────────────────────── */
@media(max-width:680px){
  .sidebar{width:100%;display:none}
  .sidebar.mobile-open{display:flex;position:fixed;inset:0;z-index:50}
}
</style>
</head>
<body>

<div id="auth">
  <div class="auth-bg"></div>
  <div class="auth-noise"></div>
  <div class="auth-card">
    <div class="auth-wordmark">
      <div class="burn-icon">🔥</div>
      <div class="wordmark-text">
        <h1>BurnChat</h1>
        <p>RSA-OAEP · AES-256-GCM · SELF-DESTRUCT</p>
      </div>
    </div>
    <div class="auth-tabs">
      <button class="auth-tab active" id="tab-in" onclick="switchAuthTab('login')">Sign in</button>
      <button class="auth-tab" id="tab-up" onclick="switchAuthTab('signup')">Create account</button>
    </div>
    <div id="auth-fields">
      <div class="form-field" id="field-name" style="display:none">
        <label>Display name</label>
        <input id="f-name" type="text" placeholder="How should people know you?" autocomplete="name">
      </div>
      <div class="form-field">
        <label>Email</label>
        <input id="f-email" type="email" placeholder="you@example.com" autocomplete="email"
          onkeydown="if(event.key==='Enter')document.getElementById('f-pw').focus()">
      </div>
      <div class="form-field">
        <label>Password</label>
        <input id="f-pw" type="password" placeholder="••••••••" autocomplete="current-password"
          onkeydown="if(event.key==='Enter' && S.authMode==='login')doAuth(); else if(event.key==='Enter')document.getElementById('f-ck-key').focus()">
      </div>
      <div class="form-field" id="field-ck-key" style="display:none">
        <label>ChaosKey API key</label>
        <input id="f-ck-key" type="text" placeholder="ck_live_…" autocomplete="off" spellcheck="false"
          style="font-family:'Fira Code',monospace;font-size:.82rem;letter-spacing:.01em"
          onkeydown="if(event.key==='Enter')doAuth()">
        <div style="font-family:'Fira Code',monospace;font-size:.63rem;color:var(--fog);margin-top:.4rem;line-height:1.5">
          Register on ChaosKey → copy your <code style="color:var(--ember)">ck_live_…</code> key here
        </div>
      </div>
    </div>
    <button class="auth-submit" id="auth-btn" onclick="doAuth()">Sign in →</button>
    <div class="auth-err" id="auth-err"></div>
  </div>
</div>

<div id="app" class="hidden">

  <div class="sidebar" id="sidebar">
    <div class="sidebar-top">
      <div class="user-row">
        <div class="user-chip">
          <div class="avatar" id="my-avatar" style="background:#ff6b35">U</div>
          <div class="user-meta">
            <div class="uname" id="my-name">–</div>
            <div class="uemail" id="my-email">–</div>
          </div>
        </div>
        <button class="logout-btn" onclick="doLogout()">exit</button>
      </div>
      <div id="ck-key-bar" style="display:none;align-items:center;justify-content:space-between;margin-bottom:.75rem;padding:.45rem .7rem;background:var(--ash);border:1px solid var(--smoke);border-radius:8px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="font-size:.7rem">⚿</span>
          <span id="ck-key-prefix" style="font-family:'Fira Code',monospace;font-size:.65rem;color:var(--fog)"></span>
        </div>
        <button onclick="showUpdateKeyModal()" style="background:none;border:none;font-family:'Fira Code',monospace;font-size:.62rem;color:var(--dust);cursor:pointer;padding:0;transition:color .15s;" onmouseover="this.style.color='var(--ember)'" onmouseout="this.style.color='var(--dust)'">update</button>
      </div>
      <div id="ck-key-warn" style="display:none;padding:.5rem .7rem;background:rgba(255,107,53,.1);border:1px solid rgba(255,107,53,.25);border-radius:8px;margin-bottom:.75rem;">
        <div style="font-family:'Fira Code',monospace;font-size:.65rem;color:var(--ember);margin-bottom:.3rem">⚠ No ChaosKey API key</div>
        <button onclick="showUpdateKeyModal()" style="background:var(--ember);border:none;color:#fff;font-family:'Syne',sans-serif;font-size:.72rem;font-weight:700;padding:.3rem .7rem;border-radius:6px;cursor:pointer;width:100%">Add key →</button>
      </div>
      <div id="e2ee-status" style="display:none;align-items:center;gap:6px;margin-bottom:.75rem;padding:.4rem .7rem;background:rgba(78,205,196,.06);border:1px solid rgba(78,205,196,.15);border-radius:8px;">
        <span style="font-size:.7rem">🔑</span>
        <span style="font-family:'Fira Code',monospace;font-size:.63rem;color:var(--cold)">RSA keys ready</span>
      </div>
      <div class="search-wrap">
        <span class="search-icon">⌕</span>
        <input id="search-input" type="email" placeholder="Find user by email…"
          oninput="onSearchInput(this.value)"
          onblur="setTimeout(()=>closeSearch(),150)">
        <div class="search-results" id="search-results"></div>
      </div>
    </div>
    <div class="sidebar-label">Conversations</div>
    <div class="thread-list" id="thread-list">
      <div class="no-threads">
        <div class="nt-icon">🔒</div>
        <div>Search for a user above<br>to start a conversation.</div>
      </div>
    </div>
  </div>

  <div class="main">
    <div class="empty-state" id="empty-state">
      <div class="es-icon">🔥</div>
      <div class="es-title">Select a conversation</div>
      <div class="es-sub">
        End-to-end encrypted with RSA-OAEP<br>
        AES-256-GCM server layer via ChaosKey
      </div>
    </div>

    <div class="chat-view" id="chat-view">
      <div class="chat-header">
        <div class="chat-header-left">
          <div class="avatar" id="contact-avatar" style="background:#888">C</div>
          <div class="contact-info">
            <div class="cname" id="contact-name">–</div>
            <div class="cemail" id="contact-email">–</div>
          </div>
          <div class="enc-badge" id="enc-badge">⚿ E2EE</div>
        </div>
        <div style="display:flex;align-items:center;gap:.75rem">
          <button class="burn-thread-btn" onclick="confirmBurn()">🔥 Burn thread</button>
        </div>
      </div>

      <div class="messages" id="messages-area"></div>

      <div class="compose">
        <div class="compose-wrap">
          <textarea class="compose-input" id="compose-input" rows="1"
            placeholder="Write an encrypted message… (Enter to send)"
            oninput="autoResize(this)"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage();}">
          </textarea>
        </div>
        <button class="send-btn" id="send-btn" onclick="sendMessage()">➤</button>
      </div>
    </div>
  </div>
</div>

<div class="modal-overlay" id="burn-modal">
  <div class="modal">
    <div class="modal-icon">🔥</div>
    <h2>Burn this thread?</h2>
    <p id="burn-modal-text">This will permanently delete all messages. The ashes will never be recovered.</p>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeBurnModal()">Cancel</button>
      <button class="modal-confirm" onclick="executeBurn()">Burn it</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="key-modal">
  <div class="modal">
    <div class="modal-icon">⚿</div>
    <h2>Update ChaosKey API key</h2>
    <p>Paste a fresh <code style="font-family:'Fira Code',monospace;color:var(--ember)">ck_live_…</code> key from your ChaosKey account. The old key will be replaced.</p>
    <div style="margin:1rem 0">
      <input id="modal-ck-input" type="text" placeholder="ck_live_…"
        style="width:100%;padding:.75rem 1rem;background:var(--ash);border:1px solid var(--smoke);border-radius:8px;color:var(--snow);font-family:'Fira Code',monospace;font-size:.82rem;outline:none;"
        onfocus="this.style.borderColor='var(--ember)'" onblur="this.style.borderColor='var(--smoke)'"
        onkeydown="if(event.key==='Enter')saveUpdatedKey()">
      <div id="key-modal-err" style="font-family:'Fira Code',monospace;font-size:.72rem;color:#ff8fab;min-height:1.1rem;margin-top:.4rem"></div>
    </div>
    <div class="modal-btns">
      <button class="modal-cancel" onclick="closeKeyModal()">Cancel</button>
      <button class="modal-confirm" style="background:linear-gradient(135deg,var(--ember),var(--flame));box-shadow:0 4px 15px rgba(255,107,53,.3)" onclick="saveUpdatedKey()">Save key</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
'use strict';

// ════════════════════════════════════════════════════════════════
//  State
// ════════════════════════════════════════════════════════════════
const S = {
  me:            null,
  activeContact: null,
  threads:       [],
  pollTimer:     null,
  authMode:      'login',
  rsaPublicKey:  null,
  rsaPrivateKey: null,
};

// ════════════════════════════════════════════════════════════════
//  Utilities
// ════════════════════════════════════════════════════════════════
const $  = id => document.getElementById(id);
const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const initials = s => (s||'?')[0].toUpperCase();

function toast(msg, type='ok', dur=2800) {
  const el = $('toast');
  el.textContent = msg;
  el.className = `toast ${type} show`;
  setTimeout(() => el.classList.remove('show'), dur);
}

async function api(path, opts={}) {
  const r = await fetch(path, {
    credentials: 'same-origin',
    headers: {'Content-Type':'application/json', ...(opts.headers||{})},
    ...opts,
  });
  const ct = r.headers.get('Content-Type') || '';
  const data = ct.includes('json') ? await r.json() : {error: 'Server error'};
  return {ok: r.ok, status: r.status, data};
}

function autoResize(ta) {
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
}
function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return 'Today';
  const yesterday = new Date(now); yesterday.setDate(now.getDate()-1);
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], {month:'short', day:'numeric'});
}

// ════════════════════════════════════════════════════════════════
//  Cross-Device Key Escrow & RSA Management
// ════════════════════════════════════════════════════════════════

/** Derive an AES-GCM key from the user's password using PBKDF2 */
async function deriveKeyFromPassword(password, email) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]
  );
  const salt = enc.encode(email + "_burnchat_salt");
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"]
  );
}

/** Generate keys, encrypt the private key with the password, and return both */
async function genAndRegisterKeys(password, email) {
  const kp = await crypto.subtle.generateKey(
    {name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'},
    true, ['encrypt','decrypt']
  );
  S.rsaPublicKey  = kp.publicKey;
  S.rsaPrivateKey = kp.privateKey;

  // Export Public Key
  const pubRaw = await crypto.subtle.exportKey('spki', kp.publicKey);
  const pubB64 = btoa(String.fromCharCode(...new Uint8Array(pubRaw)));

  // Export Private Key
  const privRaw = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
  const privB64 = btoa(String.fromCharCode(...new Uint8Array(privRaw)));
  localStorage.setItem('bc_priv_' + email, privB64);

  // Lock Private Key with Password-derived AES key
  const aesKey = await deriveKeyFromPassword(password, email);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedPriv = await crypto.subtle.encrypt({name: "AES-GCM", iv: iv}, aesKey, privRaw);

  // Combine IV + Ciphertext for storage
  const combined = new Uint8Array(iv.length + encryptedPriv.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encryptedPriv), iv.length);
  const encPrivB64 = btoa(String.fromCharCode(...combined));

  return { pubB64, encPrivB64 };
}

/** Load private key from localStorage and import it back into a CryptoKey. */
async function loadPrivateKey(email) {
  const privB64 = localStorage.getItem('bc_priv_' + email);
  if (!privB64) return null;
  try {
    const privRaw = Uint8Array.from(atob(privB64), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      'pkcs8', privRaw,
      {name:'RSA-OAEP', hash:'SHA-256'},
      false, ['decrypt']
    );
  } catch { return null; }
}

/** Import a recipient's public key from base64 SPKI. */
async function importPublicKey(pubB64) {
  const raw = Uint8Array.from(atob(pubB64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'spki', raw,
    {name:'RSA-OAEP', hash:'SHA-256'},
    false, ['encrypt']
  );
}

/**
 * Decrypt base64 RSA-OAEP ciphertext with the local private key.
 * Returns the plaintext string, or null on any failure.
 */
async function rsaDecrypt(cipherB64) {
  if (!S.rsaPrivateKey) return null;
  try {
    const dec = await crypto.subtle.decrypt(
      {name:'RSA-OAEP'},
      S.rsaPrivateKey,
      Uint8Array.from(atob(cipherB64), c => c.charCodeAt(0))
    );
    return new TextDecoder().decode(dec);
  } catch { return null; }
}

// ════════════════════════════════════════════════════════════════
//  Auth Flow
// ════════════════════════════════════════════════════════════════
function switchAuthTab(mode) {
  S.authMode = mode;
  $('tab-in').classList.toggle('active', mode==='login');
  $('tab-up').classList.toggle('active', mode==='signup');
  $('field-name').style.display   = mode==='signup' ? 'block' : 'none';
  $('field-ck-key').style.display = mode==='signup' ? 'block' : 'none';
  $('auth-btn').textContent = mode==='login' ? 'Sign in →' : 'Create account →';
  $('auth-err').textContent = '';
}

async function doAuth() {
  const email  = $('f-email').value.trim().toLowerCase();
  const pw     = $('f-pw').value;
  const name   = $('f-name').value.trim();
  const ckKey  = $('f-ck-key').value.trim();
  const err    = $('auth-err');
  const btn    = $('auth-btn');

  if (!email || !pw) { err.textContent = '⚠ Email and Password required'; return; }

  btn.disabled = true;
  err.textContent = '';

  let pubB64 = null;
  let encPrivB64 = null;

  if (S.authMode === 'signup') {
    try {
      const keys = await genAndRegisterKeys(pw, email);
      pubB64 = keys.pubB64;
      encPrivB64 = keys.encPrivB64;
    } catch(e) {
      err.textContent = '⚠ Key generation failed: ' + e.message;
      btn.disabled = false; return;
    }
  }

  const path = S.authMode === 'signup' ? '/auth/signup' : '/auth/login';
  const body = S.authMode === 'signup'
    ? {email, password:pw, name, chaoskey_api_key:ckKey, public_key:pubB64, encrypted_private_key:encPrivB64}
    : {email, password:pw};

  const {ok, data} = await api(path, {method:'POST', body:JSON.stringify(body)});
  if (ok) {
    S.me = {email:data.email, name:data.name, color:data.color};

    if (S.authMode === 'login') {
      S.rsaPrivateKey = await loadPrivateKey(email);

      // New device: no local key found — try to unwrap the server-side vault
      if (!S.rsaPrivateKey && data.encrypted_private_key) {
        try {
          const combined = Uint8Array.from(atob(data.encrypted_private_key), c => c.charCodeAt(0));
          const iv = combined.slice(0, 12);
          const ciphertext = combined.slice(12);

          const aesKey = await deriveKeyFromPassword(pw, email);
          const privRaw = await crypto.subtle.decrypt({name: "AES-GCM", iv: iv}, aesKey, ciphertext);

          S.rsaPrivateKey = await crypto.subtle.importKey(
            'pkcs8', privRaw, {name:'RSA-OAEP', hash:'SHA-256'}, false, ['decrypt']
          );

          // Cache in localStorage to avoid vault decryption on every page refresh
          const privB64 = btoa(String.fromCharCode(...new Uint8Array(privRaw)));
          localStorage.setItem('bc_priv_' + email, privB64);

          toast('🔑 RSA keys synced to new device', 'ok', 4000);
        } catch(e) {
          toast('⚠ Could not unwrap keys (wrong password?)', 'err', 5000);
        }
      }
    }

    enterApp(data);
  } else {
    err.textContent = '⚠ ' + (data.error || 'Authentication failed');
    btn.disabled = false;
  }
}

async function doLogout() {
  await api('/auth/logout', {method:'POST'});
  location.reload();
}

async function checkSession() {
  const {ok, data} = await api('/auth/me');
  if (ok && data.authenticated) {
    S.me = {email:data.email, name:data.name, color:data.color};
    S.rsaPrivateKey = await loadPrivateKey(data.email);
    enterApp(data);
  }
}

// ════════════════════════════════════════════════════════════════
//  App
// ════════════════════════════════════════════════════════════════
function enterApp(data={}) {
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');

  $('my-avatar').textContent = initials(S.me.name);
  $('my-avatar').style.background = S.me.color;
  $('my-name').textContent  = S.me.name;
  $('my-email').textContent = S.me.email;

  const hasCk = data.has_ck_key;
  if (hasCk && data.key_prefix) {
    $('ck-key-bar').style.display = 'flex';
    $('ck-key-prefix').textContent = data.key_prefix;
  } else if (!hasCk) {
    $('ck-key-warn').style.display = 'block';
  }

  if (S.rsaPrivateKey) {
    $('e2ee-status').style.display = 'flex';
  }

  loadInbox();
  S.pollTimer = setInterval(async () => {
    await loadInbox();
    if (S.activeContact) {
      $('messages-area').dataset.hash = '';
      await loadThread(S.activeContact.email, false);
    }
  }, 3000);
}

// ════════════════════════════════════════════════════════════════
//  Inbox / sidebar helpers
// ════════════════════════════════════════════════════════════════
async function loadInbox() {
  const {ok, data} = await api('/msg/inbox');
  if (!ok || !Array.isArray(data)) return;
  S.threads = data;
  renderThreadList();
}

function renderThreadList() {
  const el = $('thread-list');
  if (!S.threads.length) {
    el.innerHTML = `<div class="no-threads"><div class="nt-icon">🔒</div><div>No conversations yet.<br>Search for a user above.</div></div>`;
    return;
  }
  el.innerHTML = S.threads.map(t => `
    <div class="thread-item ${S.activeContact?.email === t.contact ? 'active' : ''}"
         onclick="openThread('${t.contact}','${esc(t.name)}','${t.color}')">
      <div class="avatar" style="background:${t.color}">${initials(t.name)}</div>
      <div class="thread-info">
        <div class="thread-name">${esc(t.name)}</div>
        <div class="thread-email">${esc(t.contact)}</div>
      </div>
      <div class="thread-time">${fmtDate(t.last_at)}</div>
    </div>`).join('');
}

async function onSearchInput(val) {
  const res = $('search-results');
  if (!val || val.length < 3) { res.classList.remove('open'); return; }
  const {ok, data} = await api('/msg/search_user?q=' + encodeURIComponent(val));
  if (!ok || !data.length) { res.classList.remove('open'); return; }
  res.innerHTML = data.map(u => `
    <div class="search-result-item" onclick="openThread('${u.email}','${esc(u.name)}','${u.color}')">
      <div class="avatar" style="background:${u.color};width:28px;height:28px;font-size:.75rem">${initials(u.name)}</div>
      <div class="sr-info">
        <div class="sr-name">${esc(u.name)}</div>
        <div class="sr-email">${esc(u.email)}</div>
      </div>
    </div>`).join('');
  res.classList.add('open');
}

function closeSearch() {
  $('search-results').classList.remove('open');
}

// ════════════════════════════════════════════════════════════════
//  Thread / messages
// ════════════════════════════════════════════════════════════════
function openThread(email, name, color) {
  S.activeContact = {email, name, color};
  $('contact-name').textContent  = name;
  $('contact-email').textContent = email;
  $('contact-avatar').textContent = initials(name);
  $('contact-avatar').style.background = color;

  $('enc-badge').textContent = S.rsaPrivateKey ? '⚿ ChaosKey + RSA-OAEP' : '⚿ ChaosKey AES-256';

  $('empty-state').style.display = 'none';
  $('chat-view').classList.add('active');

  $('search-input').value = '';
  closeSearch();
  renderThreadList();
  loadThread(email, true);
}

async function loadThread(email, scrollToBottom=true) {
  const {ok, data} = await api(`/msg/thread?with=${encodeURIComponent(email)}`);
  if (!ok || !Array.isArray(data)) return;

  const area = $('messages-area');
  const msgs = [];

  for (const m of data) {
    const mine = m.from === S.me.email;
    let text = null;
    let isError = false;

    if (!m.ciphertext || !m.nonce) {
      text = '[Missing encryption data]';
      isError = true;
    } else if (!S.rsaPrivateKey) {
      text = '[No RSA private key on this device — log in again to restore]';
      isError = true;
    } else {
      // ── FIX: Use the explicit rsa_wrapped flag, not a length heuristic ──
      let rawEncKey = null;

      if (m.rsa_wrapped) {
        // Key was RSA-OAEP wrapped by the server — decrypt it with our private key
        rawEncKey = await rsaDecrypt(m.rsa_enc_key);
        if (!rawEncKey) {
          text = mine
            ? '[Sent — key was encrypted for recipient only]'
            : '[RSA unwrap failed — key mismatch or different device session?]';
          isError = true;
        }
      } else {
        // Server stored the enc_key raw (no cryptography package at send time)
        rawEncKey = m.rsa_enc_key;
      }

      // Only call ChaosKey if we successfully resolved a raw enc_key
      if (!isError && rawEncKey) {
        const dr = await api('/msg/decrypt', {
          method: 'POST',
          body: JSON.stringify({msg_id: m.id, enc_key: rawEncKey}),
        });
        if (dr.ok) {
          text = dr.data.plaintext;
        } else {
          text = '[ChaosKey: ' + (dr.data.error || 'decryption failed') + ']';
          isError = true;
        }
      }
    }

    msgs.push({...m, resolved: text || '[empty]', isError});
  }

  let html = '';
  for (const m of msgs) {
    const mine = m.from === S.me.email;
    html += `
      <div class="msg-group ${mine ? 'mine' : 'theirs'}">
        <div class="bubble${m.isError ? ' error-bubble' : ''}">${esc(m.resolved)}</div>
        <div class="msg-meta">${fmtTime(m.sent_at)}</div>
        <div class="e2ee-tag">${m.rsa_wrapped ? '⚿ ChaosKey + RSA-OAEP' : '⚿ ChaosKey AES-256'}</div>
      </div>`;
  }

  const newHash = btoa(unescape(encodeURIComponent(html))).slice(0, 20);
  if (area.dataset.hash !== newHash) {
    area.innerHTML = html || `<div style="text-align:center;color:var(--dust);font-family:'Fira Code',monospace;font-size:.75rem;margin-top:2rem">No messages yet. Say something!</div>`;
    area.dataset.hash = newHash;
    if (scrollToBottom) area.scrollTop = area.scrollHeight;
  }
}

// ════════════════════════════════════════════════════════════════
//  Send
// ════════════════════════════════════════════════════════════════
async function sendMessage() {
  const inp = $('compose-input');
  const txt = inp.value.trim();
  if (!txt || !S.activeContact) return;

  const btn = $('send-btn');
  btn.disabled = true;

  const {ok, data} = await api('/msg/send', {
    method: 'POST',
    body: JSON.stringify({
      recipient: S.activeContact.email,
      plaintext: txt,
    }),
  });

  btn.disabled = false;

  if (!ok) {
    toast('✗ ' + (data.error || 'Send failed'), 'err');
    return;
  }

  inp.value = '';
  inp.style.height = 'auto';
  $('messages-area').dataset.hash = '';
  await loadThread(S.activeContact.email, true);
  await loadInbox();
}

// ════════════════════════════════════════════════════════════════
//  Burn thread
// ════════════════════════════════════════════════════════════════
function confirmBurn() {
  if (!S.activeContact) return;
  $('burn-modal-text').textContent =
    `Burn all messages with ${S.activeContact.name}? This cannot be undone.`;
  $('burn-modal').classList.add('open');
}
function closeBurnModal() { $('burn-modal').classList.remove('open'); }

async function executeBurn() {
  closeBurnModal();
  if (!S.activeContact) return;
  const {ok} = await api('/msg/burn', {
    method: 'POST',
    body: JSON.stringify({contact: S.activeContact.email}),
  });
  if (ok) {
    $('messages-area').innerHTML = '';
    $('messages-area').dataset.hash = '';
    toast('🔥 Thread burned', 'ok');
    await loadInbox();
  } else {
    toast('✗ Burn failed', 'err');
  }
}

// ════════════════════════════════════════════════════════════════
//  Update ChaosKey modal
// ════════════════════════════════════════════════════════════════
function showUpdateKeyModal() { $('key-modal').classList.add('open'); }
function closeKeyModal() {
  $('key-modal').classList.remove('open');
  $('key-modal-err').textContent = '';
  $('modal-ck-input').value = '';
}

async function saveUpdatedKey() {
  const val = $('modal-ck-input').value.trim();
  const errEl = $('key-modal-err');
  if (!val || !val.startsWith('ck_live_')) {
    errEl.textContent = '⚠ Key must start with ck_live_';
    return;
  }
  const {ok, data} = await api('/auth/update_ck_key', {
    method:'POST', body:JSON.stringify({chaoskey_api_key:val})
  });
  if (ok) {
    $('ck-key-prefix').textContent = data.key_prefix;
    $('ck-key-bar').style.display = 'flex';
    $('ck-key-warn').style.display = 'none';
    closeKeyModal();
    toast('⚿ ChaosKey API key updated', 'ok');
  } else {
    errEl.textContent = '⚠ ' + (data.error || 'Update failed');
  }
}

// ════════════════════════════════════════════════════════════════
//  Boot
// ════════════════════════════════════════════════════════════════
checkSession();
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML)


# ── Boot ──────────────────────────────────────────────────────────────────────
try:
    init_db()
except Exception as e:
    log.error(f"DB init failed: {e}")

if __name__ == "__main__":
    log.info(f"BurnChat starting on port {PORT}")
    log.info(f"ChaosKey URL: {CHAOSKEY_URL or '(not set)'}")
    log.info("Every message encrypted by ChaosKey; enc_key RSA-OAEP wrapped per recipient.")
    app.run(host="0.0.0.0", port=PORT, debug=False)
