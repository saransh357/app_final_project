"""
CryptoAPI — Key Issuance & Encryption-as-a-Service  (WebSocket Edition)
========================================================================
Manages customer accounts, API key minting, usage tracking,
and proxies encrypt/decrypt requests to the cloud WebSocket relay,
which forwards them to the local ws_bridge.py (key never leaves local machine).

Architecture:
  Customer → HTTP → [app.py] → HTTP → [cloud_relay.py] → WebSocket → [ws_bridge.py] → Key

Install:
    pip install flask flask-cors requests python-dotenv

Env vars (required in production):
    RELAY_URL       wss://your-relay.example.com  (HTTP URL for relay API)
    RELAY_TOKEN     same as BRIDGE_SECRET in cloud_relay / ws_bridge
    ADMIN_SECRET    your admin password
    DB_PATH         path to sqlite db (default: cryptoapi.db)
"""

import os
import sqlite3
import secrets
import hashlib
import hmac
import time
import json
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps

import requests
from flask import Flask, request, jsonify, g, abort
from flask_cors import CORS

# ── Config ────────────────────────────────────────────────────────────────────

RELAY_URL      = os.getenv("RELAY_URL",     "http://localhost:7000")   # cloud_relay HTTP URL
RELAY_TOKEN    = os.getenv("RELAY_TOKEN",   "")                        # == BRIDGE_SECRET
ADMIN_SECRET   = os.getenv("ADMIN_SECRET",  secrets.token_urlsafe(32))
DB_PATH        = os.getenv("DB_PATH",       "cryptoapi.db")

FREE_QUOTA_DAY = 100
PRO_QUOTA_DAY  = 10_000
KEY_PREFIX     = "ck_live_"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("CryptoAPI")

app = Flask("CryptoAPI")
CORS(app)

# ── Database ──────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT    UNIQUE NOT NULL,
    name        TEXT    NOT NULL,
    tier        TEXT    NOT NULL DEFAULT 'free',
    created_at  TEXT    NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    key_hash    TEXT    UNIQUE NOT NULL,
    key_prefix  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    revoked_at  TEXT,
    label       TEXT    DEFAULT 'default'
);

CREATE TABLE IF NOT EXISTS usage_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id      INTEGER NOT NULL REFERENCES api_keys(id),
    endpoint    TEXT    NOT NULL,
    ts          TEXT    NOT NULL,
    status      INTEGER NOT NULL,
    latency_ms  INTEGER
);

CREATE TABLE IF NOT EXISTS daily_counts (
    key_id      INTEGER NOT NULL REFERENCES api_keys(id),
    day         TEXT    NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, day)
);
"""

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

def init_db():
    with app.app_context():
        db = sqlite3.connect(DB_PATH)
        db.executescript(SCHEMA)
        db.commit()
        db.close()
        log.info(f"Database ready at {DB_PATH}")

# ── Key helpers ───────────────────────────────────────────────────────────────

def mint_key():
    raw    = KEY_PREFIX + secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    prefix = raw[:16] + "…"
    return raw, hashed, prefix

def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()

def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ── Auth middleware ───────────────────────────────────────────────────────────

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing Authorization header"}), 401

        raw_key = auth[7:]
        if not raw_key.startswith(KEY_PREFIX):
            return jsonify({"error": "Invalid key format"}), 401

        key_hash = hash_key(raw_key)
        db = get_db()

        row = db.execute("""
            SELECT k.id, k.customer_id, c.tier, c.active, k.revoked_at
            FROM api_keys k
            JOIN customers c ON c.id = k.customer_id
            WHERE k.key_hash = ?
        """, (key_hash,)).fetchone()

        if not row:
            return jsonify({"error": "Invalid API key"}), 401
        if row["revoked_at"]:
            return jsonify({"error": "API key has been revoked"}), 401
        if not row["active"]:
            return jsonify({"error": "Account suspended"}), 403

        quota   = FREE_QUOTA_DAY if row["tier"] == "free" else PRO_QUOTA_DAY
        day     = today()
        cnt_row = db.execute(
            "SELECT count FROM daily_counts WHERE key_id=? AND day=?",
            (row["id"], day)
        ).fetchone()
        current = cnt_row["count"] if cnt_row else 0

        if current >= quota:
            return jsonify({
                "error": "Daily quota exceeded",
                "quota": quota,
                "used":  current,
                "resets": f"{day}T00:00:00Z (next UTC midnight)"
            }), 429

        g.key_id      = row["id"]
        g.customer_id = row["customer_id"]
        g.tier        = row["tier"]
        g.t0          = time.monotonic()
        return f(*args, **kwargs)
    return decorated


def log_usage(endpoint: str, status: int):
    if not hasattr(g, "key_id"):
        return
    latency = int((time.monotonic() - g.t0) * 1000) if hasattr(g, "t0") else None
    db = get_db()
    db.execute("""
        INSERT INTO usage_log (key_id, endpoint, ts, status, latency_ms)
        VALUES (?, ?, ?, ?, ?)
    """, (g.key_id, endpoint, now_iso(), status, latency))
    db.execute("""
        INSERT INTO daily_counts (key_id, day, count) VALUES (?, ?, 1)
        ON CONFLICT(key_id, day) DO UPDATE SET count = count + 1
    """, (g.key_id, today()))
    db.commit()


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Admin-Secret", "")
        if not hmac.compare_digest(token, ADMIN_SECRET):
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Relay helper (routes to cloud_relay.py → ws_bridge.py → local key) ────────

def relay_request(path: str, method: str = "GET", body: dict = None):
    """
    Call the cloud relay's HTTP endpoints.
    The relay forwards the operation over WebSocket to the local bridge.
    Key material never travels beyond the bridge process.
    """
    if not RELAY_TOKEN:
        return None, {"error": "Relay not configured — set RELAY_TOKEN env var"}, 503

    headers = {
        "X-Relay-Token": RELAY_TOKEN,
        "Content-Type":  "application/json",
    }
    try:
        url  = RELAY_URL.rstrip("/") + path
        resp = requests.request(
            method, url, headers=headers,
            json=body, timeout=20
        )
        return resp, resp.json(), resp.status_code
    except requests.exceptions.ConnectionError:
        return None, {"error": "Cannot reach cloud relay"}, 503
    except Exception as e:
        return None, {"error": str(e)}, 500


# ── Customer self-service API ─────────────────────────────────────────────────

@app.route("/v1/register", methods=["POST"])
def register():
    body  = request.get_json(force=True) or {}
    email = (body.get("email") or "").strip().lower()
    name  = (body.get("name")  or "").strip()

    if not email or "@" not in email:
        return jsonify({"error": "Valid email required"}), 400
    if not name:
        return jsonify({"error": "Name required"}), 400

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO customers (email, name, created_at) VALUES (?, ?, ?)",
            (email, name, now_iso())
        )
        customer_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already registered"}), 409

    raw, key_hash, prefix = mint_key()
    db.execute("""
        INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at)
        VALUES (?, ?, ?, ?)
    """, (customer_id, key_hash, prefix, now_iso()))
    db.commit()

    log.info(f"New customer: {email}")
    return jsonify({
        "message":    "Account created",
        "email":      email,
        "api_key":    raw,
        "key_prefix": prefix,
        "tier":       "free",
        "quota":      f"{FREE_QUOTA_DAY} requests/day"
    }), 201


@app.route("/v1/keys", methods=["GET"])
@require_api_key
def list_keys():
    db   = get_db()
    rows = db.execute("""
        SELECT key_prefix, created_at, revoked_at, label
        FROM api_keys WHERE customer_id = ?
        ORDER BY created_at DESC
    """, (g.customer_id,)).fetchall()
    log_usage("/v1/keys", 200)
    return jsonify({"keys": [dict(r) for r in rows]})


@app.route("/v1/keys", methods=["POST"])
@require_api_key
def create_key():
    body  = request.get_json(force=True) or {}
    label = body.get("label", "secondary")
    raw, key_hash, prefix = mint_key()
    db = get_db()
    db.execute("""
        INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label)
        VALUES (?, ?, ?, ?, ?)
    """, (g.customer_id, key_hash, prefix, now_iso(), label))
    db.commit()
    log_usage("/v1/keys", 201)
    return jsonify({"api_key": raw, "key_prefix": prefix, "label": label}), 201


@app.route("/v1/keys/revoke", methods=["POST"])
@require_api_key
def revoke_key():
    body   = request.get_json(force=True) or {}
    prefix = body.get("key_prefix", "")
    db     = get_db()
    row = db.execute("""
        SELECT id FROM api_keys
        WHERE customer_id = ? AND key_prefix = ? AND revoked_at IS NULL
    """, (g.customer_id, prefix)).fetchone()
    if not row:
        return jsonify({"error": "Key not found or already revoked"}), 404
    db.execute("UPDATE api_keys SET revoked_at = ? WHERE id = ?", (now_iso(), row["id"]))
    db.commit()
    log_usage("/v1/keys/revoke", 200)
    return jsonify({"message": "Key revoked", "key_prefix": prefix})


@app.route("/v1/usage", methods=["GET"])
@require_api_key
def usage():
    db    = get_db()
    day   = today()
    quota = FREE_QUOTA_DAY if g.tier == "free" else PRO_QUOTA_DAY

    row = db.execute("""
        SELECT COALESCE(SUM(dc.count), 0) as total
        FROM daily_counts dc
        JOIN api_keys k ON k.id = dc.key_id
        WHERE k.customer_id = ? AND dc.day = ?
    """, (g.customer_id, day)).fetchone()

    history = db.execute("""
        SELECT dc.day, SUM(dc.count) as count
        FROM daily_counts dc
        JOIN api_keys k ON k.id = dc.key_id
        WHERE k.customer_id = ?
        GROUP BY dc.day ORDER BY dc.day DESC LIMIT 30
    """, (g.customer_id,)).fetchall()

    log_usage("/v1/usage", 200)
    return jsonify({
        "tier":       g.tier,
        "quota":      quota,
        "used_today": row["total"],
        "remaining":  max(0, quota - row["total"]),
        "resets":     f"{day} at UTC midnight",
        "history":    [dict(r) for r in history]
    })


# ── Encryption endpoints (proxied → relay → bridge → local key) ────────────────

@app.route("/v1/encrypt", methods=["POST"])
@require_api_key
def encrypt():
    body = request.get_json(force=True) or {}
    if "plaintext" not in body:
        return jsonify({"error": "Missing 'plaintext'"}), 400
    _, data, status = relay_request("/relay/encrypt", "POST", {"plaintext": body["plaintext"]})
    log_usage("/v1/encrypt", status)
    return jsonify(data), status


@app.route("/v1/decrypt", methods=["POST"])
@require_api_key
def decrypt():
    body = request.get_json(force=True) or {}
    if not {"ciphertext", "nonce"}.issubset(body):
        return jsonify({"error": "Missing ciphertext or nonce"}), 400
    _, data, status = relay_request("/relay/decrypt", "POST", {
        "ciphertext": body["ciphertext"],
        "nonce":      body["nonce"],
    })
    log_usage("/v1/decrypt", status)
    return jsonify(data), status


@app.route("/v1/status", methods=["GET"])
@require_api_key
def status():
    _, data, code = relay_request("/relay/status")
    log_usage("/v1/status", code)
    return jsonify(data), code


@app.route("/v1/key_info", methods=["GET"])
@require_api_key
def key_info():
    _, data, code = relay_request("/relay/key_info")
    log_usage("/v1/key_info", code)
    return jsonify(data), code


# ── Admin endpoints ───────────────────────────────────────────────────────────

@app.route("/admin/customers", methods=["GET"])
@require_admin
def admin_customers():
    db   = get_db()
    rows = db.execute("""
        SELECT c.id, c.email, c.name, c.tier, c.created_at, c.active,
               COUNT(k.id) as key_count
        FROM customers c
        LEFT JOIN api_keys k ON k.customer_id = c.id
        GROUP BY c.id ORDER BY c.created_at DESC
    """).fetchall()
    return jsonify({"customers": [dict(r) for r in rows]})


@app.route("/admin/customers/<int:cid>/tier", methods=["POST"])
@require_admin
def admin_set_tier(cid):
    body = request.get_json(force=True) or {}
    tier = body.get("tier", "free")
    if tier not in ("free", "pro"):
        return jsonify({"error": "tier must be free or pro"}), 400
    db = get_db()
    db.execute("UPDATE customers SET tier=? WHERE id=?", (tier, cid))
    db.commit()
    return jsonify({"message": f"Customer {cid} set to {tier}"})


@app.route("/admin/stats", methods=["GET"])
@require_admin
def admin_stats():
    db = get_db()
    stats = {
        "total_customers": db.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
        "active_keys":     db.execute("SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL").fetchone()[0],
        "requests_today":  db.execute("SELECT COALESCE(SUM(count),0) FROM daily_counts WHERE day=?", (today(),)).fetchone()[0],
        "requests_total":  db.execute("SELECT COUNT(*) FROM usage_log").fetchone()[0],
    }
    # Also get relay health
    _, relay_data, relay_code = relay_request("/health", method="GET")
    stats["relay"] = relay_data if relay_code == 200 else {"error": "relay unreachable"}
    return jsonify(stats)


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": now_iso()})


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    log.info(f"Admin secret : {ADMIN_SECRET}")
    log.info(f"Relay URL    : {RELAY_URL}")
    log.info(f"Relay token  : {'SET' if RELAY_TOKEN else 'NOT SET — set RELAY_TOKEN env var!'}")
    app.run(host="0.0.0.0", port=8000, debug=False)