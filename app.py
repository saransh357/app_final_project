"""
CryptoAPI — Key Issuance & Encryption-as-a-Service (Tunnel Edition)
Architecture: Customer → HTTP → [app.py (Render)] → HTTP → [Ngrok Tunnel] → [ws_bridge.py (Local)] → Key
"""
import os, sqlite3, secrets, hashlib, hmac, time, logging
from datetime import datetime, timezone
import requests
from flask import Flask, request, jsonify, g, abort
from flask_cors import CORS

RELAY_TOKEN       = os.getenv("RELAY_TOKEN", "60214a27a9f1ee39361b70b3fa8c98d6")
ADMIN_SECRET      = os.getenv("ADMIN_SECRET", "QWErty#1")
DB_PATH           = os.getenv("DB_PATH", "cryptoapi.db")
DYNAMIC_RELAY_URL = os.getenv("RELAY_URL", "") # Updated dynamically by the launcher

FREE_QUOTA_DAY, PRO_QUOTA_DAY, KEY_PREFIX = 100, 10_000, "ck_live_"
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("CryptoAPI")

app = Flask("CryptoAPI")
CORS(app)

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, tier TEXT NOT NULL DEFAULT 'free', created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER NOT NULL REFERENCES customers(id), key_hash TEXT UNIQUE NOT NULL, key_prefix TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT, label TEXT DEFAULT 'default');
CREATE TABLE IF NOT EXISTS usage_log (id INTEGER PRIMARY KEY AUTOINCREMENT, key_id INTEGER NOT NULL REFERENCES api_keys(id), endpoint TEXT NOT NULL, ts TEXT NOT NULL, status INTEGER NOT NULL, latency_ms INTEGER);
CREATE TABLE IF NOT EXISTS daily_counts (key_id INTEGER NOT NULL REFERENCES api_keys(id), day TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (key_id, day));
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
    if db: db.close()

def init_db():
    with app.app_context():
        db = sqlite3.connect(DB_PATH)
        db.executescript(SCHEMA)
        db.commit()

def mint_key():
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest(), raw[:16] + "…"

def today(): return datetime.now(timezone.utc).strftime("%Y-%m-%d")
def now_iso(): return datetime.now(timezone.utc).isoformat()

def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "): return jsonify({"error": "Missing Authorization header"}), 401
        key_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
        
        row = get_db().execute("SELECT k.id, k.customer_id, c.tier, c.active, k.revoked_at FROM api_keys k JOIN customers c ON c.id = k.customer_id WHERE k.key_hash = ?", (key_hash,)).fetchone()
        
        if not row: return jsonify({"error": "Invalid API key"}), 401
        if row["revoked_at"]: return jsonify({"error": "API key revoked"}), 401
        if not row["active"]: return jsonify({"error": "Account suspended"}), 403

        quota = FREE_QUOTA_DAY if row["tier"] == "free" else PRO_QUOTA_DAY
        cnt_row = get_db().execute("SELECT count FROM daily_counts WHERE key_id=? AND day=?", (row["id"], today())).fetchone()
        if (cnt_row["count"] if cnt_row else 0) >= quota: return jsonify({"error": "Daily quota exceeded"}), 429

        g.key_id, g.customer_id, g.tier, g.t0 = row["id"], row["customer_id"], row["tier"], time.monotonic()
        return f(*args, **kwargs)
    return decorated

def log_usage(endpoint: str, status: int):
    if not hasattr(g, "key_id"): return
    get_db().execute("INSERT INTO usage_log (key_id, endpoint, ts, status, latency_ms) VALUES (?, ?, ?, ?, ?)", (g.key_id, endpoint, now_iso(), status, int((time.monotonic() - g.t0) * 1000)))
    get_db().execute("INSERT INTO daily_counts (key_id, day, count) VALUES (?, ?, 1) ON CONFLICT(key_id, day) DO UPDATE SET count = count + 1", (g.key_id, today()))
    get_db().commit()

# ── Tunnel Proxy Logic ────────────────────────────────────────────────────────
def relay_request(path: str, method: str = "GET", body: dict = None):
    if not DYNAMIC_RELAY_URL: return None, {"error": "Local engine offline (No tunnel URL set)"}, 503
    try:
        url = DYNAMIC_RELAY_URL.rstrip("/") + path
        resp = requests.request(method, url, headers={"X-Relay-Token": RELAY_TOKEN, "Content-Type": "application/json"}, json=body, timeout=20)
        return resp, resp.json(), resp.status_code
    except Exception as e: return None, {"error": str(e)}, 500

# ── Dynamic Tunnel Routing (Called by Launcher) ────────────────────────────────
@app.route("/admin/set_relay", methods=["POST"])
def set_relay():
    if not hmac.compare_digest(request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET): abort(403)
    global DYNAMIC_RELAY_URL
    new_url = (request.get_json(force=True) or {}).get("url")
    if not new_url: return jsonify({"error": "Missing URL"}), 400
    DYNAMIC_RELAY_URL = new_url
    log.info(f"Relay dynamically updated to: {DYNAMIC_RELAY_URL}")
    return jsonify({"message": "Relay updated", "url": DYNAMIC_RELAY_URL})

# ── Customer API ──────────────────────────────────────────────────────────────
@app.route("/v1/encrypt", methods=["POST"])
@require_api_key
def encrypt():
    body = request.get_json(force=True) or {}
    _, data, status = relay_request("/relay/encrypt", "POST", {"plaintext": body.get("plaintext")})
    log_usage("/v1/encrypt", status)
    return jsonify(data), status

@app.route("/v1/decrypt", methods=["POST"])
@require_api_key
def decrypt():
    body = request.get_json(force=True) or {}
    _, data, status = relay_request("/relay/decrypt", "POST", {"ciphertext": body.get("ciphertext"), "nonce": body.get("nonce")})
    log_usage("/v1/decrypt", status)
    return jsonify(data), status

@app.route("/health")
def health(): return jsonify({"status": "ok", "tunnel_active": bool(DYNAMIC_RELAY_URL)})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
