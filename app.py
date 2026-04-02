"""
CryptoAPI — Key Issuance & Encryption-as-a-Service (Tunnel Edition)
Architecture: Customer → HTTP → [app.py (Render)] → HTTP → [Ngrok Tunnel] → [ws_bridge.py (Local)] → Key
"""
import os, sqlite3, secrets, hashlib, hmac, time, logging
from datetime import datetime, timezone
import requests
from flask import Flask, request, jsonify, g, abort, render_template_string
from flask_cors import CORS

RELAY_TOKEN       = os.getenv("RELAY_TOKEN", "60214a27a9f1ee39361b70b3fa8c98d6")
ADMIN_SECRET      = os.getenv("ADMIN_SECRET", "QWErty#1")
DB_PATH           = os.getenv("DB_PATH", "cryptoapi.db")
DYNAMIC_RELAY_URL = os.getenv("RELAY_URL", "")

FREE_QUOTA_DAY, PRO_QUOTA_DAY, KEY_PREFIX = 100, 10_000, "ck_live_"
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("CryptoAPI")

app = Flask("CryptoAPI")
CORS(app)

# Always return JSON errors — never HTML pages
@app.errorhandler(400)
def err400(e): return jsonify({"error": "Bad request", "detail": str(e)}), 400
@app.errorhandler(401)
def err401(e): return jsonify({"error": "Unauthorized"}), 401
@app.errorhandler(403)
def err403(e): return jsonify({"error": "Forbidden"}), 403
@app.errorhandler(404)
def err404(e): return jsonify({"error": "Not found"}), 404
@app.errorhandler(405)
def err405(e): return jsonify({"error": "Method not allowed"}), 405
@app.errorhandler(429)
def err429(e): return jsonify({"error": "Too many requests"}), 429
@app.errorhandler(500)
def err500(e): return jsonify({"error": "Internal server error", "detail": str(e)}), 500

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
        row = get_db().execute(
            "SELECT k.id, k.customer_id, c.tier, c.active, k.revoked_at FROM api_keys k JOIN customers c ON c.id = k.customer_id WHERE k.key_hash = ?",
            (key_hash,)
        ).fetchone()
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
    get_db().execute("INSERT INTO usage_log (key_id, endpoint, ts, status, latency_ms) VALUES (?, ?, ?, ?, ?)",
                     (g.key_id, endpoint, now_iso(), status, int((time.monotonic() - g.t0) * 1000)))
    get_db().execute("INSERT INTO daily_counts (key_id, day, count) VALUES (?, ?, 1) ON CONFLICT(key_id, day) DO UPDATE SET count = count + 1",
                     (g.key_id, today()))
    get_db().commit()

def relay_request(path: str, method: str = "GET", body: dict = None):
    if not DYNAMIC_RELAY_URL: return None, {"error": "Local engine offline — tunnel not connected"}, 503
    try:
        url = DYNAMIC_RELAY_URL.rstrip("/") + path
        resp = requests.request(method, url,
                                headers={"X-Relay-Token": RELAY_TOKEN, "Content-Type": "application/json"},
                                json=body, timeout=20)
        return resp, resp.json(), resp.status_code
    except Exception as e: return None, {"error": str(e)}, 500

# ── Admin endpoints ────────────────────────────────────────────────────────────

@app.route("/admin/set_relay", methods=["POST"])
def set_relay():
    if not hmac.compare_digest(request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET): abort(403)
    global DYNAMIC_RELAY_URL
    new_url = (request.get_json(force=True) or {}).get("url")
    if not new_url: return jsonify({"error": "Missing URL"}), 400
    DYNAMIC_RELAY_URL = new_url
    log.info(f"Relay dynamically updated to: {DYNAMIC_RELAY_URL}")
    return jsonify({"message": "Relay updated", "url": DYNAMIC_RELAY_URL})

@app.route("/admin/register", methods=["POST"])
def admin_register():
    """Admin-only: Register a new customer and issue an API key."""
    if not hmac.compare_digest(request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET): abort(403)
    body = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    name  = body.get("name", "").strip()
    tier  = body.get("tier", "free")
    if not email or not name: return jsonify({"error": "email and name required"}), 400
    if tier not in ("free", "pro"): return jsonify({"error": "tier must be free or pro"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO customers (email, name, tier, created_at) VALUES (?, ?, ?, ?)",
                   (email, name, tier, now_iso()))
        db.commit()
        cust = db.execute("SELECT id FROM customers WHERE email=?", (email,)).fetchone()
        raw_key, key_hash, key_prefix = mint_key()
        db.execute("INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at) VALUES (?, ?, ?, ?)",
                   (cust["id"], key_hash, key_prefix, now_iso()))
        db.commit()
        return jsonify({"message": "Customer registered", "api_key": raw_key,
                        "email": email, "name": name, "tier": tier}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already registered"}), 409

@app.route("/admin/customers", methods=["GET"])
def admin_customers():
    if not hmac.compare_digest(request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET): abort(403)
    rows = get_db().execute("""
        SELECT c.id, c.email, c.name, c.tier, c.active, c.created_at,
               COUNT(k.id) as key_count
        FROM customers c LEFT JOIN api_keys k ON k.customer_id = c.id
        GROUP BY c.id ORDER BY c.created_at DESC
    """).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/stats", methods=["GET"])
def admin_stats():
    if not hmac.compare_digest(request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET): abort(403)
    db = get_db()
    total_customers = db.execute("SELECT COUNT(*) FROM customers WHERE active=1").fetchone()[0]
    total_requests  = db.execute("SELECT COUNT(*) FROM usage_log").fetchone()[0]
    today_requests  = db.execute("SELECT SUM(count) FROM daily_counts WHERE day=?", (today(),)).fetchone()[0] or 0
    return jsonify({
        "total_customers": total_customers,
        "total_requests":  total_requests,
        "today_requests":  today_requests,
        "relay_active":    bool(DYNAMIC_RELAY_URL),
        "relay_url":       DYNAMIC_RELAY_URL or None,
    })

# ── Customer self-service ──────────────────────────────────────────────────────

@app.route("/v1/keys", methods=["POST"])
def issue_key():
    """Issue a new API key for an existing customer (authenticated by existing key)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): return jsonify({"error": "Missing Authorization header"}), 401
    key_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
    row = get_db().execute(
        "SELECT k.customer_id, k.revoked_at, c.active FROM api_keys k JOIN customers c ON c.id=k.customer_id WHERE k.key_hash=?",
        (key_hash,)
    ).fetchone()
    if not row or row["revoked_at"] or not row["active"]:
        return jsonify({"error": "Invalid or revoked API key"}), 401
    body = request.get_json(force=True) or {}
    label = body.get("label", "default")
    raw_key, new_hash, prefix = mint_key()
    get_db().execute("INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, ?)",
                     (row["customer_id"], new_hash, prefix, now_iso(), label))
    get_db().commit()
    return jsonify({"api_key": raw_key, "label": label,
                    "note": "Store this key safely — it won't be shown again."}), 201

@app.route("/v1/usage", methods=["GET"])
@require_api_key
def usage():
    db = get_db()
    today_count = db.execute("SELECT count FROM daily_counts WHERE key_id=? AND day=?",
                              (g.key_id, today())).fetchone()
    quota = FREE_QUOTA_DAY if g.tier == "free" else PRO_QUOTA_DAY
    recent = db.execute(
        "SELECT endpoint, ts, status, latency_ms FROM usage_log WHERE key_id=? ORDER BY id DESC LIMIT 20",
        (g.key_id,)
    ).fetchall()
    return jsonify({
        "tier": g.tier,
        "quota_today": quota,
        "used_today": today_count["count"] if today_count else 0,
        "remaining_today": quota - (today_count["count"] if today_count else 0),
        "recent_calls": [dict(r) for r in recent],
    })

# ── Crypto endpoints ───────────────────────────────────────────────────────────

@app.route("/v1/encrypt", methods=["POST"])
@require_api_key
def encrypt():
    body = request.get_json(force=True) or {}
    if "plaintext" not in body: return jsonify({"error": "Missing 'plaintext' field"}), 400
    _, data, status = relay_request("/relay/encrypt", "POST", {"plaintext": body.get("plaintext")})
    log_usage("/v1/encrypt", status)
    return jsonify(data), status

@app.route("/v1/decrypt", methods=["POST"])
@require_api_key
def decrypt():
    body = request.get_json(force=True) or {}
    if not {"ciphertext", "nonce"}.issubset(body): return jsonify({"error": "Missing ciphertext or nonce"}), 400
    _, data, status = relay_request("/relay/decrypt", "POST",
                                    {"ciphertext": body.get("ciphertext"), "nonce": body.get("nonce")})
    log_usage("/v1/decrypt", status)
    return jsonify(data), status

@app.route("/v1/status", methods=["GET"])
@require_api_key
def api_status():
    _, data, status = relay_request("/relay/status")
    return jsonify(data), status

# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "tunnel_active": bool(DYNAMIC_RELAY_URL)})

# ── Landing / Docs UI ─────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ChaosKey — Encryption API</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:      #050608;
  --surface: #0d0f14;
  --border:  #1a1e28;
  --muted:   #3a3f52;
  --text:    #c8cedd;
  --bright:  #f0f4ff;
  --green:   #00e5a0;
  --red:     #ff4d6d;
  --blue:    #4d8aff;
  --amber:   #ffb347;
  --purple:  #a78bfa;
  --glow-g:  rgba(0,229,160,0.15);
  --glow-b:  rgba(77,138,255,0.12);
}

html { scroll-behavior: smooth; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Syne', sans-serif;
  min-height: 100vh;
  overflow-x: hidden;
}

/* ── Grid noise texture ── */
body::before {
  content: '';
  position: fixed; inset: 0;
  background-image:
    linear-gradient(rgba(0,229,160,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,229,160,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none; z-index: 0;
}

/* ── Ambient orbs ── */
.orb {
  position: fixed; border-radius: 50%;
  filter: blur(120px); pointer-events: none; z-index: 0;
}
.orb-1 { width:600px; height:600px; top:-200px; left:-200px; background: radial-gradient(circle, rgba(0,229,160,0.07), transparent 70%); animation: drift1 18s ease-in-out infinite; }
.orb-2 { width:500px; height:500px; bottom:-100px; right:-100px; background: radial-gradient(circle, rgba(77,138,255,0.07), transparent 70%); animation: drift2 22s ease-in-out infinite; }

@keyframes drift1 { 0%,100%{transform:translate(0,0)} 50%{transform:translate(60px,40px)} }
@keyframes drift2 { 0%,100%{transform:translate(0,0)} 50%{transform:translate(-40px,-60px)} }

/* ── Layout ── */
.wrap { position: relative; z-index: 1; max-width: 1100px; margin: 0 auto; padding: 0 2rem; }

/* ── Nav ── */
nav {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1.5rem 2rem;
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 100;
  background: rgba(5,6,8,0.85);
  backdrop-filter: blur(16px);
}
.logo {
  display: flex; align-items: center; gap: 0.75rem;
  font-family: 'Space Mono', monospace;
  font-size: 1.1rem; font-weight: 700; color: var(--bright);
  letter-spacing: -0.02em;
}
.logo-icon {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, var(--green), var(--blue));
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  font-size: 16px;
}
.nav-pill {
  display: flex; align-items: center; gap: 0.5rem;
  padding: 0.4rem 1rem;
  border: 1px solid var(--border);
  border-radius: 100px;
  font-size: 0.8rem; font-family: 'Space Mono', monospace;
  color: var(--muted);
}
.status-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--muted);
  transition: background 0.3s, box-shadow 0.3s;
}
.status-dot.live { background: var(--green); box-shadow: 0 0 8px var(--green); }

/* ── Hero ── */
.hero {
  padding: 7rem 0 5rem;
  text-align: center;
  position: relative;
}
.hero-badge {
  display: inline-flex; align-items: center; gap: 0.5rem;
  padding: 0.4rem 1rem;
  border: 1px solid rgba(0,229,160,0.3);
  border-radius: 100px;
  background: rgba(0,229,160,0.06);
  font-family: 'Space Mono', monospace;
  font-size: 0.75rem; color: var(--green);
  margin-bottom: 2rem;
  letter-spacing: 0.05em;
}
h1 {
  font-size: clamp(3rem, 7vw, 5.5rem);
  font-weight: 800;
  line-height: 1.0;
  letter-spacing: -0.04em;
  color: var(--bright);
  margin-bottom: 1.5rem;
}
h1 span {
  background: linear-gradient(135deg, var(--green) 0%, var(--blue) 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.hero-sub {
  font-size: 1.1rem; line-height: 1.7;
  color: var(--muted); max-width: 560px; margin: 0 auto 3rem;
}
.cta-row { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }
.btn {
  padding: 0.85rem 2rem; border-radius: 8px;
  font-family: 'Syne', sans-serif; font-weight: 600; font-size: 0.95rem;
  cursor: pointer; border: none; text-decoration: none;
  display: inline-flex; align-items: center; gap: 0.5rem;
  transition: transform 0.15s, opacity 0.15s, box-shadow 0.15s;
}
.btn:hover { transform: translateY(-1px); opacity: 0.92; }
.btn-primary {
  background: linear-gradient(135deg, var(--green), #00c8a0);
  color: #000; box-shadow: 0 4px 20px rgba(0,229,160,0.25);
}
.btn-ghost {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text);
}
.btn-ghost:hover { border-color: var(--muted); }

/* ── Stats bar ── */
.stats-bar {
  display: grid; grid-template-columns: repeat(3, 1fr);
  gap: 1px; background: var(--border);
  border: 1px solid var(--border); border-radius: 12px;
  overflow: hidden; margin: 4rem 0;
}
.stat-cell {
  background: var(--surface);
  padding: 1.5rem 2rem;
  text-align: center;
}
.stat-num {
  font-family: 'Space Mono', monospace;
  font-size: 2rem; font-weight: 700;
  color: var(--bright);
}
.stat-label { font-size: 0.8rem; color: var(--muted); margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.08em; }

/* ── Section titles ── */
.section-label {
  font-family: 'Space Mono', monospace;
  font-size: 0.75rem; color: var(--green);
  letter-spacing: 0.12em; text-transform: uppercase;
  margin-bottom: 0.75rem;
}
.section-title {
  font-size: 2rem; font-weight: 700;
  color: var(--bright); letter-spacing: -0.03em;
  margin-bottom: 1rem;
}

/* ── Code block ── */
.code-wrap {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px; overflow: hidden;
  margin: 1.5rem 0;
}
.code-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0.75rem 1.25rem;
  border-bottom: 1px solid var(--border);
  background: rgba(255,255,255,0.02);
}
.code-dots { display: flex; gap: 6px; }
.code-dots span { width: 10px; height: 10px; border-radius: 50%; }
.d1{background:#ff5f57} .d2{background:#ffbd2e} .d3{background:#28c840}
.code-lang {
  font-family: 'Space Mono', monospace;
  font-size: 0.7rem; color: var(--muted); letter-spacing: 0.05em;
}
.copy-btn {
  font-family: 'Space Mono', monospace; font-size: 0.7rem;
  color: var(--muted); background: none; border: 1px solid var(--border);
  border-radius: 4px; padding: 0.2rem 0.6rem; cursor: pointer;
  transition: color 0.2s, border-color 0.2s;
}
.copy-btn:hover { color: var(--green); border-color: var(--green); }
.copy-btn.copied { color: var(--green); border-color: var(--green); }
pre {
  padding: 1.5rem;
  font-family: 'Space Mono', monospace;
  font-size: 0.82rem;
  line-height: 1.7;
  overflow-x: auto;
  color: var(--text);
}
.c-key { color: var(--blue); }
.c-str { color: var(--green); }
.c-cmt { color: var(--muted); font-style: italic; }
.c-meth { color: var(--amber); }
.c-num { color: var(--purple); }

/* ── Endpoint cards ── */
.endpoint-grid { display: flex; flex-direction: column; gap: 1rem; margin-top: 2rem; }
.endpoint-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px; overflow: hidden;
  transition: border-color 0.2s;
}
.endpoint-card:hover { border-color: var(--muted); }
.endpoint-header {
  display: flex; align-items: center; gap: 1rem;
  padding: 1rem 1.25rem; cursor: pointer;
}
.method-badge {
  font-family: 'Space Mono', monospace; font-size: 0.7rem; font-weight: 700;
  padding: 0.25rem 0.6rem; border-radius: 4px;
  letter-spacing: 0.05em; min-width: 48px; text-align: center;
}
.GET  { background: rgba(77,138,255,0.15); color: var(--blue); border: 1px solid rgba(77,138,255,0.3); }
.POST { background: rgba(0,229,160,0.12); color: var(--green); border: 1px solid rgba(0,229,160,0.25); }
.endpoint-path {
  font-family: 'Space Mono', monospace; font-size: 0.85rem; color: var(--bright);
}
.endpoint-desc { font-size: 0.85rem; color: var(--muted); margin-left: auto; }
.endpoint-body {
  display: none; padding: 0 1.25rem 1.25rem;
  border-top: 1px solid var(--border);
}
.endpoint-body.open { display: block; }

/* ── Tier cards ── */
.tier-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-top: 2rem; }
.tier-card {
  border-radius: 12px; padding: 2rem;
  border: 1px solid var(--border);
  background: var(--surface);
  position: relative; overflow: hidden;
}
.tier-card.pro {
  border-color: rgba(0,229,160,0.4);
  background: linear-gradient(135deg, rgba(0,229,160,0.06), rgba(77,138,255,0.04));
}
.tier-card.pro::before {
  content: 'RECOMMENDED';
  position: absolute; top: 1rem; right: -1.5rem;
  background: var(--green); color: #000;
  font-family: 'Space Mono', monospace; font-size: 0.6rem; font-weight: 700;
  padding: 0.25rem 2.5rem; transform: rotate(35deg);
  letter-spacing: 0.1em;
}
.tier-name { font-size: 1.5rem; font-weight: 700; color: var(--bright); margin-bottom: 0.5rem; }
.tier-price {
  font-family: 'Space Mono', monospace;
  font-size: 2.5rem; font-weight: 700; color: var(--green);
  margin: 1rem 0;
}
.tier-price small { font-size: 1rem; color: var(--muted); }
.tier-features { list-style: none; display: flex; flex-direction: column; gap: 0.6rem; margin-top: 1.5rem; }
.tier-features li {
  display: flex; align-items: center; gap: 0.75rem;
  font-size: 0.9rem; color: var(--text);
}
.tier-features li::before { content: '✓'; color: var(--green); font-weight: 700; }

/* ── Try it live ── */
.try-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-top: 2rem; }
.try-panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px; padding: 1.5rem;
}
.try-label { font-size: 0.75rem; color: var(--muted); font-family: 'Space Mono', monospace; margin-bottom: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }
textarea, input[type=text] {
  width: 100%; background: var(--bg);
  border: 1px solid var(--border); border-radius: 6px;
  color: var(--text); font-family: 'Space Mono', monospace; font-size: 0.82rem;
  padding: 0.75rem; resize: vertical;
  transition: border-color 0.2s;
}
textarea:focus, input[type=text]:focus { outline: none; border-color: var(--green); }
.try-btn {
  margin-top: 1rem; width: 100%;
  padding: 0.75rem; border-radius: 6px;
  background: linear-gradient(135deg, var(--green), #00c8a0);
  border: none; color: #000; font-family: 'Syne', sans-serif;
  font-weight: 700; font-size: 0.9rem; cursor: pointer;
  transition: transform 0.15s, opacity 0.15s;
}
.try-btn:hover { transform: translateY(-1px); opacity: 0.9; }
.try-btn:disabled { opacity: 0.4; cursor: not-allowed; transform: none; }
.try-output {
  margin-top: 1rem; padding: 0.75rem;
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  font-family: 'Space Mono', monospace; font-size: 0.75rem;
  min-height: 80px; color: var(--text); white-space: pre-wrap;
  word-break: break-all; line-height: 1.5;
}
.try-output.success { border-color: rgba(0,229,160,0.4); color: var(--green); }
.try-output.error   { border-color: rgba(255,77,109,0.4); color: var(--red); }

/* ── Footer ── */
footer {
  margin-top: 8rem; padding: 3rem 2rem;
  border-top: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  color: var(--muted); font-size: 0.85rem;
}
.footer-note { font-family: 'Space Mono', monospace; font-size: 0.7rem; color: var(--border); }

/* ── Scroll reveal ── */
.reveal { opacity: 0; transform: translateY(24px); transition: opacity 0.6s, transform 0.6s; }
.reveal.visible { opacity: 1; transform: none; }

/* ── Responsiveness ── */
@media (max-width: 700px) {
  .tier-grid, .try-grid { grid-template-columns: 1fr; }
  .stats-bar { grid-template-columns: 1fr; }
  h1 { font-size: 2.8rem; }
  nav { padding: 1rem; }
}
</style>
</head>
<body>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>

<nav>
  <div class="logo">
    <div class="logo-icon">🔑</div>
    ChaosKey
  </div>
  <div class="nav-pill">
    <div class="status-dot" id="nav-status-dot"></div>
    <span id="nav-status-text" style="font-size:0.75rem">checking...</span>
  </div>
</nav>

<div class="wrap">

  <!-- Hero -->
  <section class="hero">
    <div class="hero-badge">⚡ Physical Entropy · AES-256-GCM · Zero Key Exposure</div>
    <h1>Encryption Keys<br>from <span>Physical Chaos</span></h1>
    <p class="hero-sub">
      Keys derived from real-world motion and audio entropy — never stored in the cloud.
      Your data stays yours. Our key never leaves the machine.
    </p>
    <div class="cta-row">
      <a href="#try" class="btn btn-primary">Try the API →</a>
      <a href="#docs" class="btn btn-ghost">View Docs</a>
    </div>
  </section>

  <!-- Stats -->
  <div class="stats-bar reveal">
    <div class="stat-cell">
      <div class="stat-num" id="stat-customers">—</div>
      <div class="stat-label">Active Customers</div>
    </div>
    <div class="stat-cell">
      <div class="stat-num" id="stat-today">—</div>
      <div class="stat-label">API Calls Today</div>
    </div>
    <div class="stat-cell">
      <div class="stat-num">256</div>
      <div class="stat-label">Bit Key Strength</div>
    </div>
  </div>

  <!-- Quickstart -->
  <section id="docs" style="padding: 4rem 0;" class="reveal">
    <div class="section-label">Quickstart</div>
    <div class="section-title">Two calls. That's it.</div>
    <p style="color:var(--muted); margin-bottom:1.5rem; line-height:1.7">
      Authenticate with your Bearer token, send plaintext, get AES-256-GCM ciphertext back.
      Decryption is the same key — symmetric and stateless.
    </p>

    <div class="code-wrap">
      <div class="code-header">
        <div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div>
        <span class="code-lang">SHELL · Encrypt</span>
        <button class="copy-btn" onclick="copyCode(this, 'enc-code')">copy</button>
      </div>
      <pre id="enc-code"><span class="c-meth">curl</span> <span class="c-key">-X POST</span> https://your-api.onrender.com/v1/encrypt \
  <span class="c-key">-H</span> <span class="c-str">"Authorization: Bearer ck_live_YOUR_KEY"</span> \
  <span class="c-key">-H</span> <span class="c-str">"Content-Type: application/json"</span> \
  <span class="c-key">-d</span> <span class="c-str">'{"plaintext": "Hello, World!"}'</span>

<span class="c-cmt"># Response</span>
{
  <span class="c-key">"ciphertext"</span>: <span class="c-str">"base64-encoded-ciphertext"</span>,
  <span class="c-key">"nonce"</span>:      <span class="c-str">"base64-encoded-nonce"</span>,
  <span class="c-key">"algorithm"</span>:  <span class="c-str">"AES-256-GCM"</span>
}</pre>
    </div>

    <div class="code-wrap">
      <div class="code-header">
        <div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div>
        <span class="code-lang">SHELL · Decrypt</span>
        <button class="copy-btn" onclick="copyCode(this, 'dec-code')">copy</button>
      </div>
      <pre id="dec-code"><span class="c-meth">curl</span> <span class="c-key">-X POST</span> https://your-api.onrender.com/v1/decrypt \
  <span class="c-key">-H</span> <span class="c-str">"Authorization: Bearer ck_live_YOUR_KEY"</span> \
  <span class="c-key">-H</span> <span class="c-str">"Content-Type: application/json"</span> \
  <span class="c-key">-d</span> <span class="c-str">'{"ciphertext": "...", "nonce": "..."}'</span>

<span class="c-cmt"># Response</span>
{
  <span class="c-key">"plaintext"</span>: <span class="c-str">"Hello, World!"</span>
}</pre>
    </div>

    <div class="code-wrap">
      <div class="code-header">
        <div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div>
        <span class="code-lang">PYTHON · SDK-style</span>
        <button class="copy-btn" onclick="copyCode(this, 'py-code')">copy</button>
      </div>
      <pre id="py-code"><span class="c-key">import</span> requests

BASE  = <span class="c-str">"https://your-api.onrender.com"</span>
TOKEN = <span class="c-str">"ck_live_YOUR_KEY"</span>
HDR   = {<span class="c-str">"Authorization"</span>: <span class="c-str">f"Bearer {TOKEN}"</span>}

<span class="c-cmt"># Encrypt</span>
enc = requests.<span class="c-meth">post</span>(f<span class="c-str">"{BASE}/v1/encrypt"</span>, headers=HDR,
      json={<span class="c-str">"plaintext"</span>: <span class="c-str">"my secret data"</span>}).json()
print(enc[<span class="c-str">"ciphertext"</span>], enc[<span class="c-str">"nonce"</span>])

<span class="c-cmt"># Decrypt</span>
plain = requests.<span class="c-meth">post</span>(f<span class="c-str">"{BASE}/v1/decrypt"</span>, headers=HDR, json={
    <span class="c-str">"ciphertext"</span>: enc[<span class="c-str">"ciphertext"</span>],
    <span class="c-str">"nonce"</span>:      enc[<span class="c-str">"nonce"</span>]
}).json()
print(plain[<span class="c-str">"plaintext"</span>])  <span class="c-cmt"># → "my secret data"</span></pre>
    </div>
  </section>

  <!-- Endpoints reference -->
  <section style="padding: 4rem 0;" class="reveal">
    <div class="section-label">Reference</div>
    <div class="section-title">All Endpoints</div>

    <div class="endpoint-grid">
      <!-- POST /v1/encrypt -->
      <div class="endpoint-card">
        <div class="endpoint-header" onclick="toggleEndpoint(this)">
          <span class="method-badge POST">POST</span>
          <span class="endpoint-path">/v1/encrypt</span>
          <span class="endpoint-desc">AES-256-GCM encrypt</span>
        </div>
        <div class="endpoint-body">
          <p style="color:var(--muted);font-size:0.85rem;margin-bottom:1rem;">Encrypt a plaintext string using the chaos-derived AES-256-GCM key. Requires Bearer auth.</p>
          <div class="code-wrap"><div class="code-header"><div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="code-lang">REQUEST BODY</span></div>
          <pre>{ <span class="c-key">"plaintext"</span>: <span class="c-str">"string"</span> }</pre></div>
          <div class="code-wrap"><div class="code-header"><div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="code-lang">RESPONSE 200</span></div>
          <pre>{ <span class="c-key">"ciphertext"</span>: <span class="c-str">"base64"</span>, <span class="c-key">"nonce"</span>: <span class="c-str">"base64"</span>, <span class="c-key">"algorithm"</span>: <span class="c-str">"AES-256-GCM"</span> }</pre></div>
        </div>
      </div>

      <!-- POST /v1/decrypt -->
      <div class="endpoint-card">
        <div class="endpoint-header" onclick="toggleEndpoint(this)">
          <span class="method-badge POST">POST</span>
          <span class="endpoint-path">/v1/decrypt</span>
          <span class="endpoint-desc">AES-256-GCM decrypt</span>
        </div>
        <div class="endpoint-body">
          <p style="color:var(--muted);font-size:0.85rem;margin-bottom:1rem;">Decrypt a ciphertext using the stored nonce. Both fields required.</p>
          <div class="code-wrap"><div class="code-header"><div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="code-lang">REQUEST BODY</span></div>
          <pre>{ <span class="c-key">"ciphertext"</span>: <span class="c-str">"base64"</span>, <span class="c-key">"nonce"</span>: <span class="c-str">"base64"</span> }</pre></div>
          <div class="code-wrap"><div class="code-header"><div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="code-lang">RESPONSE 200</span></div>
          <pre>{ <span class="c-key">"plaintext"</span>: <span class="c-str">"string"</span> }</pre></div>
        </div>
      </div>

      <!-- GET /v1/usage -->
      <div class="endpoint-card">
        <div class="endpoint-header" onclick="toggleEndpoint(this)">
          <span class="method-badge GET">GET</span>
          <span class="endpoint-path">/v1/usage</span>
          <span class="endpoint-desc">Quota & call history</span>
        </div>
        <div class="endpoint-body">
          <p style="color:var(--muted);font-size:0.85rem;margin-bottom:1rem;">Returns current usage, tier limits, and last 20 API calls for your key.</p>
          <div class="code-wrap"><div class="code-header"><div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="code-lang">RESPONSE 200</span></div>
          <pre>{ <span class="c-key">"tier"</span>: <span class="c-str">"free"</span>, <span class="c-key">"quota_today"</span>: <span class="c-num">100</span>, <span class="c-key">"used_today"</span>: <span class="c-num">12</span>,
  <span class="c-key">"remaining_today"</span>: <span class="c-num">88</span>, <span class="c-key">"recent_calls"</span>: [ ... ] }</pre></div>
        </div>
      </div>

      <!-- GET /v1/status -->
      <div class="endpoint-card">
        <div class="endpoint-header" onclick="toggleEndpoint(this)">
          <span class="method-badge GET">GET</span>
          <span class="endpoint-path">/v1/status</span>
          <span class="endpoint-desc">Engine health check</span>
        </div>
        <div class="endpoint-body">
          <p style="color:var(--muted);font-size:0.85rem;margin-bottom:1rem;">Check whether the local encryption engine is online and the chaos key is ready.</p>
          <div class="code-wrap"><div class="code-header"><div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="code-lang">RESPONSE 200</span></div>
          <pre>{ <span class="c-key">"status"</span>: <span class="c-str">"ok"</span>, <span class="c-key">"bridge"</span>: <span class="c-str">"online"</span> }</pre></div>
        </div>
      </div>

      <!-- POST /v1/keys -->
      <div class="endpoint-card">
        <div class="endpoint-header" onclick="toggleEndpoint(this)">
          <span class="method-badge POST">POST</span>
          <span class="endpoint-path">/v1/keys</span>
          <span class="endpoint-desc">Issue additional API key</span>
        </div>
        <div class="endpoint-body">
          <p style="color:var(--muted);font-size:0.85rem;margin-bottom:1rem;">Issue a second API key under your account (e.g. for different environments). Authenticate with an existing valid key.</p>
          <div class="code-wrap"><div class="code-header"><div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="code-lang">REQUEST BODY</span></div>
          <pre>{ <span class="c-key">"label"</span>: <span class="c-str">"production"</span> }</pre></div>
          <div class="code-wrap"><div class="code-header"><div class="code-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="code-lang">RESPONSE 201</span></div>
          <pre>{ <span class="c-key">"api_key"</span>: <span class="c-str">"ck_live_..."</span>, <span class="c-key">"label"</span>: <span class="c-str">"production"</span> }</pre></div>
        </div>
      </div>
    </div>
  </section>

  <!-- Pricing -->
  <section style="padding: 4rem 0;" class="reveal">
    <div class="section-label">Pricing</div>
    <div class="section-title">Simple, honest tiers.</div>
    <div class="tier-grid">
      <div class="tier-card">
        <div class="tier-name">Free</div>
        <div class="tier-price">$0 <small>/ month</small></div>
        <ul class="tier-features">
          <li>100 API calls / day</li>
          <li>AES-256-GCM encryption</li>
          <li>JSON REST API</li>
          <li>Usage analytics</li>
        </ul>
      </div>
      <div class="tier-card pro">
        <div class="tier-name">Pro</div>
        <div class="tier-price">$29 <small>/ month</small></div>
        <ul class="tier-features">
          <li>10,000 API calls / day</li>
          <li>AES-256-GCM encryption</li>
          <li>Priority routing</li>
          <li>Multiple API keys</li>
          <li>Full call history</li>
        </ul>
      </div>
    </div>
  </section>

  <!-- Try it live -->
  <section id="try" style="padding: 4rem 0;" class="reveal">
    <div class="section-label">Interactive</div>
    <div class="section-title">Try it live.</div>
    <p style="color:var(--muted); margin-bottom:1.5rem; font-size:0.9rem;">
      Test encrypt &amp; decrypt right here. Enter your key once — it stays for the session.
    </p>

    <div id="key-entry-row" style="margin-bottom:1.25rem;">
      <div style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap;">
        <input type="text" id="live-key-input" placeholder="Paste your API key (ck_live_…)"
               autocomplete="off" spellcheck="false"
               style="flex:1;min-width:240px;font-family:Space Mono,monospace;font-size:0.82rem;"
               onkeydown="if(event.key==='Enter')saveKey()">
        <button class="btn btn-primary" style="padding:0.6rem 1.25rem;font-size:0.85rem;white-space:nowrap;"
                onclick="saveKey()">Use this key &#8594;</button>
      </div>
      <p style="font-size:0.75rem;color:var(--muted);margin-top:0.5rem;">
        No key yet? Ask an admin or use the <span style="color:var(--green);font-family:monospace">/admin/register</span> endpoint.
      </p>
    </div>

    <div id="key-active-row" style="display:none;margin-bottom:1.25rem;">
      <div style="display:inline-flex;align-items:center;gap:0.75rem;padding:0.6rem 1rem;
                  background:rgba(0,229,160,0.07);border:1px solid rgba(0,229,160,0.25);border-radius:8px;">
        <div style="width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);flex-shrink:0;"></div>
        <span style="font-family:Space Mono,monospace;font-size:0.78rem;color:var(--green);" id="key-active-label">ck_live_…</span>
        <button onclick="clearKey()"
                style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:0.75rem;padding:0 0.25rem;">
          &#x2715; change
        </button>
      </div>
    </div>

    <div class="try-grid">
      <div class="try-panel">
        <div class="try-label">Encrypt</div>
        <textarea id="enc-plain" rows="4" placeholder="Enter text to encrypt…">Hello, ChaosKey!</textarea>
        <button class="try-btn" onclick="liveEncrypt()">Encrypt &#8594;</button>
        <div class="try-output" id="enc-out">Enter your API key above, then click Encrypt.</div>
      </div>
      <div class="try-panel">
        <div class="try-label">Decrypt</div>
        <textarea id="dec-cipher" rows="4" placeholder="Encrypt something — the result auto-fills here."></textarea>
        <button class="try-btn" onclick="liveDecrypt()">Decrypt &#8594;</button>
        <div class="try-output" id="dec-out">Decrypted text will appear here.</div>
      </div>
    </div>
  </section>

</div><!-- /wrap -->

<footer>
  <div class="logo" style="font-size:0.9rem;">
    <div class="logo-icon" style="width:24px;height:24px;font-size:12px;">🔑</div>
    ChaosKey API
  </div>
  <div class="footer-note">Physical entropy. Zero cloud key storage.</div>
</footer>

<script>
// ── Status poll ────────────────────────────────────────────────────────────────
async function pollStatus() {
  try {
    const r = await fetch('/health');
    const d = await r.json();
    const dot  = document.getElementById('nav-status-dot');
    const text = document.getElementById('nav-status-text');
    if (d.tunnel_active) {
      dot.classList.add('live');
      text.textContent = 'Engine Online';
    } else {
      dot.classList.remove('live');
      text.textContent = 'Engine Offline';
    }
  } catch(e) {}
  try {
    const r = await fetch('/admin/stats', { headers: { 'X-Admin-Secret': '' } });
    if (r.ok) {
      const d = await r.json();
      document.getElementById('stat-customers').textContent = d.total_customers;
      document.getElementById('stat-today').textContent     = d.today_requests;
    }
  } catch(e) {}
}
pollStatus(); setInterval(pollStatus, 5000);

// ── Endpoint accordion ─────────────────────────────────────────────────────────
function toggleEndpoint(header) {
  const body = header.nextElementSibling;
  body.classList.toggle('open');
}

// ── Copy code ──────────────────────────────────────────────────────────────────
function copyCode(btn, id) {
  const el = document.getElementById(id);
  navigator.clipboard.writeText(el.innerText).then(() => {
    btn.textContent = 'copied!'; btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 2000);
  });
}

// ── API key persistence (session only — never written to disk) ─────────────────
let _apiKey = sessionStorage.getItem('ck_api_key') || '';

function saveKey() {
  const val = document.getElementById('live-key-input').value.trim();
  if (!val) return;
  _apiKey = val;
  sessionStorage.setItem('ck_api_key', val);
  renderKeyState();
}

function clearKey() {
  _apiKey = '';
  sessionStorage.removeItem('ck_api_key');
  renderKeyState();
}

function renderKeyState() {
  const entryRow  = document.getElementById('key-entry-row');
  const activeRow = document.getElementById('key-active-row');
  const label     = document.getElementById('key-active-label');
  if (_apiKey) {
    entryRow.style.display  = 'none';
    activeRow.style.display = 'block';
    // Show first 16 chars + ellipsis so the key isn't fully exposed
    label.textContent = _apiKey.length > 20 ? _apiKey.slice(0, 20) + '…' : _apiKey;
  } else {
    entryRow.style.display  = 'block';
    activeRow.style.display = 'none';
    document.getElementById('live-key-input').value = '';
  }
}

// Restore on page load
renderKeyState();

// ── Live API tester ────────────────────────────────────────────────────────────

// Safe fetch — never blindly calls .json(); handles HTML error pages gracefully
async function apiFetch(path, options) {
  const r  = await fetch(path, options);
  const ct = r.headers.get('Content-Type') || '';
  let data;
  if (ct.includes('application/json')) {
    data = await r.json();
  } else {
    const txt   = await r.text();
    const match = txt.match(/<title>([^<]*)<\/title>/i);
    data = { error: match ? match[1] : 'HTTP ' + r.status + ' — server returned a non-JSON response' };
  }
  return { ok: r.ok, status: r.status, data };
}

async function liveEncrypt() {
  const out   = document.getElementById('enc-out');
  const plain = document.getElementById('enc-plain').value.trim();
  if (!_apiKey) { out.textContent = '⚠ Enter your API key above first.'; out.className = 'try-output error'; return; }
  if (!plain)   { out.textContent = '⚠ Enter some text to encrypt.';     out.className = 'try-output error'; return; }
  out.className = 'try-output'; out.textContent = 'Encrypting…';
  try {
    const { ok, data } = await apiFetch('/v1/encrypt', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + _apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ plaintext: plain })
    });
    if (ok) {
      document.getElementById('dec-cipher').value = JSON.stringify(data, null, 2);
      out.className = 'try-output success';
      out.textContent = JSON.stringify(data, null, 2);
    } else {
      out.className = 'try-output error';
      out.textContent = '✗ ' + (data.error || JSON.stringify(data, null, 2));
    }
  } catch(e) { out.className = 'try-output error'; out.textContent = '✗ Network error: ' + String(e); }
}

async function liveDecrypt() {
  const out = document.getElementById('dec-out');
  const raw = document.getElementById('dec-cipher').value.trim();
  if (!_apiKey) { out.textContent = '⚠ Enter your API key above first.'; out.className = 'try-output error'; return; }
  if (!raw)     { out.textContent = '⚠ Encrypt something first, or paste JSON with ciphertext + nonce.'; out.className = 'try-output error'; return; }
  let body;
  try { body = JSON.parse(raw); }
  catch(e) { out.className = 'try-output error'; out.textContent = '✗ Invalid JSON — paste the full encrypt response here.'; return; }
  if (!body.ciphertext || !body.nonce) {
    out.className = 'try-output error';
    out.textContent = '✗ JSON must contain both "ciphertext" and "nonce" fields.';
    return;
  }
  out.className = 'try-output'; out.textContent = 'Decrypting…';
  try {
    const { ok, data } = await apiFetch('/v1/decrypt', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + _apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ciphertext: body.ciphertext, nonce: body.nonce })
    });
    if (ok) {
      out.className = 'try-output success';
      out.textContent = data.plaintext ?? JSON.stringify(data, null, 2);
    } else {
      out.className = 'try-output error';
      out.textContent = '✗ ' + (data.error || JSON.stringify(data, null, 2));
    }
  } catch(e) { out.className = 'try-output error'; out.textContent = '✗ Network error: ' + String(e); }
}

// ── Scroll reveal ──────────────────────────────────────────────────────────────
const obs = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); obs.unobserve(e.target); } });
}, { threshold: 0.08 });
document.querySelectorAll('.reveal').forEach(el => obs.observe(el));
</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000, debug=False)
