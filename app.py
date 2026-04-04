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

def relay_request(path: str, method: str = "GET", body: dict = None):
    if not DYNAMIC_RELAY_URL: return None, {"error": "Local engine offline — tunnel not connected"}, 503
    try:
        # ADDED ngrok-skip-browser-warning HERE
        headers = {
            "X-Relay-Token": RELAY_TOKEN, 
            "Content-Type": "application/json",
            "ngrok-skip-browser-warning": "true"
        }
        resp = requests.request(method, DYNAMIC_RELAY_URL.rstrip("/") + path, 
                                headers=headers, json=body, timeout=20)
        return resp, resp.json(), resp.status_code
    except Exception as e: 
        return None, {"error": str(e)}, 500

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
    if not hmac.compare_digest(request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET): abort(403)
    body = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    name  = body.get("name", "").strip()
    tier  = body.get("tier", "free")
    if not email or not name: return jsonify({"error": "email and name required"}), 400
    if tier not in ("free", "pro"): return jsonify({"error": "tier must be free or pro"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO customers (email, name, tier, created_at) VALUES (?, ?, ?, ?)", (email, name, tier, now_iso()))
        db.commit()
        cust = db.execute("SELECT id FROM customers WHERE email=?", (email,)).fetchone()
        raw_key, key_hash, key_prefix = mint_key()
        db.execute("INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at) VALUES (?, ?, ?, ?)", (cust["id"], key_hash, key_prefix, now_iso()))
        db.commit()
        return jsonify({"message": "Customer registered", "api_key": raw_key, "email": email, "name": name, "tier": tier}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already registered"}), 409

@app.route("/admin/customers", methods=["GET"])
def admin_customers():
    if not hmac.compare_digest(request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET): abort(403)
    rows = get_db().execute("SELECT c.id, c.email, c.name, c.tier, c.active, c.created_at, COUNT(k.id) as key_count FROM customers c LEFT JOIN api_keys k ON k.customer_id = c.id GROUP BY c.id ORDER BY c.created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/stats", methods=["GET"])
def admin_stats():
    if not hmac.compare_digest(request.headers.get("X-Admin-Secret", ""), ADMIN_SECRET): abort(403)
    db = get_db()
    return jsonify({
        "total_customers": db.execute("SELECT COUNT(*) FROM customers WHERE active=1").fetchone()[0],
        "total_requests":  db.execute("SELECT COUNT(*) FROM usage_log").fetchone()[0],
        "today_requests":  db.execute("SELECT SUM(count) FROM daily_counts WHERE day=?", (today(),)).fetchone()[0] or 0,
        "relay_active":    bool(DYNAMIC_RELAY_URL),
        "relay_url":       DYNAMIC_RELAY_URL or None,
    })

@app.route("/v1/keys", methods=["POST"])
def issue_key():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): return jsonify({"error": "Missing Authorization header"}), 401
    key_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
    row = get_db().execute("SELECT k.customer_id, k.revoked_at, c.active FROM api_keys k JOIN customers c ON c.id=k.customer_id WHERE k.key_hash=?", (key_hash,)).fetchone()
    if not row or row["revoked_at"] or not row["active"]: return jsonify({"error": "Invalid or revoked API key"}), 401
    body = request.get_json(force=True) or {}
    label = body.get("label", "default")
    raw_key, new_hash, prefix = mint_key()
    get_db().execute("INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, ?)", (row["customer_id"], new_hash, prefix, now_iso(), label))
    get_db().commit()
    return jsonify({"api_key": raw_key, "label": label, "note": "Store this key safely — it won't be shown again."}), 201

@app.route("/v1/usage", methods=["GET"])
@require_api_key
def usage():
    db = get_db()
    today_count = db.execute("SELECT count FROM daily_counts WHERE key_id=? AND day=?", (g.key_id, today())).fetchone()
    quota = FREE_QUOTA_DAY if g.tier == "free" else PRO_QUOTA_DAY
    recent = db.execute("SELECT endpoint, ts, status, latency_ms FROM usage_log WHERE key_id=? ORDER BY id DESC LIMIT 20", (g.key_id,)).fetchall()
    return jsonify({
        "tier": g.tier, "quota_today": quota,
        "used_today": today_count["count"] if today_count else 0,
        "remaining_today": quota - (today_count["count"] if today_count else 0),
        "recent_calls": [dict(r) for r in recent],
    })

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
    if not {"ciphertext", "nonce", "encryption_key"}.issubset(body): 
        return jsonify({"error": "Missing ciphertext, nonce, or encryption_key"}), 400
        
    _, data, status = relay_request("/relay/decrypt", "POST", {
        "ciphertext": body.get("ciphertext"), 
        "nonce": body.get("nonce"),
        "encryption_key": body.get("encryption_key")
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

@app.route("/health")
def health(): return jsonify({"status": "ok", "tunnel_active": bool(DYNAMIC_RELAY_URL)})

@app.route("/v1/register", methods=["POST"])
def public_register():
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    name  = body.get("name", "").strip() or email.split("@")[0]
    if not email or "@" not in email: return jsonify({"error": "Valid email required"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO customers (email, name, tier, created_at) VALUES (?, ?, 'free', ?)", (email, name, now_iso()))
        db.commit()
        cust = db.execute("SELECT id FROM customers WHERE email=?", (email,)).fetchone()
        raw_key, key_hash, prefix = mint_key()
        db.execute("INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at) VALUES (?, ?, ?, ?)", (cust["id"], key_hash, prefix, now_iso()))
        db.commit()
        return jsonify({"api_key": raw_key, "tier": "free", "quota": 100, "note": "Save this key — it won't be shown again."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already registered."}), 409

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
:root{ --ink:#08090c;--ink2:#0f1117;--ink3:#161b26; --line:#1e2535;--line2:#252d3e; --dust:#384158;--mist:#5a6a8a;--fog:#8898b8; --paper:#c5cede;--white:#eef2fb; --lime:#b8f552;--lime2:#d4ff7a;--lime3:rgba(184,245,82,.12); --teal:#52e5c8;--teal3:rgba(82,229,200,.1); --rose:#ff6b8a; --glow-lime:0 0 40px rgba(184,245,82,.25); --glow-teal:0 0 40px rgba(82,229,200,.2); }
html{scroll-behavior:smooth;-webkit-font-smoothing:antialiased}
body{ background:var(--ink);color:var(--paper); font-family:'Outfit',sans-serif;font-weight:400; min-height:100vh;overflow-x:hidden; }
::selection{background:var(--lime);color:#000}
#entropy-canvas{ position:fixed;inset:0;width:100%;height:100%; pointer-events:none;z-index:0;opacity:.45; }
.wrap{position:relative;z-index:1;max-width:1080px;margin:0 auto;padding:0 2rem}
nav{ display:flex;align-items:center;justify-content:space-between; padding:1.4rem 2.5rem; position:sticky;top:0;z-index:100; background:rgba(8,9,12,.8);backdrop-filter:blur(20px); border-bottom:1px solid var(--line); }
.nav-logo{ display:flex;align-items:center;gap:.75rem; font-family:'DM Mono',monospace;font-size:.95rem; color:var(--white);letter-spacing:-.01em;font-weight:500; text-decoration:none; }
.logo-hex{ width:34px;height:34px; background:linear-gradient(135deg,var(--lime),var(--teal)); clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%); display:flex;align-items:center;justify-content:center; font-size:15px;flex-shrink:0; }
.nav-status{ display:flex;align-items:center;gap:.5rem; font-family:'DM Mono',monospace;font-size:.72rem; color:var(--mist); padding:.35rem .9rem; border:1px solid var(--line2);border-radius:100px; transition:all .3s; }
.nav-status.live{color:var(--lime);border-color:rgba(184,245,82,.3);}
.pulse-dot{ width:6px;height:6px;border-radius:50%; background:var(--dust);transition:background .3s,box-shadow .3s; }
.pulse-dot.live{ background:var(--lime); box-shadow:0 0 8px var(--lime); animation:blink 2s ease-in-out infinite; }
@keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
.hero{ padding:7rem 0 5rem; text-align:center; position:relative; }
.hero-eyebrow{ display:inline-flex;align-items:center;gap:.6rem; font-family:'DM Mono',monospace;font-size:.72rem; color:var(--lime);letter-spacing:.12em;text-transform:uppercase; padding:.4rem 1.1rem; border:1px solid rgba(184,245,82,.25); border-radius:100px;background:rgba(184,245,82,.06); margin-bottom:2.5rem; }
.hero-eyebrow::before{content:'◈';font-size:.8rem}
h1{ font-family:'Instrument Serif',serif; font-size:clamp(3.2rem,7.5vw,6rem); line-height:1.02;letter-spacing:-.03em; color:var(--white);margin-bottom:1.75rem; font-weight:400; }
h1 em{ font-style:italic; background:linear-gradient(125deg,var(--lime) 0%,var(--teal) 55%,var(--lime2) 100%); -webkit-background-clip:text;-webkit-text-fill-color:transparent; }
.hero-lead{ font-size:1.1rem;line-height:1.75;color:var(--mist); max-width:560px;margin:0 auto 3.5rem;font-weight:300; }
.hero-lead strong{color:var(--paper);font-weight:500}
.get-key-widget{ max-width:500px;margin:0 auto 2rem; background:var(--ink2); border:1px solid var(--line2); border-radius:16px; overflow:hidden; box-shadow:0 20px 60px rgba(0,0,0,.5); transition:box-shadow .3s; }
.get-key-widget:focus-within{ border-color:rgba(184,245,82,.35); box-shadow:0 20px 60px rgba(0,0,0,.5),var(--glow-lime); }
.gkw-header{ padding:1.4rem 1.75rem 1rem; border-bottom:1px solid var(--line); display:flex;align-items:center;justify-content:space-between; }
.gkw-title{font-size:.8rem;font-weight:600;color:var(--paper);letter-spacing:.04em;text-transform:uppercase}
.gkw-free-badge{ font-family:'DM Mono',monospace;font-size:.68rem; color:var(--lime);background:var(--lime3); border:1px solid rgba(184,245,82,.2); padding:.2rem .6rem;border-radius:100px; }
.gkw-body{padding:1.25rem 1.75rem 1.5rem;display:flex;flex-direction:column;gap:.75rem}
.gkw-row{display:flex;gap:.6rem}
.gkw-input{ flex:1;background:var(--ink3); border:1px solid var(--line2);border-radius:8px; color:var(--white); font-family:'Outfit',sans-serif;font-size:.9rem; padding:.75rem 1rem; outline:none;transition:border-color .2s; }
.gkw-input::placeholder{color:var(--dust)}
.gkw-input:focus{border-color:rgba(184,245,82,.4)}
.gkw-btn{ background:var(--lime);color:#000; border:none;border-radius:8px; font-family:'Outfit',sans-serif;font-weight:700;font-size:.9rem; padding:.75rem 1.5rem;cursor:pointer;white-space:nowrap; transition:background .2s,transform .15s,box-shadow .2s; }
.gkw-btn:hover{background:var(--lime2);transform:translateY(-1px);box-shadow:var(--glow-lime)}
.gkw-btn:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}
.gkw-msg{ font-family:'DM Mono',monospace;font-size:.75rem; min-height:1.4rem;text-align:center; transition:color .2s;color:var(--mist); }
.gkw-msg.ok{color:var(--lime)} .gkw-msg.err{color:var(--rose)}
.key-result{ display:none; max-width:500px;margin:0 auto 1.5rem; background:linear-gradient(135deg,rgba(184,245,82,.06),rgba(82,229,200,.04)); border:1px solid rgba(184,245,82,.3); border-radius:16px;padding:1.5rem 1.75rem; animation:fadeSlide .5s ease; }
.key-result.show{display:block}
@keyframes fadeSlide{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.kr-label{ font-family:'DM Mono',monospace;font-size:.68rem; color:var(--lime);letter-spacing:.1em;text-transform:uppercase; margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem; }
.kr-label::before{content:'✓';font-size:.9rem}
.kr-key{ font-family:'DM Mono',monospace;font-size:.78rem; color:var(--white);word-break:break-all;line-height:1.6; background:var(--ink3);border:1px solid var(--line2); border-radius:8px;padding:.85rem 1rem;margin-bottom:1rem; position:relative;cursor:pointer;transition:border-color .2s; }
.kr-key:hover{border-color:rgba(184,245,82,.3)}
.kr-copy-hint{ position:absolute;top:.5rem;right:.65rem; font-size:.6rem;color:var(--mist); transition:color .2s; }
.kr-key:hover .kr-copy-hint{color:var(--lime)}
.kr-note{font-size:.78rem;color:var(--mist);line-height:1.5}
.kr-note strong{color:var(--rose)}
.kr-actions{display:flex;gap:.6rem;margin-top:1rem}
.kr-action-btn{ flex:1;padding:.6rem;border-radius:8px; font-family:'Outfit',sans-serif;font-size:.8rem;font-weight:600; cursor:pointer;transition:all .15s;border:none; }
.kr-btn-primary{background:var(--lime);color:#000} .kr-btn-primary:hover{background:var(--lime2)}
.kr-btn-ghost{background:var(--ink3);color:var(--paper);border:1px solid var(--line2)} .kr-btn-ghost:hover{border-color:var(--fog);color:var(--white)}
.flow{ display:flex;align-items:center;justify-content:center; gap:0;margin:5rem 0;flex-wrap:wrap; }
.flow-step{ display:flex;flex-direction:column;align-items:center;gap:.75rem; padding:1.5rem 1.25rem; min-width:140px; text-align:center; }
.flow-icon{ width:52px;height:52px;border-radius:14px; display:flex;align-items:center;justify-content:center; font-size:1.4rem; border:1px solid var(--line2); background:var(--ink2); position:relative; }
.flow-icon.active{ background:var(--lime3); border-color:rgba(184,245,82,.3); box-shadow:var(--glow-lime); }
.flow-title{font-size:.82rem;font-weight:600;color:var(--paper)}
.flow-sub{font-size:.72rem;color:var(--mist);line-height:1.4}
.flow-arrow{ font-size:1.2rem;color:var(--line2); padding:0 .25rem;align-self:center; margin-bottom:1.5rem;flex-shrink:0; }
.section{padding:5rem 0}
.section-tag{ font-family:'DM Mono',monospace;font-size:.7rem; color:var(--teal);letter-spacing:.12em;text-transform:uppercase; margin-bottom:.75rem; }
.section-h{ font-family:'Instrument Serif',serif; font-size:clamp(1.8rem,4vw,2.8rem); color:var(--white);letter-spacing:-.02em; margin-bottom:1rem;font-weight:400;line-height:1.1; }
.section-sub{font-size:.95rem;color:var(--mist);line-height:1.7;max-width:500px}
.playground{ display:grid;grid-template-columns:1fr 1fr; gap:1px;background:var(--line); border:1px solid var(--line);border-radius:16px; overflow:hidden;margin-top:2rem; }
.pg-pane{ background:var(--ink2);padding:1.5rem; display:flex;flex-direction:column;gap:1rem; }
.pg-pane-header{ display:flex;align-items:center;justify-content:space-between; }
.pg-pane-label{ font-family:'DM Mono',monospace;font-size:.7rem; color:var(--mist);letter-spacing:.08em;text-transform:uppercase; }
.pg-badge{ font-family:'DM Mono',monospace;font-size:.65rem; padding:.15rem .55rem;border-radius:100px; }
.pg-badge-enc{background:rgba(184,245,82,.12);color:var(--lime);border:1px solid rgba(184,245,82,.2)}
.pg-badge-dec{background:rgba(82,229,200,.1);color:var(--teal);border:1px solid rgba(82,229,200,.2)}
textarea{ width:100%;background:var(--ink3); border:1px solid var(--line2);border-radius:8px; color:var(--paper);font-family:'DM Mono',monospace;font-size:.78rem; padding:.85rem 1rem;resize:none;outline:none;line-height:1.6; transition:border-color .2s; min-height:110px; }
textarea:focus{border-color:var(--line)}
textarea.out{ color:var(--lime); background:rgba(184,245,82,.03); border-color:rgba(184,245,82,.15); min-height:130px; }
textarea.out.teal{color:var(--teal);background:rgba(82,229,200,.03);border-color:rgba(82,229,200,.15)}
textarea.out.err{color:var(--rose);background:rgba(255,107,138,.03);border-color:rgba(255,107,138,.15)}
.pg-key-row{ display:flex;align-items:center;gap:.5rem; padding:.6rem .9rem; background:var(--ink3);border:1px solid var(--line2);border-radius:8px; font-family:'DM Mono',monospace;font-size:.72rem; }
.pg-key-dot{ width:7px;height:7px;border-radius:50%;background:var(--dust);flex-shrink:0; transition:background .3s,box-shadow .3s; }
.pg-key-dot.set{background:var(--lime);box-shadow:0 0 6px var(--lime)}
.pg-key-text{flex:1;color:var(--mist);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pg-key-text.set{color:var(--paper)}
.pg-key-clear{background:none;border:none;color:var(--dust);cursor:pointer;font-size:.75rem; padding:0 .2rem;transition:color .15s}
.pg-key-clear:hover{color:var(--rose)}
.pg-action{ background:var(--lime);color:#000;border:none;border-radius:8px; font-family:'Outfit',sans-serif;font-weight:700;font-size:.85rem; padding:.75rem;cursor:pointer; transition:background .2s,transform .15s,box-shadow .2s; }
.pg-action:hover{background:var(--lime2);transform:translateY(-1px);box-shadow:var(--glow-lime)}
.pg-action:disabled{opacity:.35;cursor:not-allowed;transform:none;box-shadow:none}
.pg-action.teal-btn{ background:rgba(82,229,200,.15);color:var(--teal); border:1px solid rgba(82,229,200,.2); }
.pg-action.teal-btn:hover{background:rgba(82,229,200,.25);box-shadow:var(--glow-teal)}
.pg-key-setup{ grid-column:1/-1; background:var(--ink2); display:flex;align-items:center;justify-content:center; padding:2rem;gap:1rem;flex-wrap:wrap; }
.pg-key-setup.hidden{display:none}
.pg-setup-input{ flex:1;min-width:220px;max-width:340px; background:var(--ink3);border:1px solid var(--line2);border-radius:8px; color:var(--white);font-family:'DM Mono',monospace;font-size:.82rem; padding:.7rem 1rem;outline:none;transition:border-color .2s; }
.pg-setup-input:focus{border-color:rgba(184,245,82,.4)}
.pg-setup-btn{ background:var(--lime);color:#000;border:none;border-radius:8px; font-family:'Outfit',sans-serif;font-weight:700;font-size:.85rem; padding:.7rem 1.4rem;cursor:pointer; transition:background .2s,transform .15s;white-space:nowrap; }
.pg-setup-btn:hover{background:var(--lime2);transform:translateY(-1px)}
.pg-setup-hint{ font-size:.75rem;color:var(--mist);text-align:center;width:100%; }
.pg-setup-hint a{color:var(--lime);cursor:pointer;text-decoration:none}
.pg-setup-hint a:hover{text-decoration:underline}
.docs-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-top:2rem}
.code-card{ background:var(--ink2);border:1px solid var(--line); border-radius:12px;overflow:hidden; }
.cc-header{ display:flex;align-items:center;justify-content:space-between; padding:.75rem 1.1rem;border-bottom:1px solid var(--line); background:rgba(255,255,255,.02); }
.cc-dots{display:flex;gap:5px} .cc-dots span{width:9px;height:9px;border-radius:50%}
.d1{background:#ff5f57}.d2{background:#febc2e}.d3{background:#28c840}
.cc-lang{font-family:'DM Mono',monospace;font-size:.68rem;color:var(--dust);letter-spacing:.06em}
.cc-copy{ font-family:'DM Mono',monospace;font-size:.65rem; color:var(--mist);background:none; border:1px solid var(--line2);border-radius:4px; padding:.15rem .55rem;cursor:pointer;transition:color .2s,border-color .2s; }
.cc-copy:hover,.cc-copy.ok{color:var(--lime);border-color:rgba(184,245,82,.3)}
pre{ padding:1.25rem;font-family:'DM Mono',monospace; font-size:.76rem;line-height:1.7;overflow-x:auto;color:var(--paper); }
.tk{color:var(--teal)}.ts{color:var(--lime)}.tc{color:var(--dust);font-style:italic}
.tm{color:#ff9f7f}.tn{color:#c792ea}
.stats-row{ display:grid;grid-template-columns:repeat(3,1fr); gap:1px;background:var(--line); border:1px solid var(--line);border-radius:16px;overflow:hidden; margin:4rem 0; }
.stat-cell{ background:var(--ink2);padding:2rem;text-align:center; }
.stat-n{ font-family:'Instrument Serif',serif; font-size:2.8rem;color:var(--white);line-height:1; margin-bottom:.4rem; }
.stat-l{font-size:.75rem;color:var(--mist);text-transform:uppercase;letter-spacing:.08em}
footer{ border-top:1px solid var(--line); padding:2.5rem 2.5rem; display:flex;align-items:center;justify-content:space-between; color:var(--dust);font-size:.8rem;flex-wrap:wrap;gap:1rem; }
.footer-left{display:flex;align-items:center;gap:.75rem}
.footer-tag{font-family:'DM Mono',monospace;font-size:.65rem;color:var(--line2)}
.sr{opacity:0;transform:translateY(28px);transition:opacity .7s ease,transform .7s ease}
.sr.in{opacity:1;transform:none}
@media(max-width:680px){ .playground,.docs-grid,.stats-row{grid-template-columns:1fr} .flow{flex-direction:column;gap:0} .flow-arrow{transform:rotate(90deg);padding:.5rem 0;margin-bottom:0} h1{font-size:2.8rem} nav{padding:1rem 1.25rem} }
</style>
</head>
<body>

<canvas id="entropy-canvas"></canvas>

<nav>
  <a href="/" class="nav-logo"><div class="logo-hex">⬡</div>ChaosKey</a>
  <div class="nav-status" id="nav-pill"><div class="pulse-dot" id="nav-dot"></div><span id="nav-txt" style="font-size:.72rem">checking engine…</span></div>
</nav>

<div class="wrap">
  <section class="hero">
    <div class="hero-eyebrow">Physical Entropy · AES-256-GCM · 10s Key Rotation</div>
    <h1>Your encryption key<br>born from <em>real chaos</em></h1>
    <p class="hero-lead">
      A camera watches a moving pendulum. A microphone listens to the room.<br>
      <strong>That unpredictable motion derives a NEW cryptographic key every 10 seconds</strong> — generated on a local machine, never stored in the cloud.
    </p>

    <div class="get-key-widget" id="gkw">
      <div class="gkw-header"><span class="gkw-title">Get your free API key</span><span class="gkw-free-badge">Free · 100 calls/day</span></div>
      <div class="gkw-body">
        <div class="gkw-row"><input class="gkw-input" type="email" id="gkw-email" placeholder="you@example.com" autocomplete="email"><button class="gkw-btn" id="gkw-btn" onclick="getKey()">Get key →</button></div>
        <div class="gkw-msg" id="gkw-msg">No credit card. No verification. Instant.</div>
      </div>
    </div>

    <div class="key-result" id="key-result">
      <div class="kr-label">Your API Key is ready</div>
      <div class="kr-key" id="kr-key-val" onclick="copyKeyResult(this)" title="Click to copy"><span id="kr-key-text">ck_live_…</span><span class="kr-copy-hint">click to copy</span></div>
      <p class="kr-note"><strong>Save this now.</strong> For your security, we don't store the key — only its hash. It cannot be recovered.</p>
      <div class="kr-actions">
        <button class="kr-action-btn kr-btn-primary" onclick="useKeyInPlayground()">Try it below ↓</button>
        <button class="kr-action-btn kr-btn-ghost" onclick="copyKeyResult(document.getElementById('kr-key-val'))">Copy key</button>
      </div>
    </div>
  </section>

  <div class="flow sr">
    <div class="flow-step"><div class="flow-icon active">🎥</div><div class="flow-title">Physical Chaos</div><div class="flow-sub">Webcam tracks pendulum motion &amp; audio captures room noise</div></div>
    <div class="flow-arrow">→</div>
    <div class="flow-step"><div class="flow-icon active">🌀</div><div class="flow-title">10s Rotation</div><div class="flow-sub">Every 10 seconds, the pool is sampled to create a brand new key.</div></div>
    <div class="flow-arrow">→</div>
    <div class="flow-step"><div class="flow-icon active">🔑</div><div class="flow-title">Key Derivation</div><div class="flow-sub">SHA-512 → Scrypt → HKDF-SHA256 locks the 256-bit key in</div></div>
    <div class="flow-arrow">→</div>
    <div class="flow-step"><div class="flow-icon">🔐</div><div class="flow-title">Your API Call</div><div class="flow-sub">We encrypt using the *current* 10s key, and return that specific key to you.</div></div>
  </div>

  <div class="stats-row sr">
    <div class="stat-cell"><div class="stat-n" id="s-customers">—</div><div class="stat-l">Active users</div></div>
    <div class="stat-cell"><div class="stat-n" id="s-today">—</div><div class="stat-l">Encryptions today</div></div>
    <div class="stat-cell"><div class="stat-n">10s</div><div class="stat-l">Key Rotation Rate</div></div>
  </div>

  <section class="section sr">
    <div class="section-tag">Playground</div>
    <div class="section-h">Encrypt something right now.</div>
    <p class="section-sub">Paste your key once — it stays for this session. Encrypt, decrypt, verify it all works.</p>

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
      
      <div class="pg-pane" id="pane-export" style="display:none; grid-column: 1 / -1;">
        <div class="pg-pane-header">
          <span class="pg-pane-label">Master Chaos Key</span>
          <span class="pg-badge" style="background:rgba(255,107,138,.12);color:var(--rose);border:1px solid rgba(255,107,138,.2)">EXPORT</span>
        </div>
        <p style="font-size:.75rem;color:var(--mist);line-height:1.5">This retrieves the *currently active* 10-second master key directly from the physical entropy engine.</p>
        <div style="display:flex; gap:1rem;">
            <button class="pg-action" style="background:transparent; border:1px solid var(--rose); color:var(--rose);" onclick="exportChaosKey()">Reveal Active Master Key</button>
        </div>
        <textarea class="out" id="export-output" rows="2" readonly style="display:none; margin-top:1rem;"></textarea>
      </div>
    </div>
  </section>

  <section class="section sr">
    <div class="section-tag">Integration</div>
    <div class="section-h">Copy. Paste. Done.</div>
    <p class="section-sub">Two endpoints. Bearer auth. Works with any HTTP client.</p>

    <div class="docs-grid">
      <div class="code-card">
        <div class="cc-header"><div class="cc-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="cc-lang">PYTHON</span><button class="cc-copy" onclick="cpCode(this,'c1')">copy</button></div>
        <pre id="c1"><span class="tc"># pip install requests</span>
<span class="tk">import</span> requests

BASE = <span class="ts">"https://your-app.onrender.com"</span>
KEY  = <span class="ts">"ck_live_YOUR_KEY"</span>
H    = {<span class="ts">"Authorization"</span>: <span class="ts">f"Bearer {KEY}"</span>}

<span class="tc"># Encrypt</span>
r = requests.<span class="tm">post</span>(f<span class="ts">"{BASE}/v1/encrypt"</span>, headers=H,
        json={<span class="ts">"plaintext"</span>: <span class="ts">"secret data"</span>})
enc = r.json()
<span class="tc"># Contains: ciphertext, nonce, encryption_key</span>

<span class="tc"># Decrypt (Pass the entire object back)</span>
r = requests.<span class="tm">post</span>(f<span class="ts">"{BASE}/v1/decrypt"</span>, headers=H,
        json=enc)
print(r.json()[<span class="ts">"plaintext"</span>])  <span class="tc"># → "secret data"</span></pre>
      </div>

      <div class="code-card">
        <div class="cc-header"><div class="cc-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="cc-lang">JAVASCRIPT</span><button class="cc-copy" onclick="cpCode(this,'c2')">copy</button></div>
        <pre id="c2"><span class="tk">const</span> BASE = <span class="ts">"https://your-app.onrender.com"</span>;
<span class="tk">const</span> KEY  = <span class="ts">"ck_live_YOUR_KEY"</span>;
<span class="tk">const</span> H    = { <span class="ts">"Authorization"</span>: <span class="ts">`Bearer ${KEY}`</span>, <span class="ts">"Content-Type"</span>: <span class="ts">"application/json"</span> };

<span class="tc">// Encrypt</span>
<span class="tk">const</span> enc = <span class="tk">await</span> <span class="tm">fetch</span>(<span class="ts">`${BASE}/v1/encrypt`</span>, {
  method: <span class="ts">"POST"</span>, headers: H,
  body: JSON.<span class="tm">stringify</span>({ plaintext: <span class="ts">"secret"</span> })
}).<span class="tm">then</span>(r => r.<span class="tm">json</span>());

<span class="tc">// Decrypt</span>
<span class="tk">const</span> out = <span class="tk">await</span> <span class="tm">fetch</span>(<span class="ts">`${BASE}/v1/decrypt`</span>, {
  method: <span class="ts">"POST"</span>, headers: H,
  body: JSON.<span class="tm">stringify</span>(enc)
}).<span class="tm">then</span>(r => r.<span class="tm">json</span>());
console.<span class="tm">log</span>(out.plaintext); <span class="tc">// → "secret"</span></pre>
      </div>

      <div class="code-card">
        <div class="cc-header"><div class="cc-dots"><span class="d1"></span><span class="d2"></span><span class="d3"></span></div><span class="cc-lang">API REFERENCE</span><button class="cc-copy" onclick="cpCode(this,'c4')">copy</button></div>
        <pre id="c4"><span class="tc"># Register (get a free key)</span>
<span class="tm">POST</span> /v1/register
  body: { <span class="ts">"email"</span>: <span class="ts">"you@example.com"</span> }
  → { <span class="ts">"api_key"</span>: <span class="ts">"ck_live_…"</span> }

<span class="tc"># Encrypt plaintext</span>
<span class="tm">POST</span> /v1/encrypt  <span class="tn">[Bearer token]</span>
  body: { <span class="ts">"plaintext"</span>: <span class="ts">"…"</span> }
  → { <span class="ts">"ciphertext"</span>: <span class="ts">"…"</span>, <span class="ts">"nonce"</span>: <span class="ts">"…"</span>, <span class="ts">"encryption_key"</span>: <span class="ts">"…"</span> }

<span class="tc"># Decrypt ciphertext</span>
<span class="tm">POST</span> /v1/decrypt  <span class="tn">[Bearer token]</span>
  body: { <span class="ts">"ciphertext"</span>: <span class="ts">"…"</span>, <span class="ts">"nonce"</span>: <span class="ts">"…"</span>, <span class="ts">"encryption_key"</span>: <span class="ts">"…"</span> }
  → { <span class="ts">"plaintext"</span>: <span class="ts">"…"</span> }</pre>
      </div>
    </div>
  </section>
</div>

<footer>
  <div class="footer-left"><div class="logo-hex" style="width:24px;height:24px;font-size:11px">⬡</div><span style="font-family:'DM Mono',monospace;font-size:.75rem;color:var(--dust)">ChaosKey</span></div>
  <div class="footer-tag">Physical entropy. Key never leaves our machine.</div>
</footer>

<script>
(function(){
  const cv = document.getElementById('entropy-canvas'); const cx = cv.getContext('2d');
  let W,H,particles=[]; const N=90, SPEED=.4;
  function resize(){ W=cv.width=innerWidth; H=cv.height=innerHeight; }
  resize(); addEventListener('resize',resize);
  class Particle{
    constructor(){this.reset(true)}
    reset(init){
      this.x = Math.random()*W; this.y = init ? Math.random()*H : (Math.random()<.5?-4:H+4);
      this.vx = (Math.random()-.5)*SPEED; this.vy = (Math.random()*.6+.2)*SPEED*(this.y<0?1:-1);
      this.r  = Math.random()*1.5+.4; this.life=0; this.maxLife=300+Math.random()*400;
      this.hue = Math.random()<.6?150:175;
    }
    step(){
      const t=Date.now()*.0003; const nx=this.x/W*4+t, ny=this.y/H*4+t*.7;
      const angle=(Math.sin(nx)*Math.cos(ny))*Math.PI*2;
      this.vx+=Math.cos(angle)*.008; this.vy+=Math.sin(angle)*.008;
      this.vx*=.98; this.vy*=.98; this.x+=this.vx; this.y+=this.vy; this.life++;
      if(this.life>this.maxLife||this.x<-10||this.x>W+10||this.y<-10||this.y>H+10) this.reset(false);
    }
    draw(){
      const alpha=Math.min(this.life/60,1)*Math.min((this.maxLife-this.life)/60,1)*.6;
      cx.beginPath(); cx.arc(this.x,this.y,this.r,0,Math.PI*2); cx.fillStyle=`hsla(${this.hue},90%,65%,${alpha})`; cx.fill();
    }
  }
  for(let i=0;i<N;i++) particles.push(new Particle());
  function draw(){
    cx.clearRect(0,0,W,H);
    for(let i=0;i<particles.length;i++){
      for(let j=i+1;j<particles.length;j++){
        const dx=particles[i].x-particles[j].x, dy=particles[i].y-particles[j].y, d=Math.sqrt(dx*dx+dy*dy);
        if(d<120){ cx.beginPath(); cx.moveTo(particles[i].x,particles[i].y); cx.lineTo(particles[j].x,particles[j].y); cx.strokeStyle=`rgba(184,245,82,${(1-d/120)*.07})`; cx.lineWidth=.5; cx.stroke(); }
      }
    }
    particles.forEach(p=>{p.step();p.draw()}); requestAnimationFrame(draw);
  }
  draw();
})();

let _key = sessionStorage.getItem('ck_key') || '';
let _newKey = '';

async function pollStatus(){
  try{
    const d=await(await fetch('/health')).json();
    const dot=document.getElementById('nav-dot'), txt=document.getElementById('nav-txt'), pill=document.getElementById('nav-pill');
    if(d.tunnel_active){ dot.classList.add('live'); pill.classList.add('live'); txt.textContent='Engine online'; }
    else { dot.classList.remove('live'); pill.classList.remove('live'); txt.textContent='Engine offline'; }
    try{
      const s=await(await fetch('/public/stats')).json();
      document.getElementById('s-customers').textContent=s.total_customers??'—';
      document.getElementById('s-today').textContent=s.today_requests??'—';
    }catch(e){}
  }catch(e){}
}
pollStatus(); setInterval(pollStatus,6000);

async function getKey(){
  const emailEl=document.getElementById('gkw-email'), btn=document.getElementById('gkw-btn'), msg=document.getElementById('gkw-msg'), email=emailEl.value.trim();
  if(!email||!email.includes('@')){ msg.textContent='Enter a valid email address.'; msg.className='gkw-msg err'; return; }
  btn.disabled=true; msg.textContent='Generating your key…'; msg.className='gkw-msg';
  try{
    const {ok,data}=await apiFetch('/v1/register',{ method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email}) });
    if(ok){
      _newKey=data.api_key;
      document.getElementById('kr-key-text').textContent=data.api_key; document.getElementById('key-result').classList.add('show'); document.getElementById('gkw').style.display='none'; msg.textContent=''; 
    } else { msg.textContent='✗ '+(data.error||'Registration failed'); msg.className='gkw-msg err'; btn.disabled=false; }
  }catch(e){ msg.textContent='✗ Network error — try again'; msg.className='gkw-msg err'; btn.disabled=false; }
}
document.getElementById('gkw-email').addEventListener('keydown',e=>{if(e.key==='Enter')getKey()});
function copyKeyResult(el){
  navigator.clipboard.writeText(document.getElementById('kr-key-text').textContent).then(()=>{
    const hint=el.querySelector('.kr-copy-hint'); if(hint){hint.textContent='copied!';setTimeout(()=>hint.textContent='click to copy',2000)}
  });
}
function useKeyInPlayground(){ const k=_newKey||document.getElementById('kr-key-text').textContent; sessionStorage.setItem('ck_key',k); _key=k; activateKeyValue(k); document.getElementById('playground').scrollIntoView({behavior:'smooth',block:'start'}); }
function scrollToTop(){ document.getElementById('gkw').scrollIntoView({behavior:'smooth',block:'center'}); }
function activateKey(){ const v=document.getElementById('pg-key-input').value.trim(); if(!v)return; sessionStorage.setItem('ck_key',v); _key=v; activateKeyValue(v); }
function activateKeyValue(k){
  document.getElementById('pg-key-setup').classList.add('hidden');
  document.getElementById('pane-enc').style.display='flex'; document.getElementById('pane-enc').style.flexDirection='column';
  document.getElementById('pane-dec').style.display='flex'; document.getElementById('pane-dec').style.flexDirection='column';
  document.getElementById('pane-export').style.display='block';
  document.getElementById('enc-key-label').textContent=k.length>22?k.slice(0,22)+'…':k;
}
function clearKey(){
  sessionStorage.removeItem('ck_key'); _key=''; document.getElementById('pg-key-setup').classList.remove('hidden');
  document.getElementById('pane-enc').style.display='none'; document.getElementById('pane-dec').style.display='none'; document.getElementById('pane-export').style.display='none';
  document.getElementById('pg-key-input').value=''; document.getElementById('enc-output').value=''; document.getElementById('dec-output').value=''; document.getElementById('dec-input').value='';
  document.getElementById('export-output').style.display='none'; document.getElementById('export-output').value='';
}
if(_key) activateKeyValue(_key);

async function doEncrypt(){
  const plain=document.getElementById('enc-input').value.trim(), out=document.getElementById('enc-output');
  if(!plain){out.value='⚠ Enter some text first.';out.className='out err';return}
  out.value='Encrypting…'; out.className='out';
  const {ok,data}=await apiFetch('/v1/encrypt',{ method:'POST', headers:{'Authorization':'Bearer '+_key,'Content-Type':'application/json'}, body:JSON.stringify({plaintext:plain}) });
  if(ok){ out.value=JSON.stringify(data,null,2); out.className='out'; document.getElementById('dec-input').value=JSON.stringify(data,null,2); } 
  else { out.value='✗ '+(data.error||JSON.stringify(data)); out.className='out err'; }
}
async function doDecrypt(){
  const raw=document.getElementById('dec-input').value.trim(), out=document.getElementById('dec-output');
  if(!raw){out.value='⚠ Paste ciphertext JSON or encrypt something first.';out.className='out err';return}
  let body; try{body=JSON.parse(raw)}catch(e){out.value='✗ Invalid JSON.';out.className='out err';return}
  if(!body.ciphertext||!body.nonce||!body.encryption_key){ out.value='✗ JSON needs "ciphertext", "nonce", and "encryption_key".'; out.className='out err';return }
  out.value='Decrypting…'; out.className='out teal';
  const {ok,data}=await apiFetch('/v1/decrypt',{ method:'POST', headers:{'Authorization':'Bearer '+_key,'Content-Type':'application/json'}, body:JSON.stringify({ ciphertext: body.ciphertext, nonce: body.nonce, encryption_key: body.encryption_key }) });
  if(ok){ out.value=data.plaintext??JSON.stringify(data); out.className='out teal'; } else { out.value='✗ '+(data.error||JSON.stringify(data)); out.className='out err'; }
}
async function exportChaosKey(){
  const out = document.getElementById('export-output'); out.style.display = 'block'; out.value = 'Requesting raw master key...'; out.className = 'out';
  const {ok, data} = await apiFetch('/v1/export_key', { method:'GET', headers:{'Authorization':'Bearer '+_key} });
  if(ok){ out.value = data.chaos_key ?? JSON.stringify(data); } else { out.value = '✗ '+(data.error||JSON.stringify(data)); out.className = 'out err'; }
}
async function apiFetch(path,opts){
  const r=await fetch(path,opts), ct=r.headers.get('Content-Type')||''; let data;
  if(ct.includes('application/json')){data=await r.json()} else{ const t=await r.text(), m=t.match(/<title>([^<]*)<\/title>/i); data={error:m?m[1]:'HTTP '+r.status}; }
  return{ok:r.ok,status:r.status,data};
}
function cpCode(btn,id){ navigator.clipboard.writeText(document.getElementById(id).innerText).then(()=>{ btn.textContent='copied!'; btn.classList.add('ok'); setTimeout(()=>{btn.textContent='copy';btn.classList.remove('ok')},2000); }); }
const sro=new IntersectionObserver(es=>{ es.forEach(e=>{if(e.isIntersecting){e.target.classList.add('in');sro.unobserve(e.target)}}); },{threshold:.07});
document.querySelectorAll('.sr').forEach(el=>sro.observe(el));
</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

# MUST BE OUTSIDE THE MAIN BLOCK SO RENDER RUNS IT!
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
