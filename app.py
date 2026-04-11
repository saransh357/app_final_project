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
RELAY_TOKEN       = os.getenv("RELAY_TOKEN", "60214a27a9f1ee39361b70b3fa8c98d6")
ADMIN_SECRET      = os.getenv("ADMIN_SECRET", "change-me-in-production")
DATABASE_URL      = os.getenv("DATABASE_URL", "")
DB_PATH           = os.getenv("DB_PATH", "")

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

# ── Database abstraction ──────────────────────────────────────────────────────
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    from psycopg2.pool import ThreadedConnectionPool
    _pool = None

    def get_pool():
        global _pool
        if _pool is None:
            url = DATABASE_URL
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            _pool = ThreadedConnectionPool(1, 10, url, sslmode="require")
        return _pool

    def get_db():
        if "db" not in g:
            g.db = get_pool().getconn()
            g.db.autocommit = False
        return g.db

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db:
            if exc: db.rollback()
            else: db.commit()
            get_pool().putconn(db)

    def db_execute(sql, params=()):
        sql = sql.replace("?", "%s")
        cur = get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return cur

    AUTOINCREMENT = "SERIAL PRIMARY KEY"
else:
    import sqlite3
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH or "local.db")
            g.db.row_factory = sqlite3.Row
        return g.db
    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db: db.close()
    def db_execute(sql, params=()): return get_db().execute(sql, params)
    AUTOINCREMENT = "INTEGER PRIMARY KEY AUTOINCREMENT"

def db_commit(): get_db().commit()

# ── Schema ────────────────────────────────────────────────────────────────────
def get_schema():
    ai = AUTOINCREMENT
    return f"""
CREATE TABLE IF NOT EXISTS customers (id {ai}, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, tier TEXT NOT NULL DEFAULT 'free', created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, password_hash TEXT);
CREATE TABLE IF NOT EXISTS api_keys (id {ai}, customer_id INTEGER NOT NULL REFERENCES customers(id), key_hash TEXT UNIQUE NOT NULL, key_prefix TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT, label TEXT DEFAULT 'default');
CREATE TABLE IF NOT EXISTS usage_log (id {ai}, key_id INTEGER NOT NULL REFERENCES api_keys(id), endpoint TEXT NOT NULL, ts TEXT NOT NULL, status INTEGER NOT NULL, latency_ms INTEGER);
CREATE TABLE IF NOT EXISTS daily_counts (key_id INTEGER NOT NULL REFERENCES api_keys(id), day TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, {"UNIQUE(key_id, day)" if USE_POSTGRES else "PRIMARY KEY (key_id, day)"});
"""

def init_db():
    with app.app_context():
        if USE_POSTGRES:
            url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
            conn = psycopg2.connect(url, sslmode="require"); conn.autocommit = True
            cur = conn.cursor()
            for stmt in get_schema().split(";"):
                if stmt.strip(): cur.execute(stmt.strip())
            try: cur.execute("ALTER TABLE customers ADD COLUMN IF NOT EXISTS password_hash TEXT")
            except: pass
            conn.close()
        else:
            db = sqlite3.connect(DB_PATH or "local.db")
            db.executescript(get_schema()); db.close()
        _seed_admin()

def _seed_admin():
    if not ADMIN_PASSWORD: return
    try:
        existing = db_execute("SELECT id FROM customers WHERE email = ?", (ADMIN_EMAIL,)).fetchone()
        if existing: return
        pw_hash = hash_password(ADMIN_PASSWORD)
        db_execute("INSERT INTO customers (email, name, tier, created_at, password_hash) VALUES (?, ?, 'admin', ?, ?)", (ADMIN_EMAIL, "Admin", now_iso(), pw_hash))
        db_commit()
        cust = db_execute("SELECT id FROM customers WHERE email = ?", (ADMIN_EMAIL,)).fetchone()
        raw_key, key_hash, prefix = mint_key()
        db_execute("INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, 'admin')", (cust["id"], key_hash, prefix, now_iso()))
        db_commit()
    except Exception as e: log.error(f"Admin seed failed: {e}")

# ── Helpers ───────────────────────────────────────────────────────────────────
def mint_key():
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest(), raw[:16] + "…"
def today(): return datetime.now(timezone.utc).strftime("%Y-%m-%d")
def now_iso(): return datetime.now(timezone.utc).isoformat()
def quota_for_tier(tier: str): return {"free": 100, "pro": 10000, "admin": 999999999}.get(tier, 100)

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "): return jsonify({"error": "Missing Auth"}), 401
        key_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
        row = db_execute("SELECT k.id, k.customer_id, c.tier, c.active, k.revoked_at FROM api_keys k JOIN customers c ON c.id = k.customer_id WHERE k.key_hash = ?", (key_hash,)).fetchone()
        if not row or row["revoked_at"] or not row["active"]: return jsonify({"error": "Invalid Key"}), 401
        g.key_id, g.customer_id, g.tier, g.t0 = row["id"], row["customer_id"], row["tier"], time.monotonic()
        return f(*args, **kwargs)
    return decorated

def log_usage(endpoint, status):
    if not hasattr(g, "key_id"): return
    try:
        db_execute("INSERT INTO usage_log (key_id, endpoint, ts, status, latency_ms) VALUES (?, ?, ?, ?, ?)", (g.key_id, endpoint, now_iso(), status, int((time.monotonic()-g.t0)*1000)))
        upsert = "INSERT INTO daily_counts (key_id, day, count) VALUES (%s, %s, 1) ON CONFLICT (key_id, day) DO UPDATE SET count = daily_counts.count + 1" if USE_POSTGRES else "INSERT INTO daily_counts (key_id, day, count) VALUES (?, ?, 1) ON CONFLICT(key_id, day) DO UPDATE SET count = count + 1"
        db_execute(upsert, (g.key_id, today())); db_commit()
    except Exception as e: log.warning(f"Log failed: {e}")

def relay_request(path, method="GET", body=None):
    if not DYNAMIC_RELAY_URL: return None, {"error": "Engine Offline"}, 503
    try:
        resp = requests.request(method, DYNAMIC_RELAY_URL.rstrip("/") + path, headers={"X-Relay-Token": RELAY_TOKEN, "Content-Type": "application/json"}, json=body, timeout=20)
        return resp, resp.json(), resp.status_code
    except Exception as e: return None, {"error": str(e)}, 500

DYNAMIC_RELAY_URL = os.getenv("RELAY_URL", "")

# ── API Routes ────────────────────────────────────────────────────────────────
@app.route("/v1/register", methods=["POST"])
def public_register():
    body = request.get_json(force=True) or {}
    email, password, name = body.get("email", "").lower(), body.get("password", ""), body.get("name", "")
    if not email or len(password) < 6: return jsonify({"error": "Invalid data"}), 400
    try:
        db_execute("INSERT INTO customers (email, name, tier, created_at, password_hash) VALUES (?, ?, 'free', ?, ?)", (email, name or email, now_iso(), hash_password(password)))
        db_commit()
        cust = db_execute("SELECT id FROM customers WHERE email = ?", (email,)).fetchone()
        raw_key, key_hash, prefix = mint_key()
        db_execute("INSERT INTO api_keys (customer_id, key_hash, key_prefix, created_at, label) VALUES (?, ?, ?, ?, 'primary')", (cust["id"], key_hash, prefix, now_iso()))
        db_commit()
        return jsonify({"api_key": raw_key, "tier": "free", "quota": 100}), 201
    except: return jsonify({"error": "User exists"}), 409

@app.route("/v1/login", methods=["POST"])
def public_login():
    body = request.get_json(force=True) or {}
    email, password = body.get("email", "").lower(), body.get("password", "")
    cust = db_execute("SELECT id, name, tier, active, password_hash FROM customers WHERE email = ?", (email,)).fetchone()
    if not cust or not check_password(password, cust["password_hash"]): return jsonify({"error": "Auth failed"}), 401
    key_row = db_execute("SELECT key_prefix FROM api_keys WHERE customer_id = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1", (cust["id"],)).fetchone()
    return jsonify({"name": cust["name"], "tier": cust["tier"], "quota": quota_for_tier(cust["tier"]), "key_prefix": key_row["key_prefix"] if key_row else "none"}), 200

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
    _, data, status = relay_request("/relay/decrypt", "POST", body)
    log_usage("/v1/decrypt", status)
    return jsonify(data), status

@app.route("/v1/export_key", methods=["GET"])
@require_api_key
def export_key():
    _, data, status = relay_request("/relay/export_key", "GET")
    return jsonify(data), status

@app.route("/public/stats")
def public_stats():
    total = db_execute("SELECT COUNT(*) as c FROM customers").fetchone()["c"]
    return jsonify({"total_customers": total})

@app.route("/health")
def health(): return jsonify({"status": "ok", "tunnel": bool(DYNAMIC_RELAY_URL)})

# ── Dashboard UI ──────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ChaosKey — Physical Entropy Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono&family=Instrument+Serif:ital@0;1&family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
<style>
:root {
    --ink: #050608; --ink2: #0a0c12; --line: #1e2535; --paper: #c5cede;
    --lime: #b8f552; --lime-glow: rgba(184, 245, 82, 0.3); --white: #eef2fb;
}
body { background: var(--ink); color: var(--paper); font-family: 'Outfit', sans-serif; margin: 0; overflow-x: hidden; }
#entropy-canvas { position: fixed; inset: 0; z-index: 0; }
.wrap { position: relative; z-index: 1; max-width: 1000px; margin: 0 auto; padding: 2rem; }
nav { display: flex; justify-content: space-between; padding: 1rem 2rem; background: rgba(5,6,8,0.8); backdrop-filter: blur(10px); border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 10; }
.auth-widget, .key-result, .playground, .login-success { 
    background: var(--ink2); border: 1px solid var(--line); border-radius: 16px; 
    padding: 2rem; margin-bottom: 2rem; animation: aura 8s infinite ease-in-out;
}
@keyframes aura { 0%, 100% { box-shadow: 0 0 20px rgba(184,245,82,0.05); } 50% { box-shadow: 0 0 50px rgba(184,245,82,0.15); } }
h1 { font-family: 'Instrument Serif', serif; font-size: 4rem; text-align: center; }
h1 em { color: var(--lime); font-style: italic; text-shadow: 0 0 15px var(--lime-glow); }
input, textarea { width: 100%; background: #11141d; border: 1px solid var(--line); color: white; padding: 0.8rem; border-radius: 8px; margin-bottom: 1rem; font-family: 'DM Mono', monospace; }
.aw-btn, .pg-action { background: var(--lime); color: black; border: none; padding: 1rem; border-radius: 8px; font-weight: 700; cursor: pointer; width: 100%; transition: 0.3s; }
.aw-btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px var(--lime-glow); }
.aw-tabs { display: flex; gap: 1rem; margin-bottom: 1rem; }
.aw-tab { flex: 1; padding: 0.5rem; background: none; border: 1px solid var(--line); color: var(--paper); cursor: pointer; border-radius: 4px; }
.aw-tab.active { border-color: var(--lime); color: var(--lime); }
.out { background: rgba(184,245,82,0.05); color: var(--lime); border-color: var(--lime-glow); }
</style>
</head>
<body>
<canvas id="entropy-canvas"></canvas>
<nav><div style="font-family:'DM Mono';">⬡ ChaosKey</div><div id="nav-status">Checking Engine...</div></nav>
<div class="wrap">
    <h1>Born from <em>Real Chaos</em></h1>
    <div class="auth-widget" id="auth-widget">
        <div class="aw-tabs"><button class="aw-tab active" onclick="tab('reg')">Register</button><button class="aw-tab" onclick="tab('log')">Login</button></div>
        <div id="pane-reg">
            <input id="r-email" placeholder="Email"><input id="r-pw" type="password" placeholder="Password">
            <button class="aw-btn" onclick="doRegister()">Create Account →</button>
        </div>
        <div id="pane-log" style="display:none">
            <input id="l-email" placeholder="Email"><input id="l-pw" type="password" placeholder="Password">
            <button class="aw-btn" onclick="doLogin()">Login →</button>
        </div>
    </div>
    <div class="key-result" id="key-result" style="display:none">
        <div style="color:var(--lime)">✓ Your API Key:</div>
        <div id="key-display" style="word-break:break-all; padding:1rem; background:#000; margin:1rem 0; border-radius:8px;"></div>
        <button class="aw-btn" onclick="scrollToPG()">Go to Playground ↓</button>
    </div>
    <div class="playground" id="pg-section">
        <div id="pg-lock">
            <input id="pg-key-input" placeholder="Paste ck_live_... to unlock">
            <button class="aw-btn" onclick="unlock()">Unlock Playground</button>
        </div>
        <div id="pg-controls" style="display:none">
            <textarea id="plain" placeholder="Message to Encrypt">Hello Chaos!</textarea>
            <button class="pg-action" onclick="enc()">Encrypt with 10s Key</button>
            <textarea id="cipher" class="out" readonly rows="4"></textarea>
        </div>
    </div>
</div>
<script>
let _key = "";
function tab(t){ 
    document.getElementById('pane-reg').style.display=t==='reg'?'block':'none';
    document.getElementById('pane-log').style.display=t==='log'?'block':'none';
}
async function doRegister(){
    const email=document.getElementById('r-email').value, pw=document.getElementById('r-pw').value;
    const r=await fetch('/v1/register',{method:'POST', body:JSON.stringify({email,password:pw})});
    const d=await r.json();
    if(d.api_key){
        _key=d.api_key;
        document.getElementById('key-display').textContent=_key;
        document.getElementById('key-result').style.display='block';
        document.getElementById('auth-widget').style.display='none';
        unlock(_key); // AUTO-ACTIVATE
    } else alert(d.error);
}
async function doLogin(){
    const email=document.getElementById('l-email').value, pw=document.getElementById('l-pw').value;
    const r=await fetch('/v1/login',{method:'POST', body:JSON.stringify({email,password:pw})});
    const d=await r.json();
    if(d.tier) {
        document.getElementById('auth-widget').innerHTML="<h3>Welcome back!</h3><p>Paste your saved key below to start.</p>";
    } else alert(d.error);
}
function unlock(k){
    const key = k || document.getElementById('pg-key-input').value;
    if(key){ _key=key; document.getElementById('pg-lock').style.display='none'; document.getElementById('pg-controls').style.display='block'; }
}
async function enc(){
    const txt=document.getElementById('plain').value;
    const r=await fetch('/v1/encrypt',{method:'POST', headers:{'Authorization':'Bearer '+_key}, body:JSON.stringify({plaintext:txt})});
    const d=await r.json();
    document.getElementById('cipher').value = JSON.stringify(d,null,2);
}
function scrollToPG(){ document.getElementById('pg-section').scrollIntoView({behavior:'smooth'}); }

// ── Chaotic Background ───────────────────────────────────────────────────────
const cv=document.getElementById('entropy-canvas'), cx=cv.getContext('2d');
let W,H,p=[];
function res(){W=cv.width=window.innerWidth;H=cv.height=window.innerHeight;}
window.onresize=res; res();
class Part {
    constructor(){this.init();}
    init(){this.x=Math.random()*W;this.y=Math.random()*H;this.v=0.5+Math.random()*1.5;this.a=Math.random()*Math.PI*2;this.l=0;this.m=100+Math.random()*200;}
    up(){
        this.a += Math.sin(this.x*0.005)*0.1;
        this.x += Math.cos(this.a)*this.v; this.y += Math.sin(this.a)*this.v;
        this.l++; if(this.l>this.m||this.x<0||this.x>W||this.y<0||this.y>H)this.init();
    }
    dr(){
        cx.fillStyle=`rgba(184,245,82,${Math.sin(this.l/this.m*Math.PI)*0.3})`;
        cx.beginPath();cx.arc(this.x,this.y,1.5,0,7);cx.fill();
    }
}
for(let i=0;i<150;i++)p.push(new Part());
function draw(){
    cx.fillStyle='rgba(5,6,8,0.15)';cx.fillRect(0,0,W,H);
    p.forEach(x=>{x.up();x.dr();}); requestAnimationFrame(draw);
}
draw();
</script>
</body>
</html>"""

@app.route("/")
def index(): return render_template_string(DASHBOARD_HTML)

try: init_db()
except Exception as e: log.error(f"DB Init Error: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
