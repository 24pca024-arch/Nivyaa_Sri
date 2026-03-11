"""
NexCloud Multi-Tenant Cloud Platform
Algorithm: ATCA — Adaptive Tenant Cloaking Algorithm
"""

from flask import Flask, request, jsonify, g, render_template
from flask_cors import CORS
import sqlite3, hashlib, hmac, jwt, time, os, json, re
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

SECRET_KEY = os.environ.get("SECRET_KEY", "nexcloud-atca-super-secret-change-in-prod")
DB_PATH    = "nexcloud.db"

# ─────────────────────────────────────────────────────────
#  ATCA ENGINE
# ─────────────────────────────────────────────────────────
class ATCAEngine:

    def generate_cloaked_id(self, tenant_id, domain):
        payload = f"{tenant_id}:{domain}:{SECRET_KEY}"
        digest  = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return f"ATCA{digest[:8].upper()}"

    def extract_tenant_domain(self, request):
        header_tenant = request.headers.get("X-Tenant-Domain")
        if header_tenant:
            return header_tenant.strip().lower()
        host  = request.headers.get("Host", "")
        parts = host.split(".")
        if len(parts) >= 3:
            subdomain = parts[0].lower()
            if subdomain not in ("www", "api", "admin", "localhost"):
                return subdomain
        return request.args.get("tenant", "").lower() or None

    def identify_tenant(self, db, domain):
        if not domain:
            return None
        row = db.execute(
            "SELECT * FROM tenants WHERE domain=? AND status!='inactive'", (domain,)
        ).fetchone()
        return dict(row) if row else None

    def validate_token_tenant(self, token, expected_cloak_id):
        if not token:
            return False, {}, "Missing token"
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return False, {}, "Token expired"
        except jwt.InvalidTokenError as e:
            return False, {}, f"Invalid token: {e}"
        token_tenant_id = payload.get("tenant_id", "")
        if token_tenant_id != expected_cloak_id:
            return False, payload, f"Tenant ID mismatch: token={token_tenant_id} expected={expected_cloak_id}"
        return True, payload, ""

    def run(self, request, require_tenant=True):
        with sqlite3.connect(DB_PATH) as db:
            db.row_factory = sqlite3.Row
            domain = self.extract_tenant_domain(request)
            if not domain and require_tenant:
                self._log(db, None, "MISSING_DOMAIN", "warning", "Request missing tenant domain", request.remote_addr)
                return False, {}, "Missing tenant domain"
            tenant = self.identify_tenant(db, domain) if domain else None
            if not tenant and require_tenant:
                self._log(db, None, "UNKNOWN_DOMAIN", "warning", f"Unknown tenant domain: {domain}", request.remote_addr)
                return False, {}, f"Unknown tenant domain: {domain}"
            if tenant:
                cloak_id = tenant["cloak_id"]
                token    = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
                valid, payload, err = self.validate_token_tenant(token, cloak_id)
                if not valid:
                    self._log(db, tenant["id"], "ATCA_BLOCK", "critical", f"Layer 3 block: {err}", request.remote_addr)
                    db.execute("UPDATE atca_stats SET blocks=blocks+1")
                    db.commit()
                    return False, {}, f"ATCA blocked: {err}"
                db.execute("UPDATE atca_stats SET validations=validations+1")
                self._log(db, tenant["id"], "ATCA_ALLOW", "info", f"Access granted | user={payload.get('user_id')} | action={request.path}", request.remote_addr)
                db.commit()
                return True, {"tenant": tenant, "payload": payload, "cloak_id": cloak_id}, ""
        return True, {}, ""

    def _log(self, db, tenant_id, event_type, severity, desc, ip=""):
        db.execute(
            "INSERT INTO security_events (tenant_id,event_type,severity,description,source_ip,timestamp) VALUES (?,?,?,?,?,?)",
            (tenant_id, event_type, severity, desc, ip, datetime.now().isoformat())
        )

atca = ATCAEngine()

# ─────────────────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────────────────
def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
    return db

@app.teardown_appcontext
def close_db(e=None):
    db = getattr(g, '_db', None)
    if db: db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
            domain TEXT NOT NULL UNIQUE, schema_name TEXT NOT NULL,
            cloak_id TEXT NOT NULL UNIQUE, plan TEXT DEFAULT 'starter',
            status TEXT DEFAULT 'active', iso_mode TEXT DEFAULT 'shared',
            mem_quota REAL DEFAULT 5.0, mem_used REAL DEFAULT 0.0,
            req_limit INTEGER DEFAULT 500, req_min INTEGER DEFAULT 0,
            monthly_cost REAL DEFAULT 500.0, compute_cost REAL DEFAULT 0.0,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT,
            event_type TEXT, severity TEXT, description TEXT,
            source_ip TEXT, timestamp TEXT
        );
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT,
            amount REAL, status TEXT DEFAULT 'pending', period TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS atca_stats (
            id INTEGER PRIMARY KEY CHECK (id=1),
            validations INTEGER DEFAULT 0, blocks INTEGER DEFAULT 0, rotations INTEGER DEFAULT 0
        );
        INSERT OR IGNORE INTO atca_stats (id,validations,blocks,rotations) VALUES (1,14823,247,6);
        """)
        seeds = [
            ("T001","TechFlow Inc",   "admin@techflow.com",  "techflow",  "enterprise","active",   "schema",32, 18.2,5000,4200,8000,1200),
            ("T002","DataBridge Ltd", "admin@databridge.com","databridge","growth",    "warning",  "shared",10, 9.8, 2000,1900,2000,400),
            ("T003","Nexus Analytics","admin@nexus.com",     "nexus",     "enterprise","active",   "db",   30, 14.5,5000,2100,8000,900),
            ("T004","CloudMesh",      "admin@cloudmesh.com", "cloudmesh", "starter",   "active",   "shared",5,  3.2, 500, 480, 500, 80),
            ("T005","Quantum SaaS",   "admin@quantum.com",   "quantum",   "growth",    "active",   "schema",10, 7.1, 2000,1200,2000,300),
            ("T006","ByteForge",      "admin@byteforge.com", "byteforge", "starter",   "throttled","shared",5,  4.8, 500, 510, 500, 120),
        ]
        for s in seeds:
            tid, name, email, domain = s[0], s[1], s[2], s[3]
            schema   = f"{domain}_schema"
            cloak_id = atca.generate_cloaked_id(tid, domain)
            db.execute(
                """INSERT OR IGNORE INTO tenants
                   (id,name,email,domain,schema_name,cloak_id,plan,status,iso_mode,
                    mem_quota,mem_used,req_limit,req_min,monthly_cost,compute_cost,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (tid,name,email,domain,schema,cloak_id,s[4],s[5],s[6],s[7],s[8],s[9],s[10],s[11],s[12],datetime.now().isoformat())
            )
        db.executemany(
            "INSERT OR IGNORE INTO security_events (tenant_id,event_type,severity,description,source_ip,timestamp) VALUES (?,?,?,?,?,?)",
            [
                ("T002","ATCA_BLOCK","critical","Cross-tenant access: token mismatch. IP 45.77.12.99","45.77.12.99","2024-01-15 02:14:33"),
                ("T001","ATCA_BLOCK","critical","URL manipulation: databridge domain + techflow token","12.34.56.78","2024-01-15 01:58:12"),
                ("T003","ATCA_BLOCK","warning","API exploit: ?tenant=T002 with T003 JWT","99.88.77.66","2024-01-15 01:22:07"),
                ("T006","CLOAK_ROTATION","info","CloakedID rotated for T006","internal","2024-01-15 00:55:41"),
                ("SYSTEM","ATCA_ALLOW","info","1,240 requests validated. Zero schema exposures.","internal","2024-01-15 00:30:09"),
            ]
        )
        db.commit()

# ─────────────────────────────────────────────────────────
#  AUTH DECORATORS
# ─────────────────────────────────────────────────────────
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization","").replace("Bearer ","").strip()
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if payload.get("role") != "admin":
                return jsonify({"error":"Admin only"}), 403
            g.admin = payload
        except Exception as e:
            return jsonify({"error":f"Auth failed: {e}"}), 401
        return f(*args, **kwargs)
    return decorated

def require_atca(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        allowed, ctx, err = atca.run(request, require_tenant=True)
        if not allowed:
            return jsonify({"error":"ATCA validation failed","detail":err,"code":"ATCA_BLOCK"}), 403
        g.tenant   = ctx["tenant"]
        g.cloak_id = ctx["cloak_id"]
        g.jwt_user = ctx["payload"]
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────────────────
#  FIREWALL
# ─────────────────────────────────────────────────────────
ATTACK_PATTERNS = [
    (r"('|--|;|\/\*|\*\/|xp_|exec\s)",         "SQL_INJECTION"),
    (r"(<script|javascript:|onerror=|onload=)",  "XSS"),
    (r"(\.\./|\.\.\\|%2e%2e)",                  "PATH_TRAVERSAL"),
    (r"(union\s+select|drop\s+table)",           "SQL_INJECTION"),
]

@app.before_request
def firewall():
    payload = request.url + str(dict(request.args))
    if request.is_json:
        payload += json.dumps(request.get_json(silent=True) or {})
    for pattern, attack_type in ATTACK_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            with sqlite3.connect(DB_PATH) as db:
                db.execute(
                    "INSERT INTO security_events (tenant_id,event_type,severity,description,source_ip,timestamp) VALUES (?,?,?,?,?,?)",
                    ("UNKNOWN",attack_type,"critical",f"Firewall: {attack_type} pattern",request.remote_addr,datetime.now().isoformat())
                )
                db.commit()
            return jsonify({"error":"Blocked by security firewall","code":attack_type}), 403

# ─────────────────────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────────────────────
@app.post("/api/admin/login")
def admin_login():
    data = request.get_json() or {}
    if data.get("username")=="admin" and data.get("password")=="nexcloud2024":
        token = jwt.encode(
            {"sub":"admin","role":"admin","exp":datetime.utcnow()+timedelta(hours=8)},
            SECRET_KEY, algorithm="HS256"
        )
        return jsonify({"token":token,"message":"Login successful"})
    return jsonify({"error":"Invalid credentials"}), 401

@app.post("/api/tenant/login")
def tenant_login():
    data   = request.get_json() or {}
    domain = data.get("domain","").lower()
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        tenant = db.execute(
            "SELECT * FROM tenants WHERE domain=? AND status!='inactive'",(domain,)
        ).fetchone()
    if not tenant or data.get("password","") != "demo123":
        return jsonify({"error":"Invalid credentials"}), 401
    if tenant["status"] == "throttled":
        return jsonify({"error":"Tenant throttled — quota exceeded","retry_after":60}), 429
    token = jwt.encode(
        {"user_id":1,"tenant_id":tenant["cloak_id"],"domain":domain,"role":"user","exp":datetime.utcnow()+timedelta(hours=4)},
        SECRET_KEY, algorithm="HS256"
    )
    return jsonify({"token":token,"tenant":tenant["name"],"cloak_id":tenant["cloak_id"],"message":"Login successful"})

# ─────────────────────────────────────────────────────────
#  ADMIN API ROUTES
# ─────────────────────────────────────────────────────────
@app.get("/api/tenants")
@require_admin
def list_tenants():
    db   = get_db()
    rows = db.execute(
        "SELECT id,name,email,domain,cloak_id,plan,status,iso_mode,mem_quota,mem_used,req_limit,req_min,monthly_cost,compute_cost,created_at FROM tenants WHERE status!='inactive' ORDER BY created_at DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post("/api/tenants")
@require_admin
def create_tenant():
    data = request.get_json() or {}
    req_fields = ["name","email","domain","plan","mem_quota","req_limit","iso_mode"]
    if not all(k in data for k in req_fields):
        return jsonify({"error":f"Missing fields: {req_fields}"}), 400
    costs  = {"starter":500,"growth":2000,"enterprise":8000}
    tid    = f"T{int(time.time()*1000)%100000:05d}"
    schema = f"{data['domain']}_schema"
    cloak  = atca.generate_cloaked_id(tid, data["domain"])
    db = get_db()
    try:
        db.execute(
            "INSERT INTO tenants (id,name,email,domain,schema_name,cloak_id,plan,status,iso_mode,mem_quota,mem_used,req_limit,req_min,monthly_cost,compute_cost,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid,data["name"],data["email"],data["domain"].lower(),schema,cloak,data["plan"],"active",data["iso_mode"],data["mem_quota"],0.1,data["req_limit"],0,costs.get(data["plan"],500),0,datetime.now().isoformat())
        )
        db.commit()
    except sqlite3.IntegrityError as e:
        return jsonify({"error":f"Duplicate entry: {e}"}), 409
    return jsonify({"message":"Tenant created","tenant_id":tid,"cloak_id":cloak,"domain":data["domain"]}), 201

@app.delete("/api/tenants/<tid>")
@require_admin
def delete_tenant(tid):
    db = get_db()
    db.execute("UPDATE tenants SET status='inactive' WHERE id=?",(tid,))
    db.commit()
    return jsonify({"message":f"Tenant {tid} deactivated"})

@app.get("/api/dashboard")
@require_admin
def dashboard():
    db  = get_db()
    tc  = db.execute("SELECT COUNT(*) as c FROM tenants WHERE status!='inactive'").fetchone()["c"]
    mu  = db.execute("SELECT SUM(mem_used) as s FROM tenants WHERE status!='inactive'").fetchone()["s"] or 0
    mrr = db.execute("SELECT SUM(monthly_cost+compute_cost) as s FROM tenants WHERE status!='inactive'").fetchone()["s"] or 0
    st  = db.execute("SELECT * FROM atca_stats WHERE id=1").fetchone()
    thr = db.execute("SELECT COUNT(*) as c FROM security_events WHERE severity='critical'").fetchone()["c"]
    return jsonify({"active_tenants":tc,"total_memory_used_gb":round(mu,2),"monthly_revenue":round(mrr,2),"atca_blocks":st["blocks"] if st else 0,"atca_validations":st["validations"] if st else 0,"threats_total":thr})

@app.get("/api/memory")
@require_admin
def memory_status():
    db          = get_db()
    rows        = db.execute("SELECT id,name,cloak_id,mem_used,mem_quota,status FROM tenants WHERE status!='inactive' ORDER BY mem_used DESC").fetchall()
    tenants     = [dict(r) for r in rows]
    total_used  = sum(t["mem_used"]  for t in tenants)
    total_quota = sum(t["mem_quota"] for t in tenants)
    noisy       = [t for t in tenants if t["mem_used"]/t["mem_quota"] > 0.85]
    return jsonify({"total_used_gb":round(total_used,2),"total_quota_gb":round(total_quota,2),"utilization_pct":round(total_used/max(total_quota,1)*100,1),"noisy_tenants":noisy,"tenants":tenants})

@app.get("/api/payments")
@require_admin
def payments():
    db      = get_db()
    tenants = db.execute("SELECT * FROM tenants WHERE status!='inactive'").fetchall()
    result, mrr = [], 0
    for t in [dict(r) for r in tenants]:
        mc    = round(t["mem_used"]*0.08*30, 2)
        total = t["monthly_cost"]+t["compute_cost"]+mc
        mrr  += total
        result.append({"tenant_id":t["id"],"name":t["name"],"cloak_id":t["cloak_id"],"plan":t["plan"],"memory_cost":mc,"compute_cost":t["compute_cost"],"base_cost":t["monthly_cost"],"total_due":round(total,2),"status":"overdue" if t["id"]=="T006" else "paid","next_billing":(datetime.now()+timedelta(days=30)).strftime("%Y-%m-%d")})
    return jsonify({"mrr":round(mrr,2),"invoices":result})

@app.get("/api/atca/status")
@require_admin
def atca_status():
    db   = get_db()
    st   = db.execute("SELECT * FROM atca_stats WHERE id=1").fetchone()
    evts = db.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10").fetchall()
    return jsonify({"algorithm":"ATCA — Adaptive Tenant Cloaking Algorithm","version":"1.0","status":"active","stats":dict(st) if st else {},"recent_events":[dict(e) for e in evts]})

@app.get("/api/security/events")
@require_admin
def security_events():
    limit = int(request.args.get("limit", 50))
    db    = get_db()
    rows  = db.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?",(limit,)).fetchall()
    return jsonify({"events":[dict(r) for r in rows],"total":len(rows)})

# ─────────────────────────────────────────────────────────
#  TENANT ROUTES
# ─────────────────────────────────────────────────────────
@app.get("/api/data/my-records")
@require_atca
def tenant_records():
    tenant   = g.tenant
    jwt_user = g.jwt_user
    db       = get_db()
    events   = db.execute(
        "SELECT timestamp,event_type,severity,description FROM security_events WHERE tenant_id=? ORDER BY timestamp DESC LIMIT 20",
        (tenant["id"],)
    ).fetchall()
    return jsonify({"tenant":tenant["name"],"cloak_id":tenant["cloak_id"],"domain":tenant["domain"],"memory_used_gb":tenant["mem_used"],"memory_quota_gb":tenant["mem_quota"],"status":tenant["status"],"user_id":jwt_user.get("user_id"),"my_events":[dict(e) for e in events]})

# ─────────────────────────────────────────────────────────
#  HOME & HEALTH
# ─────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")

@app.get("/api/health")
def health():
    return jsonify({"status":"ok","platform":"NexCloud","algorithm":"ATCA v1.0 active"})

# ─────────────────────────────────────────────────────────
#  START SERVER
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        init_db()
    print("=" * 60)
    print("  NexCloud — ATCA Multi-Tenant Platform")
    print("  Open : http://localhost:5000")
    print("  Admin: admin / nexcloud2024")
    print("  Tenant: techflow / demo123")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)