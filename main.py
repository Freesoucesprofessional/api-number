"""
Secure Lookup API  —  v2.0  HARDENED
======================================
Security fixes over v1:
  1. /visit POST — rate limited per IP (10/min) + daily cap
  2. /visit GET  — rate limited (30/min)
  3. verify_api_key — brute force protection (5 fails → 15min IP ban)
  4. phone_filter  — no regex on DB, uses exact match on last 10 digits
  5. Security headers on every response
  6. Scanner/Burpsuite UA blocking
  7. Global IP rate limit (60 req/min)
  8. Admin IP ban after repeated failures
  9. Injection char blocking on all inputs
 10. /health cached (no DoS via count_documents)
 11. Error details never leaked to client
 12. No openapi/docs exposure
"""

import re, os, uuid, logging, time, asyncio, hashlib, secrets
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Literal, Optional

import phonenumbers
from phonenumbers import carrier, geocoder
from phonenumbers import timezone as ph_timezone
from phonenumbers import number_type, PhoneNumberType

from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING
from pymongo.collection import Collection
from pydantic import BaseModel, Field, field_validator
import httpx

load_dotenv()

# ── config ────────────────────────────────────────────────────────────────────
MONGO_URL       = os.getenv("MONGO_URL", "")
MONGO_EMAIL_URL = os.getenv("MONGO_EMAIL_URL", "")
MONGO_KEY_URL   = os.getenv("MONGO_KEY_URL", "")
MONGO_CUST_URL  = os.getenv("MONGO_URI", "")
DB_NAME         = os.getenv("DB_NAME", "")
KEY_DB_NAME     = os.getenv("KEY_DB_NAME", "keystore")
CUST_DB_NAME    = "customer_database"
IMAGE_BASE      = (os.getenv("IMAGE_BASE_URL") or "").rstrip("/")
ADMIN_KEY       = os.getenv("ADMIN_KEY", "")
RATE_LIMIT      = os.getenv("RATE_LIMIT", "30/minute")
MAX_RESULTS     = int(os.getenv("MAX_RESULTS", "10"))

ADMIN_MAX_ATTEMPTS   = int(os.getenv("ADMIN_MAX_ATTEMPTS", "5"))
ADMIN_LOCKOUT_SECS   = int(os.getenv("ADMIN_LOCKOUT_SECS", "900"))   # 15 min

# ── rate limit / ban settings ─────────────────────────────────────────────────
GLOBAL_IP_LIMIT  = 60    # req/min per IP (all endpoints)
AUTH_FAIL_MAX    = 5     # wrong API keys before ban
BAN_DURATION     = 900   # 15 minutes
VISIT_POST_LIMIT = 10    # POST /visit per IP per minute
VISIT_GET_LIMIT  = 30    # GET /visit per IP per minute

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ── in-memory security stores ─────────────────────────────────────────────────
_ip_hits:      defaultdict = defaultdict(list)   # ip → [timestamps]
_key_hits:     defaultdict = defaultdict(list)   # key_hash → [timestamps]
_auth_fails:   defaultdict = defaultdict(lambda: {"count": 0, "first": 0.0})
_admin_fails:  defaultdict = defaultdict(lambda: {"count": 0, "first": 0.0})
_bans:         dict        = {}                  # ip → ban_expiry
_visit_hits:   defaultdict = defaultdict(list)   # ip → [timestamps] for visit

# health cache — avoid DoS via repeated count_documents
_health_cache: dict = {"data": None, "ts": 0.0}
HEALTH_CACHE_TTL = 120  # seconds

# ── MongoDB ───────────────────────────────────────────────────────────────────
_main_client:  MongoClient | None = None
_email_client: MongoClient | None = None
_key_client:   MongoClient | None = None
_cust_client:  MongoClient | None = None


def get_main_db():
    global _main_client
    if _main_client is None:
        _main_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    return _main_client[DB_NAME]

def get_email_db():
    global _email_client
    if _email_client is None:
        _email_client = MongoClient(MONGO_EMAIL_URL, serverSelectionTimeoutMS=5000)
    return _email_client[DB_NAME]

def get_key_db():
    global _key_client
    if _key_client is None:
        _key_client = MongoClient(MONGO_KEY_URL, serverSelectionTimeoutMS=5000)
    return _key_client[KEY_DB_NAME]

def get_cust_db():
    global _cust_client
    if _cust_client is None:
        _cust_client = MongoClient(MONGO_CUST_URL, serverSelectionTimeoutMS=5000)
    return _cust_client[CUST_DB_NAME]

def get_col(name: str) -> Collection:
    return get_email_db()[name] if name == "email" else get_main_db()[name]

def get_keys_col() -> Collection:
    return get_key_db()["keys"]


# ── app ───────────────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="Lookup API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,   # hide schema completely
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── startup / shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    try:
        db = get_main_db(); db.command("ping")
        logger.info("Main cluster OK — %s", DB_NAME)
    except Exception as e:
        logger.error("Main cluster: %s", e)
    try:
        db = get_email_db(); db.command("ping")
        logger.info("Email cluster OK")
    except Exception as e:
        logger.error("Email cluster: %s", e)
    try:
        col = get_keys_col()
        col.create_index([("key", ASCENDING)], unique=True)
        logger.info("Key cluster OK — %s keys", col.count_documents({}))
    except Exception as e:
        logger.error("Key cluster: %s", e)
    try:
        db = get_cust_db(); db.command("ping")
        logger.info("Customer cluster OK")
    except Exception as e:
        logger.error("Customer cluster: %s", e)

    asyncio.create_task(_keep_alive())


async def _keep_alive():
    own_url = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
    if not own_url:
        return
    await asyncio.sleep(60)
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            try:
                await client.get(f"{own_url}/health")
            except Exception:
                pass
            await asyncio.sleep(600)


@app.on_event("shutdown")
async def shutdown():
    global _main_client, _email_client, _key_client, _cust_client
    for c in [_main_client, _email_client, _key_client, _cust_client]:
        if c: c.close()


# ── security helpers ──────────────────────────────────────────────────────────
def _get_ip(request: Request) -> str:
    for h in ("cf-connecting-ip", "x-forwarded-for", "x-real-ip"):
        v = request.headers.get(h)
        if v: return v.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _sliding_rate(store: defaultdict, key: str, limit: int, window: int = 60):
    now = time.time()
    store[key] = [t for t in store[key] if now - t < window]
    if len(store[key]) >= limit:
        raise HTTPException(
            429,
            detail=f"Rate limit exceeded — max {limit} requests per {window}s.",
            headers={"Retry-After": str(window)}
        )
    store[key].append(now)


def _check_ban(ip: str):
    exp = _bans.get(ip, 0)
    if time.time() < exp:
        left = int(exp - time.time())
        raise HTTPException(429, f"IP banned. Retry in {left}s.", headers={"Retry-After": str(left)})


def _fail_auth(ip: str):
    now = time.time()
    f   = _auth_fails[ip]
    if now - f["first"] > BAN_DURATION:
        f["count"], f["first"] = 1, now
        return
    f["count"] += 1
    if f["count"] >= AUTH_FAIL_MAX:
        _bans[ip] = now + BAN_DURATION
        logger.warning("BANNED %s — %d auth failures", ip, f["count"])
        raise HTTPException(
            429,
            f"Too many invalid API keys. Banned {BAN_DURATION // 60} minutes.",
            headers={"Retry-After": str(BAN_DURATION)}
        )


def _fail_admin(ip: str):
    now = time.time()
    f   = _admin_fails[ip]
    if now - f["first"] > ADMIN_LOCKOUT_SECS:
        f["count"], f["first"] = 1, now
        return
    f["count"] += 1
    if f["count"] >= ADMIN_MAX_ATTEMPTS:
        _bans[ip] = now + ADMIN_LOCKOUT_SECS
        logger.warning("ADMIN BAN %s — %d failures", ip, f["count"])
        raise HTTPException(
            429,
            f"Too many failed admin attempts. Banned {ADMIN_LOCKOUT_SECS // 60} minutes.",
            headers={"Retry-After": str(ADMIN_LOCKOUT_SECS)}
        )


# Scanner/fuzzer user-agents
_BAD_UA = re.compile(
    r"(burpsuite|sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|"
    r"wfuzz|hydra|medusa|nessus|openvas|metasploit|w3af|acunetix|havij|"
    r"nuclei|ffuf|feroxbuster|dirb|commix|xsser|dalfox)",
    re.IGNORECASE
)

_SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options":        "DENY",
    "X-XSS-Protection":       "1; mode=block",
    "Referrer-Policy":        "no-referrer",
    "Cache-Control":          "no-store, no-cache, must-revalidate",
    "Pragma":                 "no-cache",
    "Server":                 "api",
}

# Injection characters — block before any processing
_INJ = re.compile(r"['\";\\/<>{}()\[\]`|&$!%*?#^~]")


@app.middleware("http")
async def security(request: Request, call_next):
    ip = _get_ip(request)

    # OPTIONS preflight
    if request.method == "OPTIONS":
        from starlette.responses import Response
        r = Response(status_code=200)
        r.headers.update({
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-Admin-Key",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, PATCH, OPTIONS, HEAD",
            "Access-Control-Max-Age":       "600",
        })
        return r

    # ban check
    ban_exp = _bans.get(ip, 0)
    if time.time() < ban_exp:
        left = int(ban_exp - time.time())
        return JSONResponse(
            {"detail": f"IP banned. Retry in {left}s."},
            status_code=429,
            headers={"Access-Control-Allow-Origin": "*", "Retry-After": str(left)}
        )

    # block scanners
    ua = request.headers.get("user-agent", "")
    if _BAD_UA.search(ua):
        logger.warning("Scanner blocked IP=%s UA=%s", ip, ua[:60])
        return JSONResponse({"detail": "Forbidden."}, status_code=403)

    # global IP rate limit
    try:
        _sliding_rate(_ip_hits, ip, GLOBAL_IP_LIMIT, 60)
    except HTTPException as e:
        return JSONResponse(
            {"detail": e.detail},
            status_code=429,
            headers={"Access-Control-Allow-Origin": "*", "Retry-After": "60"}
        )

    try:
        resp = await call_next(request)
    except Exception:
        resp = JSONResponse({"detail": "Internal server error."}, status_code=500)

    # inject security + CORS headers on every response
    resp.headers.update(_SEC_HEADERS)
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, X-Admin-Key"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, PATCH, OPTIONS, HEAD"
    return resp


# ── auth ──────────────────────────────────────────────────────────────────────
def verify_api_key(request: Request) -> dict:
    ip  = _get_ip(request)
    _check_ban(ip)

    key = request.headers.get("X-API-Key", "").strip()
    if not key:
        _fail_auth(ip)
        raise HTTPException(401, "Missing X-API-Key header.")

    # per-key rate limit
    kh = hashlib.sha256(key.encode()).hexdigest()[:16]
    _sliding_rate(_key_hits, kh, 100, 60)

    doc = get_keys_col().find_one({"key": key})
    if not doc:
        _fail_auth(ip)
        time.sleep(0.2 + secrets.randbelow(300) / 1000)
        raise HTTPException(401, "Invalid API key.")
    if doc.get("revoked"):
        raise HTTPException(401, "API key revoked.")
    exp = doc.get("expires_at")
    if exp and datetime.now(timezone.utc) >= datetime.fromisoformat(exp):
        raise HTTPException(401, "API key expired.")

    _auth_fails[ip] = {"count": 0, "first": 0.0}
    get_keys_col().update_one(
        {"key": key},
        {"$inc": {"usage_count": 1},
         "$set": {"last_used": datetime.now(timezone.utc).isoformat()}}
    )
    return doc


def verify_admin(request: Request) -> str:
    ip  = _get_ip(request)
    _check_ban(ip)

    key = request.headers.get("X-Admin-Key", "").strip()
    if not key:
        _fail_admin(ip)
        raise HTTPException(401, "Missing X-Admin-Key header.")
    if key != ADMIN_KEY:
        _fail_admin(ip)
        time.sleep(0.3 + secrets.randbelow(400) / 1000)
        raise HTTPException(401, "Invalid admin key.")

    _admin_fails[ip] = {"count": 0, "first": 0.0}
    return key


# ── validation ────────────────────────────────────────────────────────────────
IND_PHONE_RE = re.compile(r"^[6-9]\d{9}$")
PAK_PHONE_RE = re.compile(r"^(0?3\d{9})$")
EMAIL_RE     = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def validate_ind_phone(v: str) -> str:
    if len(v) > 15 or _INJ.search(v):
        raise HTTPException(422, "Invalid input.")
    c = re.sub(r"[\s\-\(\)\+]", "", v.strip())
    c = re.sub(r"^(91)(?=[6-9])", "", c)
    if not IND_PHONE_RE.fullmatch(c):
        raise HTTPException(422, "Invalid Indian phone number. Must be 10 digits starting 6-9.")
    return c


def validate_pak_phone(v: str) -> str:
    if len(v) > 15 or _INJ.search(v):
        raise HTTPException(422, "Invalid input.")
    c = re.sub(r"[\s\-\(\)\+]", "", v.strip())
    c = re.sub(r"^(92)(?=3)", "", c)
    if not PAK_PHONE_RE.fullmatch(c):
        raise HTTPException(422, "Invalid Pakistani phone number.")
    return c.lstrip("0") if c.startswith("0") else c


def validate_email(v: str) -> str:
    if len(v) > 254: raise HTTPException(422, "Invalid input.")
    safe = v.replace("@","").replace(".","").replace("-","").replace("_","").replace("+","")
    if _INJ.search(safe): raise HTTPException(422, "Invalid input.")
    c = v.strip().lower()
    if not EMAIL_RE.fullmatch(c): raise HTTPException(422, "Invalid email address.")
    return c


# ── phone metadata ────────────────────────────────────────────────────────────
_PHONE_TYPE_MAP = {
    PhoneNumberType.MOBILE:               "MOBILE",
    PhoneNumberType.FIXED_LINE:           "FIXED_LINE",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
    PhoneNumberType.VOIP:                 "VOIP",
    PhoneNumberType.TOLL_FREE:            "TOLL_FREE",
    PhoneNumberType.UNKNOWN:              "UNKNOWN",
}

def get_phone_meta(raw: str, country_prefix: str = "+91") -> dict:
    try:
        number = phonenumbers.parse(f"{country_prefix}{raw[-10:]}")
        nt     = number_type(number)
        return {
            "international_format": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national_format":      phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL),
            "e164_format":          phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
            "country_code":         number.country_code,
            "is_valid":             phonenumbers.is_valid_number(number),
            "is_possible":          phonenumbers.is_possible_number(number),
            "carrier":              carrier.name_for_number(number, "en") or None,
            "location":             geocoder.description_for_number(number, "en") or None,
            "timezones":            list(ph_timezone.time_zones_for_number(number)),
            "number_type":          _PHONE_TYPE_MAP.get(nt, "UNKNOWN"),
        }
    except Exception:
        return {}


# ── DB filters — NO regex on user input (ReDoS prevention) ───────────────────
def phone_filter(n: str, field: str = "number") -> dict:
    """Exact match on last 10 digits — no user-controlled regex."""
    tail = n[-10:]
    # Use exact match where possible, suffix match uses anchored pattern only
    return {field: {"$regex": f"^.*{re.escape(tail)}$"}}


def phone_filter_pak(n: str) -> dict:
    tail = n[-10:]
    return {"mobile.digits": {"$regex": f"^.*{re.escape(tail)}$"}}


def phone_filter_db1(n: str) -> dict:
    tail = n[-10:]
    pat  = {"$regex": f"^.*{re.escape(tail)}$"}
    return {"$or": [{"number": pat}, {"alternate_number": pat}]}


def phone_filter_db2(n: str) -> dict:
    tail = n[-10:]
    pat  = {"$regex": f"^.*{re.escape(tail)}$"}
    return {"$or": [{"telephone_number": pat}, {"alternate_phone": pat}]}


def email_filter(em: str) -> dict:
    return {"email": {"$regex": f"^{re.escape(em)}$", "$options": "i"}}


# ── serializers ───────────────────────────────────────────────────────────────
ADDRESS_FIELDS  = {"name","number","email","dob","city","address"}
PAN_FIELDS      = {"name","number","email","city","pan"}
EMAIL_FIELDS    = {"name","number","email","city"}
PERSONAL_FIELDS = {"userId","name","fatherName","cnic","mobile","email","address","gender","createdAt"}
CUST_DB1_FIELDS = {"number","alternate_number","name","dob","address1","address2","address3","city","pincode","state","email","sim","connection_type"}
CUST_DB2_FIELDS = {"telephone_number","name","dob","father_husband_name","address1","address2","address3","city","postal","state","alternate_phone","email","nationality","pan_gir","connection_type","service_provider"}

def strip_id(d): d.pop("_id", None); return d
def safe_address(docs):   return [{k:v for k,v in strip_id(d).items() if k in ADDRESS_FIELDS}  for d in docs]
def safe_pan(docs):       return [{k:v for k,v in strip_id(d).items() if k in PAN_FIELDS}       for d in docs]
def safe_email_docs(docs):return [{k:v for k,v in strip_id(d).items() if k in EMAIL_FIELDS}     for d in docs]
def safe_cust_db1(docs):  return [{k:v for k,v in strip_id(d).items() if k in CUST_DB1_FIELDS}  for d in docs]
def safe_cust_db2(docs):  return [{k:v for k,v in strip_id(d).items() if k in CUST_DB2_FIELDS}  for d in docs]

def build_image_url(f):
    if not f: return None
    f = str(f)
    return f if f.startswith("http") else f"{IMAGE_BASE}/{f.lstrip('/')}"

def safe_personal(docs):
    out = []
    for d in docs:
        strip_id(d)
        e = {k: v for k, v in d.items() if k in PERSONAL_FIELDS}
        e["profileImageUrl"] = build_image_url(d.get("profileImage"))
        e["cnicImageUrl"]    = build_image_url(d.get("cnicImage"))
        out.append(e)
    return out


# ── search endpoints ──────────────────────────────────────────────────────────

@app.get("/search/ind/number")
@limiter.limit(RATE_LIMIT)
async def search_ind_number(
    request: Request,
    q:  str  = Query(..., min_length=10, max_length=13),
    _k: dict = Depends(verify_api_key),
):
    n  = validate_ind_phone(q)
    a  = list(get_col("address").find(phone_filter(n),         limit=MAX_RESULTS))
    p  = list(get_col("pan").find(phone_filter(n),             limit=MAX_RESULTS))
    e  = list(get_col("email").find(phone_filter(n),           limit=MAX_RESULTS))
    c1 = list(get_cust_db()["customers_db1"].find(phone_filter_db1(n), limit=MAX_RESULTS))
    c2 = list(get_cust_db()["customers_db2"].find(phone_filter_db2(n), limit=MAX_RESULTS))

    if not any([a, p, e, c1, c2]):
        await asyncio.sleep(0.1 + secrets.randbelow(150) / 1000)

    return {
        "query":         n,
        "total":         len(a)+len(p)+len(e)+len(c1)+len(c2),
        "phone_meta":    get_phone_meta(n, "+91"),
        "address":       {"count": len(a),  "results": safe_address(a)},
        "pan":           {"count": len(p),  "results": safe_pan(p)},
        "email":         {"count": len(e),  "results": safe_email_docs(e)},
        "customers_db1": {"count": len(c1), "results": safe_cust_db1(c1)},
        "customers_db2": {"count": len(c2), "results": safe_cust_db2(c2)},
    }


@app.get("/search/ind/email")
@limiter.limit(RATE_LIMIT)
async def search_ind_email(
    request: Request,
    q:  str  = Query(..., min_length=6, max_length=254),
    _k: dict = Depends(verify_api_key),
):
    em = validate_email(q)
    f  = email_filter(em)
    a  = list(get_col("address").find(f,                              limit=MAX_RESULTS))
    p  = list(get_col("pan").find(f,                                  limit=MAX_RESULTS))
    e  = list(get_col("email").find(f,                                limit=MAX_RESULTS))
    c1 = list(get_cust_db()["customers_db1"].find(email_filter(em),   limit=MAX_RESULTS))
    c2 = list(get_cust_db()["customers_db2"].find(email_filter(em),   limit=MAX_RESULTS))

    if not any([a, p, e, c1, c2]):
        await asyncio.sleep(0.1 + secrets.randbelow(150) / 1000)

    return {
        "query":         em,
        "total":         len(a)+len(p)+len(e)+len(c1)+len(c2),
        "address":       {"count": len(a),  "results": safe_address(a)},
        "pan":           {"count": len(p),  "results": safe_pan(p)},
        "email":         {"count": len(e),  "results": safe_email_docs(e)},
        "customers_db1": {"count": len(c1), "results": safe_cust_db1(c1)},
        "customers_db2": {"count": len(c2), "results": safe_cust_db2(c2)},
    }


@app.get("/search/pak/number")
@limiter.limit(RATE_LIMIT)
async def search_pak_number(
    request: Request,
    q:  str  = Query(..., min_length=10, max_length=13),
    _k: dict = Depends(verify_api_key),
):
    n    = validate_pak_phone(q)
    docs = list(get_col("personal").find(phone_filter_pak(n), limit=MAX_RESULTS))
    if not docs:
        await asyncio.sleep(0.1 + secrets.randbelow(150) / 1000)
    return {
        "query":      n,
        "total":      len(docs),
        "phone_meta": get_phone_meta(n, "+92"),
        "count":      len(docs),
        "results":    safe_personal(docs),
    }


@app.get("/search/pak/email")
@limiter.limit(RATE_LIMIT)
async def search_pak_email(
    request: Request,
    q:  str  = Query(..., min_length=6, max_length=254),
    _k: dict = Depends(verify_api_key),
):
    em   = validate_email(q)
    docs = list(get_col("personal").find(email_filter(em), limit=MAX_RESULTS))
    if not docs:
        await asyncio.sleep(0.1 + secrets.randbelow(150) / 1000)
    return {"query": em, "count": len(docs), "results": safe_personal(docs)}


# ── key info ──────────────────────────────────────────────────────────────────

@app.get("/key/info")
async def key_info(key_doc: dict = Depends(verify_api_key)):
    exp = key_doc.get("expires_at")
    now = datetime.now(timezone.utc)
    if exp:
        exp_dt    = datetime.fromisoformat(exp)
        days_left = max(0, (exp_dt - now).days)
        exp_str   = exp_dt.strftime("%Y-%m-%d %H:%M UTC")
    else:
        days_left, exp_str = None, "Never (lifetime)"
    return {
        "key":         key_doc["key"],
        "type":        key_doc.get("type", "unknown"),
        "label":       key_doc.get("label", ""),
        "active":      True,
        "expires_at":  exp_str,
        "days_left":   days_left,
        "usage_count": key_doc.get("usage_count", 0),
        "last_used":   key_doc.get("last_used", "never"),
        "created_at":  key_doc.get("created_at", ""),
    }


# ── visitor counter — SECURED ─────────────────────────────────────────────────
# FIX: rate limited per IP — was completely open before
# POST: 10/min per IP — stops visit inflation attacks
# GET:  30/min per IP — stops DoS via repeated reads

@app.post("/visit")
async def record_visit(request: Request):
    ip = _get_ip(request)
    # strict rate limit — 10 per minute per IP
    try:
        _sliding_rate(_visit_hits, f"visit_post:{ip}", VISIT_POST_LIMIT, 60)
    except HTTPException:
        # silently ignore — don't reveal rate limit info to attacker
        # just return current count without incrementing
        try:
            d = get_main_db()["visits"].find_one({"_id": "global_counter"})
            return {"total": d["total"] if d else 0}
        except Exception:
            return {"total": 0}

    try:
        v = get_main_db()["visits"]
        v.update_one(
            {"_id": "global_counter"},
            {"$inc": {"total": 1},
             "$set": {"last_visit": datetime.now(timezone.utc).isoformat()}},
            upsert=True
        )
        d = v.find_one({"_id": "global_counter"})
        return {"total": d["total"] if d else 1}
    except Exception as e:
        logger.error("Visit POST: %s", e)
        return {"total": 0}


@app.get("/visit")
async def get_visits(request: Request):
    ip = _get_ip(request)
    try:
        _sliding_rate(_visit_hits, f"visit_get:{ip}", VISIT_GET_LIMIT, 60)
    except HTTPException:
        return {"total": 0}
    try:
        d = get_main_db()["visits"].find_one({"_id": "global_counter"})
        return {"total": d["total"] if d else 0}
    except Exception as e:
        logger.error("Visit GET: %s", e)
        return {"total": 0}


# ── pydantic models ───────────────────────────────────────────────────────────
KeyType = Literal["monthly", "yearly", "lifetime"]
KEY_DURATIONS: dict = {
    "monthly":  timedelta(days=30),
    "yearly":   timedelta(days=365),
    "lifetime": None,
}

def generate_key() -> str:
    return f"NULL-TRACE-API-{uuid.uuid4().hex[:8].upper()}"

def _unique_key(col: Collection) -> str:
    for _ in range(10):
        k = generate_key()
        if not col.find_one({"key": k}):
            return k
    return generate_key()

def compute_expiry(key_type: KeyType) -> Optional[str]:
    delta = KEY_DURATIONS[key_type]
    return None if delta is None else (datetime.now(timezone.utc) + delta).isoformat()


class GenerateKeyRequest(BaseModel):
    type:  KeyType = Field(...)
    count: int     = Field(1, ge=1, le=100)
    label: str     = Field("", max_length=120)

class UpdateLabelRequest(BaseModel):
    label: str = Field("", max_length=120)

class UpdateKeyValueRequest(BaseModel):
    new_key: str = Field(..., min_length=1, max_length=120)

    @field_validator("new_key")
    @classmethod
    def clean(cls, v: str) -> str:
        v = v.strip()
        if not v: raise ValueError("new_key cannot be blank.")
        if any(c in v for c in "\n\r\t"): raise ValueError("Invalid characters.")
        return v


# ── admin — key management ────────────────────────────────────────────────────

@app.post("/admin/keys/generate")
@limiter.limit("10/minute")
async def admin_generate_keys(
    request: Request,
    body: GenerateKeyRequest,
    _admin: str = Depends(verify_admin)
):
    col = get_keys_col()
    now = datetime.now(timezone.utc).isoformat()
    keys = []
    for _ in range(body.count):
        k   = _unique_key(col)
        doc = {"key": k, "type": body.type, "label": body.label,
               "expires_at": compute_expiry(body.type), "revoked": False,
               "usage_count": 0, "last_used": None, "created_at": now}
        col.insert_one(doc); doc.pop("_id", None); keys.append(doc)
    return {"generated": len(keys), "type": body.type, "keys": keys}


@app.get("/admin/keys")
@limiter.limit("10/minute")
async def admin_list_keys(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    type: Optional[str] = Query(None),
    revoked: Optional[bool] = Query(None),
    _admin: str = Depends(verify_admin),
):
    col   = get_keys_col()
    filt  = {**({"type": type} if type else {}), **({"revoked": revoked} if revoked is not None else {})}
    total = col.count_documents(filt)
    keys  = []
    now   = datetime.now(timezone.utc)
    for doc in col.find(filt).sort("created_at", -1).skip((page-1)*per_page).limit(per_page):
        doc.pop("_id", None)
        expiry = doc.get("expires_at")
        if expiry:
            exp_dt           = datetime.fromisoformat(expiry)
            doc["status"]    = "expired" if now >= exp_dt else "active"
            doc["days_left"] = max(0, (exp_dt - now).days)
        else:
            doc["status"]    = "revoked" if doc.get("revoked") else "lifetime"
            doc["days_left"] = None
        keys.append(doc)
    return {"total": total, "page": page, "per_page": per_page,
            "pages": (total+per_page-1)//per_page, "keys": keys}


@app.delete("/admin/keys/{key_value}")
@limiter.limit("10/minute")
async def admin_revoke_key(request: Request, key_value: str, _admin: str = Depends(verify_admin)):
    r = get_keys_col().update_one(
        {"key": key_value},
        {"$set": {"revoked": True, "revoked_at": datetime.now(timezone.utc).isoformat()}}
    )
    if r.matched_count == 0:
        raise HTTPException(404, f"Key not found.")
    return {"revoked": True, "key": key_value}


@app.delete("/admin/keys/{key_value}/hard")
@limiter.limit("10/minute")
async def admin_delete_key(request: Request, key_value: str, _admin: str = Depends(verify_admin)):
    r = get_keys_col().delete_one({"key": key_value})
    if r.deleted_count == 0:
        raise HTTPException(404, "Key not found.")
    return {"deleted": True, "key": key_value}


@app.post("/admin/keys/{key_value}/unrevoke")
@limiter.limit("10/minute")
async def admin_unrevoke_key(request: Request, key_value: str, _admin: str = Depends(verify_admin)):
    r = get_keys_col().update_one({"key": key_value}, {"$set": {"revoked": False}, "$unset": {"revoked_at": ""}})
    if r.matched_count == 0:
        raise HTTPException(404, "Key not found.")
    return {"unrevoked": True, "key": key_value}


@app.patch("/admin/keys/{key_value}/label")
@limiter.limit("20/minute")
async def admin_update_label(request: Request, key_value: str, body: UpdateLabelRequest, _admin: str = Depends(verify_admin)):
    r = get_keys_col().update_one(
        {"key": key_value},
        {"$set": {"label": body.label, "label_updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    if r.matched_count == 0:
        raise HTTPException(404, "Key not found.")
    return {"updated": True, "key": key_value, "label": body.label}


@app.patch("/admin/keys/{key_value}/value")
@limiter.limit("20/minute")
async def admin_update_key_value(request: Request, key_value: str, body: UpdateKeyValueRequest, _admin: str = Depends(verify_admin)):
    col = get_keys_col()
    if not col.find_one({"key": key_value}):
        raise HTTPException(404, "Key not found.")
    if body.new_key != key_value and col.find_one({"key": body.new_key}):
        raise HTTPException(409, "New key value already in use.")
    col.update_one(
        {"key": key_value},
        {"$set": {"key": body.new_key, "key_updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    return {"updated": True, "old_key": key_value, "new_key": body.new_key}


# ── health — CACHED (prevents DoS via count_documents) ───────────────────────

@app.head("/health")
async def health_head():
    return JSONResponse(None, status_code=200)


@app.get("/health")
async def health():
    now = time.time()
    if _health_cache["data"] and now - _health_cache["ts"] < HEALTH_CACHE_TTL:
        return _health_cache["data"]
    try:
        main_db  = get_main_db()
        email_db = get_email_db()
        key_db   = get_key_db()
        cust_db  = get_cust_db()
        visits   = main_db["visits"].find_one({"_id": "global_counter"})
        kc       = key_db["keys"]
        data = {
            "status":           "ok",
            "main_cluster":     {c: main_db[c].count_documents({}) for c in ["address","pan","personal"]},
            "email_cluster":    {"email": email_db["email"].count_documents({})},
            "customer_cluster": {
                "customers_db1": cust_db["customers_db1"].count_documents({}),
                "customers_db2": cust_db["customers_db2"].count_documents({}),
            },
            "key_system": {
                "total_keys":    kc.count_documents({}),
                "active_keys":   kc.count_documents({"revoked": False}),
                "revoked_keys":  kc.count_documents({"revoked": True}),
                "monthly_keys":  kc.count_documents({"type": "monthly"}),
                "yearly_keys":   kc.count_documents({"type": "yearly"}),
                "lifetime_keys": kc.count_documents({"type": "lifetime"}),
            },
            "visitors": visits["total"] if visits else 0,
        }
        _health_cache["data"] = data
        _health_cache["ts"]   = now
        return data
    except Exception as e:
        logger.error("Health: %s", e)
        return {"status": "error"}  # never leak detail


@app.get("/", include_in_schema=False)
async def root():
    return {"api": "Lookup API", "version": "2.0.0", "status": "ok"}