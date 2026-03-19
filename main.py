"""
Secure Lookup API — Dual MongoDB Edition + Key Management System
=================================================================
Two MongoDB clusters:
  MONGO_URL       → address, pan, personal, visits  (main cluster)
  MONGO_EMAIL_URL → email collection                (dedicated cluster)
  MONGO_KEY_URL   → keys collection                 (key management cluster)

Key Types:
  - monthly   : valid for 1 month from activation
  - yearly    : valid for 1 year from activation
  - lifetime  : never expires

Endpoints:
  GET  /search/number?q=<phone>     — address + pan + email (India)
  GET  /search/email?q=<email>      — address + pan + email (India)
  GET  /search/pak/number?q=<phone> — personal (Pakistan) with images
  POST /visit                       — increment + return visitor count
  GET  /visit                       — return current visitor count
  HEAD /health                      — uptime check (UptimeRobot)
  GET  /health                      — full status with collection counts

  [Admin — requires X-Admin-Key header]
  POST  /admin/keys/generate              — generate one or more keys
  GET   /admin/keys                       — list all keys (paginated)
  DELETE /admin/keys/{key}               — revoke/delete a key
  DELETE /admin/keys/{key}/hard          — permanently delete a key
  POST  /admin/keys/{key}/unrevoke       — restore a revoked key
  PATCH /admin/keys/{key}/label          — update label/note on a key  ← NEW

  [User — requires X-API-Key header (the license key itself)]
  GET  /key/info                    — check key status, expiry, usage
"""

import re
import os
import uuid
import logging
import time
import asyncio
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Depends, Request, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING
from pymongo.collection import Collection
from pydantic import BaseModel, Field
import httpx

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()

MONGO_URL       = os.getenv("MONGO_URL", "")
MONGO_EMAIL_URL = os.getenv("MONGO_EMAIL_URL", "")
MONGO_KEY_URL   = os.getenv(
    "MONGO_KEY_URL",
    "mongodb+srv://telegrambotbydanger:siPJXsL56GQ03onP@cluster0.0om9qyw.mongodb.net/?appName=Cluster0"
)
DB_NAME         = os.getenv("DB_NAME", "pakdata")
KEY_DB_NAME     = os.getenv("KEY_DB_NAME", "keystore")
IMAGE_BASE      = os.getenv("IMAGE_BASE_URL", "https://pub-1c3225cdd2454dafa1768bf8b067d3a3.r2.dev").rstrip("/")

# Admin key to manage the key system (set this in your .env)
ADMIN_KEY       = os.getenv("ADMIN_KEY", "change-this-admin-secret")

RATE_LIMIT  = os.getenv("RATE_LIMIT", "10/minute")
MAX_RESULTS = int(os.getenv("MAX_RESULTS", "20"))

# Brute-force protection settings
ADMIN_MAX_ATTEMPTS  = int(os.getenv("ADMIN_MAX_ATTEMPTS", "5"))    # max wrong tries
ADMIN_LOCKOUT_SECS  = int(os.getenv("ADMIN_LOCKOUT_SECS", "300"))  # 5 min lockout
ADMIN_ATTEMPT_WINDOW= int(os.getenv("ADMIN_ATTEMPT_WINDOW","60"))  # count attempts within 60s

# In-memory store: ip -> list of failed attempt timestamps
_admin_fail_log: dict[str, list[float]] = defaultdict(list)

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Lookup API + Key System", docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "HEAD", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    allow_credentials=False,
)

# ─────────────────────────────────────────────────────────────────────────────
# MongoDB clients
# ─────────────────────────────────────────────────────────────────────────────

_main_client:  MongoClient | None = None
_email_client: MongoClient | None = None
_key_client:   MongoClient | None = None


def get_main_db():
    global _main_client
    if _main_client is None:
        if not MONGO_URL:
            raise RuntimeError("MONGO_URL is not set.")
        _main_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
        logger.info("✓ Main MongoDB client initialized")
    return _main_client[DB_NAME]


def get_email_db():
    global _email_client
    if _email_client is None:
        if not MONGO_EMAIL_URL:
            raise RuntimeError("MONGO_EMAIL_URL is not set.")
        _email_client = MongoClient(MONGO_EMAIL_URL, serverSelectionTimeoutMS=5000)
        logger.info("✓ Email MongoDB client initialized")
    return _email_client[DB_NAME]


def get_key_db():
    global _key_client
    if _key_client is None:
        if not MONGO_KEY_URL:
            raise RuntimeError("MONGO_KEY_URL is not set.")
        _key_client = MongoClient(MONGO_KEY_URL, serverSelectionTimeoutMS=5000)
        logger.info("✓ Key MongoDB client initialized")
    return _key_client[KEY_DB_NAME]


def get_col(name: str) -> Collection:
    """Route collection to correct cluster."""
    if name == "email":
        return get_email_db()[name]
    return get_main_db()[name]


def get_keys_col() -> Collection:
    return get_key_db()["keys"]


@app.on_event("startup")
async def startup():
    # Main cluster
    try:
        db = get_main_db()
        db.command("ping")
        logger.info("✓ Main cluster connected — database: %s", DB_NAME)
        for c in ["address", "pan", "personal"]:
            count = db[c].count_documents({})
            logger.info("  %-10s : %s records", c, f"{count:,}")
    except Exception as e:
        logger.error("✗ Main cluster failed: %s", e)

    # Email cluster
    try:
        db = get_email_db()
        db.command("ping")
        logger.info("✓ Email cluster connected — database: %s", DB_NAME)
        count = db["email"].count_documents({})
        logger.info("  %-10s : %s records", "email", f"{count:,}")
    except Exception as e:
        logger.error("✗ Email cluster failed: %s", e)

    # Key cluster
    try:
        db = get_key_db()
        db.command("ping")
        col = db["keys"]
        col.create_index([("key", ASCENDING)], unique=True)
        count = col.count_documents({})
        logger.info("✓ Key cluster connected — %s keys stored", count)
    except Exception as e:
        logger.error("✗ Key cluster failed: %s", e)

    # Self-ping keep-alive (prevents Render free tier cold starts)
    asyncio.create_task(_keep_alive())


_keep_alive_task = None

async def _keep_alive():
    """Ping own /health every 4 minutes so Render never spins down."""
    own_url = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
    if not own_url:
        logger.info("⚠ RENDER_EXTERNAL_URL not set — keep-alive disabled")
        return
    await asyncio.sleep(60)  # wait 1 min after boot before first ping
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            try:
                r = await client.get(f"{own_url}/health")
                logger.info("♥ keep-alive ping → %s", r.status_code)
            except Exception as e:
                logger.warning("♥ keep-alive failed: %s", e)
            await asyncio.sleep(240)  # ping every 4 minutes


@app.on_event("shutdown")
async def shutdown():
    global _main_client, _email_client, _key_client
    for client in [_main_client, _email_client, _key_client]:
        if client:
            client.close()
    logger.info("MongoDB clients closed.")

# ─────────────────────────────────────────────────────────────────────────────
# Key helpers
# ─────────────────────────────────────────────────────────────────────────────

KeyType = Literal["monthly", "yearly", "lifetime"]

KEY_DURATIONS: dict[str, Optional[timedelta]] = {
    "monthly":  timedelta(days=30),
    "yearly":   timedelta(days=365),
    "lifetime": None,
}


def generate_key() -> str:
    """Generate a readable API key: XXXX-XXXX-XXXX-XXXX"""
    raw = uuid.uuid4().hex.upper()
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"


def compute_expiry(key_type: KeyType) -> Optional[str]:
    delta = KEY_DURATIONS[key_type]
    if delta is None:
        return None  # lifetime
    return (datetime.now(timezone.utc) + delta).isoformat()


def is_key_valid(doc: dict) -> bool:
    """Check if a key document is active and not expired."""
    if doc.get("revoked"):
        return False
    expiry = doc.get("expires_at")
    if expiry is None:
        return True  # lifetime
    return datetime.now(timezone.utc) < datetime.fromisoformat(expiry)


def resolve_key(raw_key: str) -> dict:
    """
    Fetch key doc from MongoDB. Raises 401 if missing/revoked/expired.
    Increments usage count on each successful call.
    """
    col = get_keys_col()
    doc = col.find_one({"key": raw_key})
    if not doc:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    if doc.get("revoked"):
        raise HTTPException(status_code=401, detail="API key has been revoked.")
    expiry = doc.get("expires_at")
    if expiry and datetime.now(timezone.utc) >= datetime.fromisoformat(expiry):
        raise HTTPException(status_code=401, detail="API key has expired.")
    # Bump usage counter + last_used
    col.update_one(
        {"key": raw_key},
        {
            "$inc": {"usage_count": 1},
            "$set": {"last_used": datetime.now(timezone.utc).isoformat()},
        },
    )
    return doc

# ─────────────────────────────────────────────────────────────────────────────
# Security — Admin  (brute-force protected)
# ─────────────────────────────────────────────────────────────────────────────

def _get_ip(request: Request) -> str:
    """Best-effort real IP (works behind proxies)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def verify_admin(request: Request):
    ip  = _get_ip(request)
    now = time.time()

    # Purge old entries outside the attempt window
    _admin_fail_log[ip] = [
        t for t in _admin_fail_log[ip]
        if now - t < ADMIN_LOCKOUT_SECS
    ]

    # Check if IP is locked out
    recent = [t for t in _admin_fail_log[ip] if now - t < ADMIN_LOCKOUT_SECS]
    if len(recent) >= ADMIN_MAX_ATTEMPTS:
        wait = int(ADMIN_LOCKOUT_SECS - (now - recent[0]))
        logger.warning("Admin brute-force lockout for IP %s (%ds remaining)", ip, wait)
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {wait} seconds.",
        )

    key = request.headers.get("X-Admin-Key", "")
    if key != ADMIN_KEY:
        _admin_fail_log[ip].append(now)
        attempts_left = ADMIN_MAX_ATTEMPTS - len(_admin_fail_log[ip])
        logger.warning("Failed admin auth from IP %s (%d attempts left)", ip, attempts_left)
        raise HTTPException(
            status_code=401,
            detail=f"Invalid admin key. {max(0, attempts_left)} attempt(s) remaining before lockout.",
        )

    # Successful auth — clear fail log for this IP
    _admin_fail_log[ip] = []
    return key


def verify_api_key(request: Request) -> dict:
    """Validate the user's license key (X-API-Key header)."""
    raw = request.headers.get("X-API-Key", "")
    if not raw:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header.")
    return resolve_key(raw)

# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────

PHONE_REGEX = re.compile(r"^\d{10}(\d{2})?$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def validate_phone(value: str) -> str:
    cleaned = re.sub(r"[\s\-]", "", value.strip())
    if not PHONE_REGEX.fullmatch(cleaned):
        raise HTTPException(
            status_code=422,
            detail=(
                f"'{value}' is not a valid phone number. "
                "Provide exactly 10 digits (e.g. 9711145004) "
                "or 12 digits with country code (e.g. 919711145004)."
            ),
        )
    return cleaned


def validate_email(value: str) -> str:
    cleaned = value.strip()
    if not EMAIL_REGEX.fullmatch(cleaned):
        raise HTTPException(
            status_code=422,
            detail=f"'{value}' is not a valid email. Expected: user@domain.com",
        )
    return cleaned.lower()

# ─────────────────────────────────────────────────────────────────────────────
# Field whitelists & serializers
# ─────────────────────────────────────────────────────────────────────────────

ADDRESS_FIELDS  = {"name", "number", "email", "dob", "city", "address"}
PAN_FIELDS      = {"name", "number", "email", "city", "pan"}
EMAIL_FIELDS    = {"name", "number", "email", "city"}
PERSONAL_FIELDS = {
    "userId", "name", "fatherName", "cnic",
    "mobile", "email", "address", "gender", "createdAt",
}


def strip_id(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc

def safe_address(docs):
    return [{k: v for k, v in strip_id(d).items() if k in ADDRESS_FIELDS} for d in docs]

def safe_pan(docs):
    return [{k: v for k, v in strip_id(d).items() if k in PAN_FIELDS} for d in docs]

def safe_email_docs(docs):
    return [{k: v for k, v in strip_id(d).items() if k in EMAIL_FIELDS} for d in docs]

def build_image_url(filename) -> str | None:
    if not filename:
        return None
    f = str(filename)
    return f if f.startswith("http") else f"{IMAGE_BASE}/{f.lstrip('/')}"

def safe_personal(docs):
    results = []
    for d in docs:
        strip_id(d)
        entry = {k: v for k, v in d.items() if k in PERSONAL_FIELDS}
        entry["profileImageUrl"] = build_image_url(d.get("profileImage"))
        entry["cnicImageUrl"]    = build_image_url(d.get("cnicImage"))
        results.append(entry)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# Query helpers
# ─────────────────────────────────────────────────────────────────────────────

def phone_filter(number: str, field: str = "number") -> dict:
    short = number[-10:]
    return {field: {"$regex": f"{short}$"}}

def phone_filter_pak(number: str) -> dict:
    short = number[-10:]
    return {"mobile.digits": {"$regex": f"{short}$"}}

# ─────────────────────────────────────────────────────────────────────────────
# Search Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/search/number")
@limiter.limit(RATE_LIMIT)
async def search_by_number(
    request: Request,
    q: str = Query(..., min_length=10, max_length=12, description="10 or 12 digit phone number"),
    _key_doc: dict = Depends(verify_api_key),
):
    number       = validate_phone(q)
    filt         = phone_filter(number)
    address_docs = list(get_col("address").find(filt, limit=MAX_RESULTS))
    pan_docs     = list(get_col("pan").find(filt,     limit=MAX_RESULTS))
    email_docs   = list(get_col("email").find(filt,   limit=MAX_RESULTS))

    return {
        "query": number,
        "total": len(address_docs) + len(pan_docs) + len(email_docs),
        "address": {"count": len(address_docs), "results": safe_address(address_docs)},
        "pan":     {"count": len(pan_docs),     "results": safe_pan(pan_docs)},
        "email":   {"count": len(email_docs),   "results": safe_email_docs(email_docs)},
    }


@app.get("/search/email")
@limiter.limit(RATE_LIMIT)
async def search_by_email(
    request: Request,
    q: str = Query(..., min_length=6, max_length=254, description="Valid email address"),
    _key_doc: dict = Depends(verify_api_key),
):
    email        = validate_email(q)
    filt         = {"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}}
    address_docs = list(get_col("address").find(filt, limit=MAX_RESULTS))
    pan_docs     = list(get_col("pan").find(filt,     limit=MAX_RESULTS))
    email_docs   = list(get_col("email").find(filt,   limit=MAX_RESULTS))

    return {
        "query": email,
        "total": len(address_docs) + len(pan_docs) + len(email_docs),
        "address": {"count": len(address_docs), "results": safe_address(address_docs)},
        "pan":     {"count": len(pan_docs),     "results": safe_pan(pan_docs)},
        "email":   {"count": len(email_docs),   "results": safe_email_docs(email_docs)},
    }


@app.get("/search/pak/number")
@limiter.limit(RATE_LIMIT)
async def search_pak_by_number(
    request: Request,
    q: str = Query(..., min_length=10, max_length=12, description="10 or 12 digit Pakistani mobile"),
    _key_doc: dict = Depends(verify_api_key),
):
    number = validate_phone(q)
    filt   = phone_filter_pak(number)
    docs   = list(get_col("personal").find(filt, limit=MAX_RESULTS))

    return {
        "query":   number,
        "count":   len(docs),
        "results": safe_personal(docs),
    }

# ─────────────────────────────────────────────────────────────────────────────
# Key Info Endpoint (user checks their own key)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/key/info")
async def key_info(request: Request, key_doc: dict = Depends(verify_api_key)):
    """Return info about the current key (expiry, type, usage)."""
    expiry = key_doc.get("expires_at")
    now    = datetime.now(timezone.utc)

    if expiry:
        exp_dt      = datetime.fromisoformat(expiry)
        days_left   = max(0, (exp_dt - now).days)
        expires_str = exp_dt.strftime("%Y-%m-%d %H:%M UTC")
    else:
        days_left   = None
        expires_str = "Never (lifetime)"

    return {
        "key":         key_doc["key"],
        "type":        key_doc.get("type", "unknown"),
        "label":       key_doc.get("label", ""),
        "active":      True,
        "expires_at":  expires_str,
        "days_left":   days_left,
        "usage_count": key_doc.get("usage_count", 0),
        "last_used":   key_doc.get("last_used", "never"),
        "created_at":  key_doc.get("created_at", ""),
    }

# ─────────────────────────────────────────────────────────────────────────────
# Admin — Key Management
# ─────────────────────────────────────────────────────────────────────────────

class GenerateKeyRequest(BaseModel):
    type:  KeyType = Field(..., description="monthly | yearly | lifetime")
    count: int     = Field(1, ge=1, le=100, description="How many keys to generate")
    label: str     = Field("", description="Optional label/note for this batch")


class UpdateLabelRequest(BaseModel):
    label: str = Field("", max_length=120, description="New label/note (empty string clears it)")


@app.post("/admin/keys/generate")
@limiter.limit("10/minute")
async def admin_generate_keys(
    request: Request,
    body: GenerateKeyRequest,
    _admin: str = Depends(verify_admin),
):
    """
    Generate one or more license keys.
    Requires X-Admin-Key header.

    Body:
      {
        "type":  "monthly" | "yearly" | "lifetime",
        "count": 1,
        "label": "optional note"
      }
    """
    col  = get_keys_col()
    now  = datetime.now(timezone.utc).isoformat()
    keys = []

    for _ in range(body.count):
        new_key = generate_key()
        doc = {
            "key":         new_key,
            "type":        body.type,
            "label":       body.label,
            "expires_at":  compute_expiry(body.type),
            "revoked":     False,
            "usage_count": 0,
            "last_used":   None,
            "created_at":  now,
        }
        col.insert_one(doc)
        doc.pop("_id", None)
        keys.append(doc)

    return {
        "generated": len(keys),
        "type":      body.type,
        "keys":      keys,
    }


@app.get("/admin/keys")
@limiter.limit("10/minute")
async def admin_list_keys(
    request: Request,
    page:     int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    type:     Optional[str] = Query(None, description="Filter by type"),
    revoked:  Optional[bool] = Query(None, description="Filter by revoked status"),
    _admin:   str = Depends(verify_admin),
):
    """
    List all keys (paginated).
    Requires X-Admin-Key header.
    """
    col    = get_keys_col()
    filt: dict = {}
    if type:
        filt["type"] = type
    if revoked is not None:
        filt["revoked"] = revoked

    total  = col.count_documents(filt)
    skip   = (page - 1) * per_page
    cursor = col.find(filt).sort("created_at", -1).skip(skip).limit(per_page)

    keys = []
    now  = datetime.now(timezone.utc)
    for doc in cursor:
        doc.pop("_id", None)
        expiry = doc.get("expires_at")
        if expiry:
            exp_dt       = datetime.fromisoformat(expiry)
            doc["status"] = "expired" if now >= exp_dt else "active"
            doc["days_left"] = max(0, (exp_dt - now).days)
        else:
            doc["status"]    = "revoked" if doc.get("revoked") else "lifetime"
            doc["days_left"] = None
        keys.append(doc)

    return {
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    (total + per_page - 1) // per_page,
        "keys":     keys,
    }


@app.delete("/admin/keys/{key_value}")
@limiter.limit("10/minute")
async def admin_revoke_key(
    request:   Request,
    key_value: str,
    _admin:    str = Depends(verify_admin),
):
    """
    Revoke a key by value (marks as revoked, does NOT delete).
    Requires X-Admin-Key header.
    """
    col    = get_keys_col()
    result = col.update_one(
        {"key": key_value},
        {"$set": {"revoked": True, "revoked_at": datetime.now(timezone.utc).isoformat()}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail=f"Key '{key_value}' not found.")
    return {"revoked": True, "key": key_value}


@app.delete("/admin/keys/{key_value}/hard")
@limiter.limit("10/minute")
async def admin_delete_key(
    request:   Request,
    key_value: str,
    _admin:    str = Depends(verify_admin),
):
    """
    Permanently delete a key from the database.
    Requires X-Admin-Key header.
    """
    col    = get_keys_col()
    result = col.delete_one({"key": key_value})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"Key '{key_value}' not found.")
    return {"deleted": True, "key": key_value}


@app.post("/admin/keys/{key_value}/unrevoke")
@limiter.limit("10/minute")
async def admin_unrevoke_key(
    request:   Request,
    key_value: str,
    _admin:    str = Depends(verify_admin),
):
    """Re-activate a previously revoked key."""
    col    = get_keys_col()
    result = col.update_one(
        {"key": key_value},
        {"$set": {"revoked": False}, "$unset": {"revoked_at": ""}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail=f"Key '{key_value}' not found.")
    return {"unrevoked": True, "key": key_value}


# ─────────────────────────────────────────────────────────────────────────────
# NEW: Update label on any key (revoked or active)
# ─────────────────────────────────────────────────────────────────────────────

@app.patch("/admin/keys/{key_value}/label")
@limiter.limit("20/minute")
async def admin_update_label(
    request:   Request,
    key_value: str,
    body:      UpdateLabelRequest,
    _admin:    str = Depends(verify_admin),
):
    """
    Update (or clear) the label/note on a key.
    Works on both active and revoked keys.
    Requires X-Admin-Key header.

    Body:
      { "label": "new note here" }   — set a new label
      { "label": "" }                — clear the label
    """
    col    = get_keys_col()
    result = col.update_one(
        {"key": key_value},
        {
            "$set": {
                "label":      body.label,
                "label_updated_at": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail=f"Key '{key_value}' not found.")

    logger.info("Label updated for key %s → '%s'", key_value, body.label)
    return {"updated": True, "key": key_value, "label": body.label}

# ─────────────────────────────────────────────────────────────────────────────
# Visitor Counter
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/visit")
async def record_visit(request: Request):
    try:
        visits = get_main_db()["visits"]
        visits.update_one(
            {"_id": "global_counter"},
            {
                "$inc": {"total": 1},
                "$set": {"last_visit": datetime.now(timezone.utc).isoformat()},
            },
            upsert=True,
        )
        doc = visits.find_one({"_id": "global_counter"})
        return {"total": doc["total"] if doc else 1}
    except Exception as e:
        logger.error("Visit counter error: %s", e)
        return {"total": 0}


@app.get("/visit")
async def get_visits():
    try:
        doc = get_main_db()["visits"].find_one({"_id": "global_counter"})
        return {"total": doc["total"] if doc else 0}
    except Exception as e:
        logger.error("Get visits error: %s", e)
        return {"total": 0}

# ─────────────────────────────────────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────────────────────────────────────

@app.head("/health")
async def health_head():
    return JSONResponse(content=None, status_code=200)


@app.get("/health")
async def health():
    try:
        main_db  = get_main_db()
        email_db = get_email_db()
        key_db   = get_key_db()
        visits   = main_db["visits"].find_one({"_id": "global_counter"})
        key_col  = key_db["keys"]
        return {
            "status": "ok",
            "main_cluster": {
                c: main_db[c].count_documents({})
                for c in ["address", "pan", "personal"]
            },
            "email_cluster": {
                "email": email_db["email"].count_documents({})
            },
            "key_system": {
                "total_keys":    key_col.count_documents({}),
                "active_keys":   key_col.count_documents({"revoked": False}),
                "revoked_keys":  key_col.count_documents({"revoked": True}),
                "monthly_keys":  key_col.count_documents({"type": "monthly"}),
                "yearly_keys":   key_col.count_documents({"type": "yearly"}),
                "lifetime_keys": key_col.count_documents({"type": "lifetime"}),
            },
            "visitors": visits["total"] if visits else 0,
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}