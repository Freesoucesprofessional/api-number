"""
Secure Lookup API — Dual MongoDB Edition + Key Management System
=================================================================
Routes:
  /search/ind/number   — India phone  (address + pan + email + customers_db1 + customers_db2)
  /search/ind/email    — India email  (address + pan + email + customers_db1 + customers_db2)
  /search/pak/number   — Pakistan phone (personal)
  /search/pak/email    — Pakistan email (personal)
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

import phonenumbers
from phonenumbers import carrier, geocoder
from phonenumbers import timezone as ph_timezone
from phonenumbers import number_type, PhoneNumberType

from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING
from pymongo.collection import Collection
from pydantic import BaseModel, Field, field_validator
import httpx

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()

MONGO_URL       = os.getenv("MONGO_URL", "")
MONGO_EMAIL_URL = os.getenv("MONGO_EMAIL_URL", "")
MONGO_KEY_URL   = os.getenv("MONGO_KEY_URL")
MONGO_CUST_URL  = os.getenv("MONGO_URI", "")

DB_NAME         = os.getenv("DB_NAME")
KEY_DB_NAME     = os.getenv("KEY_DB_NAME")
CUST_DB_NAME    = "customer_database"

IMAGE_BASE      = os.getenv("IMAGE_BASE_URL").rstrip("/")
ADMIN_KEY       = os.getenv("ADMIN_KEY")
RATE_LIMIT      = os.getenv("RATE_LIMIT")
MAX_RESULTS     = int(os.getenv("MAX_RESULTS"))

ADMIN_MAX_ATTEMPTS   = int(os.getenv("ADMIN_MAX_ATTEMPTS", "5"))
ADMIN_LOCKOUT_SECS   = int(os.getenv("ADMIN_LOCKOUT_SECS", "300"))
ADMIN_ATTEMPT_WINDOW = int(os.getenv("ADMIN_ATTEMPT_WINDOW", "60"))

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
# MongoDB
# ─────────────────────────────────────────────────────────────────────────────

_main_client:  MongoClient | None = None
_email_client: MongoClient | None = None
_key_client:   MongoClient | None = None
_cust_client:  MongoClient | None = None


def get_main_db():
    global _main_client
    if _main_client is None:
        if not MONGO_URL:
            raise RuntimeError("MONGO_URL is not set.")
        _main_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    return _main_client[DB_NAME]


def get_email_db():
    global _email_client
    if _email_client is None:
        if not MONGO_EMAIL_URL:
            raise RuntimeError("MONGO_EMAIL_URL is not set.")
        _email_client = MongoClient(MONGO_EMAIL_URL, serverSelectionTimeoutMS=5000)
    return _email_client[DB_NAME]


def get_key_db():
    global _key_client
    if _key_client is None:
        if not MONGO_KEY_URL:
            raise RuntimeError("MONGO_KEY_URL is not set.")
        _key_client = MongoClient(MONGO_KEY_URL, serverSelectionTimeoutMS=5000)
    return _key_client[KEY_DB_NAME]


def get_cust_db():
    global _cust_client
    if _cust_client is None:
        if not MONGO_CUST_URL:
            raise RuntimeError("MONGO_URI (customer DB) is not set.")
        _cust_client = MongoClient(MONGO_CUST_URL, serverSelectionTimeoutMS=5000)
    return _cust_client[CUST_DB_NAME]


def get_col(name: str) -> Collection:
    return get_email_db()[name] if name == "email" else get_main_db()[name]


def get_keys_col() -> Collection:
    return get_key_db()["keys"]


# ─────────────────────────────────────────────────────────────────────────────
# Startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    try:
        db = get_main_db(); db.command("ping")
        logger.info("✓ Main cluster connected — %s", DB_NAME)
        for c in ["address", "pan", "personal"]:
            logger.info("  %-10s : %s records", c, f"{db[c].count_documents({}):,}")
    except Exception as e:
        logger.error("✗ Main cluster: %s", e)

    try:
        db = get_email_db(); db.command("ping")
        logger.info("✓ Email cluster — email: %s records",
                    f"{db['email'].count_documents({}):,}")
    except Exception as e:
        logger.error("✗ Email cluster: %s", e)

    try:
        db  = get_key_db(); db.command("ping")
        col = db["keys"]
        col.create_index([("key", ASCENDING)], unique=True)
        logger.info("✓ Key cluster — %s keys stored", col.count_documents({}))
    except Exception as e:
        logger.error("✗ Key cluster: %s", e)

    try:
        db  = get_cust_db(); db.command("ping")
        c1  = db["customers_db1"].count_documents({})
        c2  = db["customers_db2"].count_documents({})
        logger.info("✓ Customer cluster — customers_db1: %s | customers_db2: %s",
                    f"{c1:,}", f"{c2:,}")
    except Exception as e:
        logger.error("✗ Customer cluster: %s", e)

    asyncio.create_task(_keep_alive())


async def _keep_alive():
    own_url = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
    if not own_url:
        return
    await asyncio.sleep(60)
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            try:
                r = await client.get(f"{own_url}/health")
                logger.info("♥ keep-alive → %s", r.status_code)
            except Exception as e:
                logger.warning("♥ keep-alive failed: %s", e)
            await asyncio.sleep(240)


@app.on_event("shutdown")
async def shutdown():
    global _main_client, _email_client, _key_client, _cust_client
    for c in [_main_client, _email_client, _key_client, _cust_client]:
        if c:
            c.close()

# ─────────────────────────────────────────────────────────────────────────────
# Phone metadata helpers
# ─────────────────────────────────────────────────────────────────────────────

_PHONE_TYPE_MAP = {
    PhoneNumberType.MOBILE:               "MOBILE",
    PhoneNumberType.FIXED_LINE:           "FIXED_LINE",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
    PhoneNumberType.VOIP:                 "VOIP",
    PhoneNumberType.TOLL_FREE:            "TOLL_FREE",
    PhoneNumberType.PREMIUM_RATE:         "PREMIUM_RATE",
    PhoneNumberType.SHARED_COST:          "SHARED_COST",
    PhoneNumberType.PERSONAL_NUMBER:      "PERSONAL_NUMBER",
    PhoneNumberType.PAGER:                "PAGER",
    PhoneNumberType.UAN:                  "UAN",
    PhoneNumberType.UNKNOWN:              "UNKNOWN",
}


def get_phone_meta(raw: str, country_prefix: str = "+91") -> dict:
    try:
        full   = f"{country_prefix}{raw[-10:]}"
        number = phonenumbers.parse(full)
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
    except Exception as e:
        logger.warning("phone_meta failed for %s: %s", raw, e)
        return {}

# ─────────────────────────────────────────────────────────────────────────────
# Country-specific phone validation
# ─────────────────────────────────────────────────────────────────────────────

# Indian numbers: 10 digits, must start with 6, 7, 8, or 9
IND_PHONE_REGEX = re.compile(r"^[6-9]\d{9}$")

# Pakistani numbers: 10 digits, must start with 3 (e.g. 3001234567)
# Also accepts 11-digit with leading 0 (03001234567)
PAK_PHONE_REGEX = re.compile(r"^(0?3\d{9})$")


def validate_ind_phone(value: str) -> str:
    """Validate and normalise an Indian phone number to 10 digits."""
    cleaned = re.sub(r"[\s\-\(\)\+]", "", value.strip())
    # Strip country code if present: +91xxxxxxxxxx or 91xxxxxxxxxx
    cleaned = re.sub(r"^(91)(?=[6-9])", "", cleaned)
    if not IND_PHONE_REGEX.fullmatch(cleaned):
        raise HTTPException(
            422,
            detail=(
                "Invalid Indian phone number. "
                "Expected 10 digits starting with 6–9 (e.g. 9876543210). "
                "Do not use a Pakistani number on this endpoint."
            ),
        )
    return cleaned


def validate_pak_phone(value: str) -> str:
    """Validate and normalise a Pakistani phone number to 10 digits."""
    cleaned = re.sub(r"[\s\-\(\)\+]", "", value.strip())
    # Strip country code if present: +92xxxxxxxxxx or 92xxxxxxxxxx
    cleaned = re.sub(r"^(92)(?=3)", "", cleaned)
    if not PAK_PHONE_REGEX.fullmatch(cleaned):
        raise HTTPException(
            422,
            detail=(
                "Invalid Pakistani phone number. "
                "Expected 10 digits starting with 3 (e.g. 3001234567) "
                "or 11 digits with leading 0 (e.g. 03001234567). "
                "Do not use an Indian number on this endpoint."
            ),
        )
    # Normalise: strip leading 0 → always 10 digits
    return cleaned.lstrip("0") if cleaned.startswith("0") else cleaned

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


def resolve_key(raw_key: str) -> dict:
    col = get_keys_col()
    doc = col.find_one({"key": raw_key})
    if not doc:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    if doc.get("revoked"):
        raise HTTPException(status_code=401, detail="API key has been revoked.")
    expiry = doc.get("expires_at")
    if expiry and datetime.now(timezone.utc) >= datetime.fromisoformat(expiry):
        raise HTTPException(status_code=401, detail="API key has expired.")
    col.update_one(
        {"key": raw_key},
        {"$inc": {"usage_count": 1},
         "$set": {"last_used": datetime.now(timezone.utc).isoformat()}},
    )
    return doc

# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

def _get_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


def verify_admin(request: Request):
    ip  = _get_ip(request); now = time.time()
    _admin_fail_log[ip] = [t for t in _admin_fail_log[ip] if now - t < ADMIN_LOCKOUT_SECS]
    recent = [t for t in _admin_fail_log[ip] if now - t < ADMIN_LOCKOUT_SECS]
    if len(recent) >= ADMIN_MAX_ATTEMPTS:
        wait = int(ADMIN_LOCKOUT_SECS - (now - recent[0]))
        raise HTTPException(429, detail=f"Too many failed attempts. Try again in {wait}s.")
    key = request.headers.get("X-Admin-Key", "")
    if key != ADMIN_KEY:
        _admin_fail_log[ip].append(now)
        left = ADMIN_MAX_ATTEMPTS - len(_admin_fail_log[ip])
        raise HTTPException(401, detail=f"Invalid admin key. {max(0,left)} attempt(s) left before lockout.")
    _admin_fail_log[ip] = []
    return key


def verify_api_key(request: Request) -> dict:
    raw = request.headers.get("X-API-Key", "")
    if not raw:
        raise HTTPException(401, detail="Missing X-API-Key header.")
    return resolve_key(raw)

# ─────────────────────────────────────────────────────────────────────────────
# Validation (generic — kept for email)
# ─────────────────────────────────────────────────────────────────────────────

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def validate_email(value: str) -> str:
    cleaned = value.strip()
    if not EMAIL_REGEX.fullmatch(cleaned):
        raise HTTPException(422, detail=f"'{value}' is not a valid email.")
    return cleaned.lower()

# ─────────────────────────────────────────────────────────────────────────────
# Serializers — original collections
# ─────────────────────────────────────────────────────────────────────────────

ADDRESS_FIELDS  = {"name", "number", "email", "dob", "city", "address"}
PAN_FIELDS      = {"name", "number", "email", "city", "pan"}
EMAIL_FIELDS    = {"name", "number", "email", "city"}
PERSONAL_FIELDS = {"userId", "name", "fatherName", "cnic", "mobile", "email", "address", "gender", "createdAt"}

def strip_id(d): d.pop("_id", None); return d

def safe_address(docs):
    return [{k: v for k, v in strip_id(d).items() if k in ADDRESS_FIELDS} for d in docs]

def safe_pan(docs):
    return [{k: v for k, v in strip_id(d).items() if k in PAN_FIELDS} for d in docs]

def safe_email_docs(docs):
    return [{k: v for k, v in strip_id(d).items() if k in EMAIL_FIELDS} for d in docs]

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

# ─────────────────────────────────────────────────────────────────────────────
# Serializers — customers_db1
# ─────────────────────────────────────────────────────────────────────────────

CUST_DB1_FIELDS = {
    "number", "alternate_number", "name", "dob",
    "address1", "address2", "address3",
    "city", "pincode", "state",
    "email", "sim", "connection_type",
}

def safe_cust_db1(docs: list) -> list:
    return [{k: v for k, v in strip_id(d).items() if k in CUST_DB1_FIELDS} for d in docs]

# ─────────────────────────────────────────────────────────────────────────────
# Serializers — customers_db2
# ─────────────────────────────────────────────────────────────────────────────

CUST_DB2_FIELDS = {
    "telephone_number", "name", "dob", "father_husband_name",
    "address1", "address2", "address3",
    "city", "postal", "state",
    "alternate_phone", "email",
    "nationality", "pan_gir",
    "connection_type", "service_provider",
}

def safe_cust_db2(docs: list) -> list:
    return [{k: v for k, v in strip_id(d).items() if k in CUST_DB2_FIELDS} for d in docs]

# ─────────────────────────────────────────────────────────────────────────────
# Phone / email filter helpers
# ─────────────────────────────────────────────────────────────────────────────

def phone_filter(n, field="number"):
    return {field: {"$regex": f"{n[-10:]}$"}}

def phone_filter_pak(n):
    return {"mobile.digits": {"$regex": f"{n[-10:]}$"}}

def phone_filter_db1(n):
    tail = n[-10:]
    return {"$or": [
        {"number":           {"$regex": f"{tail}$"}},
        {"alternate_number": {"$regex": f"{tail}$"}},
    ]}

def phone_filter_db2(n):
    tail = n[-10:]
    return {"$or": [
        {"telephone_number": {"$regex": f"{tail}$"}},
        {"alternate_phone":  {"$regex": f"{tail}$"}},
    ]}

def email_filter(em):
    return {"email": {"$regex": f"^{re.escape(em)}$", "$options": "i"}}

# ─────────────────────────────────────────────────────────────────────────────
# Search endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/search/ind/number")
@limiter.limit(RATE_LIMIT)
async def search_ind_by_number(
    request: Request,
    q: str = Query(..., min_length=10, max_length=13),
    _k: dict = Depends(verify_api_key),
):
    n  = validate_ind_phone(q)
    f  = phone_filter(n)
    a  = list(get_col("address").find(f,                               limit=MAX_RESULTS))
    p  = list(get_col("pan").find(f,                                   limit=MAX_RESULTS))
    e  = list(get_col("email").find(f,                                 limit=MAX_RESULTS))
    c1 = list(get_cust_db()["customers_db1"].find(phone_filter_db1(n), limit=MAX_RESULTS))
    c2 = list(get_cust_db()["customers_db2"].find(phone_filter_db2(n), limit=MAX_RESULTS))
    return {
        "query":         n,
        "total":         len(a) + len(p) + len(e) + len(c1) + len(c2),
        "phone_meta":    get_phone_meta(n, country_prefix="+91"),
        "address":       {"count": len(a),  "results": safe_address(a)},
        "pan":           {"count": len(p),  "results": safe_pan(p)},
        "email":         {"count": len(e),  "results": safe_email_docs(e)},
        "customers_db1": {"count": len(c1), "results": safe_cust_db1(c1)},
        "customers_db2": {"count": len(c2), "results": safe_cust_db2(c2)},
    }


@app.get("/search/ind/email")
@limiter.limit(RATE_LIMIT)
async def search_ind_by_email(
    request: Request,
    q: str = Query(..., min_length=6, max_length=254),
    _k: dict = Depends(verify_api_key),
):
    em = validate_email(q)
    f  = email_filter(em)
    a  = list(get_col("address").find(f,                          limit=MAX_RESULTS))
    p  = list(get_col("pan").find(f,                              limit=MAX_RESULTS))
    e  = list(get_col("email").find(f,                            limit=MAX_RESULTS))
    c1 = list(get_cust_db()["customers_db1"].find(email_filter(em), limit=MAX_RESULTS))
    c2 = list(get_cust_db()["customers_db2"].find(email_filter(em), limit=MAX_RESULTS))
    return {
        "query":         em,
        "total":         len(a) + len(p) + len(e) + len(c1) + len(c2),
        "address":       {"count": len(a),  "results": safe_address(a)},
        "pan":           {"count": len(p),  "results": safe_pan(p)},
        "email":         {"count": len(e),  "results": safe_email_docs(e)},
        "customers_db1": {"count": len(c1), "results": safe_cust_db1(c1)},
        "customers_db2": {"count": len(c2), "results": safe_cust_db2(c2)},
    }


@app.get("/search/pak/number")
@limiter.limit(RATE_LIMIT)
async def search_pak_by_number(
    request: Request,
    q: str = Query(..., min_length=10, max_length=13),
    _k: dict = Depends(verify_api_key),
):
    n    = validate_pak_phone(q)
    docs = list(get_col("personal").find(phone_filter_pak(n), limit=MAX_RESULTS))
    return {
        "query":      n,
        "total":      len(docs),
        "phone_meta": get_phone_meta(n, country_prefix="+92"),
        "count":      len(docs),
        "results":    safe_personal(docs),
    }


@app.get("/search/pak/email")
@limiter.limit(RATE_LIMIT)
async def search_pak_by_email(
    request: Request,
    q: str = Query(..., min_length=6, max_length=254),
    _k: dict = Depends(verify_api_key),
):
    em   = validate_email(q)
    docs = list(get_col("personal").find(email_filter(em), limit=MAX_RESULTS))
    return {
        "query":   em,
        "count":   len(docs),
        "results": safe_personal(docs),
    }

# ─────────────────────────────────────────────────────────────────────────────
# Key info (user endpoint)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/key/info")
async def key_info(request: Request, key_doc: dict = Depends(verify_api_key)):
    expiry = key_doc.get("expires_at")
    now    = datetime.now(timezone.utc)
    if expiry:
        exp_dt = datetime.fromisoformat(expiry)
        days_left, expires_str = max(0, (exp_dt - now).days), exp_dt.strftime("%Y-%m-%d %H:%M UTC")
    else:
        days_left, expires_str = None, "Never (lifetime)"
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
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

class GenerateKeyRequest(BaseModel):
    type:  KeyType = Field(...)
    count: int     = Field(1, ge=1, le=100)
    label: str     = Field("")

class UpdateLabelRequest(BaseModel):
    label: str = Field("", max_length=120)

class UpdateKeyValueRequest(BaseModel):
    new_key: str = Field(..., min_length=1, max_length=120)

    @field_validator("new_key")
    @classmethod
    def clean(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("new_key cannot be blank.")
        if any(c in v for c in "\n\r\t"):
            raise ValueError("new_key must not contain newline or tab characters.")
        return v

# ─────────────────────────────────────────────────────────────────────────────
# Admin — key management
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/admin/keys/generate")
@limiter.limit("10/minute")
async def admin_generate_keys(request: Request, body: GenerateKeyRequest, _admin: str = Depends(verify_admin)):
    col  = get_keys_col()
    now  = datetime.now(timezone.utc).isoformat()
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
    page: int = Query(1, ge=1), per_page: int = Query(50, ge=1, le=200),
    type: Optional[str] = Query(None), revoked: Optional[bool] = Query(None),
    _admin: str = Depends(verify_admin),
):
    col   = get_keys_col()
    filt  = {**({"type": type} if type else {}), **({"revoked": revoked} if revoked is not None else {})}
    total = col.count_documents(filt)
    keys  = []
    now   = datetime.now(timezone.utc)
    for doc in col.find(filt).sort("created_at", -1).skip((page - 1) * per_page).limit(per_page):
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
            "pages": (total + per_page - 1) // per_page, "keys": keys}


@app.delete("/admin/keys/{key_value}")
@limiter.limit("10/minute")
async def admin_revoke_key(request: Request, key_value: str, _admin: str = Depends(verify_admin)):
    col = get_keys_col()
    r   = col.update_one({"key": key_value}, {"$set": {"revoked": True, "revoked_at": datetime.now(timezone.utc).isoformat()}})
    if r.matched_count == 0:
        raise HTTPException(404, detail=f"Key '{key_value}' not found.")
    return {"revoked": True, "key": key_value}


@app.delete("/admin/keys/{key_value}/hard")
@limiter.limit("10/minute")
async def admin_delete_key(request: Request, key_value: str, _admin: str = Depends(verify_admin)):
    col = get_keys_col()
    r   = col.delete_one({"key": key_value})
    if r.deleted_count == 0:
        raise HTTPException(404, detail=f"Key '{key_value}' not found.")
    return {"deleted": True, "key": key_value}


@app.post("/admin/keys/{key_value}/unrevoke")
@limiter.limit("10/minute")
async def admin_unrevoke_key(request: Request, key_value: str, _admin: str = Depends(verify_admin)):
    col = get_keys_col()
    r   = col.update_one({"key": key_value}, {"$set": {"revoked": False}, "$unset": {"revoked_at": ""}})
    if r.matched_count == 0:
        raise HTTPException(404, detail=f"Key '{key_value}' not found.")
    return {"unrevoked": True, "key": key_value}


@app.patch("/admin/keys/{key_value}/label")
@limiter.limit("20/minute")
async def admin_update_label(request: Request, key_value: str, body: UpdateLabelRequest, _admin: str = Depends(verify_admin)):
    col = get_keys_col()
    r   = col.update_one({"key": key_value}, {"$set": {"label": body.label, "label_updated_at": datetime.now(timezone.utc).isoformat()}})
    if r.matched_count == 0:
        raise HTTPException(404, detail=f"Key '{key_value}' not found.")
    logger.info("Label updated: %s → '%s'", key_value, body.label)
    return {"updated": True, "key": key_value, "label": body.label}


@app.patch("/admin/keys/{key_value}/value")
@limiter.limit("20/minute")
async def admin_update_key_value(request: Request, key_value: str, body: UpdateKeyValueRequest, _admin: str = Depends(verify_admin)):
    col = get_keys_col()
    if not col.find_one({"key": key_value}):
        raise HTTPException(404, detail=f"Key '{key_value}' not found.")
    if body.new_key != key_value and col.find_one({"key": body.new_key}):
        raise HTTPException(409, detail=f"'{body.new_key}' is already in use.")
    col.update_one({"key": key_value}, {"$set": {"key": body.new_key, "key_updated_at": datetime.now(timezone.utc).isoformat()}})
    logger.info("Key renamed: %s → %s", key_value, body.new_key)
    return {"updated": True, "old_key": key_value, "new_key": body.new_key}

# ─────────────────────────────────────────────────────────────────────────────
# Visitor counter
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/visit")
async def record_visit(request: Request):
    try:
        v = get_main_db()["visits"]
        v.update_one({"_id": "global_counter"},
                     {"$inc": {"total": 1}, "$set": {"last_visit": datetime.now(timezone.utc).isoformat()}},
                     upsert=True)
        d = v.find_one({"_id": "global_counter"})
        return {"total": d["total"] if d else 1}
    except Exception as e:
        logger.error("Visit counter: %s", e); return {"total": 0}


@app.get("/visit")
async def get_visits():
    try:
        d = get_main_db()["visits"].find_one({"_id": "global_counter"})
        return {"total": d["total"] if d else 0}
    except Exception as e:
        logger.error("Get visits: %s", e); return {"total": 0}

# ─────────────────────────────────────────────────────────────────────────────
# Health
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
        cust_db  = get_cust_db()
        visits   = main_db["visits"].find_one({"_id": "global_counter"})
        kc       = key_db["keys"]
        return {
            "status": "ok",
            "main_cluster":     {c: main_db[c].count_documents({}) for c in ["address", "pan", "personal"]},
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
    except Exception as e:
        return {"status": "error", "detail": str(e)}