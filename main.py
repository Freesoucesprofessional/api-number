"""
Secure Lookup API — Dual MongoDB Edition
==========================================
Two MongoDB clusters:
  MONGO_URL       → address, pan, personal  (main cluster)
  MONGO_EMAIL_URL → email collection        (dedicated cluster)

Endpoints:
  GET /search/number?q=<phone>      — address + pan + email (India)
  GET /search/email?q=<email>       — address + pan + email (India)
  GET /search/pak/number?q=<phone>  — personal (Pakistan) with images
  GET /health                       — status check, no auth required
"""

import re
import os
import logging

from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()

MONGO_URL       = os.getenv("MONGO_URL", "")        # main cluster: address, pan, personal
MONGO_EMAIL_URL = os.getenv("MONGO_EMAIL_URL", "")  # email cluster: email collection
DB_NAME         = os.getenv("DB_NAME")
IMAGE_BASE      = os.getenv("IMAGE_BASE_URL").rstrip("/")

VALID_API_KEYS: set[str] = set(
    k.strip() for k in os.getenv("API_KEYS", "").split(",") if k.strip()
)
RATE_LIMIT  = os.getenv("RATE_LIMIT", "10/minute")
MAX_RESULTS = int(os.getenv("MAX_RESULTS", "20"))

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Lookup API", docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# MongoDB clients — main (address/pan/personal) + email cluster
# ─────────────────────────────────────────────────────────────────────────────

_main_client:  MongoClient | None = None
_email_client: MongoClient | None = None


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


def col(name: str) -> Collection:
    """Route collection to correct cluster."""
    if name == "email":
        return get_email_db()[name]
    return get_main_db()[name]


@app.on_event("startup")
async def startup():
    # Main cluster — address, pan, personal
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


@app.on_event("shutdown")
async def shutdown():
    global _main_client, _email_client
    for client in [_main_client, _email_client]:
        if client:
            client.close()
    logger.info("MongoDB clients closed.")

# ─────────────────────────────────────────────────────────────────────────────
# Security
# ─────────────────────────────────────────────────────────────────────────────

def verify_api_key(request: Request) -> str:
    key = request.headers.get("X-API-Key", "")
    if not VALID_API_KEYS or key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return key

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

def safe_email(docs):
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
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/search/number")
@limiter.limit(RATE_LIMIT)
async def search_by_number(
    request: Request,
    q: str = Query(..., min_length=10, max_length=12, description="10 or 12 digit phone number"),
    _key: str = Depends(verify_api_key),
):
    """Search address + pan (main cluster) + email (email cluster) by phone."""
    number = validate_phone(q)
    filt   = phone_filter(number)

    address_docs = list(col("address").find(filt, limit=MAX_RESULTS))
    pan_docs     = list(col("pan").find(filt,     limit=MAX_RESULTS))
    email_docs   = list(col("email").find(filt,   limit=MAX_RESULTS))

    return {
        "query": number,
        "total": len(address_docs) + len(pan_docs) + len(email_docs),
        "address": {"count": len(address_docs), "results": safe_address(address_docs)},
        "pan":     {"count": len(pan_docs),     "results": safe_pan(pan_docs)},
        "email":   {"count": len(email_docs),   "results": safe_email(email_docs)},
    }


@app.get("/search/email")
@limiter.limit(RATE_LIMIT)
async def search_by_email(
    request: Request,
    q: str = Query(..., min_length=6, max_length=254, description="Valid email address"),
    _key: str = Depends(verify_api_key),
):
    """Search address + pan (main cluster) + email (email cluster) by email."""
    email = validate_email(q)
    filt  = {"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}}

    address_docs = list(col("address").find(filt, limit=MAX_RESULTS))
    pan_docs     = list(col("pan").find(filt,     limit=MAX_RESULTS))
    email_docs   = list(col("email").find(filt,   limit=MAX_RESULTS))

    return {
        "query": email,
        "total": len(address_docs) + len(pan_docs) + len(email_docs),
        "address": {"count": len(address_docs), "results": safe_address(address_docs)},
        "pan":     {"count": len(pan_docs),     "results": safe_pan(pan_docs)},
        "email":   {"count": len(email_docs),   "results": safe_email(email_docs)},
    }


@app.get("/search/pak/number")
@limiter.limit(RATE_LIMIT)
async def search_pak_by_number(
    request: Request,
    q: str = Query(..., min_length=10, max_length=12, description="10 or 12 digit Pakistani mobile"),
    _key: str = Depends(verify_api_key),
):
    """Search personal collection (main cluster) by Pakistani mobile number."""
    number = validate_phone(q)
    filt   = phone_filter_pak(number)
    docs   = list(col("personal").find(filt, limit=MAX_RESULTS))

    return {
        "query":   number,
        "count":   len(docs),
        "results": safe_personal(docs),
    }


@app.get("/health")
async def health():
    try:
        main_db  = get_main_db()
        email_db = get_email_db()
        return {
            "status": "ok",
            "main_cluster": {
                c: main_db[c].count_documents({})
                for c in ["address", "pan", "personal"]
            },
            "email_cluster": {
                "email": email_db["email"].count_documents({})
            },
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}