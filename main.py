"""
Secure Lookup API  — Address + PAN + Email + Personal (PAK)
============================================================
Endpoints:
  GET /search/number?q=<phone>      — address + pan + email (India)
  GET /search/email?q=<email>       — address + pan + email (India)
  GET /search/pak/number?q=<phone>  — personal.json (Pakistan) with images
  GET /health                       — status check, no auth required
"""

import re
import os
import asyncio
import httpx
import logging

from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()

ADDRESS_DATA_URL  = os.getenv("ADDRESS_DATA_URL")
PAN_DATA_URL      = os.getenv("PAN_DATA_URL")
PERSONAL_DATA_URL = os.getenv("PERSONAL_DATA_URL")
EMAIL_DATA_URL    = os.getenv("EMAIL_DATA_URL")
IMAGE_BASE_URL    = os.getenv("IMAGE_BASE_URL", "").rstrip("/")

VALID_API_KEYS: set[str] = set(
    k.strip()
    for k in os.getenv("API_KEYS", "").split(",")
    if k.strip()
)
RATE_LIMIT = os.getenv("RATE_LIMIT", "10/minute")

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
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"], allow_headers=["*"])

# ─────────────────────────────────────────────────────────────────────────────
# In-memory caches
# ─────────────────────────────────────────────────────────────────────────────

_address_cache:  list[dict] = []
_pan_cache:      list[dict] = []
_personal_cache: list[dict] = []
_email_cache:    list[dict] = []


def _extract_list(data) -> list[dict]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return next((v for v in data.values() if isinstance(v, list)), [])
    return []


async def _fetch_json(url: str | None, label: str) -> list[dict]:
    if not url:
        logger.warning("No URL configured for %s — skipping.", label)
        return []
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            records = _extract_list(resp.json())
            logger.info("✓ Loaded %d records from %s", len(records), label)
            return records
    except Exception as exc:
        logger.error("✗ Failed to load %s: %s", label, exc)
        return []


async def load_all_data():
    global _address_cache, _pan_cache, _personal_cache, _email_cache
    _address_cache, _pan_cache, _personal_cache, _email_cache = await asyncio.gather(
        _fetch_json(ADDRESS_DATA_URL,  "address.json"),
        _fetch_json(PAN_DATA_URL,      "pan.json"),
        _fetch_json(PERSONAL_DATA_URL, "personal.json"),
        _fetch_json(EMAIL_DATA_URL,    "email.json"),
    )

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


def safe_address(records):
    return [{k: v for k, v in r.items() if k in ADDRESS_FIELDS} for r in records]

def safe_pan(records):
    return [{k: v for k, v in r.items() if k in PAN_FIELDS} for r in records]

def safe_email(records):
    return [{k: v for k, v in r.items() if k in EMAIL_FIELDS} for r in records]

def build_image_url(filename) -> str | None:
    if not filename:
        return None
    f = str(filename)
    return f if f.startswith("http") else f"{IMAGE_BASE_URL}/{f.lstrip('/')}"

def safe_personal(records):
    results = []
    for r in records:
        entry = {k: v for k, v in r.items() if k in PERSONAL_FIELDS}
        entry["profileImageUrl"] = build_image_url(r.get("profileImage"))
        entry["cnicImageUrl"]    = build_image_url(r.get("cnicImage"))
        results.append(entry)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# Matching helpers
# ─────────────────────────────────────────────────────────────────────────────

def number_matches_flat(stored: str, query: str) -> bool:
    s = re.sub(r"[\s\-]", "", (stored or ""))
    return s == query or s.endswith(query) or query.endswith(s)

def number_matches_pak(record: dict, query: str) -> bool:
    mobile = record.get("mobile")
    if not mobile or not isinstance(mobile, dict):
        return False
    digits = re.sub(r"[\s\-]", "", (mobile.get("digits") or ""))
    return digits == query or digits.endswith(query) or query.endswith(digits)

# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    await load_all_data()

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
    number       = validate_phone(q)
    address_hits = [r for r in _address_cache if number_matches_flat(r.get("number", ""), number)]
    pan_hits     = [r for r in _pan_cache     if number_matches_flat(r.get("number", ""), number)]
    email_hits   = [r for r in _email_cache   if number_matches_flat(r.get("number", ""), number)]

    return {
        "query": number,
        "total": len(address_hits) + len(pan_hits) + len(email_hits),
        "address": {"count": len(address_hits), "results": safe_address(address_hits)},
        "pan":     {"count": len(pan_hits),     "results": safe_pan(pan_hits)},
        "email":   {"count": len(email_hits),   "results": safe_email(email_hits)},
    }


@app.get("/search/email")
@limiter.limit(RATE_LIMIT)
async def search_by_email(
    request: Request,
    q: str = Query(..., min_length=6, max_length=254, description="Valid email address"),
    _key: str = Depends(verify_api_key),
):
    email        = validate_email(q)
    address_hits = [r for r in _address_cache if (r.get("email") or "").lower() == email]
    pan_hits     = [r for r in _pan_cache     if (r.get("email") or "").lower() == email]
    email_hits   = [r for r in _email_cache   if (r.get("email") or "").lower() == email]

    return {
        "query": email,
        "total": len(address_hits) + len(pan_hits) + len(email_hits),
        "address": {"count": len(address_hits), "results": safe_address(address_hits)},
        "pan":     {"count": len(pan_hits),     "results": safe_pan(pan_hits)},
        "email":   {"count": len(email_hits),   "results": safe_email(email_hits)},
    }


@app.get("/search/pak/number")
@limiter.limit(RATE_LIMIT)
async def search_pak_by_number(
    request: Request,
    q: str = Query(..., min_length=10, max_length=12, description="10 or 12 digit Pakistani mobile number"),
    _key: str = Depends(verify_api_key),
):
    number = validate_phone(q)
    hits   = [r for r in _personal_cache if number_matches_pak(r, number)]

    return {
        "query":   number,
        "count":   len(hits),
        "results": safe_personal(hits),
    }


@app.get("/health")
async def health():
    return {
        "status":           "ok",
        "address_records":  len(_address_cache),
        "pan_records":      len(_pan_cache),
        "personal_records": len(_personal_cache),
        "email_records":    len(_email_cache),
    }