import os
import re
from typing import Optional
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load environment variables
load_dotenv()

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI")
API_KEY = os.getenv("SECRET_API_KEY")
API_KEY_NAME = "access_token"

# Rate Limiter setup (Prevents abuse)
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PakData Secure API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security Header
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Database Connection
client = MongoClient(MONGO_URI)
db_main = client["email_finder"]
db_pan = client["pan_database"]

# ── MODELS & SECURITY ─────────────────────────────────────────────────────────
class SearchRequest(BaseModel):
    query: str

async def get_api_key(header: str = Security(api_key_header)):
    if header == API_KEY:
        return header
    raise HTTPException(status_code=403, detail="Unauthorized: Invalid Access Token")

# ── HELPERS ───────────────────────────────────────────────────────────────────
def normalize(raw: str):
    digits = re.sub(r"\D", "", str(raw))
    return digits.lstrip("0") if digits.startswith("0") else digits

def get_number_variants(raw: str):
    digits = normalize(raw)
    variants = [digits]
    if len(digits) == 10:
        variants.append("91" + digits)
    elif len(digits) == 12 and digits.startswith("91"):
        variants.append(digits[2:])
    return list(set(variants))

def clean(res):
    if res: res.pop("_id", None)
    return res

# ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Change to your frontend URL for better security
    allow_methods=["POST"],
    allow_headers=["*"],
)

# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.post("/search/personal", dependencies=[Depends(get_api_key)])
@limiter.limit("20/minute")
async def search_personal(request: SearchRequest):
    variants = get_number_variants(request.query)
    res = db_main["personal_data"].find_one({"mobile.digits": {"$in": variants}})
    if not res:
        raise HTTPException(status_code=404, detail="Personal record not found")
    return {"status": "success", "data": clean(res)}

@app.post("/search/number", dependencies=[Depends(get_api_key)])
@limiter.limit("30/minute")
async def search_number(request: SearchRequest):
    variants = get_number_variants(request.query)
    int_variants = [int(v) for v in variants if v.isdigit()]
    
    # Sequential search across all collections
    targets = [
        (db_main["address_records"], "number"),
        (db_pan["pan_records"], "number"),
        (db_pan["pan_records"], "m"),
        (db_main["users"], "number")
    ]
    
    for coll, field in targets:
        res = coll.find_one({field: {"$in": variants + int_variants}})
        if res:
            return {"status": "success", "source": coll.name, "data": clean(res)}
            
    raise HTTPException(status_code=404, detail="Number not found in any database")

@app.post("/search/email", dependencies=[Depends(get_api_key)])
@limiter.limit("30/minute")
async def search_email(request: SearchRequest):
    q = request.query.strip()
    regex_query = re.compile(f"^{re.escape(q)}$", re.IGNORECASE)
    
    targets = [
        (db_main["address_records"], "email"),
        (db_pan["pan_records"], "email"),
        (db_pan["pan_records"], "e")
    ]
    
    for coll, field in targets:
        res = coll.find_one({field: regex_query})
        if res:
            return {"status": "success", "source": coll.name, "data": clean(res)}

    raise HTTPException(status_code=404, detail="Email not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)