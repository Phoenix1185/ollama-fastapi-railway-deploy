import os
import time
import secrets
import hashlib
import json
import base64
import requests
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, BigInteger, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError

# ============ CONFIG ============
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://neondb_owner:npg_1imPJgOw5qBc@ep-divine-fog-ajro56fz-pooler.c-3.us-east-2.aws.neon.tech/Dailymotion%20?sslmode=require&channel_binding=require")
# Clean the DATABASE_URL just in case there are trailing spaces or problematic characters
DATABASE_URL = DATABASE_URL.strip()
# Ensure the database name and other components are properly URL-encoded
if " " in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace(" ", "%20")
# Some Neon URLs might have multiple spaces or other characters
DATABASE_URL = DATABASE_URL.replace(" ", "%20")
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-key-now")
MASTER_KEY = os.getenv("MASTER_KEY", "change-this-master-key-now")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "qwen2.5:0.5b")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# ============ DATABASE SETUP ============
db_available = False
engine = None
SessionLocal = None
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)
    password_hash = Column(String(255))
    name = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    key_hash = Column(String(255), unique=True, index=True)
    name = Column(String(255))
    rate_limit = Column(Integer, default=1000)
    usage_count = Column(BigInteger, default=0)
    token_count = Column(BigInteger, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked = Column(Boolean, default=False)

class UsageLog(Base):
    __tablename__ = "usage_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    api_key_id = Column(Integer, index=True)
    endpoint = Column(String(255))
    model = Column(String(255))
    tokens_used = Column(Integer, default=0)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    status = Column(String(50))
    duration_ms = Column(Float, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

class WebhookConfig(Base):
    __tablename__ = "webhooks"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    url = Column(String(500))
    events = Column(String(255), default="*")
    secret = Column(String(255))
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# Initialize database
try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args={"connect_timeout": 10})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db_available = True
    print("Database connected successfully.")
except Exception as e:
    print(f"WARNING: Database connection failed at startup: {e}")
    print("App will start without database. DB-dependent endpoints will return errors.")

# ============ AUTH SETUP ============
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

def get_db():
    if not db_available or SessionLocal is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# ============ DEPENDENCIES ============

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    # Try API key first
    key_hash = hash_key(token)
    api_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash, ApiKey.revoked == False).first()
    if api_key:
        api_key.usage_count += 1
        db.commit()
        return {"type": "api_key", "id": api_key.id, "user_id": api_key.user_id, "name": api_key.name}
    # Try JWT token
    payload = decode_token(token)
    if payload and "sub" in payload:
        user = db.query(User).filter(User.id == payload["sub"], User.is_active == True).first()
        if user:
            return {"type": "user", "id": user.id, "email": user.email, "name": user.name}
    raise HTTPException(status_code=401, detail="Invalid credentials")

def require_master_key(x_master_key: str = Header(None)):
    if not x_master_key or x_master_key != MASTER_KEY:
        raise HTTPException(status_code=403, detail="Invalid master key")
    return True

def require_user_auth(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Login required")
    payload = decode_token(credentials.credentials)
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = db.query(User).filter(User.id == payload["sub"], User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ============ FASTAPI APP ============

app = FastAPI(
    title="Phoenix AI API",
    description="Self-hosted LLM API with Ollama. Vision, Webhooks, Analytics, and User Management.",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    global engine, SessionLocal, db_available
    if not db_available:
        import asyncio
        import threading
        def retry_db():
            global engine, SessionLocal, db_available
            for attempt in range(5):
                try:
                    time.sleep(5 * (attempt + 1))
                    engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args={"connect_timeout": 10})
                    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
                    Base.metadata.create_all(bind=engine)
                    db_available = True
                    print(f"Database connected on retry attempt {attempt + 1}")
                    break
                except Exception as e:
                    print(f"DB retry {attempt + 1} failed: {e}")
        threading.Thread(target=retry_db, daemon=True).start()

# ============ REQUEST MODELS ============

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: Optional[str] = None
    messages: List[ChatMessage]
    stream: bool = False
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 2048

class GenerateRequest(BaseModel):
    model: Optional[str] = None
    prompt: str
    stream: bool = False
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 2048

class PullModelRequest(BaseModel):
    name: str

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = ""

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class CreateKeyRequest(BaseModel):
    name: str
    rate_limit: Optional[int] = 1000

class RevokeKeyRequest(BaseModel):
    key_id: int

class WebhookSetup(BaseModel):
    url: str
    events: Optional[str] = "*"

class VisionRequest(BaseModel):
    model: Optional[str] = None
    prompt: str
    image_url: Optional[str] = None

# ============ WEBHOOK HELPERS ============

def send_webhook(url: str, payload: dict, secret: str = ""):
    try:
        headers = {"Content-Type": "application/json"}
        if secret:
            headers["X-Webhook-Secret"] = secret
        requests.post(url, json=payload, headers=headers, timeout=10)
    except Exception as e:
        print(f"Webhook failed: {e}")

def trigger_webhooks(user_id: int, event: str, data: dict, db: Session):
    webhooks = db.query(WebhookConfig).filter(WebhookConfig.user_id == user_id, WebhookConfig.active == True).all()
    for wh in webhooks:
        if wh.events == "*" or event in wh.events.split(","):
            payload = {"event": event, "timestamp": datetime.utcnow().isoformat(), "data": data}
            send_webhook(wh.url, payload, wh.secret)

# ============ LOGGING ============

def log_usage(db: Session, user_id: int, api_key_id: Optional[int], endpoint: str, model: str, tokens: int, prompt_tokens: int = 0, completion_tokens: int = 0, status: str = "success", duration_ms: float = 0):
    log = UsageLog(
        user_id=user_id,
        api_key_id=api_key_id,
        endpoint=endpoint,
        model=model,
        tokens_used=tokens,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        status=status,
        duration_ms=duration_ms
    )
    db.add(log)
    db.commit()
    # Update API key token count
    if api_key_id:
        key = db.query(ApiKey).filter(ApiKey.id == api_key_id).first()
        if key:
            key.token_count += tokens
            db.commit()

# ============ PUBLIC ENDPOINTS ============

@app.get("/")
def root():
    return {
        "service": "Phoenix AI API",
        "version": "3.0.0",
        "tagline": "Your self-hosted AI infrastructure",
        "features": ["chat", "vision", "webhooks", "analytics", "user-auth", "api-keys"],
        "documentation": "/docs",
        "web_ui": "/ui",
        "api_docs": "/api-docs",
        "health": "/health"
    }

@app.get("/health")
def health():
    status = {"auth": "enabled"}
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        status["ollama"] = "connected"
    except:
        status["ollama"] = "not ready"
    status["db"] = "connected" if db_available else "unavailable"
    status["status"] = "ok" if status["ollama"] == "connected" else "degraded"
    return status

# ============ AUTH ENDPOINTS ============

@app.post("/auth/register")
def register(req: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=req.email,
        password_hash=get_password_hash(req.password),
        name=req.name
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"status": "success", "user_id": user.id}

@app.post("/auth/login")
def login(req: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": user.id})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/auth/me")
def get_me(user = Depends(require_user_auth)):
    return user

# ============ API KEY ENDPOINTS ============

@app.post("/api-keys")
def create_key(req: CreateKeyRequest, user = Depends(require_user_auth), db: Session = Depends(get_db)):
    raw_key = f"phoenix_{secrets.token_urlsafe(32)}"
    key_hash = hash_key(raw_key)
    new_key = ApiKey(
        user_id=user.id,
        key_hash=key_hash,
        name=req.name,
        rate_limit=req.rate_limit
    )
    db.add(new_key)
    db.commit()
    return {"api_key": raw_key, "name": req.name}

@app.get("/api-keys")
def list_keys(user = Depends(require_user_auth), db: Session = Depends(get_db)):
    keys = db.query(ApiKey).filter(ApiKey.user_id == user.id, ApiKey.revoked == False).all()
    return {"api_keys": [{"id": k.id, "name": k.name, "usage": k.usage_count, "tokens": k.token_count, "created_at": k.created_at} for k in keys]}

@app.post("/api-keys/revoke")
def revoke_key(req: RevokeKeyRequest, user = Depends(require_user_auth), db: Session = Depends(get_db)):
    key = db.query(ApiKey).filter(ApiKey.id == req.key_id, ApiKey.user_id == user.id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    key.revoked = True
    db.commit()
    return {"status": "revoked"}

# ============ WEBHOOK ENDPOINTS ============

@app.post("/webhooks")
def setup_webhook(req: WebhookSetup, user = Depends(require_user_auth), db: Session = Depends(get_db)):
    wh = WebhookConfig(
        user_id=user.id,
        url=req.url,
        events=req.events,
        secret=secrets.token_hex(16)
    )
    db.add(wh)
    db.commit()
    return {"id": wh.id, "secret": wh.secret}

# ============ ANALYTICS ENDPOINTS ============

@app.get("/analytics/usage")
def get_usage(user = Depends(require_user_auth), db: Session = Depends(get_db)):
    logs = db.query(UsageLog).filter(UsageLog.user_id == user.id).order_by(UsageLog.created_at.desc()).limit(100).all()
    total_tokens = db.query(UsageLog).with_entities(UsageLog.tokens_used).filter(UsageLog.user_id == user.id).all()
    sum_tokens = sum([t[0] or 0 for t in total_tokens])
    return {
        "total_tokens": sum_tokens,
        "request_count": len(total_tokens),
        "recent_logs": logs
    }

# ============ OLLAMA PROXY ENDPOINTS ============

@app.get("/v1/models")
def list_models(auth = Depends(get_current_user)):
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=10)
        data = r.json()
        models = []
        for m in data.get("models", []):
            models.append({
                "id": m["name"],
                "object": "model",
                "created": int(time.time()),
                "owned_by": "ollama"
            })
        return {"object": "list", "data": models}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama error: {str(e)}")

@app.post("/v1/chat/completions")
def chat_completions(
    req: ChatRequest, 
    background_tasks: BackgroundTasks,
    auth = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    model = req.model or DEFAULT_MODEL
    start_time = time.time()
    try:
        payload = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in req.messages],
            "stream": req.stream,
            "options": {
                "temperature": req.temperature,
                "num_predict": req.max_tokens
            }
        }
        r = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, stream=req.stream, timeout=120)
        
        if req.stream:
            def streamer():
                for line in r.iter_lines():
                    if line:
                        yield line.decode("utf-8") + "\n"
            return StreamingResponse(streamer(), media_type="application/x-ndjson")

        data = r.json()
        content = data.get("message", {}).get("content", "")
        tokens = len(content.split())
        duration = (time.time() - start_time) * 1000

        log_usage(db, auth["id"], auth.get("id") if auth["type"] == "api_key" else None,
                 "/v1/chat/completions", model, tokens, status="success", duration_ms=duration)

        background_tasks.add_task(trigger_webhooks, auth["id"], "chat.completed", 
                                 {"model": model, "tokens": tokens, "preview": content[:100]}, db)

        return {
            "id": f"chatcmpl-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": len(str(req.messages)), "completion_tokens": tokens, "total_tokens": tokens}
        }
    except Exception as e:
        duration = (time.time() - start_time) * 1000
        log_usage(db, auth["id"], None, "/v1/chat/completions", model, 0, status="error", duration_ms=duration)
        raise HTTPException(status_code=503, detail=f"Ollama error: {str(e)}")

@app.post("/api/generate")
def generate(req: GenerateRequest, auth = Depends(get_current_user), db: Session = Depends(get_db)):
    model = req.model or DEFAULT_MODEL
    start_time = time.time()
    try:
        payload = {
            "model": model,
            "prompt": req.prompt,
            "stream": req.stream,
            "options": {
                "temperature": req.temperature,
                "num_predict": req.max_tokens
            }
        }
        r = requests.post(f"{OLLAMA_HOST}/api/generate", json=payload, stream=req.stream, timeout=120)

        if req.stream:
            def streamer():
                for line in r.iter_lines():
                    if line:
                        yield line.decode("utf-8") + "\n"
            return StreamingResponse(streamer(), media_type="application/x-ndjson")

        data = r.json()
        content = data.get("response", "")
        tokens = len(content.split())
        duration = (time.time() - start_time) * 1000

        log_usage(db, auth["id"], auth.get("id") if auth["type"] == "api_key" else None,
                 "/api/generate", model, tokens, status="success", duration_ms=duration)

        return data
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama error: {str(e)}")

@app.get("/api/models")
def ollama_models(auth = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=30)
        return r.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama error: {str(e)}")

@app.post("/api/pull")
def pull_model(req: PullModelRequest, auth = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        payload = {"name": req.name, "stream": False}
        r = requests.post(f"{OLLAMA_HOST}/api/pull", json=payload, timeout=300)
        return r.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama error: {str(e)}")

# ============ VISION ENDPOINT ============

@app.post("/v1/chat/vision")
def vision_chat(
    req: VisionRequest,
    auth = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    model = req.model or "llava:7b"
    start_time = time.time()
    try:
        messages = [{"role": "user", "content": req.prompt}]
        if req.image_url:
            # Download and encode image
            try:
                img_data = requests.get(req.image_url, timeout=10).content
                b64 = base64.b64encode(img_data).decode("utf-8")
                messages[0]["images"] = [b64]
            except:
                pass

        payload = {
            "model": model,
            "messages": messages,
            "stream": False
        }
        r = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, timeout=120)
        data = r.json()
        content = data.get("message", {}).get("content", "")
        tokens = len(content.split())
        duration = (time.time() - start_time) * 1000

        log_usage(db, auth["id"], auth.get("id") if auth["type"] == "api_key" else None,
                 "/v1/chat/vision", model, tokens, status="success", duration_ms=duration)

        return {
            "id": f"vision-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop"
            }]
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Vision error: {str(e)}")

@app.post("/v1/chat/vision/upload")
def vision_upload(
    prompt: str = Form(...),
    model: Optional[str] = Form("llava:7b"),
    image: UploadFile = File(...),
    auth = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    start_time = time.time()
    try:
        img_data = image.file.read()
        b64 = base64.b64encode(img_data).decode("utf-8")

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt, "images": [b64]}],
            "stream": False
        }
        r = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, timeout=120)
        data = r.json()
        content = data.get("message", {}).get("content", "")
        tokens = len(content.split())
        duration = (time.time() - start_time) * 1000

        log_usage(db, auth["id"], auth.get("id") if auth["type"] == "api_key" else None,
                 "/v1/chat/vision/upload", model, tokens, status="success", duration_ms=duration)

        return {
            "id": f"vision-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop"
            }]
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Vision upload error: {str(e)}")

# ============ ADMIN ENDPOINTS (MASTER KEY) ============

@app.get("/admin/users")
def admin_users(master: bool = Depends(require_master_key), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return {"users": [{"id": u.id, "email": u.email, "name": u.name, "created_at": u.created_at.isoformat() if u.created_at else None} for u in users]}

@app.get("/admin/stats")
def admin_stats(master: bool = Depends(require_master_key), db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    total_keys = db.query(ApiKey).count()
    total_requests = db.query(UsageLog).count()
    total_tokens = db.query(UsageLog).with_entities(UsageLog.tokens_used).all()
    total_tokens_sum = sum([t[0] or 0 for t in total_tokens])
    return {"total_users": total_users, "total_api_keys": total_keys, "total_requests": total_requests, "total_tokens": total_tokens_sum}

# ============ UI ROUTES ============

@app.get("/ui", response_class=HTMLResponse)
def web_ui():
    try:
        with open("ui.html", "r") as f:
            return f.read()
    except:
        return "<h1>Phoenix AI - UI file not found</h1>"

@app.get("/api-docs", response_class=HTMLResponse)
def api_docs():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Docs - Phoenix AI by Phoenix Teams & IYANU</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0a0a1a;color:#e0e0e0;min-height:100vh}
.container{max-width:1000px;margin:0 auto;padding:40px 20px}
.header{text-align:center;padding:40px 0;border-bottom:1px solid #1a1a3e;margin-bottom:40px}
.logo{font-size:2.5rem;font-weight:800;background:linear-gradient(90deg,#00d4ff,#7b2cbf);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:10px}
.tagline{color:#888;font-size:1rem}
.badge{display:inline-block;background:#1a1a3e;border:1px solid #2a2a5e;padding:4px 12px;border-radius:20px;font-size:.8rem;color:#00d4ff;margin-top:10px}
.card{background:#12122a;border:1px solid #1a1a3e;border-radius:16px;padding:24px;margin-bottom:20px}
.card h2{color:#00d4ff;margin-bottom:16px;font-size:1.2rem}
.card h3{color:#e0e0e0;margin:20px 0 10px;font-size:1rem}
.endpoint{background:#0a0a1a;border-left:3px solid #00d4ff;padding:12px 16px;margin:8px 0;border-radius:0 8px 8px 0;font-family:"Courier New",monospace;font-size:.9rem}
.method{color:#7ee787;font-weight:bold;margin-right:8px}
.url{color:#dcdcaa}
.code-block{background:#0a0a1a;border-radius:8px;padding:16px;overflow-x:auto;font-family:"Courier New",monospace;font-size:.85rem;color:#dcdcaa;margin:10px 0}
.table{width:100%;border-collapse:collapse;margin:10px 0}
.table th,.table td{padding:10px;text-align:left;border-bottom:1px solid #1a1a3e;font-size:.9rem}
.table th{color:#00d4ff;font-weight:600}
.nav{display:flex;gap:10px;margin-bottom:30px;flex-wrap:wrap}
.nav a{color:#00d4ff;text-decoration:none;padding:8px 16px;border:1px solid #2a2a5e;border-radius:8px;font-size:.9rem}
.nav a:hover{background:#1a1a3e}
.note{background:#1a3a5c;border-left:3px solid #00d4ff;padding:12px 16px;margin:10px 0;border-radius:0 8px 8px 0;font-size:.9rem;color:#e0e0e0}
.warning{background:#4a3a1a;border-left:3px solid #ffa500;padding:12px 16px;margin:10px 0;border-radius:0 8px 8px 0;font-size:.9rem;color:#ffa500}
.footer{text-align:center;padding:40px 0;color:#888;font-size:.85rem;border-top:1px solid #1a1a3e;margin-top:40px}
</style>
</head>
<body>
<div class="container">
<div class="nav">
<a href="/ui">Dashboard</a>
<a href="/api-docs">API Docs</a>
<a href="/docs">Swagger UI</a>
<a href="/redoc">ReDoc</a>
</div>

<div class="header">
<div class="logo">PHOENIX AI</div>
<p class="tagline">Self-Hosted LLM Infrastructure</p>
<span class="badge">Developed by Phoenix Teams & IYANU</span>
</div>

<div class="card">
<h2>Authentication</h2>
<p style="color:#888;margin-bottom:10px">Phoenix AI supports two authentication methods:</p>
<h3>1. User Authentication (Email + Password)</h3>
<p style="color:#888;margin:8px 0">Register and login to get a JWT token. Use it in the Authorization header.</p>
<div class="code-block">POST /auth/register<br>Body: {"email": "user@example.com", "password": "secret", "name": "User"}<br><br>POST /auth/login<br>Body: {"email": "user@example.com", "password": "secret"}<br><br>Response: {"access_token": "eyJ...", "token_type": "bearer"}</div>
<h3>2. API Key Authentication</h3>
<p style="color:#888;margin:8px 0">Create API keys from the dashboard. Use them as Bearer tokens.</p>
<div class="code-block">Authorization: Bearer phoenix_xxxxxxxxxxxx</div>
<div class="warning">Never share your API keys. They grant full access to your account.</div>
</div>

<div class="card">
<h2>OpenAI-Compatible Endpoints</h2>
<div class="endpoint"><span class="method">GET</span><span class="url">/v1/models</span></div>
<p style="color:#888;margin:8px 0">List all available models.</p>

<div class="endpoint"><span class="method">POST</span><span class="url">/v1/chat/completions</span></div>
<table class="table">
<tr><th>Parameter</th><th>Type</th><th>Required</th><th>Description</th></tr>
<tr><td>model</td><td>string</td><td>No</td><td>Model name (default: qwen2.5:0.5b)</td></tr>
<tr><td>messages</td><td>array</td><td>Yes</td><td>[{role, content}]</td></tr>
<tr><td>stream</td><td>boolean</td><td>No</td><td>Stream response</td></tr>
<tr><td>temperature</td><td>float</td><td>No</td><td>0.0 - 2.0</td></tr>
<tr><td>max_tokens</td><td>integer</td><td>No</td><td>Max tokens to generate</td></tr>
</table>
<div class="code-block">curl -X POST <span class="base-url"></span>/v1/chat/completions<br>
-H "Authorization: Bearer YOUR_TOKEN"<br>
-H "Content-Type: application/json"<br>
-d '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"Hello!"}]}'</div>
</div>

<div class="card">
<h2>Vision Endpoints</h2>
<div class="endpoint"><span class="method">POST</span><span class="url">/v1/chat/vision</span></div>
<p style="color:#888;margin:8px 0">Analyze images with text prompts. Provide image URL.</p>
<div class="code-block">Body: {"model": "llava:7b", "prompt": "What's in this image?", "image_url": "https://..."}</div>

<div class="endpoint"><span class="method">POST</span><span class="url">/v1/chat/vision/upload</span></div>
<p style="color:#888;margin:8px 0">Upload image file directly (multipart/form-data).</p>
<div class="code-block">Form: prompt="Describe this", image=&lt;file&gt;</div>
<div class="note">Vision models like llava:7b or llava-phi3 are required. Pull them first.</div>
</div>

<div class="card">
<h2>User Management</h2>
<div class="endpoint"><span class="method">POST</span><span class="url">/auth/register</span></div>
<div class="endpoint"><span class="method">POST</span><span class="url">/auth/login</span></div>
<div class="endpoint"><span class="method">GET</span><span class="url">/auth/me</span></div>
</div>

<div class="card">
<h2>API Key Management</h2>
<div class="endpoint"><span class="method">POST</span><span class="url">/api-keys</span></div>
<p style="color:#888;margin:8px 0">Create new API key. Returns key once - save it!</p>
<div class="endpoint"><span class="method">GET</span><span class="url">/api-keys</span></div>
<div class="endpoint"><span class="method">POST</span><span class="url">/api-keys/revoke</span></div>
</div>

<div class="card">
<h2>Analytics</h2>
<div class="endpoint"><span class="method">GET</span><span class="url">/analytics/usage</span></div>
<p style="color:#888;margin:8px 0">Total requests, tokens, model breakdown, recent logs.</p>
<div class="endpoint"><span class="method">GET</span><span class="url">/analytics/daily</span></div>
<p style="color:#888;margin:8px 0">Daily aggregated stats.</p>
</div>

<div class="card">
<h2>Webhooks</h2>
<div class="endpoint"><span class="method">POST</span><span class="url">/webhooks</span></div>
<p style="color:#888;margin:8px 0">Register a URL to receive event notifications.</p>
<div class="code-block">Body: {"url": "https://your-app.com/webhook", "events": "*"}<br><br>Payload sent to webhook:<br>{"event": "chat.completed", "timestamp": "2026-...", "data": {"model": "...", "tokens": 42}}</div>
</div>

<div class="card">
<h2>Environment Variables</h2>
<table class="table">
<tr><th>Variable</th><th>Description</th></tr>
<tr><td>DATABASE_URL</td><td>PostgreSQL connection string</td></tr>
<tr><td>SECRET_KEY</td><td>JWT signing secret</td></tr>
<tr><td>MASTER_KEY</td><td>Admin master key for /admin endpoints</td></tr>
<tr><td>DEFAULT_MODEL</td><td>Auto-pulled model on startup</td></tr>
<tr><td>OLLAMA_HOST</td><td>Internal Ollama URL</td></tr>
<tr><td>WEBHOOK_URL</td><td>Default webhook URL (optional)</td></tr>
</table>
</div>

<div class="footer">
<p>Phoenix AI v3.0.0 - Developed by Phoenix Teams & IYANU</p>
<p style="margin-top:8px;font-size:.75rem">Self-hosted LLM infrastructure powered by Ollama & FastAPI</p>
</div>
</div>
<script>
document.querySelectorAll('.base-url').forEach(el=>el.textContent=window.location.origin);
</script>
</body>
</html>"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
