        import os
import secrets
import re
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv

# ==========================================
# 1. Configuration & Setup
# ==========================================
load_dotenv()

# Database URL (Fallback to SQLite for local dev if missing)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")

# SQLAlchemy Setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password Hashing Setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# API Security Header Setup
security = HTTPBearer()

# ==========================================
# 2. Database Models
# ==========================================
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    api_keys = relationship("ApiKey", back_populates="user")

class ApiKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    key = Column(String, unique=True, index=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    user = relationship("User", back_populates="api_keys")

# ==========================================
# 3. Pydantic Schemas
# ==========================================
class UserCredentials(BaseModel):
    email: EmailStr
    password: str

class ScanRequest(BaseModel):
    repo_name: str
    commit_hash: str
    code_snippet: str

# ==========================================
# 4. Security & Helper Functions
# ==========================================
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def generate_api_key() -> str:
    # 16 bytes = 32 hex characters
    random_hex = secrets.token_hex(16)
    return f"dfx_live_{random_hex}"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 5. Secret Scanning Engine
# ==========================================
# Pre-compile regex patterns for performance
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
    "Stripe Live Secret Key": re.compile(r"sk_live_[0-9a-zA-Z]{24}", re.IGNORECASE),
    "GitHub Personal Access Token": re.compile(r"ghp_[0-9a-zA-Z]{36}")
}

def mask_secret(secret_type: str, secret: str) -> str:
    """Masks the secret, leaving only the recognizable prefix exposed."""
    prefix_length = 8 if secret_type == "Stripe Live Secret Key" else 4
    if len(secret) <= prefix_length:
        return "********"
    return secret[:prefix_length] + "*" * (len(secret) - prefix_length)

def scan_for_secrets(code_snippet: str) -> list:
    """Scans code against known patterns and returns masked findings."""
    findings = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(code_snippet):
            raw_secret = match.group()
            findings.append({
                "type": secret_type,
                "match": mask_secret(secret_type, raw_secret)
            })
    return findings

# ==========================================
# 6. FastAPI App Initialization & CORS
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup if they don't exist
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(title="Defphonix Security API", lifespan=lifespan)

# FIXED CORS CONFIGURATION (Bulletproof Bypass)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Ab hum wildcard use kar sakte hain
    allow_credentials=False, # Isay False kar diya kyunke hum Cookies nahi, API Keys use kar rahe hain
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# 7. Endpoints
# ==========================================

@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register_user(credentials: UserCredentials, db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == credentials.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash password and create User
    hashed_pwd = get_password_hash(credentials.password)
    new_user = User(email=credentials.email, hashed_password=hashed_pwd)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Generate and attach API key
    new_api_key = ApiKey(user_id=new_user.id, key=generate_api_key())
    db.add(new_api_key)
    db.commit()
    
    return {
        "status": "success", 
        "message": "User registered successfully. API Key generated."
    }

@app.post("/auth/login")
def login_user(credentials: UserCredentials, db: Session = Depends(get_db)):
    # Fetch User
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Fetch the active API key for this user
    api_key_record = db.query(ApiKey).filter(
        ApiKey.user_id == user.id, 
        ApiKey.is_active == True
    ).first()
    
    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No active API key found for this user."
        )
        
    return {
        "status": "success",
        "email": user.email,
        "api_key": api_key_record.key
    }

@app.post("/v1/scan")
def trigger_scan(
    payload: ScanRequest,
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    provided_key = credentials.credentials
    
    # 1. Authenticate the API Key
    api_key_record = db.query(ApiKey).filter(
        ApiKey.key == provided_key,
        ApiKey.is_active == True
    ).first()
    
    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API Key",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # 2. Run the Scanning Engine
    findings = scan_for_secrets(payload.code_snippet)
    
    # 3. Format the Response
    if findings:
        return {
            "status": "vulnerable",
            "repo_name": payload.repo_name,
            "findings": findings
        }
    
    return {
        "status": "secure", 
        "message": "No hardcoded secrets detected."
    }
