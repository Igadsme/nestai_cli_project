```python
from fastapi import FastAPI, Depends, HTTPException, status, Request, Security
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, constr, ValidationError
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional, List
import logging
import re
import uvicorn
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict
import asyncio

# Configuration constants (in production, load from environment variables or secure vault)
DATABASE_URL = "sqlite:///./secure_login.db"  # Use a real DB in production
JWT_SECRET_KEY = "CHANGE_THIS_TO_A_SECURE_RANDOM_SECRET"  # Must be changed in production
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MAX_FAILED_ATTEMPTS = 5
ACCOUNT_LOCK_DURATION_MINUTES = 15
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60

# Initialize logging securely
logger = logging.getLogger("auth_logger")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("auth.log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Database setup
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Password hashing context with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for bearer token
oauth2_scheme = HTTPBearer()

# Role-based access control decorator
def require_roles(allowed_roles: List[str]):
    def role_checker(token_data=Depends(lambda token=Depends(oauth2_scheme): verify_token(token.credentials))):
        if token_data.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient privileges")
        return token_data
    return role_checker

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, nullable=False, index=True)
    hashed_password = Column(String(128), nullable=False)
    role = Column(String(50), default="user", nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    account_locked_until = Column(DateTime, nullable=True)

class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(36), unique=True, nullable=False, index=True)
    revoked_at = Column(DateTime, default=func.now(), nullable=False)

Base.metadata.create_all(bind=engine)

# Pydantic Schemas
class LoginRequest(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=150, regex=r"^[a-zA-Z0-9_.-]+$")
    password: constr(min_length=8, max_length=128)

class TokenData(BaseModel):
    username: str
    role: str
    exp: int
    jti: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

# Rate limiting middleware
class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.requests = defaultdict(list)  # IP -> [timestamps]

    async def dispatch(self, request: StarletteRequest, call_next):
        client_ip = request.client.host
        now = datetime.utcnow().timestamp()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS
        timestamps = self.requests[client_ip]
        # Remove outdated timestamps
        while timestamps and timestamps[0] < window_start:
            timestamps.pop(0)
        if len(timestamps) >= RATE_LIMIT_REQUESTS:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many requests, please try again later."},
            )
        timestamps.append(now)
        response = await call_next(request)
        return response

# Utility functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "jti": generate_jti()})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def generate_jti() -> str:
    import uuid
    return str(uuid.uuid4())

def verify_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        if jti is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        # Check if token is revoked
        with SessionLocal() as db:
            revoked = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
            if revoked:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
        username: str = payload.get("username")
        role: str = payload.get("role")
        if username is None or role is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        return TokenData(username=username, role=role, exp=payload.get("exp"), jti=jti)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

def sanitize_input(input_str: str) -> str:
    # Basic sanitization: strip and remove suspicious characters
    sanitized = input_str.strip()
    sanitized = re.sub(r"[^\w@.-]", "", sanitized)
    return sanitized

def log_auth_attempt(username: str, success: bool, ip: str):
    msg = f"Authentication attempt for user '{username}' from IP {ip} - {'SUCCESS' if success else 'FAILURE'}"
    logger.info(msg)

# Application instance
app = FastAPI(title="Secure Login API", version="1.0")

# Enforce HTTPS redirect middleware (should be used behind HTTPS proxy in production)
app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(RateLimiterMiddleware)

@app.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def login(request: Request, login_req: LoginRequest, db: Session = Depends(get_db)):
    ip = request.client.host
    username = sanitize_input(login_req.username)
    password = login_req.password  # Password is validated by Pydantic length constraints

    user = db.query(User).filter(User.username == username).first()
    if not user:
        log_auth_attempt(username, False, ip)
        # Do not reveal if user exists
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Check if account is locked
    if user.account_locked_until and user.account_locked_until > datetime.utcnow():
        log_auth_attempt(username, False, ip)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account temporarily locked due to multiple failed login attempts")

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.account_locked_until = datetime.utcnow() + timedelta(minutes=ACCOUNT_LOCK_DURATION_MINUTES)
            user.failed_login_attempts = 0  # reset counter after lock
        db.commit()
        log_auth_attempt(username, False, ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Successful login resets failed attempts and lockout
    user.failed_login_attempts = 0
    user.account_locked_until = None
    db.commit()

    token_data = {
        "username": user.username,
        "role": user.role,
    }
    access_token = create_access_token(token_data)
    log_auth_attempt(username, True, ip)
    return TokenResponse(access_token=access_token, expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60)

@app.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(credentials: HTTPAuthorizationCredentials = Security(oauth2_scheme), db: Session = Depends(get_db)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        if jti is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        # Revoke token
        revoked_token = RevokedToken(jti=jti)
        db.add(revoked_token)
        db.commit()
        return
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@app.get("/sensitive-data", dependencies=[Depends(require_roles(["admin"]))])
async def sensitive_data():
    # Example protected endpoint
    return {"data": "This is sensitive data accessible only to admins."}

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(login_req: LoginRequest, db: Session = Depends(get_db)):
    username = sanitize_input(login_req.username)
    password = login_req.password

    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")

    hashed_pw = hash_password(password)
    user = User(username=username, hashed_password=hashed_pw, role="user")
    db.add(user)
    db.commit()
    return {"msg": "User registered successfully"}

# Exception handlers for security
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Invalid input data"},
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Do not expose internal details
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

# Run with: uvicorn this_file_name:app --host 0.0.0.0 --port 8000 --ssl-keyfile=key.pem --ssl-certfile=cert.pem
# HTTPS must be enforced at deployment level (reverse proxy or uvicorn SSL config)

if __name__ == "__main__":
    uvicorn.run("secure_login:app", host="0.0.0.0", port=8000, ssl_keyfile="key.pem", ssl_certfile="cert.pem")
```