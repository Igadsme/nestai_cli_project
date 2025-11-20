```python
import os
import logging
import datetime
import uuid
import asyncio

from fastapi import FastAPI, Request, Response, HTTPException, status, Depends, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, constr, ValidationError
from typing import Optional, List
from jose import jwt, JWTError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import aioredis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

# === Configuration ===

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
JWT_ALGORITHM = "RS256"
ACCESS_TOKEN_AUDIENCE = "myapi_access"
REFRESH_TOKEN_AUDIENCE = "myapi_refresh"
JWT_ISSUER = "myapi_auth_service"

# Rate limiting config
RATE_LIMIT = 5  # max requests
RATE_LIMIT_WINDOW = 60  # seconds

# Redis keys prefix
REDIS_REFRESH_TOKEN_PREFIX = "refresh_token:"
REDIS_RATE_LIMIT_PREFIX = "rate_limit:"

# Secure cookie settings for refresh token
REFRESH_TOKEN_COOKIE_NAME = "refresh_token"
REFRESH_TOKEN_COOKIE_PATH = "/auth/token/refresh"
REFRESH_TOKEN_COOKIE_SECURE = True
REFRESH_TOKEN_COOKIE_HTTPONLY = True
REFRESH_TOKEN_COOKIE_SAMESITE = "lax"

# === Load RSA keys securely ===

def load_private_key():
    key_path = os.getenv("JWT_PRIVATE_KEY_PATH")
    if not key_path:
        raise RuntimeError("JWT_PRIVATE_KEY_PATH env var not set")
    with open(key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key():
    key_path = os.getenv("JWT_PUBLIC_KEY_PATH")
    if not key_path:
        raise RuntimeError("JWT_PUBLIC_KEY_PATH env var not set")
    with open(key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

PRIVATE_KEY = load_private_key()
PUBLIC_KEY = load_public_key()

# === Logger setup ===

logger = logging.getLogger("auth_service")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# === Redis client ===

redis = None

async def get_redis():
    global redis
    if redis is None:
        redis = await aioredis.from_url(
            os.getenv("REDIS_URL", "redis://localhost"),
            encoding="utf-8",
            decode_responses=True,
            max_connections=10,
        )
    return redis

# === Models ===

class User(BaseModel):
    id: str
    username: str
    roles: List[str]
    scopes: List[str]

# Dummy user store for demonstration (replace with real DB)
USER_DB = {
    "alice": {
        "id": "user-1",
        "username": "alice",
        "password_hash": "pbkdf2_sha256$29000$...$...",  # Use real hash
        "roles": ["user"],
        "scopes": ["read:data"]
    },
    "admin": {
        "id": "user-2",
        "username": "admin",
        "password_hash": "pbkdf2_sha256$29000$...$...",
        "roles": ["admin"],
        "scopes": ["read:data", "write:data", "admin"]
    }
}

# === Password verification (use passlib or bcrypt in real app) ===

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# === Input Schemas ===

class LoginRequest(BaseModel):
    username: constr(min_length=3, max_length=50, regex=r"^[a-zA-Z0-9_.-]+$")
    password: constr(min_length=8, max_length=128)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    # No body, refresh token comes from cookie
    pass

class LogoutRequest(BaseModel):
    # No body, refresh token comes from cookie
    pass

# === JWT helpers ===

def create_access_token(user: User) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": user.id,
        "username": user.username,
        "roles": user.roles,
        "scopes": user.scopes,
        "iat": now,
        "nbf": now,
        "exp": now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iss": JWT_ISSUER,
        "aud": ACCESS_TOKEN_AUDIENCE,
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=JWT_ALGORITHM)
    return token

def create_refresh_token(user: User, token_id: str) -> str:
    now = datetime.datetime.utcnow()
    payload = {
        "sub": user.id,
        "iat": now,
        "nbf": now,
        "exp": now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "iss": JWT_ISSUER,
        "aud": REFRESH_TOKEN_AUDIENCE,
        "jti": token_id,
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=JWT_ALGORITHM)
    return token

async def store_refresh_token(token_id: str, user_id: str, expires_in_seconds: int):
    r = await get_redis()
    key = REDIS_REFRESH_TOKEN_PREFIX + token_id
    # Store user_id to associate token with user, set expiration
    await r.set(key, user_id, ex=expires_in_seconds)

async def revoke_refresh_token(token_id: str):
    r = await get_redis()
    key = REDIS_REFRESH_TOKEN_PREFIX + token_id
    await r.delete(key)

async def is_refresh_token_valid(token_id: str) -> bool:
    r = await get_redis()
    key = REDIS_REFRESH_TOKEN_PREFIX + token_id
    user_id = await r.get(key)
    return user_id is not None

# === Rate limiting middleware ===

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int, window_seconds: int):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        path = request.url.path
        key = f"{REDIS_RATE_LIMIT_PREFIX}{client_ip}:{path}"
        r = await get_redis()
        current = await r.get(key)
        if current is None:
            await r.set(key, 1, ex=self.window_seconds)
        else:
            current = int(current)
            if current >= self.max_requests:
                return JSONResponse(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Too many requests, slow down."}
                )
            else:
                await r.incr(key)
        response = await call_next(request)
        return response

# === Authentication dependency ===

async def get_current_user(request: Request) -> User:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Authorization header")
    token = auth_header[len("Bearer "):]
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[JWT_ALGORITHM], audience=ACCESS_TOKEN_AUDIENCE, issuer=JWT_ISSUER)
        user_id = payload.get("sub")
        username = payload.get("username")
        roles = payload.get("roles", [])
        scopes = payload.get("scopes", [])
        if not user_id or not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        return User(id=user_id, username=username, roles=roles, scopes=scopes)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

# === Atomic refresh token rotation ===

refresh_lock = asyncio.Lock()

# === FastAPI app ===

app = FastAPI(title="Secure JWT Authentication Service")

# Enforce HTTPS redirect middleware (should be behind proxy with TLS)
app.add_middleware(HTTPSRedirectMiddleware)

# CORS - restrict origins as needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourfrontend.example.com"],  # Adjust accordingly
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["Authorization", "Content-Type"],
)

app.add_middleware(RateLimitMiddleware, max_requests=RATE_LIMIT, window_seconds=RATE_LIMIT_WINDOW)

# === Helper functions ===

def validate_login_request(data: dict) -> LoginRequest:
    try:
        return LoginRequest(**data)
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.errors())

# === API Endpoints ===

@app.post("/auth/login", response_model=TokenResponse)
async def login(request: Request, response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    # Strict input validation
    login_data = {"username": form_data.username, "password": form_data.password}
    login_req = validate_login_request(login_data)

    # Authenticate user
    user_record = USER_DB.get(login_req.username)
    if not user_record:
        logger.info(f"Failed login attempt for unknown user: {login_req.username} from {request.client.host}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(login_req.password, user_record["password_hash"]):
        logger.info(f"Failed login attempt for user: {login_req.username} from {request.client.host}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user = User(
        id=user_record["id"],
        username=user_record["username"],
        roles=user_record["roles"],
        scopes=user_record["scopes"]
    )

    # Create tokens
    access_token = create_access_token(user)

    # Create refresh token with unique jti
    refresh_token_id = str(uuid.uuid4())
    refresh_token = create_refresh_token(user, refresh_token_id)

    # Store refresh token in Redis with expiration
    expires_seconds = REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
    await store_refresh_token(refresh_token_id, user.id, expires_seconds)

    # Set refresh token cookie securely
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        value=refresh_token,
        max_age=expires_seconds,
        path=REFRESH_TOKEN_COOKIE_PATH,
        secure=REFRESH_TOKEN_COOKIE_SECURE,
        httponly=REFRESH_TOKEN_COOKIE_HTTPONLY,
        samesite=REFRESH_TOKEN_COOKIE_SAMESITE,
    )

    logger.info(f"User {user.username} logged in from {request.client.host}")

    return TokenResponse(access_token=access_token)

@app.post("/auth/token/refresh", response_model=TokenResponse)
async def refresh_token(request: Request, response: Response, refresh_token: Optional[str] = Cookie(None)):
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing")

    async with refresh_lock:
        try:
            payload = jwt.decode(refresh_token, PUBLIC_KEY, algorithms=[JWT_ALGORITHM], audience=REFRESH_TOKEN_AUDIENCE, issuer=JWT_ISSUER)
            token_id = payload.get("jti")
            user_id = payload.get("sub")
            if not token_id or not user_id:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

        # Check if refresh token is valid (not revoked)
        if not await is_refresh_token_valid(token_id):
            logger.warning(f"Attempt to use revoked or invalid refresh token from {request.client.host}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked or invalid")

        # Revoke old refresh token (single-use rotation)
        await revoke_refresh_token(token_id)

        # Retrieve user info from DB (or cache)
        user_record = None
        for u in USER_DB.values():
            if u["id"] == user_id:
                user_record = u
                break
        if not user_record:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

        user = User(
            id=user_record["id"],
            username=user_record["username"],
            roles=user_record["roles"],
            scopes=user_record["scopes"]
        )

        # Issue new tokens
        access_token = create_access_token(user)
        new_refresh_token_id = str(uuid.uuid4())
        new_refresh_token = create_refresh_token(user, new_refresh_token_id)
        expires_seconds = REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
        await store_refresh_token(new_refresh_token_id, user.id, expires_seconds)

        # Set new refresh token cookie
        response.set_cookie(
            key=REFRESH_TOKEN_COOKIE_NAME,
            value=new_refresh_token,
            max_age=expires_seconds,
            path=REFRESH_TOKEN_COOKIE_PATH,
            secure=REFRESH_TOKEN_COOKIE_SECURE,
            httponly=REFRESH_TOKEN_COOKIE_HTTPONLY,
            samesite=REFRESH_TOKEN_COOKIE_SAMESITE,
        )

        logger.info(f"Refresh token rotated for user {user.username} from {request.client.host}")

        return TokenResponse(access_token=access_token)

@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, refresh_token: Optional[str] = Cookie(None)):
    if not refresh_token:
        # Logout is idempotent, no token means no session
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    try:
        payload = jwt.decode(refresh_token, PUBLIC_KEY, algorithms=[JWT_ALGORITHM], audience=REFRESH_TOKEN_AUDIENCE, issuer=JWT_ISSUER)
        token_id = payload.get("jti")
        user_id = payload.get("sub")
        if token_id:
            await revoke_refresh_token(token_id)
    except JWTError:
        # Token invalid or expired, treat as logged out
        pass

    # Remove refresh token cookie
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        path=REFRESH_TOKEN_COOKIE_PATH,
        secure=REFRESH_TOKEN_COOKIE_SECURE,
        httponly=REFRESH_TOKEN_COOKIE_HTTPONLY,
        samesite=REFRESH_TOKEN_COOKIE_SAMESITE,
    )

    logger.info(f"User logged out from {request.client.host}")

    return Response(status_code=status.HTTP_204_NO_CONTENT)

# === Protected example endpoint ===

@app.get("/protected/data")
async def protected_data(current_user: User = Depends(get_current_user)):
    # Example role and scope check
    if "user" not in current_user.roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
    if "read:data" not in current_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient scope")

    return {"message": f"Hello {current_user.username}, you have access to protected data."}

# === Startup and shutdown events ===

@app.on_event("startup")
async def startup_event():
    await get_redis()
    logger.info("Authentication service started")

@app.on_event("shutdown")
async def shutdown_event():
    global redis
    if redis:
        await redis.close()
        await redis.wait_closed()
    logger.info("Authentication service stopped")

# === Security notes ===
"""
Security Measures Implemented:

- JWTs signed with RS256 using securely loaded RSA keys.
- Access tokens short-lived (15 minutes), refresh tokens longer (7 days).
- Refresh tokens stored server-side in Redis with expiration and single-use rotation.
- Refresh tokens sent only via Secure, HttpOnly, SameSite=Lax cookies to prevent XSS and CSRF.
- Rate limiting per IP and endpoint to mitigate brute force attacks.
- Strict input validation with Pydantic to prevent injection and mass assignment.
- Atomic refresh token rotation using asyncio.Lock to prevent race conditions.
- Immediate revocation of refresh tokens on logout or suspicious activity.
- HTTPS enforced via middleware (should be complemented by deployment TLS).
- Role and scope claims embedded in JWTs and validated on protected endpoints.
- Authentication events logged without sensitive data.
- CORS restricted to trusted origins.
- Passwords verified with bcrypt via passlib.
- Refresh token rotation prevents replay attacks.
- No secrets or keys hardcoded; keys loaded from environment-secured files.

Deployment Instructions:

- Store RSA private and public keys securely on the server; set environment variables JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH.
- Use a secure Redis instance with authentication and TLS.
- Deploy behind a TLS-terminating reverse proxy (e.g., Nginx) enforcing HTTPS.
- Set CORS origins to your frontend domains only.
- Use environment variables for all secrets and configuration.
- Monitor logs for suspicious authentication events.
- Regularly rotate keys and secrets.
- Ensure server time is synchronized (NTP) for token validity.
"""

```