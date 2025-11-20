```python
import os
import re
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import jwt
import pyotp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Load environment variables securely
load_dotenv()

# Configuration
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour token expiration
JWT_REFRESH_EXP_DELTA_SECONDS = 86400  # 24 hours refresh token expiration
MAX_FAILED_ATTEMPTS = 5
ACCOUNT_LOCK_DURATION = timedelta(minutes=15)

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is not set")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI", "sqlite:///secure_login.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Setup logging securely
logger = logging.getLogger("auth_logger")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("auth.log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

ph = PasswordHasher(time_cost=3, memory_cost=2 ** 16, parallelism=4, hash_len=32, salt_len=16)

# Models

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(512), nullable=False)
    email = db.Column(db.String(320), unique=True, nullable=False, index=True)
    role = db.Column(db.String(50), nullable=False, default="user")
    mfa_secret = db.Column(db.String(32), nullable=True)  # base32 encoded secret for TOTP
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RevokedToken(db.Model):
    __tablename__ = "revoked_tokens"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)  # JWT ID
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)

# Utilities

def validate_username(username: str) -> bool:
    # Username: 3-150 chars, alphanumeric + underscore, no leading/trailing spaces
    return bool(re.fullmatch(r"^[A-Za-z0-9_]{3,150}$", username))

def validate_email(email: str) -> bool:
    # Simple RFC5322 email regex approximation
    return bool(re.fullmatch(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email))

def validate_password(password: str) -> bool:
    # Password policy:
    # Minimum 12 chars, at least one uppercase, one lowercase, one digit, one special char
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*()_\-+=\[\]{}|\\:;\"'<>,.?/~`]", password):
        return False
    return True

def generate_jwt(user_id: int, role: str, exp_seconds: int = JWT_EXP_DELTA_SECONDS) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(seconds=exp_seconds),
        "jti": os.urandom(16).hex()
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # Check if token is revoked
        if RevokedToken.query.filter_by(jti=payload.get("jti")).first():
            return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def revoke_token(jti: str):
    if not RevokedToken.query.filter_by(jti=jti).first():
        revoked = RevokedToken(jti=jti)
        db.session.add(revoked)
        db.session.commit()

def require_auth(role: Optional[str] = None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Authentication required"}), 401
            token = auth_header.split(" ", 1)[1]
            payload = decode_jwt(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            g.user_id = payload["sub"]
            g.user_role = payload["role"]
            g.token_jti = payload["jti"]
            if role and g.user_role != role:
                return jsonify({"error": "Insufficient privileges"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

def log_auth_attempt(username: str, ip: str, success: bool):
    logger.info(f"Auth attempt - Username: {username}, IP: {ip}, Success: {success}")

def is_account_locked(user: User) -> bool:
    if user.account_locked_until and user.account_locked_until > datetime.utcnow():
        return True
    return False

def lock_account(user: User):
    user.account_locked_until = datetime.utcnow() + ACCOUNT_LOCK_DURATION
    user.failed_login_attempts = 0
    db.session.commit()

def reset_failed_attempts(user: User):
    user.failed_login_attempts = 0
    user.account_locked_until = None
    db.session.commit()

# Routes

@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    """
    POST /api/register
    Request JSON:
    {
        "username": "string",
        "email": "string",
        "password": "string"
    }
    Response:
    201 Created on success
    400 Bad Request on validation failure
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input"}), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not (username and email and password):
        return jsonify({"error": "Missing required fields"}), 400

    if not validate_username(username):
        return jsonify({"error": "Invalid username"}), 400

    if not validate_email(email):
        return jsonify({"error": "Invalid email"}), 400

    if not validate_password(password):
        return jsonify({"error": "Password does not meet complexity requirements"}), 400

    try:
        password_hash = ph.hash(password)
        user = User(username=username, email=email, password_hash=password_hash, role="user")
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username or email already exists"}), 400
    except Exception:
        return jsonify({"error": "Registration failed"}), 500

    return jsonify({"message": "User registered successfully"}), 201

@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    """
    POST /api/login
    Request JSON:
    {
        "username": "string",
        "password": "string",
        "mfa_code": "string" (optional, required if MFA enabled)
    }
    Response:
    200 OK with JWT token on success
    401 Unauthorized on failure
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")
    mfa_code = data.get("mfa_code", None)

    if not (username and password):
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    ip = request.remote_addr or "unknown"

    if not user:
        log_auth_attempt(username, ip, False)
        return jsonify({"error": "Invalid credentials"}), 401

    if is_account_locked(user):
        log_auth_attempt(username, ip, False)
        return jsonify({"error": "Account temporarily locked due to multiple failed login attempts"}), 403

    try:
        ph.verify(user.password_hash, password)
    except argon2_exceptions.VerifyMismatchError:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            lock_account(user)
        else:
            db.session.commit()
        log_auth_attempt(username, ip, False)
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception:
        return jsonify({"error": "Authentication failed"}), 401

    # Password verified, check MFA if enabled
    if user.mfa_secret:
        if not mfa_code:
            return jsonify({"error": "MFA code required"}), 401
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(mfa_code, valid_window=1):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                lock_account(user)
            else:
                db.session.commit()
            log_auth_attempt(username, ip, False)
            return jsonify({"error": "Invalid MFA code"}), 401

    reset_failed_attempts(user)
    token = generate_jwt(user.id, user.role)
    log_auth_attempt(username, ip, True)
    return jsonify({"token": token}), 200

@app.route("/api/mfa/setup", methods=["POST"])
@require_auth()
def mfa_setup():
    """
    POST /api/mfa/setup
    Headers:
        Authorization: Bearer <token>
    Response:
    200 OK with provisioning URI for authenticator apps
    """
    user = User.query.get(g.user_id)
    if user.mfa_secret:
        return jsonify({"error": "MFA already enabled"}), 400

    secret = pyotp.random_base32()
    user.mfa_secret = secret
    db.session.commit()

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name="SecureLoginAPI")

    return jsonify({"provisioning_uri": provisioning_uri}), 200

@app.route("/api/mfa/disable", methods=["POST"])
@require_auth()
def mfa_disable():
    """
    POST /api/mfa/disable
    Headers:
        Authorization: Bearer <token>
    Request JSON:
    {
        "mfa_code": "string"
    }
    Response:
    200 OK on success
    400 Bad Request on failure
    """
    data = request.get_json()
    if not data or "mfa_code" not in data:
        return jsonify({"error": "MFA code required"}), 400

    user = User.query.get(g.user_id)
    if not user.mfa_secret:
        return jsonify({"error": "MFA not enabled"}), 400

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(data["mfa_code"], valid_window=1):
        return jsonify({"error": "Invalid MFA code"}), 400

    user.mfa_secret = None
    db.session.commit()
    return jsonify({"message": "MFA disabled"}), 200

@app.route("/api/logout", methods=["POST"])
@require_auth()
def logout():
    """
    POST /api/logout
    Headers:
        Authorization: Bearer <token>
    Response:
    200 OK on success
    """
    revoke_token(g.token_jti)
    return jsonify({"message": "Logged out successfully"}), 200

@app.route("/api/userinfo", methods=["GET"])
@require_auth()
def userinfo():
    """
    GET /api/userinfo
    Headers:
        Authorization: Bearer <token>
    Response:
    200 OK with user info (excluding sensitive data)
    """
    user = User.query.get(g.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "mfa_enabled": bool(user.mfa_secret),
        "created_at": user.created_at.isoformat(),
    }), 200

@app.route("/api/admin/users", methods=["GET"])
@require_auth(role="admin")
def admin_list_users():
    """
    GET /api/admin/users
    Headers:
        Authorization: Bearer <token>
    Response:
    200 OK with list of users (admin only)
    """
    users = User.query.all()
    users_data = [{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "mfa_enabled": bool(u.mfa_secret),
        "created_at": u.created_at.isoformat(),
    } for u in users]
    return jsonify(users_data), 200

# Initialization

@app.before_first_request
def create_tables():
    db.create_all()

# Run with HTTPS recommended (e.g., behind a reverse proxy with TLS)
# For development only:
if __name__ == "__main__":
    # Do NOT use debug=True in production
    app.run(host="0.0.0.0", port=5000, debug=False)
```
