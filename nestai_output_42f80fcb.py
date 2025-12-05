```python
import os
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional

from flask import Flask, request, jsonify, make_response, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import jwt

# Configuration
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable must be set")

JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour token expiration

SESSION_COOKIE_NAME = "session_token"
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"



# Flask app and extensions
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["5 per minute"])

# Logger setup
logger = logging.getLogger("auth_logger")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("auth.log")
formatter = logging.Formatter(
    '%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%dT%H:%M:%SZ'
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# Password hasher
ph = PasswordHasher(time_cost=3, memory_cost=2 ** 16, parallelism=4, hash_len=32, salt_len=16)

# Models
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")  # e.g., user, admin

class RevokedToken(db.Model):
    __tablename__ = "revoked_tokens"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.now(timezone.utc))

# Helpers
def validate_username(username: str) -> bool:
    if not username or not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 150:
        return False
    if not username.isalnum():
        return False
    return True

def validate_password(password: str) -> bool:
    if not password or not isinstance(password, str):
        return False
    if len(password) < 8:
        return False
    # Additional password policy checks can be added here
    return True

def generate_jwt(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    jti = os.urandom(16).hex()
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now.timestamp(),
        "exp": exp.timestamp(),
        "jti": jti,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def is_token_revoked(jti: str) -> bool:
    return RevokedToken.query.filter_by(jti=jti).first() is not None

def revoke_token(jti: str):
    if not is_token_revoked(jti):
        revoked = RevokedToken(jti=jti, revoked_at=datetime.now(timezone.utc))
        db.session.add(revoked)
        db.session.commit()

def log_auth_event(event: str, username: Optional[str], ip: str, success: bool, reason: Optional[str] = None):
    msg = f"event={event} username={username or 'N/A'} ip={ip} success={success}"
    if reason:
        msg += f" reason={reason}"
    logger.info(msg)

# Decorators
def login_required(role: Optional[str] = None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.cookies.get(SESSION_COOKIE_NAME)
            if not token:
                return jsonify({"error": "Authentication required"}), 401
            payload = decode_jwt(token)
            if not payload:
                return jsonify({"error": "Invalid or expired session"}), 401
            if is_token_revoked(payload.get("jti")):
                return jsonify({"error": "Session revoked"}), 401
            user_id = payload.get("sub")
            user_role = payload.get("role")
            if role and user_role != role:
                return jsonify({"error": "Insufficient permissions"}), 403
            g.user_id = user_id
            g.user_role = user_role
            g.token_jti = payload.get("jti")
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Routes
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    ip = get_remote_address()
    data = request.get_json(silent=True)
    if not data:
        log_auth_event("login_attempt", None, ip, False, "Missing JSON body")
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not validate_username(username) or not validate_password(password):
        log_auth_event("login_attempt", username, ip, False, "Invalid username or password format")
        return jsonify({"error": "Invalid username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        log_auth_event("login_attempt", username, ip, False, "User not found")
        # Do not reveal user existence
        return jsonify({"error": "Invalid username or password"}), 401

    try:
        ph.verify(user.password_hash, password)
    except argon2_exceptions.VerifyMismatchError:
        log_auth_event("login_attempt", username, ip, False, "Password mismatch")
        return jsonify({"error": "Invalid username or password"}), 401
    except Exception:
        log_auth_event("login_attempt", username, ip, False, "Password verification error")
        return jsonify({"error": "Authentication failed"}), 500

    # Password rehashing if needed
    try:
        if ph.check_needs_rehash(user.password_hash):
            user.password_hash = ph.hash(password)
            db.session.commit()
    except Exception:
        # Log but do not fail login
        logger.warning(f"Password rehash failed for user {username}")

    # Generate JWT token atomically
    try:
        token = generate_jwt(user.id, user.role)
    except Exception:
        log_auth_event("login_attempt", username, ip, False, "Token generation failed")
        return jsonify({"error": "Authentication failed"}), 500

    resp = make_response(jsonify({"message": "Login successful"}))
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=JWT_EXP_DELTA_SECONDS,
        secure=SESSION_COOKIE_SECURE,
        httponly=SESSION_COOKIE_HTTPONLY,
        samesite=SESSION_COOKIE_SAMESITE,
        path="/",
    )

    log_auth_event("login_success", username, ip, True)
    return resp

@app.route("/logout", methods=["POST"])
@login_required()
def logout():
    ip = get_remote_address()
    username = None
    try:
        user = User.query.get(g.user_id)
        username = user.username if user else None
    except Exception:
        pass

    # Revoke token
    try:
        revoke_token(g.token_jti)
    except Exception:
        logger.warning(f"Failed to revoke token for user_id={g.user_id}")

    resp = make_response(jsonify({"message": "Logout successful"}))
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        "",
        expires=0,
        secure=SESSION_COOKIE_SECURE,
        httponly=SESSION_COOKIE_HTTPONLY,
        samesite=SESSION_COOKIE_SAMESITE,
        path="/",
    )
    log_auth_event("logout", username, ip, True)
    return resp

@app.route("/protected-resource", methods=["GET"])
@login_required(role="admin")
def protected_resource():
    return jsonify({"message": f"Hello Admin user {g.user_id}!"})

# User registration endpoint (for completeness, secure and rate-limited)
# User registration endpoints to complete and secure the rate-limited
# The user endpoint needs to be secure and connected to the API and needs to follow basic RBAC controls and security measures

@app.route("/register", methods=["POST"])
@limiter.limit("3 per minute")
def register():
    ip = get_remote_address()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not validate_username(username) or not validate_password(password):
        return jsonify({"error": "Invalid username or password"}), 400

    try:
        password_hash = ph.hash(password)
    except Exception:
        return jsonify({"error": "Failed to process password"}), 500

    user = User(username=username, password_hash=password_hash, role="user")
    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username already exists"}), 409
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Registration failed"}), 500

    return jsonify({"message": "User registered successfully"}), 201

# Initialize DB (for first run)
@app.before_first_request
def create_tables():
    db.create_all()

# Enforce HTTPS (Flask does not enforce HTTPS by default)
@app.before_request
def enforce_https():
    if not request.is_secure and not app.debug:
        return jsonify({"error": "HTTPS required"}), 403

# Run the app (for production, use WSGI server)
if __name__ == "__main__":
    # Do NOT run with debug=True in production
    app.run(ssl_context="adhoc", host="0.0.0.0", port=443)
```
