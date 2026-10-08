from flask import Flask, request, jsonify
from argon2 import PasswordHasher
from functools import wraps
import jwt
import datetime
import os

app = Flask(__name__)

# JWT secret must be supplied through an environment variable
SECRET_KEY = os.environ.get("JWT_SECRET")

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET environment variable is not set")

password_hasher = PasswordHasher()

# Temporary in-memory user storage.
# This will later be replaced by PostgreSQL.
users = {}


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["POST"])
def register():

    data = request.get_json() or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({
            "error": "Username and password are required"
        }), 400

    if len(password) < 8:
        return jsonify({
            "error": "Password must contain at least 8 characters"
        }), 400

    if username in users:
        return jsonify({
            "error": "User already exists"
        }), 409

    password_hash = password_hasher.hash(password)

    users[username] = {
        "username": username,
        "password_hash": password_hash,
        "role": "VIEWER"
    }

    return jsonify({
        "message": "User registered successfully",
        "username": username
    }), 201


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json() or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({
            "error": "Username and password are required"
        }), 400

    user = users.get(username)

    if not user:
        return jsonify({
            "error": "Invalid username or password"
        }), 401

    try:
        password_hasher.verify(
            user["password_hash"],
            password
        )

    except Exception:
        return jsonify({
            "error": "Invalid username or password"
        }), 401

    expiration = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=30)
    )

    token = jwt.encode(
        {
            "sub": username,
            "role": user["role"],
            "exp": expiration
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({
        "message": "Login successful",
        "token": token
    })


# ============================================================
# JWT AUTHENTICATION DECORATOR
# ============================================================

def token_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        authorization = request.headers.get("Authorization", "")

        if not authorization.startswith("Bearer "):
            return jsonify({
                "error": "Bearer token required"
            }), 401

        token = authorization.split(" ", 1)[1]

        try:

            decoded = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=["HS256"]
            )

            request.current_user = decoded

        except jwt.ExpiredSignatureError:

            return jsonify({
                "error": "Token has expired"
            }), 401

        except jwt.InvalidTokenError:

            return jsonify({
                "error": "Invalid token"
            }), 401

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# PROTECTED PROFILE ENDPOINT
# ============================================================

@app.route("/me", methods=["GET"])
@token_required
def profile():

    return jsonify({
        "message": "Authenticated request successful",
        "username": request.current_user["sub"],
        "role": request.current_user["role"]
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "system": "Secure Drone Fleet Management",
        "service": "Authentication API",
        "status": "running"
    })


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )