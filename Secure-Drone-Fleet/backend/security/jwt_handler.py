import os
import jwt
import datetime
from functools import wraps
from flask import request, jsonify


SECRET_KEY = os.environ.get("JWT_SECRET")

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET environment variable is not set")


def create_token(username, role):

    expiration = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=30)
    )

    return jwt.encode(
        {
            "sub": username,
            "role": role,
            "exp": expiration
        },
        SECRET_KEY,
        algorithm="HS256"
    )


def token_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        authorization = request.headers.get(
            "Authorization",
            ""
        )

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