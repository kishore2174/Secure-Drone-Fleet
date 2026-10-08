import jwt
import datetime
from functools import wraps
from flask import request, jsonify

from config.settings import (
    JWT_SECRET,
    JWT_ALGORITHM,
    JWT_EXPIRATION_MINUTES
)


def create_token(username, role):

    expiration = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(
            minutes=JWT_EXPIRATION_MINUTES
        )
    )

    return jwt.encode(
        {
            "sub": username,
            "role": role,
            "exp": expiration
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
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
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM]
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