from flask import Blueprint, request, jsonify

from services.auth_service import (
    register_user,
    authenticate_user
)

from security.jwt_handler import (
    create_token,
    token_required
)


auth_bp = Blueprint(
    "auth",
    __name__
)


@auth_bp.route("/register", methods=["POST"])
def register():

    data = request.get_json() or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({
            "error": "Username and password are required"
        }), 400

    success, message = register_user(
        username,
        password
    )

    if not success:
        return jsonify({
            "error": message
        }), 409

    return jsonify({
        "message": message,
        "username": username
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():

    data = request.get_json() or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({
            "error": "Username and password are required"
        }), 400

    user = authenticate_user(
        username,
        password
    )

    if not user:
        return jsonify({
            "error": "Invalid username or password"
        }), 401

    token = create_token(
        user["username"],
        user["role"]
    )

    return jsonify({
        "message": "Login successful",
        "token": token
    })


@auth_bp.route("/me", methods=["GET"])
@token_required
def profile():

    return jsonify({
        "message": "Authenticated request successful",
        "username": request.current_user["sub"],
        "role": request.current_user["role"]
    })