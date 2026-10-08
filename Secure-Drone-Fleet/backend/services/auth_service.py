from argon2 import PasswordHasher

password_hasher = PasswordHasher()

# Temporary storage for Phase 1.
# PostgreSQL will replace this later.
users = {}


def register_user(username, password):

    if username in users:
        return False, "User already exists"

    if len(password) < 8:
        return False, "Password must contain at least 8 characters"

    password_hash = password_hasher.hash(password)

    users[username] = {
        "username": username,
        "password_hash": password_hash,
        "role": "VIEWER"
    }

    return True, "User registered successfully"


def authenticate_user(username, password):

    user = users.get(username)

    if not user:
        return None

    try:
        password_hasher.verify(
            user["password_hash"],
            password
        )
    except Exception:
        return None

    return user