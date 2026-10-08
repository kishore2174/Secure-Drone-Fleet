from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify
)

from functools import wraps
from argon2 import PasswordHasher
import jwt
import datetime
import os


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

# ------------------------------------------------------------
# SECURITY SECRETS
# Secrets must be supplied through environment variables.
# Do not hard-code production secrets in source code.
# ------------------------------------------------------------

FLASK_SECRET = os.environ.get("FLASK_SECRET")
JWT_SECRET = os.environ.get("JWT_SECRET")

if not FLASK_SECRET:
    raise RuntimeError(
        "FLASK_SECRET environment variable is not set"
    )

if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET environment variable is not set"
    )

app.secret_key = FLASK_SECRET

password_hasher = PasswordHasher()

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 30


# ============================================================
# USERS
# Temporary in-memory storage for prototype.
# PostgreSQL will replace this later.
# ============================================================

USERS = {

    "admin": {
        "password_hash": password_hasher.hash(
            "Admin@123"
        ),
        "role": "ADMIN",
        "name": "System Administrator"
    },

    "operator": {
        "password_hash": password_hasher.hash(
            "Operator@123"
        ),
        "role": "OPERATOR",
        "name": "Flight Operator"
    },

    "viewer": {
        "password_hash": password_hasher.hash(
            "Viewer@123"
        ),
        "role": "VIEWER",
        "name": "Fleet Viewer"
    }

}


# ============================================================
# DRONE DATA
# Temporary in-memory data for prototype.
# ============================================================

DRONES = [

    {
        "id": "DR-001",
        "name": "Falcon-01",
        "status": "Active",
        "battery": 87,
        "location": "Chennai Sector A",
        "telemetry": "Normal"
    },

    {
        "id": "DR-002",
        "name": "Falcon-02",
        "status": "Idle",
        "battery": 64,
        "location": "Chennai Sector B",
        "telemetry": "Normal"
    },

    {
        "id": "DR-003",
        "name": "Falcon-03",
        "status": "Maintenance",
        "battery": 31,
        "location": "Base Station",
        "telemetry": "Warning"
    }

]


# ============================================================
# MISSION DATA
# ============================================================

MISSIONS = [

    {
        "id": "MS-1001",
        "name": "Campus Surveillance",
        "drone": "DR-001",
        "operator": "Flight Operator",
        "status": "Running",
        "path": "Sector A → Sector C"
    },

    {
        "id": "MS-1002",
        "name": "Perimeter Inspection",
        "drone": "DR-002",
        "operator": "Flight Operator",
        "status": "Scheduled",
        "path": "Sector B → North Gate"
    }

]


# ============================================================
# JWT FUNCTIONS
# ============================================================

def create_token(username, role):

    expiration = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(
            minutes=JWT_EXPIRATION_MINUTES
        )
    )

    token = jwt.encode(
        {
            "sub": username,
            "role": role,
            "exp": expiration
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )

    return token


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

        token = authorization.split(
            " ",
            1
        )[1]

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

        return function(
            *args,
            **kwargs
        )

    return wrapper


# ============================================================
# SESSION FUNCTIONS
# ============================================================

def current_user():

    return session.get("user")


def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not current_user():

            return redirect(
                url_for("login")
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            user = current_user()

            if not user:

                return redirect(
                    url_for("login")
                )

            if user["role"] not in allowed_roles:

                return render_template(
                    "error.html",
                    code=403,
                    message=(
                        "You do not have permission "
                        "to perform this action."
                    )
                ), 403

            return function(
                *args,
                **kwargs
            )

        return wrapper

    return decorator


# ============================================================
# HOME / HEALTH CHECK
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return jsonify({

        "system":
            "Secure Drone Fleet Management",

        "service":
            "Authentication API",

        "status":
            "running"

    })


# ============================================================
# REGISTER API
# ============================================================

@app.route(
    "/register",
    methods=["POST"]
)
def register_api():

    data = request.get_json(
        silent=True
    ) or {}

    username = data.get(
        "username",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )

    if not username or not password:

        return jsonify({
            "error":
                "Username and password are required"
        }), 400

    if username in USERS:

        return jsonify({
            "error":
                "User already exists"
        }), 409

    if len(password) < 8:

        return jsonify({
            "error":
                "Password must contain at least 8 characters"
        }), 400

    password_hash = password_hasher.hash(
        password
    )

    USERS[username] = {

        "password_hash":
            password_hash,

        "role":
            "VIEWER",

        "name":
            username

    }

    return jsonify({

        "message":
            "User registered successfully",

        "username":
            username

    }), 201


# ============================================================
# LOGIN
#
# Supports BOTH:
#
# 1. JSON API login
# 2. HTML UI login
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    # --------------------------------------------------------
    # GET → Show Login UI
    # --------------------------------------------------------

    if request.method == "GET":

        return render_template(
            "login.html",
            error=None
        )


    # --------------------------------------------------------
    # JSON → API LOGIN
    # --------------------------------------------------------

    if request.is_json:

        data = request.get_json(
            silent=True
        ) or {}

        username = data.get(
            "username",
            ""
        ).strip().lower()

        password = data.get(
            "password",
            ""
        )

        user = USERS.get(
            username
        )

        if not user:

            return jsonify({
                "error":
                    "Invalid username or password"
            }), 401

        try:

            password_hasher.verify(
                user["password_hash"],
                password
            )

        except Exception:

            return jsonify({
                "error":
                    "Invalid username or password"
            }), 401

        token = create_token(
            username,
            user["role"]
        )

        return jsonify({

            "message":
                "Login successful",

            "token":
                token

        })


    # --------------------------------------------------------
    # HTML FORM LOGIN
    # --------------------------------------------------------

    username = request.form.get(
        "username",
        ""
    ).strip().lower()

    password = request.form.get(
        "password",
        ""
    )

    user = USERS.get(
        username
    )

    try:

        valid = (

            user is not None

            and

            password_hasher.verify(
                user["password_hash"],
                password
            )

        )

    except Exception:

        valid = False


    if not valid:

        return render_template(
            "login.html",
            error="Invalid username or password."
        )


    token = create_token(
        username,
        user["role"]
    )

    session["user"] = {

        "username":
            username,

        "name":
            user["name"],

        "role":
            user["role"],

        "token":
            token

    }

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# JWT PROFILE API
# ============================================================

@app.route(
    "/me",
    methods=["GET"]
)
@token_required
def profile():

    return jsonify({

        "message":
            "Authenticated request successful",

        "username":
            request.current_user["sub"],

        "role":
            request.current_user["role"]

    })


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route(
    "/dashboard"
)
@login_required
def dashboard():

    return render_template(

        "dashboard.html",

        drones=DRONES,

        missions=MISSIONS,

        user=current_user()

    )


# ============================================================
# DRONE MANAGEMENT
# ============================================================

@app.route(
    "/drones"
)
@login_required
def drones():

    return render_template(

        "drones.html",

        drones=DRONES,

        user=current_user()

    )


@app.route(
    "/drones/register",
    methods=["POST"]
)
@role_required(
    "ADMIN",
    "OPERATOR"
)
def register_drone():

    drone_id = request.form.get(
        "drone_id",
        ""
    ).strip().upper()

    name = request.form.get(
        "name",
        ""
    ).strip()


    if not drone_id or not name:

        return render_template(

            "error.html",

            code=400,

            message=
                "Drone ID and name are required."

        ), 400


    if any(
        drone["id"] == drone_id
        for drone in DRONES
    ):

        return render_template(

            "error.html",

            code=409,

            message=
                "Drone ID already exists."

        ), 409


    DRONES.append({

        "id":
            drone_id,

        "name":
            name,

        "status":
            "Idle",

        "battery":
            100,

        "location":
            "Base Station",

        "telemetry":
            "Normal"

    })


    return redirect(
        url_for("drones")
    )


# ============================================================
# MISSION MANAGEMENT
# ============================================================

@app.route(
    "/missions"
)
@login_required
def missions():

    return render_template(

        "missions.html",

        missions=MISSIONS,

        drones=DRONES,

        user=current_user()

    )


@app.route(
    "/missions/create",
    methods=["POST"]
)
@role_required(
    "ADMIN",
    "OPERATOR"
)
def create_mission():

    name = request.form.get(
        "name",
        ""
    ).strip()

    drone = request.form.get(
        "drone",
        ""
    )

    path = request.form.get(
        "path",
        ""
    ).strip()


    if not name or not drone or not path:

        return render_template(

            "error.html",

            code=400,

            message=(
                "Mission name, drone and "
                "flight path are required."
            )

        ), 400


    # --------------------------------------------------------
    # Check whether drone exists
    # --------------------------------------------------------

    selected_drone = next(

        (
            d for d in DRONES
            if d["id"] == drone
        ),

        None

    )


    if not selected_drone:

        return render_template(

            "error.html",

            code=404,

            message="Selected drone was not found."

        ), 404


    # --------------------------------------------------------
    # Prevent maintenance drone assignment
    # --------------------------------------------------------

    if selected_drone["status"] == "Maintenance":

        return render_template(

            "error.html",

            code=409,

            message=(
                "A drone in maintenance "
                "cannot be assigned to a mission."
            )

        ), 409


    new_id = (
        f"MS-{1000 + len(MISSIONS) + 1}"
    )


    MISSIONS.append({

        "id":
            new_id,

        "name":
            name,

        "drone":
            drone,

        "operator":
            current_user()["name"],

        "status":
            "Scheduled",

        "path":
            path

    })


    return redirect(
        url_for("missions")
    )


# ============================================================
# TELEMETRY
# ============================================================

@app.route(
    "/telemetry"
)
@login_required
def telemetry():

    return render_template(

        "telemetry.html",

        drones=DRONES,

        user=current_user()

    )


@app.route(
    "/api/telemetry",
    methods=["GET"]
)
@login_required
def telemetry_api():

    return jsonify({

        "drones":
            DRONES,

        "updated":
            datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()

    })


# ============================================================
# REPORTS
# ============================================================

@app.route(
    "/reports"
)
@login_required
def reports():

    return render_template(

        "reports.html",

        drones=DRONES,

        missions=MISSIONS,

        user=current_user()

    )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=False

    )