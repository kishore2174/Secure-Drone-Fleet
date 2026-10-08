import sys
from pathlib import Path

# Add backend directory to Python path
BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app import app


def test_login_page_loads():
    app.config["TESTING"] = True

    client = app.test_client()

    response = client.get("/login")

    assert response.status_code == 200
    assert b"Secure Drone Fleet Management" in response.data


def test_valid_admin_login():
    app.config["TESTING"] = True

    client = app.test_client()

    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "Admin@123"
        },
        follow_redirects=False
    )

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_invalid_login_rejected():
    app.config["TESTING"] = True

    client = app.test_client()

    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "WrongPassword123"
        }
    )

    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_dashboard_requires_login():
    app.config["TESTING"] = True

    client = app.test_client()

    response = client.get(
        "/dashboard",
        follow_redirects=False
    )

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]