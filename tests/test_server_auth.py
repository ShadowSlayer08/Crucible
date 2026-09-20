"""--serve auth — the FastAPI dashboard/API gated by a password → HS256 JWT.
Exercised through TestClient. The no-password app stays open (embedded/library use);
a password-configured app enforces Bearer JWT on everything but /health, / and login.
"""
import pytest

pytest.importorskip("httpx")          # TestClient transport dependency
from fastapi.testclient import TestClient

import server
import serve_auth

PW = "hunter2"


def _client(password=PW, secret="unit-secret"):
    return TestClient(server.create_app(password=password, secret=secret))


# ── open endpoints ────────────────────────────────────────────────────────────
def test_health_open_without_token():
    assert _client().get("/health").status_code == 200


def test_index_open_without_token():
    # "/" must render so the login field can load
    assert _client().get("/").status_code == 200


# ── protected endpoints ───────────────────────────────────────────────────────
def test_protected_endpoint_401_without_token():
    r = _client().get("/modes")
    assert r.status_code == 401
    assert "unauthorized" in r.json()["detail"].lower()


def test_protected_endpoint_401_with_garbage_token():
    r = _client().get("/modes", headers={"Authorization": "Bearer not-a-real-jwt"})
    assert r.status_code == 401


def test_login_wrong_password_401():
    assert _client().post("/auth/login", json={"password": "nope"}).status_code == 401


def test_login_then_access():
    c = _client()
    r = c.post("/auth/login", json={"password": PW})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["token"]
    token = body["token"]
    ok = c.get("/modes", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200
    assert "modes" in ok.json()


def test_issued_token_verifies_against_secret():
    token = _client(secret="s2").post("/auth/login", json={"password": PW}).json()["token"]
    assert serve_auth.verify_token("s2", token) is not None
    assert serve_auth.verify_token("wrong", token) is None


# ── open mode (no password) preserves the pre-auth behaviour ──────────────────
def test_no_password_app_is_open():
    c = TestClient(server.create_app())          # no password → no enforcement
    assert c.get("/modes").status_code == 200
    # login on an open app reports auth disabled rather than erroring
    assert c.post("/auth/login", json={"password": "x"}).json()["auth"] == "disabled"
