"""serve_auth — HS256 JWT + password verify for the --serve dashboard. Security
code, so the adversarial cases (tamper, wrong secret, expiry, alg confusion,
malformed) are covered explicitly, not just the happy path.
"""
import json

import serve_auth as sa

SECRET = "test-signing-secret"


# ── round trip ────────────────────────────────────────────────────────────────
def test_make_verify_roundtrip():
    tok = sa.make_token(SECRET, sub="operator", ttl=3600, now=1000)
    claims = sa.verify_token(SECRET, tok, now=1000)
    assert claims is not None
    assert claims["sub"] == "operator"
    assert claims["iat"] == 1000 and claims["exp"] == 4600


def test_expiry_enforced():
    tok = sa.make_token(SECRET, ttl=100, now=1000)
    assert sa.verify_token(SECRET, tok, now=1050) is not None   # still valid
    assert sa.verify_token(SECRET, tok, now=1101) is None       # expired


def test_wrong_secret_rejected():
    tok = sa.make_token(SECRET, now=1000)
    assert sa.verify_token("other-secret", tok, now=1000) is None


def test_tampered_payload_rejected():
    tok = sa.make_token(SECRET, sub="operator", now=1000)
    h, p, sig = tok.split(".")
    forged_payload = sa._b64u_encode(
        json.dumps({"sub": "admin", "iat": 1000, "exp": 9999999999}).encode())
    forged = f"{h}.{forged_payload}.{sig}"
    assert sa.verify_token(SECRET, forged, now=1000) is None


def test_tampered_signature_rejected():
    tok = sa.make_token(SECRET, now=1000)
    h, p, _ = tok.split(".")
    assert sa.verify_token(SECRET, f"{h}.{p}.deadbeef", now=1000) is None


def test_alg_confusion_rejected():
    # a token with a VALID signature but alg != HS256 must still be rejected
    payload = sa._b64u_encode(json.dumps({"sub": "x", "exp": 9999999999}).encode())
    for bad_alg in ("none", "HS512", "RS256"):
        header = sa._b64u_encode(json.dumps({"alg": bad_alg, "typ": "JWT"}).encode())
        sig = sa._sign(SECRET, f"{header}.{payload}".encode())   # correctly signed
        assert sa.verify_token(SECRET, f"{header}.{payload}.{sig}", now=1000) is None


def test_malformed_tokens_return_none():
    for bad in (None, "", "abc", "a.b", "a.b.c.d", 123, "....", "x.y.z"):
        assert sa.verify_token(SECRET, bad, now=1000) is None


# ── password ──────────────────────────────────────────────────────────────────
def test_verify_password():
    assert sa.verify_password("hunter2", "hunter2") is True
    assert sa.verify_password("hunter2", "wrong") is False
    assert sa.verify_password("hunter2", "") is False
    assert sa.verify_password("", "anything") is False       # no password configured
    assert sa.verify_password(None, "anything") is False


def test_new_secret_is_random():
    assert sa.new_secret() != sa.new_secret()
    assert len(sa.new_secret()) >= 32
