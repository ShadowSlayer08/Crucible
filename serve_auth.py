"""
Serve auth — password → HS256 JWT for the --serve dashboard/API.

A genuine JSON Web Token (RFC 7519, HS256) implemented on the standard library
(hmac + hashlib + base64) — no PyJWT dependency, keeping the tool stdlib-lean.
Security properties that matter for a hand-verified token:
  * HMAC-SHA256 signature over header.payload, checked with a constant-time compare.
  * The `alg` header MUST be "HS256" — "none" and RS/ES confusion are rejected.
  * `exp` is enforced; malformed tokens verify to None (never raise to the caller).

The operator authenticates with a password (constant-time compared) at /auth/login
and receives a short-lived JWT to send as `Authorization: Bearer <token>`.

Public API
----------
    new_secret()                          -> str    (random signing secret)
    make_token(secret, sub=, ttl=, now=)  -> str    (signed JWT)
    verify_token(secret, token, now=)     -> dict | None   (claims, or None if invalid)
    verify_password(configured, provided) -> bool   (constant-time)
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

DEFAULT_TTL = 8 * 3600   # 8 hours


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _key(secret) -> bytes:
    return secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)


def _sign(secret, signing_input: bytes) -> str:
    return _b64u_encode(hmac.new(_key(secret), signing_input, hashlib.sha256).digest())


def new_secret() -> str:
    """A fresh random signing secret (use one per server process, or persist it)."""
    return secrets.token_urlsafe(32)


def make_token(secret, sub: str = "operator", ttl: int = DEFAULT_TTL, now=None) -> str:
    """Return a signed HS256 JWT with iat/exp claims."""
    issued = int(now if now is not None else time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": sub, "iat": issued, "exp": issued + int(ttl)}
    h = _b64u_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p = _b64u_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _sign(secret, f"{h}.{p}".encode("ascii"))
    return f"{h}.{p}.{sig}"


def verify_token(secret, token, now=None):
    """Return the claims dict if *token* is a valid, unexpired HS256 JWT for *secret*,
    else None. Never raises on malformed input."""
    if not token or not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h, p, sig = parts
    expected = _sign(secret, f"{h}.{p}".encode("ascii"))
    if not hmac.compare_digest(sig, expected):      # constant-time signature check
        return None
    try:
        header = json.loads(_b64u_decode(h))
        payload = json.loads(_b64u_decode(p))
    except Exception:
        return None
    if not isinstance(header, dict) or header.get("alg") != "HS256":   # no alg confusion / none
        return None
    if not isinstance(payload, dict):
        return None
    try:
        exp = int(payload.get("exp", 0))
    except (TypeError, ValueError):
        return None
    if exp < int(now if now is not None else time.time()):            # expired
        return None
    return payload


def verify_password(configured, provided) -> bool:
    """Constant-time compare of a provided password against the configured one.
    False when no password is configured (auth cannot succeed without one)."""
    if not configured:
        return False
    return hmac.compare_digest(str(configured), str(provided or ""))
