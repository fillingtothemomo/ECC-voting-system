"""
Ed25519 signatures — the real, production-grade primitive used by the
voting system to authenticate voters.

Math (for the report):
    - Curve: twisted Edwards curve  -x^2 + y^2 = 1 + d*x^2*y^2   over F_p
             with p = 2^255 - 19.
    - Private key: 32 random bytes, hashed to derive a scalar `s`.
    - Public key : A = s * B, where B is the base point.
    - Signature  : (R, S) where R = r*B, r = H(prefix || msg),
                   S = r + H(R || A || msg) * s  mod L.
    - Verify     : S*B ?= R + H(R || A || msg) * A.

Deterministic (no per-message randomness → immune to bad-RNG leaks that
break ECDSA), fast, and constant-time. We delegate to the `cryptography`
library so this file stays tiny and trustworthy.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ---------- Key generation ------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes) — 32 bytes each."""
    sk = Ed25519PrivateKey.generate()
    priv_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


# ---------- Sign / verify -------------------------------------------------

def sign(private_key_bytes: bytes, message: bytes) -> bytes:
    sk = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return sk.sign(message)


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
