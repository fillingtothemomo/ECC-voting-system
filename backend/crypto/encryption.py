"""
ECIES — Elliptic Curve Integrated Encryption Scheme.

This is the scheme used to keep each ballot confidential while it sits
in the hash-chained ballot box. Only the election authority (who holds
the matching X25519 private key) can decrypt.

Construction used here:

    1. Authority has a long-term keypair (d_A, Q_A) on Curve25519.
    2. To encrypt a message m for Q_A:
         a. Generate an ephemeral keypair (r, R = r*G).
         b. Shared secret  s = ECDH(r, Q_A) = r * Q_A.
         c. Derive key     k = HKDF-SHA256(s).
         d. Ciphertext     c = AES-256-GCM(k, m).
         e. Send (R || nonce || c).
    3. To decrypt with d_A:
         a. s = d_A * R       (same point, by ECDH symmetry)
         b. k = HKDF-SHA256(s)
         c. m = AES-256-GCM.decrypt(k, nonce, c)

Why each piece:
    - X25519 gives the shared secret with no curve-validation pitfalls.
    - HKDF whitens the raw ECDH output into a uniform AES key.
    - AES-GCM gives confidentiality *and* authenticity (detects tamper).
    - The ephemeral key R is *fresh per message*; reusing it would leak
      relationships between ciphertexts — one of the vulnerabilities the
      report discusses.
"""

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_HKDF_INFO = b"btp-ecc-voting/v1"


# ---------- Authority keypair --------------------------------------------

def generate_authority_keypair() -> tuple[bytes, bytes]:
    """Return (priv32, pub32) for the election authority."""
    sk = X25519PrivateKey.generate()
    priv = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


# ---------- Internals -----------------------------------------------------

def _derive_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    ).derive(shared_secret)


# ---------- Encrypt / decrypt --------------------------------------------

def encrypt(authority_pub: bytes, plaintext: bytes) -> bytes:
    """
    ECIES encrypt. Output layout:
        [  32 bytes ephemeral pub R  ][ 12 bytes nonce ][ ciphertext+tag ]
    """
    ephemeral = X25519PrivateKey.generate()
    R = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(authority_pub))
    key = _derive_key(shared)

    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)

    return R + nonce + ct


def decrypt(authority_priv: bytes, blob: bytes) -> bytes:
    if len(blob) < 32 + 12 + 16:
        raise ValueError("ciphertext too short")

    R, nonce, ct = blob[:32], blob[32:44], blob[44:]

    sk = X25519PrivateKey.from_private_bytes(authority_priv)
    shared = sk.exchange(X25519PublicKey.from_public_bytes(R))
    key = _derive_key(shared)

    return AESGCM(key).decrypt(nonce, ct, associated_data=None)
