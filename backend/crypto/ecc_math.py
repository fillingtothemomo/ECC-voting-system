"""
Pure-Python Elliptic Curve Cryptography over a small prime field.

This module is for *teaching*. It is NOT used for the real voting
signatures/encryption (those use Ed25519 / X25519 from the `cryptography`
library, which is constant-time and audited).

The goal here is to make the math visible:

    Curve:   y^2 = x^3 + a*x + b   (mod p)
    Group:   set of (x, y) on the curve, plus the point at infinity O.
    Ops:     point addition, point doubling, scalar multiplication (double-and-add)
    Hardness: given P and Q = k*P, recovering k is the
             Elliptic Curve Discrete Logarithm Problem (ECDLP).

Run this file directly to see a full demo:

    python ecc_math.py
"""

from dataclasses import dataclass
from typing import Optional


# ---------- Curve definition ----------------------------------------------

@dataclass(frozen=True)
class Curve:
    """Short Weierstrass curve y^2 = x^3 + a*x + b  over F_p."""
    p: int   # prime modulus
    a: int
    b: int

    def contains(self, P: "Point") -> bool:
        if P.is_infinity():
            return True
        lhs = (P.y * P.y) % self.p
        rhs = (P.x * P.x * P.x + self.a * P.x + self.b) % self.p
        return lhs == rhs


# ---------- Point on a curve ----------------------------------------------

@dataclass(frozen=True)
class Point:
    curve: Curve
    x: Optional[int]    # None,None = point at infinity (identity O)
    y: Optional[int]

    # ---- constructors ----
    @classmethod
    def infinity(cls, curve: Curve) -> "Point":
        return cls(curve, None, None)

    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    # ---- group law ----
    def __add__(self, other: "Point") -> "Point":
        if self.curve != other.curve:
            raise ValueError("points on different curves")

        # O + P = P
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self

        p = self.curve.p

        # P + (-P) = O
        if self.x == other.x and (self.y + other.y) % p == 0:
            return Point.infinity(self.curve)

        if self == other:
            # Point doubling:    s = (3x^2 + a) / (2y)
            s = ((3 * self.x * self.x + self.curve.a) * pow(2 * self.y, -1, p)) % p
        else:
            # Point addition:    s = (y2 - y1) / (x2 - x1)
            s = ((other.y - self.y) * pow(other.x - self.x, -1, p)) % p

        x3 = (s * s - self.x - other.x) % p
        y3 = (s * (self.x - x3) - self.y) % p
        return Point(self.curve, x3, y3)

    def __rmul__(self, k: int) -> "Point":
        """Scalar multiplication via double-and-add."""
        if k < 0:
            return (-k) * Point(self.curve, self.x, (-self.y) % self.curve.p)
        result = Point.infinity(self.curve)
        addend = self
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def __repr__(self):
        if self.is_infinity():
            return "O"
        return f"({self.x}, {self.y})"


# ---------- A tiny named curve for demos ----------------------------------
# y^2 = x^3 + 2x + 2  (mod 17).  Has 19 points — small enough to enumerate.
DEMO_CURVE = Curve(p=17, a=2, b=2)
DEMO_G = Point(DEMO_CURVE, 5, 1)        # generator
DEMO_N = 19                             # order of G (prime → whole group is cyclic)


# ---------- EC-ElGamal (for the "deeper math" deliverable) ----------------

def elgamal_keygen(G: Point, n: int, rng) -> tuple[int, Point]:
    """Return (priv, pub) where pub = priv * G."""
    priv = rng.randrange(1, n)
    return priv, priv * G


def elgamal_encrypt(M: Point, pub: Point, G: Point, n: int, rng) -> tuple[Point, Point]:
    """
    Encrypt a *point* M (the message must already be mapped onto the curve).
    Ciphertext is the pair (C1, C2) = (k*G,  M + k*pub).
    """
    k = rng.randrange(1, n)
    C1 = k * G
    C2 = M + (k * pub)
    return C1, C2


def elgamal_decrypt(C1: Point, C2: Point, priv: int) -> Point:
    """M = C2 - priv * C1."""
    S = priv * C1
    neg_S = Point(S.curve, S.x, (-S.y) % S.curve.p) if not S.is_infinity() else S
    return C2 + neg_S


# ---------- Self-test / demo ----------------------------------------------

def _demo():
    import random
    rng = random.Random(42)

    print(f"Curve:  y^2 = x^3 + {DEMO_CURVE.a}x + {DEMO_CURVE.b}  (mod {DEMO_CURVE.p})")
    print(f"G    =  {DEMO_G}")
    assert DEMO_CURVE.contains(DEMO_G)

    print("\n-- Scalar multiples of G (the cyclic subgroup) --")
    for k in range(1, DEMO_N + 1):
        print(f"  {k:2d} * G = {k * DEMO_G}")

    print("\n-- EC-ElGamal --")
    priv, pub = elgamal_keygen(DEMO_G, DEMO_N, rng)
    print(f"  private key d = {priv}")
    print(f"  public  key Q = d*G = {pub}")

    M = 7 * DEMO_G                                  # pretend this point is the message
    C1, C2 = elgamal_encrypt(M, pub, DEMO_G, DEMO_N, rng)
    print(f"  message point M  = {M}")
    print(f"  ciphertext (C1,C2) = ({C1}, {C2})")

    M_back = elgamal_decrypt(C1, C2, priv)
    print(f"  decrypted         = {M_back}")
    assert M_back == M, "ElGamal decryption failed!"
    print("  OK — decryption recovered the original point.")


if __name__ == "__main__":
    _demo()
