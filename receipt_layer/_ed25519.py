"""Pure-Python Ed25519 (RFC 8032). No dependencies.

Vendored reference construction (SHA-512 based), adapted from the public-domain
reference implementation by Daniel J. Bernstein, Niels Duif, Tanja Lange,
Peter Schwabe and Bo-Yin Yang (https://ed25519.cr.yp.to/python/ed25519.py).

Used by receipt_layer so signatures work with stdlib only. For production
throughput, inject a backend implementing the Signer/Verifier protocol
(e.g. `cryptography` or `nacl`).
"""
from __future__ import annotations

import hashlib
import os

b = 256
q = (1 << 255) - 19
l = (1 << 252) + 27742317777372353535851937790883648493  # noqa: E741


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, q - 2, q)


d = (-121665 * _inv(121666)) % q
_I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = (4 * _inv(5)) % q
_Bx = _xrecover(_By)
B = (_Bx, _By)


def _edwards(P, Q):
    # Twisted Edwards addition for -x^2 + y^2 = 1 + d x^2 y^2 (a = -1):
    # y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2). The plus sign is required;
    # verified by [l]B == identity for the subgroup order l.
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2)
    return (x3 % q, y3 % q)


def _scalarmult(P, e: int):
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8)
    )


def _encodepoint(P) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8)
    )


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def publickey(sk: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte private seed."""
    if len(sk) != 32:
        raise ValueError("private seed must be 32 bytes")
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    A = _scalarmult(B, a)
    return _encodepoint(A)


def _Hint(m: bytes) -> int:
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * b))


def signature(m: bytes, sk: bytes, pk: bytes) -> bytes:
    """Sign message m with 32-byte seed sk (pk = publickey(sk))."""
    if len(sk) != 32 or len(pk) != 32:
        raise ValueError("seed and public key must be 32 bytes each")
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(h[b // 8: b // 4] + m)
    R = _scalarmult(B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % l
    return _encodepoint(R) + _encodeint(S)


def _decodeint(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(0, b))


def _decodepoint(s: bytes):
    y = sum(2 ** i * _bit(s, i) for i in range(0, b - 1))
    sign = _bit(s, b - 1)
    x = _xrecover(y)
    if x & 1 != sign:
        x = q - x
    P = (x, y)
    # Reject non-canonical encodings and off-curve points.
    if not _isoncurve(P):
        return None
    if _encodepoint(P) != s:
        return None
    return P


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def checkvalid(s: bytes, m: bytes, pk: bytes) -> bool:
    """True iff s is a valid signature of m under public key pk."""
    try:
        if len(s) != b // 4 or len(pk) != b // 8:
            return False
        R = _decodepoint(s[: b // 8])
        A = _decodepoint(pk)
        if R is None or A is None:
            return False
        S = _decodeint(s[b // 8: b // 4])
        h = _Hint(_encodepoint(R) + pk + m)
        v1 = _scalarmult(B, S)
        v2 = _edwards(R, _scalarmult(A, h))
        return v1 == v2
    except Exception:
        return False


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh (private_seed, public_key) pair from os.urandom."""
    sk = os.urandom(32)
    return sk, publickey(sk)
