"""Signer/Verifier protocol: key separation for receipt signatures.

v0 used one HMAC secret held by everyone. v1 splits the roles:
- Signer lives in the tool-execution layer (framework middleware). It is the
  only party that can create valid receipts.
- Verifier holds only verification material (Ed25519 public key). The
  CompletionGate verifies with it; forging would require the private key.

Ship HMACSigner (v0 behavior, single-trust-domain) and Ed25519Signer
(asymmetric default). Any backend implementing the two-method protocol
(e.g. `cryptography`, `nacl` for production speed) can be injected.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Protocol, runtime_checkable

from . import _ed25519


@runtime_checkable
class Verifier(Protocol):
    @property
    def alg(self) -> str: ...
    def verify(self, payload: bytes, signature: str) -> bool: ...


@runtime_checkable
class Signer(Protocol):
    @property
    def alg(self) -> str: ...
    def sign(self, payload: bytes) -> str: ...
    @property
    def verifier(self) -> Verifier: ...


class HMACSigner:
    """v0 behavior: symmetric key. Anyone holding the secret can forge.

    Fine when signer and verifier share a trust domain (both in the
    operator's backend; the agent LLM never sees the secret). Not safe
    across a trust boundary — use Ed25519Signer there.
    """

    alg = "hmac-sha256"

    def __init__(self, secret: bytes):
        if not secret or not isinstance(secret, (bytes, bytearray)):
            raise ValueError("secret must be non-empty bytes")
        self._secret = bytes(secret)

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    @property
    def verifier(self) -> "HMACVerifier":
        # Symmetric: verification needs the same secret. This is the
        # documented v0 trust assumption, not a v1 security property.
        return HMACVerifier(self._secret)


class HMACVerifier:
    alg = "hmac-sha256"

    def __init__(self, secret: bytes):
        if not secret or not isinstance(secret, (bytes, bytearray)):
            raise ValueError("secret must be non-empty bytes")
        self._secret = bytes(secret)

    def verify(self, payload: bytes, signature: str) -> bool:
        if not signature or not isinstance(signature, str):
            return False
        try:
            expected = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        except Exception:
            return False
        return hmac.compare_digest(expected, signature)


class Ed25519Signer:
    """Asymmetric default. Private seed never leaves the tool layer."""

    alg = "ed25519"

    def __init__(self, private_seed: bytes):
        if not isinstance(private_seed, (bytes, bytearray)) or len(private_seed) != 32:
            raise ValueError("Ed25519 private seed must be 32 bytes")
        self._seed = bytes(private_seed)
        self._pub = _ed25519.publickey(self._seed)

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        seed, _ = _ed25519.generate_keypair()
        return cls(seed)

    @property
    def public_key(self) -> bytes:
        return self._pub

    def sign(self, payload: bytes) -> str:
        return _ed25519.signature(payload, self._seed, self._pub).hex()

    @property
    def verifier(self) -> "Ed25519Verifier":
        return Ed25519Verifier(self._pub)


class Ed25519Verifier:
    """Holds only the public key. Cannot forge."""

    alg = "ed25519"

    def __init__(self, public_key: bytes):
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        self._pub = bytes(public_key)

    def verify(self, payload: bytes, signature: str) -> bool:
        if not signature or not isinstance(signature, str):
            return False
        try:
            sig = bytes.fromhex(signature)
        except (ValueError, TypeError):
            return False
        return _ed25519.checkvalid(sig, payload, self._pub)
