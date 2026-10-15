"""receipt_layer: completion-evidence harness ("receipt layer")."""
from .receipts import Receipt, ReceiptLog
from .gate import CompletionGate, GateResult, make_claim
from .shim import wrap
from .signers import (
    Signer, Verifier,
    HMACSigner, HMACVerifier,
    Ed25519Signer, Ed25519Verifier,
)

__all__ = [
    "Receipt",
    "ReceiptLog",
    "CompletionGate",
    "GateResult",
    "make_claim",
    "wrap",
    "Signer",
    "Verifier",
    "HMACSigner",
    "HMACVerifier",
    "Ed25519Signer",
    "Ed25519Verifier",
]

__version__ = "0.2.0"
