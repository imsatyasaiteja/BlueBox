"""Authenticated AES-GCM payload encryption for BlueBox log records."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ModuleNotFoundError as exc:  # pragma: no cover - startup guard
    AESGCM = None  # type: ignore[assignment]
    AESGCM_IMPORT_ERROR = exc
else:
    AESGCM_IMPORT_ERROR = None


DEFAULT_DATA_KEY = Path(__file__).resolve().parent / "keys" / "logger_data_key.json"
ALGORITHM = "AES-256-GCM"
LEGACY_ALGORITHM = "BLUEBOX-HKDF-SHA256-STREAM-HMAC-SHA256"
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16


@dataclass(frozen=True)
class EncryptionResult:
    ciphertext: bytes
    metadata: dict[str, object]


def load_or_create_data_key(path: Path = DEFAULT_DATA_KEY) -> bytes:
    env_key = os.environ.get("BLUEBOX_DATA_KEY_B64")
    if env_key:
        return decode_key(env_key, "BLUEBOX_DATA_KEY_B64")

    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        return decode_key(str(payload["key_b64"]), str(path))

    key = os.urandom(KEY_BYTES)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "kty": "oct",
                "alg": ALGORITHM,
                "key_b64": base64.b64encode(key).decode("ascii"),
                "warning": "development key; use BLUEBOX_DATA_KEY_B64 or KMS/HSM in production",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return key


def decode_key(encoded: str, source: str) -> bytes:
    key = base64.b64decode(encoded, validate=True)
    if len(key) != KEY_BYTES:
        raise ValueError(f"{source} must decode to {KEY_BYTES} bytes")
    return key


def encrypt_payload(plaintext: bytes, associated_data: bytes, key: bytes) -> EncryptionResult:
    validate_aesgcm_available()
    validate_key(key)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)  # type: ignore[operator]
    encrypted_payload = nonce + ciphertext
    return EncryptionResult(
        ciphertext=encrypted_payload,
        metadata={
            "algorithm": ALGORITHM,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "tag_b64": base64.b64encode(ciphertext[-TAG_BYTES:]).decode("ascii"),
            "ciphertext_sha256": sha256(encrypted_payload).hexdigest(),
            "plaintext_sha256": sha256(plaintext).hexdigest(),
        },
    )


def decrypt_payload(
    ciphertext: bytes,
    associated_data: bytes,
    key: bytes,
    metadata: dict[str, object],
) -> bytes:
    algorithm = metadata.get("algorithm")
    if algorithm == ALGORITHM:
        return decrypt_aes_gcm_payload(ciphertext, associated_data, key, metadata)
    if algorithm == LEGACY_ALGORITHM:
        return decrypt_legacy_payload(ciphertext, associated_data, key, metadata)
    raise ValueError(f"unsupported payload encryption algorithm: {algorithm}")


def decrypt_aes_gcm_payload(
    ciphertext: bytes,
    associated_data: bytes,
    key: bytes,
    metadata: dict[str, object],
) -> bytes:
    validate_aesgcm_available()
    validate_key(key)
    if len(ciphertext) < NONCE_BYTES + TAG_BYTES:
        raise ValueError("ciphertext is too short")

    expected_hash = str(metadata.get("ciphertext_sha256", ""))
    if sha256(ciphertext).hexdigest() != expected_hash:
        raise ValueError("ciphertext hash mismatch")

    nonce = ciphertext[:NONCE_BYTES]
    encrypted_body = ciphertext[NONCE_BYTES:]
    expected_nonce = base64.b64decode(str(metadata["nonce_b64"]), validate=True)
    expected_tag = base64.b64decode(str(metadata["tag_b64"]), validate=True)
    if nonce != expected_nonce:
        raise ValueError("ciphertext nonce mismatch")
    if encrypted_body[-TAG_BYTES:] != expected_tag:
        raise ValueError("ciphertext tag mismatch")

    plaintext = AESGCM(key).decrypt(nonce, encrypted_body, associated_data)  # type: ignore[operator]
    expected_plaintext_hash = str(metadata.get("plaintext_sha256", ""))
    if sha256(plaintext).hexdigest() != expected_plaintext_hash:
        raise ValueError("payload plaintext hash mismatch")
    return plaintext


def validate_aesgcm_available() -> None:
    if AESGCM is None:
        raise RuntimeError(
            "AES-GCM requires the 'cryptography' package. Run "
            "'.\\bluebox-env\\Scripts\\python.exe -m pip install -r requirements.txt'."
        ) from AESGCM_IMPORT_ERROR


def validate_key(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise ValueError(f"data key must be {KEY_BYTES} bytes")


def decrypt_legacy_payload(
    ciphertext: bytes,
    associated_data: bytes,
    key: bytes,
    metadata: dict[str, object],
) -> bytes:
    import hmac

    validate_key(key)
    if len(ciphertext) < 16 + 32:
        raise ValueError("legacy ciphertext is too short")
    expected_hash = str(metadata.get("ciphertext_sha256", ""))
    if sha256(ciphertext).hexdigest() != expected_hash:
        raise ValueError("legacy ciphertext hash mismatch")

    salt = base64.b64decode(str(metadata["salt_b64"]), validate=True)
    nonce = ciphertext[:16]
    body = ciphertext[16:-32]
    tag = ciphertext[-32:]
    enc_key = hkdf(key, salt, b"bluebox-log-encryption", KEY_BYTES)
    mac_key = hkdf(key, salt, b"bluebox-log-authentication", KEY_BYTES)
    expected_tag = hmac.new(mac_key, associated_data + nonce + body, sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("legacy payload authentication failed")
    plaintext = xor_bytes(body, keystream(enc_key, nonce, len(body)))
    if sha256(plaintext).hexdigest() != metadata.get("plaintext_sha256"):
        raise ValueError("legacy plaintext hash mismatch")
    return plaintext


def hkdf(key: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    import hmac

    if length <= 0:
        raise ValueError("HKDF length must be positive")
    prk = hmac.new(salt, key, sha256).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), sha256).digest()
        output += previous
        counter += 1
    return output[:length]


def keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    import hmac

    output = b""
    counter = 0
    while len(output) < length:
        output += hmac.new(key, nonce + counter.to_bytes(8, "big"), sha256).digest()
        counter += 1
    return output[:length]


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor inputs must have equal length")
    return bytes(a ^ b for a, b in zip(left, right))
