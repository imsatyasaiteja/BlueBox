"""RSA signing helpers for BlueBox log entries.

The default signer is a file-backed RSA key so the demo runs locally. The
Signer interface also supports an external TPM/HSM command for deployments that
must keep the private key outside the process.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import os
import secrets
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


DEFAULT_PUBLIC_EXPONENT = 65537
DEFAULT_KEY_BITS = 2048


@dataclass(frozen=True)
class RsaPrivateKey:
    n: int
    e: int
    d: int


@dataclass(frozen=True)
class RsaPublicKey:
    n: int
    e: int


class Signer:
    key_id: str
    provider: str

    def sign_digest(self, digest_hex: str) -> str:
        raise NotImplementedError


class SoftwareRsaSigner(Signer):
    provider = "software_rsa_pkcs1v15_sha256"

    def __init__(self, private_key: RsaPrivateKey) -> None:
        self.private_key = private_key
        self.public_key = public_key(private_key)
        self.key_id = key_fingerprint(self.public_key)

    def sign_digest(self, digest_hex: str) -> str:
        return sign_digest(self.private_key, digest_hex)


class CommandTpmSigner(Signer):
    provider = "external_tpm_command"

    def __init__(self, command: str, key_id: str) -> None:
        if not command or not key_id:
            raise ValueError("TPM command signer requires command and key id")
        self.command = command
        self.key_id = key_id

    def sign_digest(self, digest_hex: str) -> str:
        validate_digest_hex(digest_hex)
        result = subprocess.run(
            [self.command, digest_hex],
            check=True,
            capture_output=True,
            text=True,
        )
        signature = result.stdout.strip()
        base64.b64decode(signature, validate=True)
        return signature


def generate_private_key(bits: int = DEFAULT_KEY_BITS) -> RsaPrivateKey:
    if bits < 1024:
        raise ValueError("RSA key size must be at least 1024 bits")

    e = DEFAULT_PUBLIC_EXPONENT
    half_bits = bits // 2
    while True:
        p = random_prime(half_bits)
        q = random_prime(bits - half_bits)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            return RsaPrivateKey(n=p * q, e=e, d=pow(e, -1, phi))


def public_key(private_key: RsaPrivateKey) -> RsaPublicKey:
    return RsaPublicKey(n=private_key.n, e=private_key.e)


def sign_digest(private_key: RsaPrivateKey, digest_hex: str) -> str:
    validate_digest_hex(digest_hex)
    width = modulus_width(private_key.n)
    encoded = emsa_pkcs1_v1_5_encode(digest_hex, width)
    signature_int = pow(int.from_bytes(encoded, "big"), private_key.d, private_key.n)
    return base64.b64encode(signature_int.to_bytes(width, "big")).decode("ascii")


def verify_digest(public_key_value: RsaPublicKey, digest_hex: str, signature_b64: str) -> bool:
    try:
        validate_digest_hex(digest_hex)
        signature_bytes = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error):
        return False

    width = modulus_width(public_key_value.n)
    if len(signature_bytes) != width:
        return False

    signature_int = int.from_bytes(signature_bytes, "big")
    if signature_int >= public_key_value.n:
        return False

    recovered = pow(signature_int, public_key_value.e, public_key_value.n).to_bytes(
        width, "big"
    )
    try:
        expected = emsa_pkcs1_v1_5_encode(digest_hex, width)
    except ValueError:
        return False

    if secrets.compare_digest(recovered, expected):
        return True

    # Backward compatibility for prototype rows that used textbook RSA.
    return int.from_bytes(recovered, "big") == int(digest_hex, 16)


def save_private_key(path: Path, private_key: RsaPrivateKey) -> None:
    validate_private_key(private_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "kty": "RSA",
        "n": str(private_key.n),
        "e": str(private_key.e),
        "d": str(private_key.d),
        "fingerprint": key_fingerprint(public_key(private_key)),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_private_key(path: Path) -> RsaPrivateKey:
    payload = json.loads(path.read_text(encoding="utf-8"))
    key = RsaPrivateKey(n=int(payload["n"]), e=int(payload["e"]), d=int(payload["d"]))
    validate_private_key(key)
    return key


def save_public_key(path: Path, public_key_value: RsaPublicKey) -> None:
    validate_public_key(public_key_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "kty": "RSA",
        "n": str(public_key_value.n),
        "e": str(public_key_value.e),
        "fingerprint": key_fingerprint(public_key_value),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_public_key(path: Path) -> RsaPublicKey:
    payload = json.loads(path.read_text(encoding="utf-8"))
    key = RsaPublicKey(n=int(payload["n"]), e=int(payload["e"]))
    validate_public_key(key)
    return key


def load_or_create_software_signer(
    private_key_path: Path, public_key_path: Path
) -> SoftwareRsaSigner:
    if private_key_path.exists():
        private_key = load_private_key(private_key_path)
        signer = SoftwareRsaSigner(private_key)
        expected_public = public_key(private_key)
        if not public_key_path.exists() or load_public_key(public_key_path) != expected_public:
            save_public_key(public_key_path, expected_public)
        return signer

    private_key = generate_private_key()
    save_private_key(private_key_path, private_key)
    save_public_key(public_key_path, public_key(private_key))
    return SoftwareRsaSigner(private_key)


def signer_from_environment(
    private_key_path: Path, public_key_path: Path, require_tpm: bool = False
) -> Signer:
    command = os.environ.get("BLUEBOX_TPM_SIGN_COMMAND")
    key_id = os.environ.get("BLUEBOX_TPM_KEY_ID")
    if command and key_id:
        return CommandTpmSigner(command, key_id)
    if require_tpm:
        raise RuntimeError(
            "TPM signing requested but BLUEBOX_TPM_SIGN_COMMAND and "
            "BLUEBOX_TPM_KEY_ID are not configured"
        )
    return load_or_create_software_signer(private_key_path, public_key_path)


def key_fingerprint(public_key_value: RsaPublicKey) -> str:
    validate_public_key(public_key_value)
    material = f"{public_key_value.n}:{public_key_value.e}".encode("ascii")
    return sha256(material).hexdigest()


def validate_digest_hex(digest_hex: str) -> None:
    if len(digest_hex) != 64:
        raise ValueError("expected SHA-256 digest hex")
    bytes.fromhex(digest_hex)


def validate_public_key(key: RsaPublicKey) -> None:
    if key.n.bit_length() < 1024:
        raise ValueError("RSA modulus must be at least 1024 bits")
    if key.e < 3 or key.e % 2 == 0:
        raise ValueError("RSA public exponent must be an odd integer >= 3")


def validate_private_key(key: RsaPrivateKey) -> None:
    validate_public_key(public_key(key))
    probe = 42
    if pow(pow(probe, key.e, key.n), key.d, key.n) != probe:
        raise ValueError("RSA private key is not self-consistent")


def modulus_width(n: int) -> int:
    return (n.bit_length() + 7) // 8


def emsa_pkcs1_v1_5_encode(digest_hex: str, width: int) -> bytes:
    digest = bytes.fromhex(digest_hex)
    if len(digest) != 32:
        raise ValueError("expected SHA-256 digest hex")
    digest_info_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info = digest_info_prefix + digest
    padding_len = width - len(digest_info) - 3
    if padding_len < 8:
        raise ValueError("RSA modulus too small for SHA-256 signature")
    return b"\x00\x01" + (b"\xff" * padding_len) + b"\x00" + digest_info


def random_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def is_probable_prime(value: int, rounds: int = 32) -> bool:
    if value < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value in small_primes:
        return True
    if any(value % prime == 0 for prime in small_primes):
        return False

    d = value - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(value - 3) + 2
        x = pow(a, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, value)
            if x == value - 1:
                break
        else:
            return False
    return True
