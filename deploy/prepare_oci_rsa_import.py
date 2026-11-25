#!/usr/bin/env python3
"""Wrap one Xbox Hub RSA private key for one OCI Vault HSM import.

This tool runs on the owner's trusted computer. It performs no network requests.
The Vault's public wrapping key is public. The encrypted application private key
and its passphrase stay on this computer. Only the wrapped output file is uploaded
to the OCI Vault import form.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding

PACKAGE_KEY_ID = "xboxhub-package-rsa3072-b845262d34ea685b"
RELEASE_KEY_ID = "xboxhub-rsa3072-9986345089cc1513"
ORACLE_AES_WRAP_IV = bytes.fromhex("a65959a6")
ROLE_KEY_IDS = {
    "package-decryption": PACKAGE_KEY_ID,
    "release-signing": RELEASE_KEY_ID,
}


def fail(message: str) -> "NoReturn":
    raise SystemExit("ERROR: " + message)


def resolve_file(value: str, label: str) -> Path:
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_file():
        fail(label + " must be a regular file.")
    return path


def require_outside_repo(path: Path, repo_root: Path, label: str) -> None:
    try:
        path.relative_to(repo_root)
    except ValueError:
        return
    fail("Refusing to use " + label + " inside the public builder repository.")


def wrap_private_key_material(
    private_key_pem: bytes,
    passphrase: bytes,
    vault_wrapping_public_pem: bytes,
    expected_key_id: str,
) -> tuple[bytes, str]:
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=passphrase)
    except (TypeError, ValueError) as exc:
        raise ValueError("Could not unlock the private RSA PEM; verify the key file and passphrase.") from exc

    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size != 3072:
        raise ValueError("Xbox Hub import requires the matching RSA-3072 private key.")

    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    prefix = "xboxhub-package-rsa3072-" if expected_key_id.startswith("xboxhub-package-") else "xboxhub-rsa3072-"
    actual_key_id = prefix + hashlib.sha256(public_der).hexdigest()[:16]
    if actual_key_id != expected_key_id:
        raise ValueError("The selected private key does not match the public key embedded in Xbox Hub.")

    try:
        wrapping_public_key = serialization.load_pem_public_key(vault_wrapping_public_pem)
    except ValueError as exc:
        raise ValueError("The OCI Vault public wrapping key is not a valid PEM public key.") from exc
    if not isinstance(wrapping_public_key, rsa.RSAPublicKey) or wrapping_public_key.key_size != 4096:
        raise ValueError("OCI Vault's RSA wrapping public key must be RSA-4096.")

    pkcs8_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    # OCI RSA_OAEP_AES_SHA256 import envelope:
    #   RSA-OAEP-SHA256(wrapping public key, temporary AES-256 key)
    #   || AES-KW-PAD(temporary AES key, unencrypted PKCS8 DER)
    temporary_aes_key = bytearray(os.urandom(32))
    try:
        wrapped_aes_key = wrapping_public_key.encrypt(
            bytes(temporary_aes_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        # cryptography's AES-KW-PAD implementation uses RFC 5649's
        # specified default IV (A6 59 59 A6), matching OCI's import format.
        wrapped_private_key = aes_key_wrap_with_padding(
            bytes(temporary_aes_key),
            pkcs8_der,
        )
        return wrapped_aes_key + wrapped_private_key, actual_key_id
    finally:
        for index in range(len(temporary_aes_key)):
            temporary_aes_key[index] = 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=sorted(ROLE_KEY_IDS))
    parser.add_argument("--private-key", required=True, help="Path to the encrypted Xbox Hub private PEM")
    parser.add_argument("--vault-wrapping-public-key", required=True, help="Public RSA wrapping key downloaded from your OCI Vault")
    parser.add_argument("--output", required=True, help="New .bin output path for the wrapped import material")
    args = parser.parse_args()

    private_path = resolve_file(args.private_key, "Private RSA key")
    wrapping_path = resolve_file(args.vault_wrapping_public_key, "Vault wrapping public key")
    output_path = Path(args.output).expanduser().absolute()
    if output_path.exists():
        fail("Output file already exists; it will not be overwritten.")
    repo_root = Path(__file__).resolve().parents[1]
    require_outside_repo(private_path, repo_root, "private key")
    require_outside_repo(output_path.resolve(), repo_root, "wrapped import output")

    raw_private = private_path.read_bytes()
    if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" not in raw_private:
        fail("The Xbox Hub private key must be an encrypted PKCS#8 PEM file.")
    passphrase = getpass.getpass("Xbox Hub private-key passphrase (input hidden): ").encode("utf-8")
    try:
        wrapped, key_id = wrap_private_key_material(
            raw_private,
            passphrase,
            wrapping_path.read_bytes(),
            ROLE_KEY_IDS[args.role],
        )
    except ValueError as exc:
        fail(str(exc))
    finally:
        del passphrase
        del raw_private

    output_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(output_path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(wrapped)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            output_path.unlink()
        except OSError:
            pass
        raise

    print("SUCCESS: OCI-compatible RSA import material created.")
    print("Role: " + args.role)
    print("Verified Xbox Hub key ID: " + key_id)
    print("Wrapped import bytes: " + str(len(wrapped)))
    print("Output: " + str(output_path))
    print("The private PEM and passphrase were not copied, transmitted, or printed.")
    print("Upload only this wrapped binary to the OCI Vault Import External Key form.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
