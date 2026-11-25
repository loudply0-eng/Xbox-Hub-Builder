#!/usr/bin/env python3
"""Pull, authenticate, sign, and publish Xbox Hub stable candidates on an OCI VM.

Authentication to OCI uses the VM's Instance Principal. Production RSA private
keys remain inside OCI Vault; this process receives only wrapped AES key material
and the resulting signature. The GitHub repository is public and read-only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import struct
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GITHUB_REPO = "loudply0-eng/Xbox-Hub-Builder"
WORKFLOW_ID = 428075352
ARTIFACT_NAME = "xboxhub-encrypted-offline-package"
METADATA_ARTIFACT_NAME = "xboxhub-release-metadata"
PACKAGE_KEY_ID = "xboxhub-package-rsa3072-b845262d34ea685b"
PACKAGE_PUBLIC_KEY_SPKI_B64 = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAnRC/9ASAHsBTtsqiyW1VNbhtiU8pN7a4r2gFEEkibvwctEYfdKpBTs9st1Og5JcNBrDS6/cl7gAj/d54ahDxKV0ApX66Io3EKkwV0zhQsYxjN14P8Gjpzf7ZB701da8mES1Go1GdUcdJE2Iz2qo/ANZ2ZEdJQuqzRuCbP8ommXcawNk8EU46kWcE4EYi/hDrYspWybxXKtRIxlxfdG1aJ7eucUST7NvSuvyJ762X0RCVstFci5iR/Bpk75YHXt0H9zOtmuBYGg8kajhj4FdgEbFuLh+c9GAlWlxMY6ZOQCU2bKHUiN/baLn6ytICR/XgGHojhLhMC5xtiIP/gwTY4A9Q8NIFrwC0NmBYzWpTKtULY/tUutt2aIJzsT32q9iuX5JuTSrKFe12rpIwhMWqbnFJxSiiKAmM/dqFMA6Wz/XVFFCxT14f6kzcD4ufsyWJsvnairtcikACwYEVApA5cympzb99rk1r1Y0dU+oYvmDePjRUS/AfX0LUWKexI/oZAgMBAAE="
RELEASE_KEY_ID = "xboxhub-rsa3072-9986345089cc1513"
RELEASE_PUBLIC_KEY_SPKI_B64 = (
    "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAjdjBmNbij7n3n/lHFpe5t6kGOsMNFMZgPvWt6NDpvMwHlswExi0/c4x+BjOQsYephTSjTyrF3yj7aLLE0OhXTtOEu1OU7aTApK8dPaLdEAWokVwCy1sVspAclOw9gqBaDuPXp5/8DdzsO5IWTm5xvZF7eJfH7Sjn0ET7b5yvS7jtVuJNhK4ujUmB/m7AAftBbh2Gur6MonFDj1gQlRauCzp5A/mozegZwnhLtkB+YkOBq1ey16SwFaVgilL5QjqGW+R3ODQ2muhfha7L2ZUI/lNdSwpVsS0n6OXJQEMyyQlGnZ8CcTX+9yo2YXgwaFiBLBJaFceQxYA4K7+f9JJHLFZxX3ig+YeywL1EJYE5lTiqHg/VoFi5zzsjtgQhbGmZ3myhzcQOsHi2OFSOYJhhPtyhULVyiIXYYEP07svlDOOEwA0wSLLoTw1cAXMWa0R6Cv/pD39FUnORgOgl4iijQry7NeHfQYeoL5sUQAk9mzq6BdvF0eiGmjTOAmlEszTRAgMBAAE="
)
PACKAGE_HOST = "updates.mahmoudaljuorany.store"
MAX_PACKAGE_BYTES = 700 * 1024 * 1024
MAX_CONTAINER_BYTES = 734_200_000
MAX_ARTIFACT_BYTES = 800 * 1024 * 1024
MAGIC = b"XHUBENC1"
AAD_PREFIX = "XboxHub-Package-Envelope-v1"
STABLE_VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_NAME_RE = re.compile(r"^XboxHub-([0-9]+\.[0-9]+\.[0-9]+)-win-x64\.zip$")


def fail(message: str) -> None:
    raise RuntimeError(message)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("JSON contains a duplicate property.")
        result[key] = value
    return result


def json_loads_strict(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_json_object)


@dataclass(frozen=True)
class Config:
    crypto_endpoint: str
    package_key_ocid: str
    package_key_version_ocid: str
    signing_key_ocid: str
    signing_key_version_ocid: str
    stable_dir: Path
    state_file: Path
    auto_publish_enabled: bool

    @classmethod
    def from_env(cls) -> "Config":
        names = {
            "XBOXHUB_KMS_CRYPTO_ENDPOINT": os.getenv("XBOXHUB_KMS_CRYPTO_ENDPOINT", ""),
            "XBOXHUB_PACKAGE_KEY_OCID": os.getenv("XBOXHUB_PACKAGE_KEY_OCID", ""),
            "XBOXHUB_PACKAGE_KEY_VERSION_OCID": os.getenv("XBOXHUB_PACKAGE_KEY_VERSION_OCID", ""),
            "XBOXHUB_SIGNING_KEY_OCID": os.getenv("XBOXHUB_SIGNING_KEY_OCID", ""),
            "XBOXHUB_SIGNING_KEY_VERSION_OCID": os.getenv("XBOXHUB_SIGNING_KEY_VERSION_OCID", ""),
        }
        missing = [k for k, v in names.items() if not v]
        if missing:
            fail("Missing required environment settings: " + ", ".join(missing))
        endpoint = names["XBOXHUB_KMS_CRYPTO_ENDPOINT"]
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            fail("XBOXHUB_KMS_CRYPTO_ENDPOINT must be a fixed HTTPS Vault crypto endpoint.")
        return cls(
            crypto_endpoint=endpoint.rstrip("/"),
            package_key_ocid=names["XBOXHUB_PACKAGE_KEY_OCID"],
            package_key_version_ocid=names["XBOXHUB_PACKAGE_KEY_VERSION_OCID"],
            signing_key_ocid=names["XBOXHUB_SIGNING_KEY_OCID"],
            signing_key_version_ocid=names["XBOXHUB_SIGNING_KEY_VERSION_OCID"],
            stable_dir=Path(os.getenv("XBOXHUB_STABLE_DIR", "/var/www/xbox-hub-updates/stable")),
            state_file=Path(os.getenv("XBOXHUB_STATE_FILE", "/var/lib/xboxhub-release-agent/state.json")),
            auto_publish_enabled=os.getenv("XBOXHUB_RELEASE_AUTO_PUBLISH_ENABLED", "false").strip().lower() == "true",
        )


class OciVaultCrypto:
    def __init__(self, config: Config) -> None:
        try:
            import oci
        except ImportError as exc:
            raise RuntimeError("OCI Python SDK is missing; install the pinned requirements.") from exc
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        self.oci = oci
        self.client = oci.key_management.KmsCryptoClient(
            config={}, service_endpoint=config.crypto_endpoint, signer=signer
        )
        self.config = config

    def unwrap_aes_key(self, wrapped_key_b64: str) -> bytes:
        model = self.oci.key_management.models.DecryptDataDetails(
            key_id=self.config.package_key_ocid,
            key_version_id=self.config.package_key_version_ocid,
            ciphertext=wrapped_key_b64,
            encryption_algorithm="RSA_OAEP_SHA_256",
        )
        response = self.client.decrypt(model).data
        plaintext = base64.b64decode(response.plaintext, validate=True)
        if len(plaintext) != 32:
            fail("Vault returned an invalid AES-256 package key.")
        return plaintext

    def sign(self, payload: bytes) -> bytes:
        model = self.oci.key_management.models.SignDataDetails(
            key_id=self.config.signing_key_ocid,
            key_version_id=self.config.signing_key_version_ocid,
            message=base64.b64encode(payload).decode("ascii"),
            message_type="RAW",
            signing_algorithm="SHA_256_RSA_PKCS1_V1_5",
        )
        response = self.client.sign(model).data
        return base64.b64decode(response.signature, validate=True)
    def self_test(self) -> None:
        package_der = base64.b64decode(PACKAGE_PUBLIC_KEY_SPKI_B64, validate=True)
        package_public = serialization.load_der_public_key(package_der)
        if not isinstance(package_public, rsa.RSAPublicKey) or package_public.key_size != 3072:
            fail("Embedded package recipient key is not RSA-3072.")
        package_fingerprint = hashlib.sha256(package_der).hexdigest()[:16]
        if "xboxhub-package-rsa3072-" + package_fingerprint != PACKAGE_KEY_ID:
            fail("Embedded package recipient key fingerprint is inconsistent.")

        test_aes_key = secrets.token_bytes(32)
        wrapped = package_public.encrypt(
            test_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        unwrapped = self.unwrap_aes_key(base64.b64encode(wrapped).decode("ascii"))
        if not hmac.compare_digest(test_aes_key, unwrapped):
            fail("Vault package-decryption key does not match the app's embedded recipient public key.")

        signing_public = load_trusted_public_key()
        challenge = b"XboxHub-OCI-Vault-self-test-v1\n" + secrets.token_bytes(32)
        signature = self.sign(challenge)
        try:
            signing_public.verify(signature, challenge, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as exc:
            raise RuntimeError("Vault release-signing key does not match the public key embedded in the app.") from exc
        print("PASS: OCI Instance Principal can use the exact package-decryption key and app-trusted release-signing key.")


def http_json(url: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "XboxHub-OCI-Release-Agent/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            fail("GitHub API returned a non-200 response.")
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        fail("GitHub API response exceeded the configured limit.")
    return json_loads_strict(data)


def http_download(url: str, max_bytes: int) -> bytes:
    parsed_url = urllib.parse.urlsplit(url)
    if parsed_url.scheme != "https" or parsed_url.hostname not in ("api.github.com", "github.com"):
        fail("Artifact download URL must originate from the public GitHub host.")
    request = urllib.request.Request(url, headers={"User-Agent": "XboxHub-OCI-Release-Agent/1.0"})
    chunks = bytearray()
    with urllib.request.urlopen(request, timeout=300) as response:
        if response.status != 200:
            fail("GitHub artifact download did not return HTTP 200.")
        final_url = urllib.parse.urlsplit(response.geturl())
        if final_url.scheme != "https" or not (final_url.hostname in ("github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com") or (final_url.hostname or "").endswith(".blob.core.windows.net")):
            fail("Artifact download redirected to an unexpected host.")
        while True:
            part = response.read(1024 * 1024)
            if not part:
                break
            chunks.extend(part)
            if len(chunks) > max_bytes:
                fail("GitHub artifact exceeded the configured download limit.")
    return bytes(chunks)

def extract_one_artifact_file(archive: bytes, expected_name: str, max_file_bytes: int) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as zf:
            files = [item for item in zf.infolist() if not item.is_dir()]
            if len(files) != 1 or Path(files[0].filename).name != expected_name:
                fail("GitHub artifact did not contain exactly the expected file: " + expected_name)
            if files[0].file_size <= 0 or files[0].file_size > max_file_bytes:
                fail("GitHub artifact file exceeded the configured size limit.")
            data = zf.read(files[0])
    except zipfile.BadZipFile as exc:
        raise RuntimeError("GitHub artifact archive is not a valid ZIP file.") from exc
    if len(data) > max_file_bytes:
        fail("Extracted GitHub artifact file exceeded the configured size limit.")
    return data


def verify_artifact_archive_digest(archive: bytes, expected_digest: Any, label: str) -> None:
    if not isinstance(expected_digest, str) or not expected_digest.startswith("sha256:"):
        fail(label + " is missing its GitHub SHA-256 archive digest.")
    expected = expected_digest.removeprefix("sha256:").lower()
    actual = hashlib.sha256(archive).hexdigest()
    if not HEX_SHA_RE.fullmatch(expected) or not hmac.compare_digest(actual, expected):
        fail(label + " archive digest does not match GitHub's artifact metadata.")


def verify_source_build_and_marker(run: dict[str, Any], metadata: dict[str, Any]) -> None:
    run_id = run.get("id")
    if not isinstance(run_id, int) or metadata.get("builderRunId") != run_id:
        fail("Release metadata run ID does not match its GitHub Actions run.")
    if metadata.get("builderRunAttempt") != run.get("run_attempt", 1):
        fail("Release metadata run attempt does not match its GitHub Actions run.")
    if (run.get("status") != "completed" or run.get("conclusion") != "success" or
            run.get("head_branch") != "main" or run.get("workflow_id") != WORKFLOW_ID or
            run.get("path") != ".github/workflows/windows-build-check.yml"):
        fail("Candidate is not backed by a successful trusted main-branch Windows build.")
    source_sha = metadata.get("sourceSha", "")
    if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
        fail("Release metadata contains an invalid source revision.")
    tag_url = f"https://api.github.com/repos/{GITHUB_REPO}/git/ref/tags/xboxhub-source-{source_sha}"
    try:
        marker = http_json(tag_url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise RuntimeError("The candidate source has no successful-build marker yet.") from exc
        raise
    marker_object = marker.get("object", {})
    if (marker.get("ref") != f"refs/tags/xboxhub-source-{source_sha}" or
            marker_object.get("sha") != source_sha):
        fail("Successful source-build marker does not match release metadata.")
    if metadata.get("releaseSequence") != release_sequence(metadata.get("version", "")):
        fail("Release metadata sequence does not match its semantic version.")


def latest_persistent_release_candidate() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=50"
    releases = http_json(url)
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not True:
            continue
        tag_name = release.get("tag_name", "")
        match = re.fullmatch(r"xboxhub-candidate-([0-9a-f]{40})", str(tag_name))
        if not match:
            continue
        source_sha = match.group(1)
        assets = release.get("assets", [])
        if not isinstance(assets, list):
            fail("Persistent candidate release asset list is invalid.")
        asset_map = {a.get("name"): a for a in assets if isinstance(a, dict)}
        metadata_asset = asset_map.get("xboxhub-release-metadata.json")
        if not metadata_asset:
            continue
        metadata_name = "xboxhub-release-metadata.json"
        if type(metadata_asset.get("size")) is not int or not 0 < metadata_asset["size"] <= 64 * 1024:
            fail("Persistent release metadata asset has an invalid size.")
        metadata_url = metadata_asset.get("browser_download_url")
        if not isinstance(metadata_url, str):
            fail("Persistent release metadata asset URL is missing.")
        try:
            metadata_bytes = http_download(metadata_url, 64 * 1024)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                continue
            raise
        verify_artifact_archive_digest(metadata_bytes, metadata_asset.get("digest"), "Persistent release metadata")
        if len(metadata_bytes) != metadata_asset["size"]:
            fail("Persistent release metadata byte count differs from GitHub asset metadata.")
        metadata = json_loads_strict(metadata_bytes)
        if not isinstance(metadata, dict) or metadata.get("channel") != "stable":
            continue
        version = metadata.get("version")
        if not isinstance(version, str) or not STABLE_VERSION_RE.fullmatch(version):
            continue
        if metadata.get("sourceSha") != source_sha:
            fail("Candidate release tag does not match the source SHA in its metadata.")
        package_name = f"XboxHub-{version}-win-x64.xhubenc"
        package_asset = asset_map.get(package_name)
        if not package_asset or len(asset_map) != 2:
            fail("Persistent candidate release must contain exactly the encrypted package and metadata sidecar.")
        if type(package_asset.get("size")) is not int or not 0 < package_asset["size"] <= MAX_CONTAINER_BYTES:
            fail("Persistent encrypted package asset has an invalid size.")
        package_url = package_asset.get("browser_download_url")
        if not isinstance(package_url, str):
            fail("Persistent encrypted package asset URL is missing.")
        run_id = metadata.get("builderRunId")
        if type(run_id) is not int or run_id <= 0:
            fail("Persistent release metadata builder run ID is invalid.")
        run = http_json(f"https://api.github.com/repos/{GITHUB_REPO}/actions/runs/{run_id}", 256 * 1024)
        verify_source_build_and_marker(run, metadata)
        if release_sequence(version) != metadata.get("releaseSequence"):
            fail("Persistent release sequence does not match its version.")
        return run, metadata, {
            "url": package_url,
            "digest": package_asset.get("digest"),
            "size": package_asset["size"],
            "kind": "release-asset",
        }
    return None


def latest_actions_artifact_candidate() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    runs_url = (
        f"https://api.github.com/repos/{GITHUB_REPO}/actions/workflows/{WORKFLOW_ID}/runs"
        "?branch=main&status=success&per_page=10"
    )
    runs = http_json(runs_url).get("workflow_runs", [])
    for run in runs:
        if run.get("head_branch") != "main" or run.get("conclusion") != "success":
            continue
        run_id = run.get("id")
        if not isinstance(run_id, int):
            continue
        artifacts_url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/runs/{run_id}/artifacts?per_page=100"
        artifacts = http_json(artifacts_url).get("artifacts", [])
        metadata_artifact = next(
            (a for a in artifacts if a.get("name") == METADATA_ARTIFACT_NAME and not a.get("expired")),
            None,
        )
        package_artifact = next(
            (a for a in artifacts if a.get("name") == ARTIFACT_NAME and not a.get("expired")),
            None,
        )
        if not metadata_artifact or not package_artifact:
            continue
        metadata_url = metadata_artifact.get("archive_download_url")
        package_url = package_artifact.get("archive_download_url")
        if not metadata_url or not package_url:
            continue
        if metadata_artifact.get("size_in_bytes", 0) > 256 * 1024:
            fail("Release metadata artifact exceeds its configured size limit.")
        if package_artifact.get("size_in_bytes", 0) > MAX_ARTIFACT_BYTES:
            fail("Encrypted package artifact exceeds its configured size limit.")
        try:
            metadata_archive = http_download(metadata_url, 256 * 1024)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                continue
            raise
        verify_artifact_archive_digest(metadata_archive, metadata_artifact.get("digest"), "Release metadata")
        metadata_bytes = extract_one_artifact_file(metadata_archive, "xboxhub-release-metadata.json", 64 * 1024)
        metadata = json_loads_strict(metadata_bytes)
        if not isinstance(metadata, dict) or metadata.get("channel") != "stable":
            continue
        version = metadata.get("version")
        if not isinstance(version, str) or not STABLE_VERSION_RE.fullmatch(version):
            continue
        verify_source_build_and_marker(run, metadata)
        return run, metadata, {
            "url": package_url,
            "digest": package_artifact.get("digest"),
            "size": package_artifact.get("size_in_bytes"),
            "kind": "actions-artifact",
        }
    return None


def latest_candidate_artifact() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    # Permanent prerelease assets are the primary durable handoff. Short-lived
    # Actions artifacts remain a fallback during the prerelease/tag handoff window.
    candidate = latest_persistent_release_candidate()
    if candidate is not None:
        return candidate
    return latest_actions_artifact_candidate()


def download_encrypted_package(package_artifact: dict[str, Any], metadata: dict[str, Any]) -> bytes:
    package_url = package_artifact.get("url")
    if not isinstance(package_url, str):
        fail("Encrypted package asset URL is missing.")
    filename = metadata.get("packageFileName")
    if not isinstance(filename, str) or not PACKAGE_NAME_RE.fullmatch(filename):
        fail("Release metadata contains an invalid encrypted package filename.")
    if package_artifact.get("kind") == "release-asset":
        encrypted = http_download(package_url, MAX_CONTAINER_BYTES)
        verify_artifact_archive_digest(encrypted, package_artifact.get("digest"), "Persistent encrypted package")
        if len(encrypted) != package_artifact.get("size"):
            fail("Persistent encrypted package size differs from GitHub asset metadata.")
        return encrypted
    archive = http_download(package_url, MAX_ARTIFACT_BYTES)
    verify_artifact_archive_digest(archive, package_artifact.get("digest"), "Encrypted package artifact")
    return extract_one_artifact_file(archive, filename.removesuffix(".zip") + ".xhubenc", MAX_CONTAINER_BYTES)

def parse_container(container: bytes, expected_key_id: str) -> tuple[dict[str, Any], bytes]:
    if not 12 <= len(container) <= MAX_CONTAINER_BYTES:
        fail("Encrypted package container size is outside the supported range.")
    if container[:8] != MAGIC:
        fail("Encrypted package magic is invalid.")
    header_len = struct.unpack("<i", container[8:12])[0]
    if not 0 < header_len <= 65536 or 12 + header_len > len(container):
        fail("Encrypted package header length is invalid.")
    header = json_loads_strict(container[12:12 + header_len])
    required = {
        "schemaVersion", "algorithm", "keyId", "originalFileName", "packageSize",
        "packageSha256", "nonceBase64", "tagBase64", "wrappedKeyBase64",
    }
    if not isinstance(header, dict) or set(header) != required:
        fail("Encrypted package header schema is invalid.")
    if header["schemaVersion"] != 1 or header["algorithm"] != "AES-256-GCM+RSA-OAEP-SHA256":
        fail("Encrypted package algorithm or schema is unsupported.")
    if header["keyId"] != expected_key_id or expected_key_id != PACKAGE_KEY_ID:
        fail("Encrypted package recipient key ID does not match the configured Vault key.")
    filename = header["originalFileName"]
    size = header["packageSize"]
    digest = header["packageSha256"]
    if not isinstance(filename, str) or not PACKAGE_NAME_RE.fullmatch(filename):
        fail("Encrypted package filename is not a stable Xbox Hub package name.")
    if type(size) is not int or not 0 < size <= MAX_PACKAGE_BYTES:
        fail("Encrypted package plaintext size is invalid.")
    if not isinstance(digest, str) or not HEX_SHA_RE.fullmatch(digest):
        fail("Encrypted package SHA-256 metadata is malformed.")
    ciphertext = container[12 + header_len:]
    if len(ciphertext) != size:
        fail("Encrypted package payload length does not match header metadata.")
    return header, ciphertext


def decrypt_container(container: bytes, unwrap_key, expected_key_id: str = PACKAGE_KEY_ID) -> tuple[dict[str, Any], bytes]:
    header, ciphertext = parse_container(container, expected_key_id)
    key = bytearray(unwrap_key(header["wrappedKeyBase64"]))
    if len(key) != 32:
        fail("Unwrapped package data key is not 256 bits.")
    nonce = base64.b64decode(header["nonceBase64"], validate=True)
    tag = base64.b64decode(header["tagBase64"], validate=True)
    if len(nonce) != 12 or len(tag) != 16:
        fail("Package nonce or authentication tag has an invalid length.")
    aad = (
        f"{AAD_PREFIX}\n{header['keyId']}\n{header['originalFileName']}\n"
        f"{header['packageSize']}\n{header['packageSha256']}"
    ).encode("utf-8")
    try:
        plaintext = AESGCM(bytes(key)).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag as exc:
        raise RuntimeError("Encrypted package authentication failed.") from exc
    finally:
        for index in range(len(key)):
            key[index] = 0
    if len(plaintext) != header["packageSize"] or hashlib.sha256(plaintext).hexdigest() != header["packageSha256"]:
        fail("Decrypted package size or SHA-256 does not match the authenticated header.")
    validate_package_zip(plaintext)
    return header, plaintext


def validate_package_zip(package: bytes) -> None:
    with zipfile.ZipFile(io.BytesIO(package), "r") as archive:
        infos = archive.infolist()
        if len(infos) != 2 or {i.filename for i in infos} != {"XboxHub.exe", "XboxHub.Updater.exe"}:
            fail("Decrypted ZIP must contain exactly the two expected root executables.")
        if archive.testzip() is not None or any(i.file_size <= 0 for i in infos):
            fail("Decrypted ZIP CRC or entry-size validation failed.")


def release_sequence(version: str) -> int:
    if not STABLE_VERSION_RE.fullmatch(version):
        fail("Preview or malformed versions cannot be published to the stable feed.")
    major, minor, patch = (int(x) for x in version.split("."))
    if max(major, minor, patch) >= 1_000_000:
        fail("Stable version component exceeds the release-sequence range.")
    return major * 1_000_000_000_000 + minor * 1_000_000 + patch


def validate_candidate_metadata(metadata: dict[str, Any]) -> None:
    if metadata.get("schemaVersion") != 1 or metadata.get("productId") != "xbox-hub-for-pc":
        fail("Release metadata schema or product ID is invalid.")
    if metadata.get("channel") != "stable" or metadata.get("platform") != "windows" or metadata.get("architecture") != "x64":
        fail("Only stable Windows x64 candidates may be published.")
    version = metadata.get("version")
    if not isinstance(version, str) or not STABLE_VERSION_RE.fullmatch(version):
        fail("Stable release version is invalid.")
    if type(metadata.get("releaseSequence")) is not int or metadata["releaseSequence"] != release_sequence(version):
        fail("Release sequence does not match the stable semantic version.")
    expected_filename = f"XboxHub-{version}-win-x64.zip"
    if metadata.get("packageFileName") != expected_filename:
        fail("Release metadata package filename does not match its stable version.")
    if type(metadata.get("packageSize")) is not int or not 0 < metadata["packageSize"] <= MAX_PACKAGE_BYTES:
        fail("Release metadata package size is invalid.")
    if not isinstance(metadata.get("packageSha256"), str) or not HEX_SHA_RE.fullmatch(metadata["packageSha256"]):
        fail("Release metadata package SHA-256 is invalid.")
    if metadata.get("minimumUpdaterVersion") != "0.1.9":
        fail("Minimum updater version is not the configured stable baseline.")
    if not isinstance(metadata.get("sourceSha"), str) or not SOURCE_SHA_RE.fullmatch(metadata["sourceSha"]):
        fail("Release metadata source SHA is invalid.")
    if type(metadata.get("builderRunId")) is not int or metadata["builderRunId"] <= 0:
        fail("Release metadata builder run ID is invalid.")
    if type(metadata.get("builderRunAttempt")) is not int or metadata["builderRunAttempt"] <= 0:
        fail("Release metadata builder run attempt is invalid.")
    if not isinstance(metadata.get("title"), str) or not 1 <= len(metadata["title"].strip()) <= 120:
        fail("Release title is invalid.")
    changes = metadata.get("changes")
    if not isinstance(changes, list) or not 1 <= len(changes) <= 20:
        fail("Release notes must contain 1 to 20 entries.")
    if any(not isinstance(change, str) or not change.strip() or len(change) > 500 for change in changes):
        fail("A release-note entry is invalid.")
    try:
        date.fromisoformat(metadata.get("date"))
    except (TypeError, ValueError):
        fail("Release date is invalid.")


def validate_metadata(metadata: dict[str, Any], header: dict[str, Any], package: bytes) -> dict[str, Any]:
    if metadata.get("schemaVersion") != 1 or metadata.get("productId") != "xbox-hub-for-pc":
        fail("Release metadata schema or product ID is invalid.")
    if metadata.get("channel") != "stable" or metadata.get("platform") != "windows" or metadata.get("architecture") != "x64":
        fail("Only stable Windows x64 candidates may be published.")
    version = metadata.get("version")
    match = PACKAGE_NAME_RE.fullmatch(header["originalFileName"])
    if not match or match.group(1) != version:
        fail("Release metadata version does not match the encrypted package filename.")
    expected_sequence = release_sequence(version)
    if metadata.get("releaseSequence") != expected_sequence:
        fail("Release sequence does not match the monotonic semantic-version mapping.")
    if metadata.get("packageFileName") != header["originalFileName"]:
        fail("Release metadata package filename does not match the encrypted package header.")
    package_hash = hashlib.sha256(package).hexdigest()
    if metadata.get("packageSize") != len(package) or metadata.get("packageSha256") != package_hash:
        fail("Release metadata package identity does not match the decrypted bytes.")
    if metadata.get("sourceSha") is None or not SOURCE_SHA_RE.fullmatch(str(metadata["sourceSha"])):
        fail("Release metadata source SHA is invalid.")
    if not isinstance(metadata.get("builderRunId"), int) or metadata["builderRunId"] <= 0:
        fail("Release metadata builder run ID is invalid.")
    title = metadata.get("title")
    changes = metadata.get("changes")
    release_date = metadata.get("date")
    if not isinstance(title, str) or not 1 <= len(title.strip()) <= 120:
        fail("Release title is invalid.")
    if not isinstance(changes, list) or not 1 <= len(changes) <= 20:
        fail("Release notes must contain 1 to 20 entries.")
    if any(not isinstance(c, str) or not c.strip() or len(c) > 500 for c in changes):
        fail("A release-note entry is invalid.")
    try:
        date.fromisoformat(release_date)
    except (TypeError, ValueError):
        fail("Release date is invalid.")
    minimum_updater = metadata.get("minimumUpdaterVersion")
    if minimum_updater != "0.1.9":
        fail("Minimum updater version is not the configured stable baseline.")
    return {
        "schemaVersion": 1,
        "productId": "xbox-hub-for-pc",
        "channel": "stable",
        "version": version,
        "releaseSequence": expected_sequence,
        "platform": "windows",
        "architecture": "x64",
        "packageUrl": f"https://{PACKAGE_HOST}/stable/{header['originalFileName']}",
        "packageFormat": "zip",
        "packageSize": len(package),
        "packageSha256": package_hash,
        "minimumUpdaterVersion": minimum_updater,
        "title": title.strip(),
        "date": release_date,
        "changes": [c.strip() for c in changes],
    }


def load_trusted_public_key():
    der = base64.b64decode(RELEASE_PUBLIC_KEY_SPKI_B64, validate=True)
    public_key = serialization.load_der_public_key(der)
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072:
        fail("Embedded release verification key is not RSA-3072 or stronger.")
    key_id = "xboxhub-rsa3072-" + hashlib.sha256(der).hexdigest()[:16]
    if key_id != RELEASE_KEY_ID:
        fail("Release verification public key fingerprint does not match the app key ID.")
    return public_key


def make_signed_envelope(payload: dict[str, Any], sign_fn) -> bytes:
    payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload_bytes) > 4096:
        fail("Release manifest payload exceeds the Vault signing operation limit.")
    signature = sign_fn(payload_bytes)
    public_key = load_trusted_public_key()
    try:
        public_key.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise RuntimeError("OCI Vault signature does not verify against the app's embedded public key.") from exc
    envelope = {
        "keyId": RELEASE_KEY_ID,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return (json.dumps(envelope, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def verify_existing_manifest(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    envelope = json_loads_strict(path.read_bytes())
    if not isinstance(envelope, dict) or envelope.get("keyId") != RELEASE_KEY_ID:
        fail("Existing stable manifest has an unknown signing key ID.")
    payload_bytes = base64.b64decode(envelope.get("payload", ""), validate=True)
    signature = base64.b64decode(envelope.get("signature", ""), validate=True)
    load_trusted_public_key().verify(payload_bytes, signature, padding.PKCS1v15(), hashes.SHA256())
    payload = json_loads_strict(payload_bytes)
    if not isinstance(payload, dict) or payload.get("channel") != "stable":
        fail("Existing stable manifest payload is invalid.")
    return payload


def atomic_write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".xboxhub-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, mode)
        try:
            os.link(temp_name, path)
        except FileExistsError:
            fail("Refusing to overwrite immutable release package: " + path.name)
        os.unlink(temp_name)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def http_verify_published(stable_dir: Path, package_name: str, package: bytes, envelope: bytes) -> None:
    manifest_url = f"https://{PACKAGE_HOST}/stable/manifest.json"
    package_url = f"https://{PACKAGE_HOST}/stable/{package_name}"
    for url, expected in ((manifest_url, envelope), (package_url, package)):
        request = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "XboxHub-OCI-Release-Agent/1.0"})
        with urllib.request.urlopen(request, timeout=40) as response:
            if response.status != 200 or response.geturl() != url:
                fail("Published update URL did not return HTTP 200 without a redirect.")
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
        if size != len(expected) or digest.digest() != hashlib.sha256(expected).digest():
            fail("Public HTTPS response does not match the exact published release bytes.")


def publish_candidate(config: Config, metadata: dict[str, Any], header: dict[str, Any], package: bytes, envelope: bytes) -> str:
    config.stable_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = config.stable_dir / "manifest.json"
    current = verify_existing_manifest(manifest_path)
    payload = json_loads_strict(base64.b64decode(json_loads_strict(envelope).get("payload", ""), validate=True))
    if current is not None:
        current_seq = current.get("releaseSequence", 0)
        new_seq = payload.get("releaseSequence", 0)
        if type(current_seq) is not int or type(new_seq) is not int:
            fail("Existing or candidate release sequence is malformed.")
        if new_seq < current_seq:
            return "older-candidate-skipped"
        if new_seq == current_seq:
            if current.get("version") != payload.get("version") or current.get("packageSha256") != payload.get("packageSha256"):
                fail("A release sequence is already occupied by different package bytes.")
            http_verify_published(config.stable_dir, header["originalFileName"], package, manifest_path.read_bytes())
            return "already-published"
    package_path = config.stable_dir / header["originalFileName"]
    if package_path.exists():
        existing_hash = hashlib.sha256(package_path.read_bytes()).hexdigest()
        if existing_hash != payload["packageSha256"]:
            fail("Immutable versioned package path exists with different bytes.")
    else:
        atomic_write_new(package_path, package)
    # Manifest is the commit point: clients do not discover a candidate until it is replaced last.
    fd, temp_name = tempfile.mkstemp(prefix=".xboxhub-manifest-", suffix=".tmp", dir=str(config.stable_dir))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(envelope)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, manifest_path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
    http_verify_published(config.stable_dir, header["originalFileName"], package, envelope)
    config.state_file.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "version": payload["version"],
        "releaseSequence": payload["releaseSequence"],
        "packageSha256": payload["packageSha256"],
        "sourceSha": metadata["sourceSha"],
        "builderRunId": metadata["builderRunId"],
    }
    fd, state_tmp = tempfile.mkstemp(prefix=".xboxhub-state-", dir=str(config.state_file.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(state_tmp, 0o600)
        os.replace(state_tmp, config.state_file)
    finally:
        try:
            os.unlink(state_tmp)
        except FileNotFoundError:
            pass
    return "published"


def run_once(config: Config, vault: OciVaultCrypto | None = None) -> str:
    if not config.auto_publish_enabled:
        return "publishing-disabled"
    candidate = latest_candidate_artifact()
    if candidate is None:
        return "no-candidate-available"
    run, metadata, package_artifact = candidate
    validate_candidate_metadata(metadata)
    candidate_version = metadata["version"]
    candidate_sequence = metadata["releaseSequence"]
    manifest_path = config.stable_dir / "manifest.json"
    current = verify_existing_manifest(manifest_path)
    if current is not None:
        current_sequence = current.get("releaseSequence", 0)
        if type(current_sequence) is not int:
            fail("Existing stable manifest release sequence is malformed.")
        if candidate_sequence < current_sequence:
            return "older-candidate-skipped"
        if candidate_sequence == current_sequence:
            if current.get("version") != candidate_version or current.get("packageSha256") != metadata.get("packageSha256"):
                fail("Release sequence is already occupied by a different candidate identity.")
            return "already-current"
    if vault is None:
        fail("OCI Vault client is required for a new stable release.")
    encrypted = download_encrypted_package(package_artifact, metadata)
    header, package = decrypt_container(encrypted, vault.unwrap_aes_key)
    payload = validate_metadata(metadata, header, package)
    envelope = make_signed_envelope(payload, vault.sign)
    return publish_candidate(config, metadata, header, package, envelope)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true", help="Verify OCI instance-principal access to both exact Xbox Hub Vault keys without publishing.")
    args = parser.parse_args()
    try:
        config = Config.from_env()
        if not args.check_only and not config.auto_publish_enabled:
            print("Xbox Hub release-agent result: publishing-disabled")
            return 0
        vault = OciVaultCrypto(config)
        if args.check_only:
            vault.self_test()
            print("Xbox Hub OCI Vault self-test completed. No release was downloaded or published.")
            return 0
        result = run_once(config, vault)
        print("Xbox Hub release-agent result: " + result)
        return 0
    except urllib.error.HTTPError as exc:
        print("ERROR: GitHub or update-host HTTP request failed with status " + str(exc.code), file=sys.stderr)
        return 1
    except Exception as exc:
        print("ERROR: Xbox Hub release agent stopped safely: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
