#!/usr/bin/env python3
"""Pull, authenticate, sign, and publish Xbox Hub stable candidates on an OCI VM.

Authentication to OCI uses the VM's Instance Principal. Production RSA private
keys remain inside OCI Vault; this process receives only wrapped AES key material
and the resulting signature. The GitHub repository is public and read-only.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
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
PACKAGE_KEY_ID = "xboxhub-package-rsa3072-b845262d34ea685b"
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
    request = urllib.request.Request(url, headers={"User-Agent": "XboxHub-OCI-Release-Agent/1.0"})
    chunks = bytearray()
    with urllib.request.urlopen(request, timeout=120) as response:
        if response.status != 200:
            fail("GitHub artifact download did not return HTTP 200.")
        final_url = urllib.parse.urlsplit(response.geturl())
        if final_url.scheme != "https" or not (final_url.hostname in ("github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com") or final_url.hostname.endswith(".blob.core.windows.net")):
            fail("Artifact download redirected to an unexpected host.")
        while True:
            part = response.read(1024 * 1024)
            if not part:
                break
            chunks.extend(part)
            if len(chunks) > max_bytes:
                fail("GitHub artifact exceeded the configured download limit.")
    return bytes(chunks)


def latest_candidate_artifact() -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    runs_url = (
        f"https://api.github.com/repos/{GITHUB_REPO}/actions/workflows/{WORKFLOW_ID}/runs"
        "?branch=main&status=success&per_page=20"
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
        artifact = next(
            (a for a in artifacts if a.get("name") == ARTIFACT_NAME and not a.get("expired")),
            None,
        )
        if not artifact or not artifact.get("archive_download_url"):
            continue
        try:
            archive = http_download(artifact["archive_download_url"], MAX_ARTIFACT_BYTES)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            raise
        with zipfile.ZipFile(io.BytesIO(archive), "r") as zf:
            infos = zf.infolist()
            if len(infos) != 2:
                continue
            metadata_info = next((i for i in infos if Path(i.filename).name == "xboxhub-release-metadata.json"), None)
            encrypted_info = next((i for i in infos if i.filename.endswith(".xhubenc")), None)
            if not metadata_info or not encrypted_info:
                continue
            if metadata_info.file_size > 64 * 1024 or encrypted_info.file_size > MAX_CONTAINER_BYTES:
                fail("Release artifact file size is outside the configured limit.")
            metadata = json_loads_strict(zf.read(metadata_info))
            encrypted = zf.read(encrypted_info)
        if metadata.get("builderRunId") != run_id:
            fail("Release metadata run ID does not match its GitHub Actions run.")
        source_sha = metadata.get("sourceSha", "")
        if not isinstance(source_sha, str) or not SOURCE_SHA_RE.fullmatch(source_sha):
            fail("Release metadata contains an invalid source revision.")
        tag_url = f"https://api.github.com/repos/{GITHUB_REPO}/git/ref/tags/xboxhub-source-{source_sha}"
        try:
            marker = http_json(tag_url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            raise
        if marker.get("ref") != f"refs/tags/xboxhub-source-{source_sha}":
            fail("Successful source-build marker does not match release metadata.")
        return run, encrypted, metadata
    return None


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


def run_once(config: Config, vault: OciVaultCrypto) -> str:
    candidate = latest_candidate_artifact()
    if candidate is None:
        return "no-candidate-available"
    run, encrypted, metadata = candidate
    header, package = decrypt_container(encrypted, vault.unwrap_aes_key)
    payload = validate_metadata(metadata, header, package)
    current = verify_existing_manifest(config.stable_dir / "manifest.json")
    if current is not None:
        old_seq = current.get("releaseSequence", 0)
        if type(old_seq) is int and payload["releaseSequence"] <= old_seq:
            if payload["releaseSequence"] == old_seq and current.get("packageSha256") == payload["packageSha256"]:
                return "already-current"
            return "older-candidate-skipped"
    envelope = make_signed_envelope(payload, vault.sign)
    return publish_candidate(config, metadata, header, package, envelope)


def main() -> int:
    try:
        config = Config.from_env()
        vault = OciVaultCrypto(config)
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
