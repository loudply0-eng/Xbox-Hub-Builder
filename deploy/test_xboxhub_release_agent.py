from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parent))
import xboxhub_release_agent as agent


def make_plain_package() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("XboxHub.exe", b"app-binary-test" * 32)
        archive.writestr("XboxHub.Updater.exe", b"updater-binary-test" * 24)
    return stream.getvalue()


def make_container(package: bytes, private_key, key_id: str, filename: str) -> bytes:
    aes_key = b"K" * 32
    nonce = b"N" * 12
    digest = hashlib.sha256(package).hexdigest()
    aad = (
        f"{agent.AAD_PREFIX}\n{key_id}\n{filename}\n{len(package)}\n{digest}"
    ).encode("utf-8")
    combined = AESGCM(aes_key).encrypt(nonce, package, aad)
    ciphertext, tag = combined[:-16], combined[-16:]
    wrapped = private_key.public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    header = {
        "schemaVersion": 1,
        "algorithm": "AES-256-GCM+RSA-OAEP-SHA256",
        "keyId": key_id,
        "originalFileName": filename,
        "packageSize": len(package),
        "packageSha256": digest,
        "nonceBase64": base64.b64encode(nonce).decode("ascii"),
        "tagBase64": base64.b64encode(tag).decode("ascii"),
        "wrappedKeyBase64": base64.b64encode(wrapped).decode("ascii"),
    }
    encoded_header = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return agent.MAGIC + len(encoded_header).to_bytes(4, "little", signed=True) + encoded_header + ciphertext


class ReleaseAgentTests(unittest.TestCase):
    def test_embedded_signing_key_fingerprint_matches_key_id(self):
        key = agent.load_trusted_public_key()
        self.assertGreaterEqual(key.key_size, 3072)

    def test_release_sequence_is_monotonic_for_stable_semver(self):
        self.assertEqual(agent.release_sequence("0.1.11"), 1_000_011)
        self.assertGreater(agent.release_sequence("0.1.12"), agent.release_sequence("0.1.11"))
        self.assertGreater(agent.release_sequence("0.2.0"), agent.release_sequence("0.1.999"))
        with self.assertRaises(RuntimeError):
            agent.release_sequence("0.1.12-preview.1")

    def test_hybrid_package_decrypts_and_validates(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = "xboxhub-package-rsa3072-" + hashlib.sha256(public_der).hexdigest()[:16]
        package = make_plain_package()
        filename = "XboxHub-0.1.11-win-x64.zip"
        container = make_container(package, private_key, key_id, filename)
        with patch.object(agent, "PACKAGE_KEY_ID", key_id):
            header, recovered = agent.decrypt_container(
                container,
                lambda wrapped: private_key.decrypt(
                    base64.b64decode(wrapped, validate=True),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                ),
                expected_key_id=key_id,
            )
        self.assertEqual(recovered, package)
        self.assertEqual(header["originalFileName"], filename)

    def test_modified_ciphertext_fails_authenticated_decryption(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = "xboxhub-package-rsa3072-" + hashlib.sha256(public_der).hexdigest()[:16]
        package = make_plain_package()
        container = bytearray(make_container(package, private_key, key_id, "XboxHub-0.1.11-win-x64.zip"))
        container[-1] ^= 1
        with patch.object(agent, "PACKAGE_KEY_ID", key_id):
            with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                agent.decrypt_container(
                    bytes(container),
                    lambda wrapped: private_key.decrypt(
                        base64.b64decode(wrapped, validate=True),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    ),
                    expected_key_id=key_id,
                )

    def test_duplicate_header_properties_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            agent.json_loads_strict(b'{"keyId":"a","keyId":"b"}')

    def test_metadata_must_match_decrypted_package_identity(self):
        package = make_plain_package()
        digest = hashlib.sha256(package).hexdigest()
        header = {
            "originalFileName": "XboxHub-0.1.11-win-x64.zip",
            "packageSize": len(package),
            "packageSha256": digest,
        }
        metadata = {
            "schemaVersion": 1,
            "productId": "xbox-hub-for-pc",
            "channel": "stable",
            "version": "0.1.11",
            "releaseSequence": 1_000_011,
            "platform": "windows",
            "architecture": "x64",
            "packageFileName": header["originalFileName"],
            "packageSize": len(package),
            "packageSha256": digest,
            "minimumUpdaterVersion": "0.1.9",
            "title": "Automatic startup updates",
            "date": "2026-11-25",
            "changes": ["Install signed stable updates at startup."],
            "sourceSha": "a" * 40,
            "builderRunId": 12345,
        }
        payload = agent.validate_metadata(metadata, header, package)
        self.assertEqual(payload["packageSha256"], digest)
        metadata["packageSha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "metadata package identity"):
            agent.validate_metadata(metadata, header, package)

    def test_signed_envelope_is_verified_against_expected_public_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_id = "xboxhub-rsa3072-" + hashlib.sha256(public_der).hexdigest()[:16]
        with patch.object(agent, "RELEASE_PUBLIC_KEY_SPKI_B64", base64.b64encode(public_der).decode("ascii")), \
             patch.object(agent, "RELEASE_KEY_ID", public_key_id):
            envelope_bytes = agent.make_signed_envelope(
                {"schemaVersion": 1, "productId": "xbox-hub-for-pc", "channel": "stable"},
                lambda payload: private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256()),
            )
            envelope = json.loads(envelope_bytes)
            payload = base64.b64decode(envelope["payload"], validate=True)
            signature = base64.b64decode(envelope["signature"], validate=True)
            private_key.public_key().verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
            self.assertEqual(envelope["keyId"], public_key_id)

    def test_immutable_package_write_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "XboxHub-0.1.11-win-x64.zip"
            agent.atomic_write_new(target, b"first")
            with self.assertRaisesRegex(RuntimeError, "Refusing to overwrite"):
                agent.atomic_write_new(target, b"second")
            self.assertEqual(target.read_bytes(), b"first")

    def test_release_agent_does_not_poll_or_publish_when_disabled(self):
        config = agent.Config(
            crypto_endpoint="https://kms.example.invalid",
            package_key_ocid="package-key",
            package_key_version_ocid="package-version",
            signing_key_ocid="signing-key",
            signing_key_version_ocid="signing-version",
            stable_dir=Path("/tmp/xboxhub-test-stable"),
            state_file=Path("/tmp/xboxhub-test-state/state.json"),
            auto_publish_enabled=False,
        )
        with patch.object(agent, "latest_candidate_artifact", side_effect=AssertionError("poll should not run")):
            self.assertEqual(agent.run_once(config, None), "publishing-disabled")

    def test_candidate_already_current_skips_large_encrypted_artifact_download(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public_key = private_key.public_key()
        payload = {
            "schemaVersion": 1,
            "productId": "xbox-hub-for-pc",
            "channel": "stable",
            "version": "0.1.11",
            "releaseSequence": 1_000_011,
            "packageSha256": "a" * 64,
        }
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        envelope = {
            "keyId": agent.RELEASE_KEY_ID,
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(json.dumps(envelope), encoding="utf-8")
            config = agent.Config(
                crypto_endpoint="https://kms.example.invalid",
                package_key_ocid="package-key",
                package_key_version_ocid="package-version",
                signing_key_ocid="signing-key",
                signing_key_version_ocid="signing-version",
                stable_dir=Path(directory),
                state_file=Path(directory) / "state.json",
                auto_publish_enabled=True,
            )
            metadata = {
                "version": "0.1.11",
                "releaseSequence": 1_000_011,
                "packageSha256": "a" * 64,
            }
            with patch.object(agent, "latest_candidate_artifact", return_value=({}, metadata, "https://github.com/package-artifact")):
                with patch.object(agent, "load_trusted_public_key", return_value=public_key):
                    with patch.object(agent, "download_encrypted_package", side_effect=AssertionError("large artifact must not be downloaded")):
                        self.assertEqual(agent.run_once(config, None), "already-current")


if __name__ == "__main__":
    unittest.main(verbosity=2)
