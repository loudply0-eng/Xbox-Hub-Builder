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
import prepare_oci_rsa_import as oci_import


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
    def test_embedded_package_recipient_key_fingerprint_matches_key_id(self):
        public_der = base64.b64decode(agent.PACKAGE_PUBLIC_KEY_SPKI_B64, validate=True)
        public_key = serialization.load_der_public_key(public_der)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)
        self.assertEqual(public_key.key_size, 3072)
        fingerprint = hashlib.sha256(public_der).hexdigest()[:16]
        self.assertEqual("xboxhub-package-rsa3072-" + fingerprint, agent.PACKAGE_KEY_ID)


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


    def test_offline_oci_import_wrapper_round_trips_pkcs8_key_material(self):
        app_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        vault_wrapping_private = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        public_der = app_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = "xboxhub-rsa3072-" + hashlib.sha256(public_der).hexdigest()[:16]
        private_pem = app_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"test-passphrase"),
        )
        wrapping_pem = vault_wrapping_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        wrapped, returned_id = oci_import.wrap_private_key_material(
            private_pem,
            b"test-passphrase",
            wrapping_pem,
            key_id,
        )
        self.assertEqual(returned_id, key_id)
        wrapped_aes_key = wrapped[:512]
        wrapped_pkcs8 = wrapped[512:]
        aes_key = vault_wrapping_private.decrypt(
            wrapped_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding
        # RFC 5649 AES-KW-PAD uses its standard default IV in cryptography,
        # which is the OCI RSA_OAEP_AES_SHA256 import-envelope IV.
        unwrapped_pkcs8 = aes_key_unwrap_with_padding(
            aes_key,
            wrapped_pkcs8,
        )
        restored_private = serialization.load_der_private_key(unwrapped_pkcs8, password=None)
        restored_public_der = restored_private.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(restored_public_der, public_der)

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
        package = b"verified-current-package-bytes"
        package_digest = hashlib.sha256(package).hexdigest()
        payload = {
            "schemaVersion": 1,
            "productId": "xbox-hub-for-pc",
            "channel": "stable",
            "version": "0.1.11",
            "releaseSequence": 1_000_011,
            "packageSha256": package_digest,
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
            manifest_bytes = json.dumps(envelope).encode("utf-8")
            manifest_path.write_bytes(manifest_bytes)
            (Path(directory) / "XboxHub-0.1.11-win-x64.zip").write_bytes(package)
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
                "schemaVersion": 1,
                "productId": "xbox-hub-for-pc",
                "channel": "stable",
                "version": "0.1.11",
                "releaseSequence": 1_000_011,
                "platform": "windows",
                "architecture": "x64",
                "packageFileName": "XboxHub-0.1.11-win-x64.zip",
                "packageSize": len(package),
                "packageSha256": package_digest,
                "minimumUpdaterVersion": "0.1.9",
                "title": "Automatic startup updates",
                "date": "2026-11-25",
                "changes": ["Installs verified updates at startup."],
                "sourceSha": "a" * 40,
                "builderRunId": 123,
                "builderRunAttempt": 1,
            }
            with patch.object(agent, "latest_candidate_artifact", return_value=({}, metadata, {"url": "https://github.com/package-artifact", "digest": "sha256:" + ("b" * 64), "size": 1000})):
                with patch.object(agent, "verify_existing_manifest", return_value=payload):
                    with patch.object(agent, "download_encrypted_package", side_effect=AssertionError("large artifact must not be downloaded")):
                        with patch.object(agent, "http_verify_published") as public_verify:
                            self.assertEqual(agent.run_once(config, None), "already-current")
            public_verify.assert_called_once_with(
                Path(directory), "XboxHub-0.1.11-win-x64.zip", package, manifest_bytes
            )

    def test_publish_restores_previous_manifest_when_public_verification_fails(self):
        package = make_plain_package()
        package_name = "XboxHub-0.1.12-win-x64.zip"
        package_digest = hashlib.sha256(package).hexdigest()
        payload = {
            "schemaVersion": 1,
            "productId": "xbox-hub-for-pc",
            "channel": "stable",
            "version": "0.1.12",
            "releaseSequence": agent.release_sequence("0.1.12"),
            "platform": "windows",
            "architecture": "x64",
            "packageUrl": "https://updates.mahmoudaljuorany.store/stable/" + package_name,
            "packageFormat": "zip",
            "packageSize": len(package),
            "packageSha256": package_digest,
            "minimumUpdaterVersion": "0.1.9",
            "title": "Test release",
            "date": "2026-11-25",
            "changes": ["Test rollback on failed endpoint verification."],
        }
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        envelope = json.dumps({
            "keyId": agent.RELEASE_KEY_ID,
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "signature": base64.b64encode(b"test-signature").decode("ascii"),
        }, separators=(",", ":")).encode("utf-8")
        previous_manifest = b"previous-stable-manifest-bytes"
        previous_payload = {
            "releaseSequence": agent.release_sequence("0.1.11"),
            "version": "0.1.11",
            "packageSha256": "b" * 64,
        }
        metadata = {"sourceSha": "c" * 40, "builderRunId": 456}
        header = {"originalFileName": package_name}

        with tempfile.TemporaryDirectory() as directory:
            stable_dir = Path(directory) / "stable"
            stable_dir.mkdir()
            manifest_path = stable_dir / "manifest.json"
            manifest_path.write_bytes(previous_manifest)
            config = agent.Config(
                crypto_endpoint="https://kms.example.invalid",
                package_key_ocid="package-key",
                package_key_version_ocid="package-version",
                signing_key_ocid="signing-key",
                signing_key_version_ocid="signing-version",
                stable_dir=stable_dir,
                state_file=Path(directory) / "state" / "state.json",
                auto_publish_enabled=True,
            )
            with patch.object(agent, "verify_existing_manifest", return_value=previous_payload):
                with patch.object(agent, "http_verify_published", side_effect=RuntimeError("public verification failed")):
                    with self.assertRaisesRegex(RuntimeError, "public verification failed"):
                        agent.publish_candidate(config, metadata, header, package, envelope)

            self.assertEqual(manifest_path.read_bytes(), previous_manifest)
            self.assertTrue((stable_dir / package_name).is_file())
            self.assertFalse(config.state_file.exists())

    def test_artifact_extraction_requires_exactly_one_expected_file(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("xboxhub-release-metadata.json", b"{\"channel\":\"stable\"}")
        extracted = agent.extract_one_artifact_file(
            buffer.getvalue(), "xboxhub-release-metadata.json", 64 * 1024
        )
        self.assertEqual(extracted, b"{\"channel\":\"stable\"}")

        bad = io.BytesIO()
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("xboxhub-release-metadata.json", b"{}")
            archive.writestr("unexpected.txt", b"unexpected")
        with self.assertRaisesRegex(RuntimeError, "exactly the expected file"):
            agent.extract_one_artifact_file(
                bad.getvalue(), "xboxhub-release-metadata.json", 64 * 1024
            )

    def test_permanent_candidate_release_is_preferred_and_validated(self):
        source_sha = "c" * 40
        run = {
            "id": 234,
            "run_attempt": 1,
            "head_branch": "main",
            "conclusion": "success",
            "status": "completed",
            "workflow_id": agent.WORKFLOW_ID,
            "path": ".github/workflows/windows-build-check.yml",
            "head_sha": "d" * 40,
        }
        metadata = {
            "schemaVersion": 1,
            "productId": "xbox-hub-for-pc",
            "channel": "stable",
            "version": "0.1.11",
            "releaseSequence": 1_000_011,
            "platform": "windows",
            "architecture": "x64",
            "packageFileName": "XboxHub-0.1.11-win-x64.zip",
            "packageSize": 12345,
            "packageSha256": "a" * 64,
            "minimumUpdaterVersion": "0.1.9",
            "title": "Automatic updates at startup",
            "date": "2026-11-25",
            "changes": ["Installs verified releases at startup."],
            "sourceSha": source_sha,
            "builderRunId": 234,
            "builderRunAttempt": 1,
        }
        metadata_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
        metadata_digest = "sha256:" + hashlib.sha256(metadata_bytes).hexdigest()
        package_bytes = b"authenticated encrypted package bytes"
        package_digest = "sha256:" + hashlib.sha256(package_bytes).hexdigest()
        release = {
            "draft": False,
            "prerelease": True,
            "tag_name": "xboxhub-candidate-" + source_sha,
            "assets": [
                {"name": "xboxhub-release-metadata.json", "size": len(metadata_bytes),
                 "digest": metadata_digest, "browser_download_url": "https://github.com/meta"},
                {"name": "XboxHub-0.1.11-win-x64.xhubenc", "size": len(package_bytes),
                 "digest": package_digest, "browser_download_url": "https://github.com/package"},
            ],
        }
        calls = []

        def fake_json(url):
            if url.endswith("/releases?per_page=50"):
                return [release]
            if url.endswith("/actions/runs/234"):
                return run
            if "/git/ref/tags/xboxhub-source-" in url:
                return {"ref": f"refs/tags/xboxhub-source-{source_sha}", "object": {"sha": "f" * 40, "type": "commit"}}
            raise AssertionError("Unexpected GitHub API URL: " + url)

        def fake_download(url, max_bytes):
            calls.append(url)
            if url == "https://github.com/meta":
                return metadata_bytes
            raise AssertionError("The encrypted release asset must not be downloaded during discovery.")

        with patch.object(agent, "http_json", side_effect=fake_json):
            with patch.object(agent, "http_download", side_effect=fake_download):
                found = agent.latest_candidate_artifact()

        self.assertIsNotNone(found)
        self.assertEqual(found[0], run)
        self.assertEqual(found[1], metadata)
        self.assertEqual(found[2]["kind"], "release-asset")
        self.assertEqual(found[2]["url"], "https://github.com/package")
        self.assertEqual(found[2]["digest"], package_digest)
        self.assertEqual(calls, ["https://github.com/meta"])

    def test_permanent_release_asset_download_returns_raw_encrypted_bytes(self):
        data = b"encrypted-xhub-container-test"
        artifact = {
            "kind": "release-asset",
            "url": "https://github.com/package",
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
        metadata = {"packageFileName": "XboxHub-0.1.11-win-x64.zip"}
        with patch.object(agent, "http_download", return_value=data):
            result = agent.download_encrypted_package(artifact, metadata)
        self.assertEqual(result, data)

    def test_candidate_poll_reads_metadata_sidecar_without_downloading_package(self):
        source_sha = "a" * 40
        run = {
            "id": 123,
            "run_attempt": 1,
            "head_branch": "main",
            "conclusion": "success",
            "status": "completed",
            "workflow_id": agent.WORKFLOW_ID,
            "path": ".github/workflows/windows-build-check.yml",
            "head_sha": "e" * 40,
        }
        metadata = {
            "channel": "stable",
            "version": "0.1.11",
            "releaseSequence": 1_000_011,
            "builderRunId": 123,
            "builderRunAttempt": 1,
            "sourceSha": source_sha,
        }
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("xboxhub-release-metadata.json", json.dumps(metadata))
        metadata_archive = archive_buffer.getvalue()
        package_url = "https://github.com/package-artifact"
        calls = []

        def fake_json(url):
            if url.endswith("/releases?per_page=50"):
                return []
            if "/actions/workflows/" in url:
                return {"workflow_runs": [run]}
            if "/actions/runs/123/artifacts" in url:
                return {"artifacts": [
                    {"name": "xboxhub-release-metadata", "expired": False, "archive_download_url": "https://github.com/meta-artifact", "size_in_bytes": 1024, "digest": "sha256:" + hashlib.sha256(metadata_archive).hexdigest()},
                    {"name": "xboxhub-encrypted-offline-package", "expired": False, "archive_download_url": package_url, "size_in_bytes": 1000, "digest": "sha256:" + ("b" * 64)},
                ]}
            if "/git/ref/tags/xboxhub-source-" in url:
                return {"ref": f"refs/tags/xboxhub-source-{source_sha}", "object": {"sha": run["head_sha"], "type": "commit"}}
            raise AssertionError("Unexpected GitHub API URL: " + url)

        def fake_download(url, max_bytes):
            calls.append(url)
            if url == "https://github.com/meta-artifact":
                return metadata_archive
            raise AssertionError("Encrypted package must not be downloaded during discovery.")

        with patch.object(agent, "http_json", side_effect=fake_json):
            with patch.object(agent, "http_download", side_effect=fake_download):
                found = agent.latest_candidate_artifact()

        self.assertIsNotNone(found)
        self.assertEqual(found[0], run)
        self.assertEqual(found[1], metadata)
        self.assertEqual(found[2]["url"], package_url)
        self.assertEqual(found[2]["digest"], "sha256:" + ("b" * 64))
        self.assertEqual(calls, ["https://github.com/meta-artifact"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
