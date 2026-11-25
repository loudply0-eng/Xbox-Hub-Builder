import base64, hashlib, io, json, struct, tempfile, unittest, zipfile
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import xboxhub_release_worker as w

class FakeVault:
    def __init__(self, private, key): self.private, self.key = private, key
    def unwrap(self, wrapped):
        result = self.private.decrypt(base64.b64decode(wrapped), padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        assert result == self.key
        return result

def sample_zip(extra=False):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("XboxHub.exe", b"app executable")
        z.writestr("XboxHub.Updater.exe", b"updater executable")
        if extra: z.writestr("extra.txt", b"no")
    return out.getvalue()

def container(plain, private):
    key, nonce = AESGCM.generate_key(bit_length=256), b"0123456789ab"
    name, digest = "XboxHub-0.1.11-win-x64.zip", hashlib.sha256(plain).hexdigest()
    wrapped = private.public_key().encrypt(key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    aad = (f"XboxHub-Package-Envelope-v1\n{w.PACKAGE_KEY_ID}\n{name}\n{len(plain)}\n{digest}").encode()
    encrypted = AESGCM(key).encrypt(nonce, plain, aad)
    header = {"schemaVersion":1,"algorithm":"AES-256-GCM+RSA-OAEP-SHA256","keyId":w.PACKAGE_KEY_ID,
              "originalFileName":name,"packageSize":len(plain),"packageSha256":digest,
              "nonceBase64":base64.b64encode(nonce).decode(),"tagBase64":base64.b64encode(encrypted[-16:]).decode(),
              "wrappedKeyBase64":base64.b64encode(wrapped).decode()}
    raw = json.dumps(header,separators=(",",":")).encode()
    return b"XHUBENC1"+struct.pack("<i",len(raw))+raw+encrypted[:-16], key

class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.private = rsa.generate_private_key(public_exponent=65537,key_size=3072)
        self.plain = sample_zip()
        self.data, self.key = container(self.plain,self.private)
        self.metadata = {"packageFileName":"XboxHub-0.1.11-win-x64.zip","packageSize":len(self.plain),
                         "packageSha256":hashlib.sha256(self.plain).hexdigest()}
    def test_encrypted_container_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"candidate.xhubenc"; path.write_bytes(self.data)
            self.assertEqual(w.decrypt_package(path,self.metadata,FakeVault(self.private,self.key)),self.plain)
    def test_tampered_ciphertext_is_rejected(self):
        damaged=bytearray(self.data); damaged[-1]^=1
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"bad.xhubenc"; path.write_bytes(damaged)
            with self.assertRaisesRegex(RuntimeError,"authentication failed"):
                w.decrypt_package(path,self.metadata,FakeVault(self.private,self.key))
    def test_wrong_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"candidate.xhubenc"; path.write_bytes(self.data)
            wrong=dict(self.metadata,packageFileName="XboxHub-9.9.9-win-x64.zip")
            with self.assertRaisesRegex(RuntimeError,"key ID or filename"):
                w.decrypt_package(path,wrong,FakeVault(self.private,self.key))
    def test_extra_zip_entry_is_rejected(self):
        plain=sample_zip(extra=True)
        data,key=container(plain,self.private)
        meta={"packageFileName":"XboxHub-0.1.11-win-x64.zip","packageSize":len(plain),
              "packageSha256":hashlib.sha256(plain).hexdigest()}
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"candidate.xhubenc"; path.write_bytes(data)
            with self.assertRaisesRegex(RuntimeError,"exactly the two Xbox Hub"):
                w.decrypt_package(path,meta,FakeVault(self.private,key))
    def test_legacy_stable_manifest_sequence_remains_readable(self):
        legacy = {
            "schemaVersion":1,"productId":w.PRODUCT,"channel":"stable","version":"0.1.10",
            "releaseSequence":2,"platform":"windows","architecture":"x64","packageFormat":"zip",
            "packageUrl":w.PACKAGE_BASE+"XboxHub-0.1.10-win-x64.zip","packageSize":1024,
            "packageSha256":"b"*64,"minimumUpdaterVersion":"0.1.9"
        }
        w.validate_manifest(legacy, legacy_compatible=True)
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            w.validate_manifest(legacy)

    def test_release_sequence_is_bound_to_semver(self):
        self.assertEqual(w.release_sequence_for_version("0.1.11"), 1000011)
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            w.validate_manifest({
                "schemaVersion":1,"productId":w.PRODUCT,"channel":"stable","version":"0.1.11",
                "releaseSequence":999999,"platform":"windows","architecture":"x64","packageFormat":"zip",
                "packageUrl":w.PACKAGE_BASE+"XboxHub-0.1.11-win-x64.zip","packageSize":1024,
                "packageSha256":"a"*64,"minimumUpdaterVersion":"0.1.9",
                "title":"Automatic updates at startup","date":"2026-11-25","changes":["Automatic signed updates"]
            })

    def test_manifest_rejects_non_iso_date_and_bad_changelog(self):
        manifest={"schemaVersion":1,"productId":w.PRODUCT,"channel":"stable","version":"0.1.11",
                  "releaseSequence":1000011,"platform":"windows","architecture":"x64","packageFormat":"zip",
                  "packageUrl":w.PACKAGE_BASE+"XboxHub-0.1.11-win-x64.zip","packageSize":1024,
                  "packageSha256":"a"*64,"minimumUpdaterVersion":"0.1.9",
                  "title":"Automatic updates at startup","date":"tomorrow","changes":["Automatic signed updates"]}
        with self.assertRaisesRegex(RuntimeError, "date is invalid"):
            w.validate_manifest(manifest)
        manifest["date"]="2026-11-25"
        manifest["changes"]=[{"unexpected":"object"}]
        with self.assertRaisesRegex(RuntimeError, "changelog is invalid"):
            w.validate_manifest(manifest)

    def test_manifest_url_is_pinned_to_stable_feed(self):
        manifest={"schemaVersion":1,"productId":w.PRODUCT,"channel":"stable","version":"0.1.11",
                  "releaseSequence":1000011,"platform":"windows","architecture":"x64","packageFormat":"zip",
                  "packageUrl":w.PACKAGE_BASE+"XboxHub-0.1.11-win-x64.zip","packageSize":1024,
                  "packageSha256":"a"*64,"minimumUpdaterVersion":"0.1.9",
                  "title":"Automatic updates at startup","date":"2026-11-25","changes":["Automatic signed updates"]}
        w.validate_manifest(manifest)
        manifest["packageUrl"]="https://attacker.example/package.zip"
        with self.assertRaisesRegex(RuntimeError,"outside the configured"):
            w.validate_manifest(manifest)

if __name__ == "__main__": unittest.main()
