#!/usr/bin/env python3
"""Xbox Hub stable publisher: GitHub encrypted handoff -> OCI Vault HSM -> HTTPS feed."""
from __future__ import annotations
import base64, hashlib, json, logging, os, re, struct, tempfile, urllib.parse, zipfile
from pathlib import Path
import requests
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG = logging.getLogger("xboxhub-release-worker")
REPO = "loudply0-eng/Xbox-Hub-Builder"
WORKFLOW_ID = 428075352
WORKFLOW_PATH = ".github/workflows/windows-build-check.yml"
TAG_PREFIX = "xboxhub-candidate-"
PRODUCT = "xbox-hub-for-pc"
PACKAGE_KEY_ID = "xboxhub-package-rsa3072-b845262d34ea685b"
SIGN_KEY_ID = "xboxhub-rsa3072-9986345089cc1513"
PACKAGE_BASE = "https://updates.mahmoudaljuorany.store/stable/"
MAX_PACKAGE = 734003200
MAX_ENCRYPTED = 734200000
MAX_JSON = 262144
ZIP_FILES = {"XboxHub.exe", "XboxHub.Updater.exe"}
PUBLIC_KEY_B64 = (
    "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAjdjBmNbij7n3n/lHFpe5t6kGOsMNFMZgPvWt6NDpvMwHlswExi0/c4x+BjOQsYephTSjTyrF3yj7aLLE0OhXTtOEu1OU7aTApK8dPaLdEAWokVwCy1sVspAclOw9gqBaDuPXp5/8DdzsO5IWTm5xvZF7eJfH7Sjn0ET7b5yvS7jtVuJNhK4ujUmB/m7AAftBbh2Gur6MonFDj1gQlRauCzp5A/mozegZwnhLtkB+YkOBq1ey16SwFaVgilL5QjqGW+R3ODQ2muhfha7L2ZUI/lNdSwpVsS0n6OXJQEMyyQlGnZ8CcTX+9yo2YXgwaFiBLBJaFceQxYA4K7+f9JJHLFZxX3ig+YeywL1EJYE5lTiqHg/VoFi5zzsjtgQhbGmZ3myhzcQOsHi2OFSOYJhhPtyhULVyiIXYYEP07svlDOOEwA0wSLLoTw1cAXMWa0R6Cv/pD39FUnORgOgl4iijQry7NeHfQYeoL5sUQAk9mzq6BdvF0eiGmjTOAmlEszTRAgMBAAE="
)

def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError("Missing required environment setting: " + name)
    return value

def trusted_public_key():
    key = serialization.load_der_public_key(base64.b64decode(PUBLIC_KEY_B64, validate=True))
    if key.key_size != 3072:
        raise RuntimeError("Embedded release key is not RSA-3072.")
    return key

class GitHub:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "XboxHub-OCI-Release-Worker/1.0"
        })
        repo = os.environ.get("XHUB_GITHUB_REPOSITORY", REPO).strip()
        self.base = "https://api.github.com/repos/" + repo

    def json(self, url, limit=8 * 1024 * 1024):
        r = self.session.get(url, timeout=(15, 45), allow_redirects=False)
        if r.status_code != 200 or len(r.content) > limit:
            raise RuntimeError("GitHub API returned an unexpected response.")
        return r.json()

    def releases(self):
        items = self.json(self.base + "/releases?per_page=100")
        return [x for x in items if isinstance(x, dict) and str(x.get("tag_name", "")).startswith(TAG_PREFIX)]

    def build_run(self, run_id):
        return self.json(self.base + "/actions/runs/" + str(run_id), MAX_JSON)

    def download(self, url, path, maximum):
        if not url.startswith("https://") or urllib.parse.urlparse(url).hostname != "github.com":
            raise RuntimeError("Asset URL is not on the expected GitHub HTTPS host.")
        allowed_redirect_hosts = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
        total = 0
        with self.session.get(url, stream=True, timeout=(20, 180), allow_redirects=True) as r:
            if r.status_code != 200 or urllib.parse.urlparse(r.url).hostname not in allowed_redirect_hosts:
                raise RuntimeError("GitHub asset redirect or response is not trusted.")
            with path.open("xb") as out:
                for chunk in r.iter_content(1024 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > maximum:
                        raise RuntimeError("Release asset exceeds the configured size limit.")
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
        if total <= 0:
            raise RuntimeError("Release asset is empty.")

class Vault:
    def __init__(self):
        import oci
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        endpoint = required("XHUB_KMS_CRYPTO_ENDPOINT").rstrip("/")
        parsed = urllib.parse.urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
            raise RuntimeError("OCI Vault crypto endpoint must be a bare HTTPS endpoint.")
        self.oci = oci
        self.client = oci.key_management.KmsCryptoClient({}, service_endpoint=endpoint, signer=signer)

    def unwrap(self, wrapped):
        model = self.oci.key_management.models.DecryptDataDetails
        result = self.client.decrypt(decrypt_data_details=model(
            ciphertext=wrapped,
            key_id=required("XHUB_PACKAGE_KEY_OCID"),
            key_version_id=required("XHUB_PACKAGE_KEY_VERSION_OCID"),
            encryption_algorithm="RSA_OAEP_SHA_256"
        )).data
        key = base64.b64decode(result.plaintext, validate=True)
        if len(key) != 32:
            raise RuntimeError("OCI Vault returned an invalid AES-256 key.")
        return key

    def sign(self, payload):
        model = self.oci.key_management.models.SignDataDetails
        result = self.client.sign(sign_data_details=model(
            message=base64.b64encode(payload).decode("ascii"),
            key_id=required("XHUB_SIGNING_KEY_OCID"),
            key_version_id=required("XHUB_SIGNING_KEY_VERSION_OCID"),
            message_type="RAW",
            signing_algorithm="SHA_256_RSA_PKCS1_V1_5"
        )).data
        signature = base64.b64decode(result.signature, validate=True)
        if len(signature) != 384:
            raise RuntimeError("OCI Vault returned a signature that is not RSA-3072 sized.")
        trusted_public_key().verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        return signature

def validate_manifest(m):
    if not isinstance(m, dict) or m.get("schemaVersion") != 1 or m.get("productId") != PRODUCT or m.get("channel") != "stable":
        raise RuntimeError("Manifest schema, product, or channel is invalid.")
    if m.get("platform") != "windows" or m.get("architecture") != "x64" or m.get("packageFormat") != "zip":
        raise RuntimeError("Manifest platform or package format is invalid.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(m.get("version", ""))):
        raise RuntimeError("Stable version is invalid.")
    if not isinstance(m.get("releaseSequence"), int) or m["releaseSequence"] <= 0:
        raise RuntimeError("Release sequence is invalid.")
    if not isinstance(m.get("packageSize"), int) or not (0 < m["packageSize"] <= MAX_PACKAGE):
        raise RuntimeError("Package size is invalid.")
    if not re.fullmatch(r"[a-f0-9]{64}", str(m.get("packageSha256", ""))):
        raise RuntimeError("Package SHA-256 is invalid.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(m.get("minimumUpdaterVersion", ""))):
        raise RuntimeError("Minimum updater version is invalid.")
    url = m.get("packageUrl", "")
    if not isinstance(url, str) or not url.startswith(PACKAGE_BASE) or urllib.parse.urlparse(url).query or urllib.parse.urlparse(url).fragment:
        raise RuntimeError("Package URL is outside the configured stable HTTPS feed.")

def verify_envelope(raw):
    if not raw or len(raw) > MAX_JSON:
        raise RuntimeError("Signed manifest size is invalid.")
    try:
        envelope = json.loads(raw)
        if envelope.get("keyId") != SIGN_KEY_ID:
            raise RuntimeError("Manifest key ID is not trusted.")
        payload = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        trusted_public_key().verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        manifest = json.loads(payload)
    except (ValueError, KeyError, TypeError, InvalidSignature) as exc:
        raise RuntimeError("Signed manifest failed cryptographic or JSON validation.") from exc
    validate_manifest(manifest)
    return manifest

def validate_candidate(release, metadata, github):
    source = metadata.get("sourceSha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", str(source)) or release.get("tag_name") != TAG_PREFIX + source:
        raise RuntimeError("Candidate tag does not match private source SHA.")
    if release.get("draft") is not False or release.get("prerelease") is not True:
        raise RuntimeError("Candidate is not a published GitHub prerelease.")
    if metadata.get("schemaVersion") != 1 or metadata.get("productId") != PRODUCT or metadata.get("channel") != "stable":
        raise RuntimeError("Candidate metadata is not a stable Xbox Hub release.")
    if metadata.get("platform") != "windows" or metadata.get("architecture") != "x64":
        raise RuntimeError("Candidate platform must be Windows x64.")
    version = str(metadata.get("version", ""))
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or metadata.get("packageFileName") != f"XboxHub-{version}-win-x64.zip":
        raise RuntimeError("Candidate version or ZIP name is invalid.")
    if not isinstance(metadata.get("releaseSequence"), int) or metadata["releaseSequence"] <= 0:
        raise RuntimeError("Candidate release sequence is invalid.")
    if not isinstance(metadata.get("packageSize"), int) or not (0 < metadata["packageSize"] <= MAX_PACKAGE):
        raise RuntimeError("Candidate package size is invalid.")
    if not re.fullmatch(r"[a-f0-9]{64}", str(metadata.get("packageSha256", ""))):
        raise RuntimeError("Candidate package digest is invalid.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(metadata.get("minimumUpdaterVersion", ""))):
        raise RuntimeError("Candidate minimum updater version is invalid.")
    if not isinstance(metadata.get("changes"), list) or not (1 <= len(metadata["changes"]) <= 20):
        raise RuntimeError("Candidate changelog is invalid.")
    run_id, attempt = metadata.get("builderRunId"), metadata.get("builderRunAttempt")
    if not isinstance(run_id, int) or not isinstance(attempt, int):
        raise RuntimeError("Candidate builder run identity is invalid.")
    run = github.build_run(run_id)
    if (run.get("status") != "completed" or run.get("conclusion") != "success" or
        run.get("head_branch") != "main" or run.get("workflow_id") != WORKFLOW_ID or
        run.get("path") != WORKFLOW_PATH or run.get("run_attempt") != attempt):
        raise RuntimeError("Candidate is not backed by a successful trusted main-branch build.")

def get_metadata(release, github):
    assets = {a.get("name"): a for a in release.get("assets", []) if isinstance(a, dict)}
    asset = assets.get("xboxhub-release-metadata.json")
    if not asset:
        raise RuntimeError("Candidate metadata sidecar is missing.")
    with tempfile.TemporaryDirectory(prefix="xhub-meta-") as td:
        path = Path(td) / "metadata.json"
        github.download(asset["browser_download_url"], path, MAX_JSON)
        return json.loads(path.read_bytes())

def decrypt_package(path, metadata, vault):
    if path.stat().st_size < 12 or path.stat().st_size > MAX_ENCRYPTED:
        raise RuntimeError("Encrypted package size is invalid.")
    with path.open("rb") as stream:
        if stream.read(8) != b"XHUBENC1":
            raise RuntimeError("Encrypted package header marker is invalid.")
        size = stream.read(4)
        if len(size) != 4:
            raise RuntimeError("Encrypted package header length is missing.")
        length = struct.unpack("<i", size)[0]
        if length <= 0 or length > 65536:
            raise RuntimeError("Encrypted package header length is invalid.")
        raw_header = stream.read(length)
        if len(raw_header) != length:
            raise RuntimeError("Encrypted package header is truncated.")
        header = json.loads(raw_header)
        ciphertext = stream.read()
    if header.get("schemaVersion") != 1 or header.get("algorithm") != "AES-256-GCM+RSA-OAEP-SHA256":
        raise RuntimeError("Encrypted package algorithm is not supported.")
    if header.get("keyId") != PACKAGE_KEY_ID or header.get("originalFileName") != metadata["packageFileName"]:
        raise RuntimeError("Encrypted package key ID or filename differs from metadata.")
    if header.get("packageSize") != metadata["packageSize"] or header.get("packageSha256") != metadata["packageSha256"]:
        raise RuntimeError("Encrypted package identity differs from metadata.")
    nonce = base64.b64decode(header["nonceBase64"], validate=True)
    tag = base64.b64decode(header["tagBase64"], validate=True)
    if len(nonce) != 12 or len(tag) != 16:
        raise RuntimeError("AES-GCM nonce or authentication tag length is invalid.")
    key = vault.unwrap(header["wrappedKeyBase64"])
    aad = (f"XboxHub-Package-Envelope-v1\n{PACKAGE_KEY_ID}\n{header['originalFileName']}\n"
           f"{header['packageSize']}\n{header['packageSha256']}").encode("utf-8")
    try:
        plain = AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag as exc:
        raise RuntimeError("Encrypted package authentication failed.") from exc
    finally:
        del key
    if len(plain) != metadata["packageSize"] or hashlib.sha256(plain).hexdigest() != metadata["packageSha256"]:
        raise RuntimeError("Decrypted package size or SHA-256 does not match metadata.")
    import io
    with zipfile.ZipFile(io.BytesIO(plain), "r") as archive:
        items = archive.infolist()
        if len(items) != 2 or {x.filename for x in items} != ZIP_FILES or any(x.is_dir() or x.file_size <= 0 for x in items):
            raise RuntimeError("ZIP must contain exactly the two Xbox Hub executables.")
        if archive.testzip() is not None:
            raise RuntimeError("Decrypted ZIP CRC test failed.")
    return plain

def sign_manifest(metadata, vault):
    filename = metadata["packageFileName"]
    payload = {
        "schemaVersion": 1, "productId": PRODUCT, "channel": "stable",
        "version": metadata["version"], "releaseSequence": metadata["releaseSequence"],
        "platform": "windows", "architecture": "x64",
        "packageUrl": PACKAGE_BASE + urllib.parse.quote(filename, safe=""),
        "packageFormat": "zip", "packageSize": metadata["packageSize"],
        "packageSha256": metadata["packageSha256"],
        "minimumUpdaterVersion": metadata["minimumUpdaterVersion"],
        "title": metadata["title"], "date": metadata["date"], "changes": metadata["changes"]
    }
    validate_manifest(payload)
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    signature = vault.sign(raw)
    envelope = {
        "keyId": SIGN_KEY_ID, "payload": base64.b64encode(raw).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii")
    }
    signed = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    verify_envelope(signed)
    return signed

def atomic_write(directory, filename, content):
    fd, temporary = tempfile.mkstemp(prefix=".xhub-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o640)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / filename)
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise

def publish(release, metadata, github, vault, directory, current):
    validate_candidate(release, metadata, github)
    sequence = metadata["releaseSequence"]
    if sequence <= current:
        return current
    zip_name = metadata["packageFileName"]
    encrypted_name = zip_name[:-4] + ".xhubenc"
    assets = {a.get("name"): a for a in release.get("assets", []) if isinstance(a, dict)}
    if set(assets) != {encrypted_name, "xboxhub-release-metadata.json"}:
        raise RuntimeError("Candidate must contain exactly the encrypted package and metadata sidecar.")
    with tempfile.TemporaryDirectory(prefix="xhub-candidate-") as td:
        work = Path(td)
        sidecar, encrypted = work / "metadata.json", work / encrypted_name
        github.download(assets["xboxhub-release-metadata.json"]["browser_download_url"], sidecar, MAX_JSON)
        if json.loads(sidecar.read_bytes()) != metadata:
            raise RuntimeError("Metadata sidecar changed during download.")
        github.download(assets[encrypted_name]["browser_download_url"], encrypted, MAX_ENCRYPTED)
        package = decrypt_package(encrypted, metadata, vault)
        signed = sign_manifest(metadata, vault)
        target = directory / zip_name
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != metadata["packageSha256"]:
                raise RuntimeError("Refusing to replace different bytes at an existing stable package name.")
        else:
            atomic_write(directory, zip_name, package)
        # Publish the signed manifest last, only after the ZIP is durable.
        atomic_write(directory, "manifest.json", signed)
    LOG.info("Published Xbox Hub %s, release sequence %d.", metadata["version"], sequence)
    return sequence

def main():
    logging.basicConfig(level=os.environ.get("XHUB_LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s")
    os.umask(0o027)
    try:
        github, vault = GitHub(), Vault()
        directory = Path(os.environ.get("XHUB_RELEASE_DIRECTORY", "/var/www/xbox-hub-updates/stable"))
        directory.mkdir(parents=True, exist_ok=True)
        manifest = directory / "manifest.json"
        current = int(verify_envelope(manifest.read_bytes())["releaseSequence"]) if manifest.exists() else 0
        candidates = []
        for release in github.releases():
            metadata = get_metadata(release, github)
            if metadata.get("channel") == "stable":
                validate_candidate(release, metadata, github)
                candidates.append((metadata["releaseSequence"], release, metadata))
        candidates.sort(key=lambda item: item[0])
        if current == 0 and candidates and os.environ.get("XHUB_ALLOW_INITIAL_STABLE", "false").lower() not in {"1", "true", "yes"}:
            LOG.warning("Initial Stable publish is disabled. Candidate %s is ready for first-release acceptance.", candidates[-1][2]["version"])
            return 0
        for _, release, metadata in candidates:
            current = publish(release, metadata, github, vault, directory, current)
        return 0
    except Exception as exc:
        LOG.error("Stopped safely: %s: %s", type(exc).__name__, exc)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
