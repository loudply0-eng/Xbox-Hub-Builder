[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA "XboxHub\ReleaseSigning")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Set-CurrentUserOnlyAcl([string]$Path, [bool]$IsDirectory) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $identity.User
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existing in @($acl.Access)) {
        $acl.RemoveAccessRuleAll($existing)
    }
    $acl.SetOwner($sid)

    if ($IsDirectory) {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                       [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    }

    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    throw "OpenSSL was not found in PATH. Install a trusted OpenSSL distribution, then rerun this script."
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outDir = [System.IO.Path]::GetFullPath($OutputDirectory)
$repoPrefix = $repoRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

if ($outDir.Equals($repoRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    $outDir.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to create private Xbox Hub keys inside the source repository."
}

[System.IO.Directory]::CreateDirectory($outDir) | Out-Null
Set-CurrentUserOnlyAcl -Path $outDir -IsDirectory $true

# Release-signing key: private half signs manifests; public half is embedded in Xbox Hub.
$signPrivate = Join-Path $outDir "xbox-hub-release-private.pem"
$signPublicDer = Join-Path $outDir "xbox-hub-release-public.der"
$signPublicBase64 = Join-Path $outDir "public-key-base64.txt"
$signKeyIdPath = Join-Path $outDir "key-id.txt"
$signFingerprintPath = Join-Path $outDir "public-key-sha256.txt"

# Separate package-decryption key: public half encrypts CI artifacts; private half decrypts locally.
$decryptPrivate = Join-Path $outDir "xbox-hub-package-decrypt-private.pem"
$encryptPublicDer = Join-Path $outDir "xbox-hub-package-encryption-public.der"
$encryptPublicBase64 = Join-Path $outDir "package-encryption-public-base64.txt"
$encryptKeyIdPath = Join-Path $outDir "package-encryption-key-id.txt"
$encryptFingerprintPath = Join-Path $outDir "package-encryption-public-sha256.txt"

$finalPaths = @(
    $signPrivate, $signPublicDer, $signPublicBase64, $signKeyIdPath, $signFingerprintPath,
    $decryptPrivate, $encryptPublicDer, $encryptPublicBase64, $encryptKeyIdPath, $encryptFingerprintPath
)
foreach ($path in $finalPaths) {
    if (Test-Path -LiteralPath $path) {
        throw "Refusing to overwrite an existing key file: $path"
    }
}

$tempSignPrivate = Join-Path $outDir (".xboxhub-sign-private-" + [guid]::NewGuid().ToString("N") + ".tmp.pem")
$tempSignPublic = Join-Path $outDir (".xboxhub-sign-public-" + [guid]::NewGuid().ToString("N") + ".tmp.der")
$tempDecryptPrivate = Join-Path $outDir (".xboxhub-decrypt-private-" + [guid]::NewGuid().ToString("N") + ".tmp.pem")
$tempEncryptPublic = Join-Path $outDir (".xboxhub-encrypt-public-" + [guid]::NewGuid().ToString("N") + ".tmp.der")

try {
    Write-Host ""
    Write-Host "STEP 1/2 — Generate the offline RSA-3072 release-signing key."
    Write-Host "Choose a strong passphrase for the RELEASE SIGNING key."
    Write-Host "OpenSSL asks for it twice, then once more to export the public key."
    & $openssl.Source genpkey -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:3072 -out $tempSignPrivate
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tempSignPrivate)) {
        throw "OpenSSL failed to generate the encrypted release-signing key."
    }

    & $openssl.Source pkey -in $tempSignPrivate -pubout -outform DER -out $tempSignPublic
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tempSignPublic)) {
        throw "OpenSSL failed to export the release-signing public key."
    }

    if (-not (Test-Path -LiteralPath $tempSignPublic -PathType Leaf)) { throw "Release public-key DER file was not created." }
    $signPublicLength = (Get-Item -LiteralPath $tempSignPublic).Length
    if ($signPublicLength -lt 400) { throw "Release public key is unexpectedly short ($signPublicLength bytes)." }
    $signBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($tempSignPublic))
    $signFingerprint = (Get-FileHash -LiteralPath $tempSignPublic -Algorithm SHA256).Hash.ToLowerInvariant()
    $signKeyId = "xboxhub-rsa3072-" + $signFingerprint.Substring(0, 16)

    Write-Host ""
    Write-Host "STEP 2/2 — Generate a SEPARATE RSA-3072 package-decryption key."
    Write-Host "Choose a different strong passphrase for the PACKAGE DECRYPTION key."
    Write-Host "This private key decrypts CI packages and is not used to sign manifests."
    Write-Host "OpenSSL asks for it twice, then once more to export the public key."
    & $openssl.Source genpkey -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:3072 -out $tempDecryptPrivate
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tempDecryptPrivate)) {
        throw "OpenSSL failed to generate the encrypted package-decryption key."
    }

    & $openssl.Source pkey -in $tempDecryptPrivate -pubout -outform DER -out $tempEncryptPublic
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tempEncryptPublic)) {
        throw "OpenSSL failed to export the package-encryption public key."
    }

    if (-not (Test-Path -LiteralPath $tempEncryptPublic -PathType Leaf)) { throw "Package-encryption public-key DER file was not created." }
    $encryptPublicLength = (Get-Item -LiteralPath $tempEncryptPublic).Length
    if ($encryptPublicLength -lt 400) { throw "Package-encryption public key is unexpectedly short ($encryptPublicLength bytes)." }
    $encryptBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($tempEncryptPublic))
    $encryptFingerprint = (Get-FileHash -LiteralPath $tempEncryptPublic -Algorithm SHA256).Hash.ToLowerInvariant()
    $encryptKeyId = "xboxhub-package-rsa3072-" + $encryptFingerprint.Substring(0, 16)

    # Move private PEMs first. If any later write fails, the files remain local and no remote upload occurs.
    Move-Item -LiteralPath $tempSignPrivate -Destination $signPrivate
    Move-Item -LiteralPath $tempDecryptPrivate -Destination $decryptPrivate
    Move-Item -LiteralPath $tempSignPublic -Destination $signPublicDer
    Move-Item -LiteralPath $tempEncryptPublic -Destination $encryptPublicDer

    [System.IO.File]::WriteAllText($signPublicBase64, $signBase64, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($signKeyIdPath, $signKeyId, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($signFingerprintPath, $signFingerprint, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($encryptPublicBase64, $encryptBase64, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($encryptKeyIdPath, $encryptKeyId, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($encryptFingerprintPath, $encryptFingerprint, [System.Text.UTF8Encoding]::new($false))

    Set-CurrentUserOnlyAcl -Path $signPrivate -IsDirectory $false
    Set-CurrentUserOnlyAcl -Path $decryptPrivate -IsDirectory $false

    Write-Host ""
    Write-Host "Xbox Hub offline keys created successfully."
    Write-Host "Private release-signing key (KEEP SECRET): $signPrivate"
    Write-Host "Private package-decryption key (KEEP SECRET): $decryptPrivate"
    Write-Host ""
    Write-Host "RELEASE SIGNING PUBLIC KEY (safe to share):"
    Write-Host "Key ID: $signKeyId"
    Write-Host "SHA-256: $signFingerprint"
    Write-Host "Base64 SPKI:"
    Write-Host $signBase64
    Write-Host ""
    Write-Host "PACKAGE ENCRYPTION PUBLIC KEY (safe to share):"
    Write-Host "Key ID: $encryptKeyId"
    Write-Host "SHA-256: $encryptFingerprint"
    Write-Host "Base64 SPKI:"
    Write-Host $encryptBase64
    Write-Host ""
    Write-Warning "Never upload or send either private PEM file or either passphrase. Keep separate encrypted offline backups of both private keys."
}
finally {
    foreach ($temp in @($tempSignPrivate, $tempSignPublic, $tempDecryptPrivate, $tempEncryptPublic)) {
        if (Test-Path -LiteralPath $temp) {
            Remove-Item -LiteralPath $temp -Force
        }
    }
}
