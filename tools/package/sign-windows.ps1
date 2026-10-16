<#
.SYNOPSIS
  Firma ejecutables o MSI con signtool y un certificado PFX (Authenticode, SHA-256 y
  sello de tiempo RFC 3161). Si no hay certificado configurado, no hace nada.

.DESCRIPTION
  Variables de entorno:
    WINDOWS_SIGN_PFX_BASE64    PFX en Base64 (secreto de CI).
    WINDOWS_SIGN_PFX_PASSWORD  Contraseña del PFX.
    WINDOWS_SIGN_TIMESTAMP_URL Servidor de sellos de tiempo (por defecto DigiCert).

  Desde junio de 2023 las CA solo emiten certificados de firma de código con la clave en
  hardware (HSM o token), así que un PFX exportable solo sirve con certificados antiguos o
  internos. Con Azure Artifact Signing (antes Trusted Signing) se usa la acción
  Azure/artifact-signing-action del flujo de publicación en lugar de este script.

.EXAMPLE
  pwsh tools/package/sign-windows.ps1 -Files target\x86_64-pc-windows-msvc\release\autofirma.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string[]] $Files,
    [string] $Description = 'AutoFirma',
    [string] $DescriptionUrl = 'https://github.com/autofirma-rs/autofirma-rs'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $env:WINDOWS_SIGN_PFX_BASE64) {
    Write-Host '==> Sin WINDOWS_SIGN_PFX_BASE64: no se firma (compilación sin firma).'
    return
}

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $found = Get-ChildItem -Path $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $found) { throw 'No se encuentra signtool.exe (Windows SDK)' }
    return $found.FullName
}

$signtool = Find-SignTool
$timestamp = if ($env:WINDOWS_SIGN_TIMESTAMP_URL) { $env:WINDOWS_SIGN_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
$pfx = Join-Path ([IO.Path]::GetTempPath()) "$([Guid]::NewGuid()).pfx"
try {
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:WINDOWS_SIGN_PFX_BASE64))
    foreach ($f in $Files) {
        $path = (Resolve-Path $f).Path
        Write-Host "==> Firmando $path"
        & $signtool sign /fd SHA256 /f $pfx /p $env:WINDOWS_SIGN_PFX_PASSWORD `
            /tr $timestamp /td SHA256 /d $Description /du $DescriptionUrl $path
        if ($LASTEXITCODE -ne 0) { throw "signtool sign ha fallado para $path" }
        & $signtool verify /pa $path
        if ($LASTEXITCODE -ne 0) { throw "La firma de $path no es válida" }
    }
}
finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $pfx
}
