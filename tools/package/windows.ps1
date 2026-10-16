<#
.SYNOPSIS
  Empaqueta AutoFirma-rs para Windows: ZIP portable y MSI (WiX Toolset v5).

.DESCRIPTION
  Parte de un autofirma.exe ya compilado (y, si procede, ya firmado con
  tools/package/sign-windows.ps1). El MSI resultante debe firmarse después.

  Requisitos: .NET SDK 8 o posterior (para instalar la herramienta «wix» si no está).

.EXAMPLE
  cargo build --release --locked -p autofirma --target x86_64-pc-windows-msvc
  pwsh tools/package/windows.ps1 -Exe target\x86_64-pc-windows-msvc\release\autofirma.exe -Arch x64
#>
[CmdletBinding()]
param(
    # Ejecutable autofirma.exe (si hay autofirma-cli.exe en el mismo directorio, se incluye).
    [Parameter(Mandatory = $true)] [string] $Exe,
    # Arquitectura del MSI: x64 o arm64.
    [ValidateSet('x64', 'arm64')] [string] $Arch = 'x64',
    # Directorio de salida.
    [string] $OutDir = 'target\dist',
    # Versión de WiX Toolset (v5: licencia MS-RL, sin cuota de mantenimiento).
    [string] $WixVersion = '5.0.2',
    # Cuarto componente de la versión del MSI (p. ej., el número de ejecución de CI).
    [int] $BuildNumber = 0,
    # No generar el MSI (solo el ZIP).
    [switch] $NoMsi
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Get-WorkspaceVersion {
    $inWorkspace = $false
    foreach ($line in Get-Content (Join-Path $Root 'Cargo.toml')) {
        if ($line -match '^\[workspace\.package\]') { $inWorkspace = $true; continue }
        if ($inWorkspace -and $line -match '^\[') { break }
        if ($inWorkspace -and $line -match '^version\s*=\s*"([^"]+)"') { return $Matches[1] }
    }
    throw 'No se pudo leer la versión de Cargo.toml'
}

function Write-CrLf([string] $Source, [string] $Destination) {
    $text = [IO.File]::ReadAllText($Source) -replace "`r?`n", "`r`n"
    [IO.File]::WriteAllText($Destination, $text, [Text.UTF8Encoding]::new($false))
}

$Version = Get-WorkspaceVersion
$NumericVersion = ($Version -split '[-+]')[0]
$Exe = (Resolve-Path $Exe).Path
$BinDir = Split-Path -Parent $Exe
$Cli = Join-Path $BinDir 'autofirma-cli.exe'
$HasCli = Test-Path $Cli
$ArchName = if ($Arch -eq 'x64') { 'x86_64' } else { 'aarch64' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

Write-Host "==> AutoFirma-rs $Version ($Arch)"

# ------------------------------------------------------------------ ZIP portable
$base = "AutoFirma-$Version-windows-$ArchName-portable"
$stage = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
$dir = Join-Path $stage $base
New-Item -ItemType Directory -Force -Path (Join-Path $dir 'LICENSE') | Out-Null
Copy-Item $Exe (Join-Path $dir 'autofirma.exe')
if ($HasCli) { Copy-Item $Cli (Join-Path $dir 'autofirma-cli.exe') }
Write-CrLf (Join-Path $Root 'packaging\windows\README-portable.txt') (Join-Path $dir 'README-portable.txt')
Write-CrLf (Join-Path $Root 'license\gpl-2.0.txt') (Join-Path $dir 'LICENSE\gpl-2.0.txt')
Write-CrLf (Join-Path $Root 'license\LICENSE.txt') (Join-Path $dir 'LICENSE\condiciones-autofirma.txt')
$zip = Join-Path $OutDir "$base.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path $dir -DestinationPath $zip -CompressionLevel Optimal
Remove-Item -Recurse -Force $stage
Write-Host "==> ZIP portable: $zip"

if ($NoMsi) { return }

# ------------------------------------------------------------------ MSI (WiX v5)
$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
    Write-Host "==> Instalando WiX Toolset $WixVersion (dotnet tool)"
    dotnet tool install --global wix --version $WixVersion
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo instalar WiX (dotnet tool install wix)' }
    $env:PATH = "$env:PATH;$env:USERPROFILE\.dotnet\tools"
}
wix extension add -g "WixToolset.Util.wixext/$WixVersion"
if ($LASTEXITCODE -ne 0) { throw 'No se pudo añadir la extensión WixToolset.Util.wixext' }

$msiVersion = "$NumericVersion.$BuildNumber"
$msi = Join-Path $OutDir "AutoFirma-$Version-windows-$ArchName.msi"
$wixArgs = @(
    'build', (Join-Path $Root 'packaging\windows\autofirma.wxs'),
    '-arch', $Arch,
    '-ext', 'WixToolset.Util.wixext',
    '-d', "Version=$msiVersion",
    '-d', "BinDir=$BinDir",
    '-o', $msi
)
if ($HasCli) { $wixArgs += @('-d', 'HasCli=1') }
Write-Host "==> wix $($wixArgs -join ' ')"
& wix @wixArgs
if ($LASTEXITCODE -ne 0) { throw "wix build ha fallado ($LASTEXITCODE)" }
Write-Host "==> MSI: $msi"
