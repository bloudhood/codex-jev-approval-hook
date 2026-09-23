param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'api-key.dpapi')
)

$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to overwrite existing key file: $OutputPath"
}
$secureKey = Read-Host 'API key (stored with Windows DPAPI for this user)' -AsSecureString
if ($secureKey.Length -lt 1) { throw 'API key cannot be empty' }
$ciphertext = ConvertFrom-SecureString -SecureString $secureKey
[IO.File]::WriteAllText($OutputPath, $ciphertext)
$secureKey.Dispose()
Write-Output "Encrypted key saved to $OutputPath"
