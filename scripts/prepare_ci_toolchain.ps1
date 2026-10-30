param([Parameter(Mandatory = $true)][string]$Destination)

$ErrorActionPreference = 'Stop'
$base = 'https://download.visualstudio.microsoft.com/download/pr/45d3b8dd-bced-4b37-9974-142f748d710c'
$packages = @(
    @{ Name = 'Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX86.base.vsix'; Hash = 'e06adb295e3a7e02e299c56f8f567a6ee2ba96f28eb99a0bf389e93769405d2a' },
    @{ Name = 'Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX86.Res.base.enu.vsix'; Hash = 'f5255db450b08476c7ea7e1fba60e7ff6839b6558e6e8b68dac85398853f7db5' },
    @{ Name = 'Microsoft.VC.14.44.17.14.CRT.x86.Desktop.base.vsix'; Hash = 'fe6ecfbc59a0df04010818574e08b77b2e0344086e83a47aa2802cc92ac5798f' },
    @{ Name = 'Microsoft.VC.14.44.17.14.CRT.x86.Store.base.vsix'; Hash = '206070ce317dd469af998980f5bdb16ce571c5f3e68720d0639a9e0dadce1edd' },
    @{ Name = 'Microsoft.VC.14.44.17.14.CRT.Headers.base.vsix'; Hash = 'bf77970fe0291576546b5089c5be421d82f43f418cfd389459c663661fa519ce' }
)

Add-Type -AssemblyName System.IO.Compression.FileSystem
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$scratch = Join-Path $env:RUNNER_TEMP 'syringe-msvc-download'
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
foreach ($package in $packages) {
    $archive = Join-Path $scratch $package.Name
    Invoke-WebRequest -Uri "$base/$($package.Hash)/$($package.Name)" -OutFile $archive
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $package.Hash) {
        throw "Invalid SHA-256 for $($package.Name)"
    }
    $archiveFile = [System.IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $prefix = 'Contents/VC/Tools/MSVC/14.44.35207/'
        foreach ($entry in $archiveFile.Entries) {
            if (-not $entry.FullName.StartsWith($prefix) -or $entry.FullName.EndsWith('/')) { continue }
            $relative = $entry.FullName.Substring($prefix.Length)
            $target = [System.IO.Path]::GetFullPath((Join-Path $Destination $relative))
            $root = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
            if (-not $target.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { throw "Invalid archive path: $relative" }
            New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
        }
    } finally { $archiveFile.Dispose() }
}
