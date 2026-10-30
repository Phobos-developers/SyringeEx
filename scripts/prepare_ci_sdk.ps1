param([Parameter(Mandatory = $true)][string]$Destination)

$ErrorActionPreference = 'Stop'
$base = 'https://download.visualstudio.microsoft.com/download/pr/62f6bc3b-8e5b-484f-b322-33672a27d6c2'
$packages = @(
    @{ Id = 'ucrt'; MsiPath = '4ee2f7d57bdcfc0676482f2b475884da/universal%20crt%20headers%20libraries%20and%20sources-x86_en-us.msi'; MsiHash = 'a0887609a8184e5e69e091c64c961de38792c8f72f01692029fa41edb0a69136'; CabPath = '5df2f77abf34dd1ecdd2b3ace36e155d/6ee7bbee8435130a869cf971694fd9e2.cab'; CabHash = 'be73ba2e6798560b8f7b81f80c3444304bf2152667a775bedd67ec761587d25c'; First = 3; Last = 11; Subdir = 'ucrt\x86' },
    @{ Id = 'store'; MsiPath = '8fc115ad761797ccde81c5f29e3a9587/windows%20sdk%20for%20windows%20store%20apps%20libs-x86_en-us.msi'; MsiHash = 'a7d0beba01e7a599509d60cc24fae45cb5e444d72b767076ce780baed9f5cbb0'; CabPath = 'dacc79757f4834b6822d48fb6625573b/e10768bb6e9d0ea730280336b697da66.cab'; CabHash = 'ecdd3ee96c6cc646ceaabd7c8e79d8872e1ddfe14a62fed833dc6d34806b7db9'; First = 122; Last = 236; Subdir = 'um\x86' },
    @{ Id = 'desktop'; MsiPath = 'a3590074b3176b0a32abaf1ff68bd86d/windows%20sdk%20desktop%20libs%20x86-x86_en-us.msi'; MsiHash = '590875069a9d03aa18076fef08d1fbcb80ee4a2287111559fc4462f357b5ae79'; CabPath = '54a39c43aa766f8ce479248e79d195bc/53174a8154da07099db041b9caffeaee.cab'; CabHash = 'f06033f63545edf4d27cabcd2d1c9e85ee0b5dd2fd32ae31d5f9c54118418c84'; First = 1; Last = 367; Subdir = 'um\x86' }
)
$scratch = Join-Path $env:RUNNER_TEMP 'syringe-sdk-download'
New-Item -ItemType Directory -Force -Path $scratch, $Destination | Out-Null
$installer = New-Object -ComObject WindowsInstaller.Installer
foreach ($package in $packages) {
    $msi = Join-Path $scratch "$($package.Id).msi"
    $cab = Join-Path $scratch "$($package.Id).cab"
    foreach ($item in @(@($package.MsiPath, $package.MsiHash, $msi), @($package.CabPath, $package.CabHash, $cab))) {
        Invoke-WebRequest -Uri "$base/$($item[0])" -OutFile $item[2]
        if ((Get-FileHash -LiteralPath $item[2] -Algorithm SHA256).Hash -ne $item[1]) { throw "Invalid SHA-256 for $($item[2])" }
    }
    $unpacked = Join-Path $scratch "$($package.Id)-files"
    New-Item -ItemType Directory -Force -Path $unpacked | Out-Null
    & expand.exe -F:* $cab $unpacked | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not extract $cab" }
    $db = $installer.OpenDatabase($msi, 0)
    $view = $db.OpenView('SELECT `File`, `FileName`, `Sequence` FROM `File`')
    $view.Execute()
    $count = 0
    while ($record = $view.Fetch()) {
        $sequence = $record.IntegerData(3)
        $name = ($record.StringData(2) -split '\|')[-1]
        if ($sequence -lt $package.First -or $sequence -gt $package.Last -or -not $name.EndsWith('.lib', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $source = Join-Path $unpacked $record.StringData(1)
        $target = Join-Path $Destination $package.Subdir
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        Copy-Item -LiteralPath $source -Destination (Join-Path $target $name) -Force
        $count++
    }
    $view.Close()
    if ($count -eq 0) { throw "No libraries extracted from $cab" }
    Write-Host "Extracted $count $($package.Id) libraries"
}
