param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('setup', 'image', 'start', 'build', 'check', 'userdata', 'stop')]
    [string]$Action,
    [string]$Size = '256M'
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
function Invoke-Wslc {
    & wslc @args
    if ($LASTEXITCODE -ne 0) { throw "wslc failed (exit $LASTEXITCODE)" }
}
function Get-WslcList {
    $lines = & wslc @args
    if ($LASTEXITCODE -ne 0) { throw "wslc list failed (exit $LASTEXITCODE)" }
    foreach ($line in $lines) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { $line | ConvertFrom-Json }
    }
}
Push-Location $root
try {
    switch ($Action) {
        'setup' {
            $images = @(Get-WslcList image list --format json)
            if (-not ($images | Where-Object { $_.Repository -eq 'ssal-builder' -and $_.Tag -eq 'dev' })) {
                Write-Host 'Building ssal-builder:dev...'
                Invoke-Wslc build -f containers/builder/Containerfile -t ssal-builder:dev .
            }
            $containers = @(Get-WslcList container list --all --format json)
            $container = $containers | Where-Object { $_.Names -eq 'ssal-dev' } | Select-Object -First 1
            if (-not $container) {
                Write-Host 'Creating ssal-dev...'
                Invoke-Wslc run -d --name ssal-dev --mount "type=bind,source=$root,target=/src" -w /src ssal-builder:dev sleep infinity
            } else {
                $detailsJson = & wslc container inspect --format json ssal-dev
                if ($LASTEXITCODE -ne 0) { throw "wslc inspect failed (exit $LASTEXITCODE)" }
                $details = @($detailsJson | ConvertFrom-Json)[0]
                $mount = $details.Mounts | Where-Object { $_.Destination -eq '/src' -and $_.Type -eq 'bind' } | Select-Object -First 1
                if (-not $mount -or $mount.Source.TrimEnd('\') -ine $root.TrimEnd('\')) {
                    throw 'ssal-dev is bound to a different workspace. Remove or rename that container before running setup.'
                }
                if ($details.Config.Image -ne 'ssal-builder:dev') {
                    throw 'ssal-dev uses a different image. Remove or rename that container before running setup.'
                }
                if ($details.State.Status -eq 'running') {
                    Write-Host 'ssal-dev is already running.'
                } elseif ($details.State.Status -in @('created', 'exited')) {
                    Write-Host 'Starting ssal-dev...'
                    Invoke-Wslc container start ssal-dev
                } else {
                    throw "ssal-dev is in unsupported state '$($details.State.Status)'."
                }
            }
        }
        'image' { Invoke-Wslc build -f containers/builder/Containerfile -t ssal-builder:dev . }
        'start' { Invoke-Wslc run -d --name ssal-dev --mount "type=bind,source=$root,target=/src" -w /src ssal-builder:dev sleep infinity }
        'build' { Invoke-Wslc exec ssal-dev bash scripts/build-android.sh }
        'check' { Invoke-Wslc exec ssal-dev bash -c 'cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked && shellcheck scripts/*.sh' }
        'userdata' { Invoke-Wslc exec ssal-dev bash scripts/make-userdata.sh /src/out/userdata-test.img $Size }
        'stop' { Invoke-Wslc container stop ssal-dev }
    }
} finally { Pop-Location }
