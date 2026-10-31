param([string]$OutputDirectory = 'out/guest-lock-compat-v4')
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$commands = @(
    'id; getenforce; cat /proc/self/attr/current; getprop ro.build.version.release; getprop ro.build.version.sdk; getprop sys.boot_completed',
    'readlink /proc/1/ns/mnt; readlink /proc/self/ns/mnt',
    'cat /proc/1/mountinfo',
    'cat /data/local/ssal/images/1793366406758-25627/manifest.json',
    'cat /sys/block/loop*/loop/backing_file'
)
$results = foreach ($command in $commands) {
    $stderrPath = Join-Path $OutputDirectory 'preflight-last.stderr'
    $stdout = & adb shell su -c $command 2> $stderrPath
    $code = $LASTEXITCODE
    @{ command = @('adb','shell','su','-c',$command); exit_code = $code; stdout = ($stdout -join "`n"); stderr = [IO.File]::ReadAllText((Join-Path $PWD $stderrPath)) }
}
$inventoryStatus = if (@($results | Where-Object { $_.exit_code -ne 0 }).Count -eq 0) { 'passed' } else { 'blocked' }
@{ status = $inventoryStatus; scope = 'read_only_device_inventory_no_probe_execution'; collected_at = [DateTimeOffset]::UtcNow.ToString('o'); commands = @($results); device_approval = 'pending'; probe_executed = $false } | ConvertTo-Json -Depth 12 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory 'preflight.json')