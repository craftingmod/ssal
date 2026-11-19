param(
    [Parameter(Mandatory)][string]$Serial,
    [Parameter(Mandatory)][ValidatePattern('\A(?-i:[0-9a-f]{32})\z')][string]$Session,
    [Parameter(Mandatory)][string]$BridgeLog
)

$records = @(Select-String -CaseSensitive -LiteralPath $BridgeLog -Pattern '^SSAL_PRESENTER_FRAME=([0-9a-f]{144})$')
if ($records.Count -ne 1) { throw 'Expected one validated frame in a fresh bridge log.' }
$hex = $records[0].Matches[0].Groups[1].Value
$bytes = [byte[]]@(for ($i = 0; $i -lt $hex.Length; $i += 2) {
    [Convert]::ToByte($hex.Substring($i, 2), 16)
})
$base64 = [Convert]::ToBase64String($bytes)
$destination = "cache/ssal-frame-$Session"
$command = 'umask 077; tmp=$(mktemp cache/.ssal-frame.XXXXXX) || exit 1; ' +
    ('printf %s {0} | base64 -d > $tmp && mv -f $tmp {1} || (rm -f $tmp; exit 1)' -f $base64, $destination)
& adb -s $Serial shell "run-as alyac.android.ssalsurface sh -c '$command'"
if ($LASTEXITCODE -ne 0) { throw "Presenter delivery failed on $Serial." }
Get-FileHash -InputStream ([IO.MemoryStream]::new($bytes)) -Algorithm SHA256
