param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
if (!(Test-Path -LiteralPath $Executable)) { throw 'KeySafe executable was not produced.' }
$p = Start-Process -FilePath $Executable -PassThru
try {
    $visible = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        $p.Refresh()
        if ($p.HasExited) { throw "KeySafe exited during GUI startup. Exit code: $($p.ExitCode)." }
        if ($p.MainWindowHandle -ne [IntPtr]::Zero -and $p.MainWindowTitle -like '*KeySafe*') { $visible = $true; break }
    }
    if (-not $visible) { throw 'Process survived but no KeySafe main window became visible within 10 seconds.' }
    Write-Host 'PASS: Windows GUI created a main window and remained running.'
}
finally {
    $p.Refresh()
    if (!$p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}
