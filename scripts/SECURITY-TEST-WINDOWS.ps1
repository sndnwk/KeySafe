param([Parameter(Mandatory=$true)][string]$ProjectRoot)
$ErrorActionPreference = 'Stop'
# Resolve a project root supplied by the batch file without depending on a trailing separator.
$projectPath = $ProjectRoot.Trim().Trim('"')
if ([string]::IsNullOrWhiteSpace($projectPath)) {
    Write-Error 'ProjectRoot is empty. Run SECURITY-TEST-WINDOWS.bat from the extracted project folder.'
    exit 2
}
try {
    $root = [IO.Path]::GetFullPath($projectPath)
} catch {
    Write-Error "Invalid project path '$projectPath': $($_.Exception.Message)"
    exit 2
}
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    Write-Error "Project folder does not exist: $root"
    exit 2
}
$reports = Join-Path $root 'security-reports'
[IO.Directory]::CreateDirectory($reports) | Out-Null
$processes = @(Get-Process -Name KeySafe -ErrorAction SilentlyContinue)
$mode = if ($processes.Count -gt 0) { 'RUNNING' } else { 'STOPPED' }
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$report = Join-Path $reports "KeySafe-Security-$mode-$timestamp.txt"
$lines = New-Object System.Collections.Generic.List[string]
$failures = 0
function Log([string]$line) { $script:lines.Add($line); Write-Host $line }
function Check([bool]$ok, [string]$message) {
    if ($ok) { Log "PASS: $message" }
    else { Log "FAIL: $message"; $script:failures++ }
}
function Run-Tool([string]$description,[string]$exe,[string[]]$arguments) {
    Log "=== $description ==="
    try {
        $priorErrorPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $output = & $exe @arguments 2>&1 | Out-String
        $ErrorActionPreference = $priorErrorPreference
        $code = $LASTEXITCODE
        foreach ($line in ($output -split "`r?`n")) { if ($line.Trim()) { Log $line } }
        Check ($code -eq 0) "$description returned exit code $code"
    } catch { $ErrorActionPreference = 'Stop'; Log "FAIL: $description could not run: $($_.Exception.GetType().Name)"; $script:failures++ }
}
try {
    Log 'KeySafe v1.1.0 security diagnostics (non-destructive)'
    Log "Timestamp: $((Get-Date).ToUniversalTime().ToString('o'))"
    Log "Mode: $mode"
    Log 'No live vault contents, memory dumps, passwords, recovery codes, or clipboard text are read.'
    Log 'This is a diagnostic test, NOT a penetration test or security certification.'
    $exe = Join-Path $root 'dist\KeySafe\KeySafe.exe'
    Check (Test-Path -LiteralPath $exe -PathType Leaf) 'Published Windows executable exists'
    if (Test-Path -LiteralPath $exe -PathType Leaf) {
        $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        Log "Executable SHA256: $hash"
        $sig = Get-AuthenticodeSignature -LiteralPath $exe
        Log "Authenticode signature: $($sig.Status) (unsigned local builds are expected; not an automatic failure)"
        $sodium = Join-Path (Split-Path $exe -Parent) 'libsodium.dll'
        Check (Test-Path -LiteralPath $sodium -PathType Leaf) 'Folder release contains libsodium.dll beside KeySafe.exe'
        if (Test-Path -LiteralPath $sodium -PathType Leaf) {
            $sodiumHash = (Get-FileHash -LiteralPath $sodium -Algorithm SHA256).Hash
            Check ($sodiumHash -eq '64A1F143868309069F0A0A3C8141C0853C4F17243DDF734E92B11C5411739771') 'Packaged libsodium.dll matches the application-pinned SHA-256'
        }
    }
    Check (Test-Path -LiteralPath (Join-Path $root 'BUILD-WINDOWS.bat')) 'Build script present'
    Check (Test-Path -LiteralPath (Join-Path $root 'tests\KeySafe.Resilience\Program.cs')) 'Crash recovery test sources present'
    foreach ($p in $processes) {
        try {
            $p.Refresh()
            Log "KeySafe process ID: $($p.Id); MainWindowTitle: $($p.MainWindowTitle); Running: $(-not $p.HasExited)"
            if ($p.MainModule -and $p.MainModule.FileName) { Log "Executable file: $($p.MainModule.FileName)" }
            if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
                $connections = @(Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction SilentlyContinue)
                if ($connections.Count -gt 0) { Log "WARNING: $($connections.Count) TCP connection(s) owned by this process. Review network access."; $script:failures++ }
                else { Log 'PASS: No TCP connections owned by KeySafe at time of snapshot' }
            } else { Log 'INCOMPLETE: Get-NetTCPConnection unavailable; networking not assessed.' }
            $nativeModules = @($p.Modules | Where-Object { $_.FileName -like "*$([IO.Path]::DirectorySeparatorChar).net$([IO.Path]::DirectorySeparatorChar)*" })
            if ($nativeModules.Count -gt 0) {
                $extractDirs = @($nativeModules | ForEach-Object { Split-Path $_.FileName -Parent } | Select-Object -Unique)
                foreach ($extractDir in $extractDirs) {
                    $extractAcl = Get-Acl -LiteralPath $extractDir
                    $foreignWrite = @($extractAcl.Access | Where-Object {
                        $_.IdentityReference.Value -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and
                        $_.FileSystemRights.ToString() -match 'Write|FullControl|Modify' -and $_.AccessControlType -eq 'Allow'
                    })
                    Check ($foreignWrite.Count -eq 0) "Single-file native extraction directory has no obvious cross-user write grant: $extractDir"
                }
            } else { Log 'INFO: No extracted native module path was visible in the running process snapshot.' }
        } catch { Log "INCOMPLETE: Could not inspect KeySafe process $($p.Id): $($_.Exception.Message)" }
    }
    if ($mode -eq 'STOPPED') { Log 'PASS: No KeySafe application process was running when the scan began.' }
    if ($mode -eq 'RUNNING') { Log 'Running-mode check only observes processes; it does not tamper with active vaults.' }
    $vaultDir = Join-Path $env:LOCALAPPDATA 'KeySafe\v1.1.0'
    if (Test-Path -LiteralPath $vaultDir) {
        $vaults = @(Get-ChildItem -LiteralPath $vaultDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.ksv' })
        Log "Vault files present: $($vaults.Count) (file contents are NOT inspected)"
        foreach ($f in $vaults) { Log "Vault metadata: $($f.Name); bytes=$($f.Length)" }
        $acl = Get-Acl -LiteralPath $vaultDir
        $broad = @($acl.Access | Where-Object { $_.IdentityReference.Value -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and $_.FileSystemRights.ToString() -match 'Write|FullControl|Modify' -and $_.AccessControlType -eq 'Allow' })
        Check ($broad.Count -eq 0) 'Vault directory has no obvious broad write permissions'
    } else { Log 'INFO: No v1.1.0 local vault directory exists; storage ACL check skipped.' }
    $aclProbe = Join-Path $env:LOCALAPPDATA ("KeySafe-AclAudit-" + [Guid]::NewGuid().ToString('N'))
    try {
        [IO.Directory]::CreateDirectory($aclProbe) | Out-Null
        $probeAcl = Get-Acl -LiteralPath $aclProbe
        $probeBroad = @($probeAcl.Access | Where-Object { $_.IdentityReference.Value -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and $_.FileSystemRights.ToString() -match 'Write|FullControl|Modify' -and $_.AccessControlType -eq 'Allow' })
        Check ($probeBroad.Count -eq 0) 'Fresh LocalApplicationData directory inheritance has no obvious broad write permissions'
    } finally { if (Test-Path -LiteralPath $aclProbe) { [IO.Directory]::Delete($aclProbe, $true) } }
    $werPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps',
        'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\KeySafe.exe'
    )
    foreach ($werPath in $werPaths) {
        $configured = $false
        if (Test-Path $werPath) {
            $properties = Get-ItemProperty -Path $werPath
            $configured = @('DumpFolder','DumpCount','DumpType','CustomDumpFlags') | Where-Object { $properties.PSObject.Properties.Name -contains $_ }
        }
        if ($configured) { Log "WARNING: Windows Error Reporting dump policy is configured at $werPath; dumps may contain unlocked secrets."; $failures++ }
        else { Log "PASS: No configured WER LocalDumps values at $werPath (administrators and Task Manager can still capture memory)." }
    }
    try {
        $pagefiles = @(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop)
        Log "INFO: Active pagefiles: $($pagefiles.Count). KeySafe cannot guarantee secrets are absent from pagefile or hibernation storage."
    } catch { Log "INCOMPLETE: Pagefile state unavailable: $($_.Exception.Message)" }
    if (Get-Command dotnet -ErrorAction SilentlyContinue) {
        Run-Tool 'Synthetic crypto and feature smoke suite' 'dotnet' @('run','--project',(Join-Path $root 'tests\KeySafe.Smoke\KeySafe.Smoke.csproj'),'--configuration','Release')
        Run-Tool 'Synthetic crash, rollback, and concurrency suite' 'dotnet' @('run','--project',(Join-Path $root 'tests\KeySafe.Resilience\KeySafe.Resilience.csproj'),'--configuration','Release')
        Run-Tool 'Synthetic full-memory exposure suite' 'dotnet' @('run','--project',(Join-Path $root 'tests\KeySafe.Memory\KeySafe.Memory.csproj'),'--configuration','Release')
        Run-Tool 'Windows secure clipboard suite' 'dotnet' @('run','--project',(Join-Path $root 'tests\KeySafe.Clipboard\KeySafe.Clipboard.csproj'),'--configuration','Release')
        Run-Tool 'Isolated WPF editor and theme suite' 'dotnet' @('run','--project',(Join-Path $root 'tests\KeySafe.Ui\KeySafe.Ui.csproj'),'--configuration','Release')
        # NuGet audit depends on network/advisory feed availability and may legitimately be inconclusive.
        Log '=== NuGet advisory audit (network required; incomplete/offline status must be reviewed) ==='
        $auditOutput = & dotnet list (Join-Path $root 'src\KeySafe\KeySafe.csproj') package --vulnerable --include-transitive --format json 2>&1 | Out-String
        $auditCode = $LASTEXITCODE
        foreach ($line in ($auditOutput -split "`r?`n")) { if ($line.Trim()) { Log $line } }
        if ($auditCode -ne 0 -or $auditOutput -match 'NU190|Unable to load|failed|offline') {
            Log 'INCOMPLETE/WARNING: NuGet vulnerability audit could not be validated; review output manually.'
            $script:failures++
        } elseif ($auditOutput -match '"vulnerabilities"\s*:') {
            Log 'WARNING: NuGet vulnerability findings require review.'
            $script:failures++
        } else { Log 'PASS: NuGet JSON audit completed without reported vulnerable packages (subject to feed coverage).' }
    } else { Log 'FAIL: dotnet SDK not found; essential tests could not run.'; $script:failures++ }
} catch { Log "FAIL: Security diagnostics terminated: $($_.Exception)"; $failures++ }
finally {
    Log "SUMMARY: mode=$mode; findings=$failures"
    Log "Report: $report"
    [IO.File]::WriteAllLines($report,$lines.ToArray(),[Text.UTF8Encoding]::new($false))
}
if ($failures -gt 0) { exit 1 }
exit 0
