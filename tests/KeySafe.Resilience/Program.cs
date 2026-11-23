using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Data.Sqlite;
using KeySafe;

const string password = "Resilience-Only-Synthetic-Master-2026";
if (args.Length == 3 && args[0] == "--child")
{
    var path = args[2];
    if (args[1] == "committed")
    {
        using var v = new VaultStore(path);
        v.Unlock(password);
        v.Upsert(new Credential { Title = "Committed", Password = "SYNTHETIC-COMMITTED" });
        Process.GetCurrentProcess().Kill();
    }
    if (args[1] == "uncommitted")
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;";
        cmd.ExecuteNonQuery();
        using var tx = connection.BeginTransaction();
        cmd.Transaction = tx;
        cmd.CommandText = "UPDATE vault_state SET encrypted_envelope=$broken,revision=revision+1 WHERE id=1;";
        cmd.Parameters.AddWithValue("$broken", RandomNumberGenerator.GetBytes(300));
        if (cmd.ExecuteNonQuery() != 1) throw new Exception("TEST_SETUP_FAILED");
        Process.GetCurrentProcess().Kill();
    }
    if (args[1] == "hold")
    {
        using var v = new VaultStore(path);
        v.Unlock(password);
        File.WriteAllText(path + ".ready", "ready");
        var timeout = Stopwatch.StartNew();
        while (!File.Exists(path + ".release") && timeout.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(20);
        Environment.Exit(0);
    }
    throw new ArgumentException("Unknown child scenario.");
}
int checks = 0;
void Check(bool success, string message)
{
    if (!success) throw new Exception("FAIL: " + message);
    checks++;
    Console.WriteLine("PASS: " + message);
}
void Rejected(Action action, string message)
{
    bool rejected = false;
    try { action(); }
    catch (Exception ex) when (ex is CryptographicException or IOException or InvalidDataException or InvalidOperationException or ArgumentException or SodiumException or System.Text.Json.JsonException or SqliteException) { rejected = true; }
    Check(rejected, message);
}
int CrashChild(string mode, string path)
{
    // No live vault is touched: only an isolated random directory under %TEMP%.
    var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot find current process executable.");
    var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
    start.ArgumentList.Add("--child"); start.ArgumentList.Add(mode); start.ArgumentList.Add(path);
    using var child = Process.Start(start) ?? throw new Exception("Cannot launch crash child process.");
    if (!child.WaitForExit(30000)) { child.Kill(true); throw new TimeoutException("Crash child timed out."); }
    return child.ExitCode;
}
void ReplaceState(string path, byte[] envelope, long revision)
{
    using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
    connection.Open();
    using var command = connection.CreateCommand();
    command.CommandText = "UPDATE vault_state SET encrypted_envelope=$data,revision=$revision WHERE id=1";
    command.Parameters.AddWithValue("$data", envelope);
    command.Parameters.AddWithValue("$revision", revision);
    if (command.ExecuteNonQuery() != 1) throw new Exception("TEST_SETUP_FAILED");
}
Process StartChild(string mode, string path)
{
    var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot find current process executable.");
    var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
    start.ArgumentList.Add("--child"); start.ArgumentList.Add(mode); start.ArgumentList.Add(path);
    return Process.Start(start) ?? throw new Exception("Cannot launch child process.");
}
var directory = Path.Combine(Path.GetTempPath(), "KeySafe-v100-resilience-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
try
{
    var path = Path.Combine(directory, "synthetic.ksv");
    using (var v = new VaultStore(path))
    {
        v.Create(password);
        v.TakeNewRecoveryKeys();
        v.Upsert(new Credential { Title = "Original", Password = "SYNTHETIC-ORIGINAL" });
    }
    Check(VaultDatabase.IsSqlite(path), "disposable vault created as SQLite");
    Check(CrashChild("uncommitted", path) != 0, "intentional process termination before transaction commit");
    var abandonedJournal = path + "-journal";
    Check(File.Exists(abandonedJournal), "rollback journal survives abrupt uncommitted process termination");
    Check(!Encoding.UTF8.GetString(File.ReadAllBytes(abandonedJournal)).Contains("SYNTHETIC-ORIGINAL"), "abandoned rollback journal contains no synthetic plaintext");
    using (var v = new VaultStore(path))
    {
        v.Unlock(password);
        Check(v.Credentials.Count == 1 && v.Credentials.Single().Title == "Original", "SQLite rollback after abrupt termination");
    }
    Check(CrashChild("committed", path) != 0, "intentional process termination after committed save");
    using (var v = new VaultStore(path))
    {
        v.Unlock(password);
        Check(v.Credentials.Count == 2 && v.Credentials.Any(c => c.Title == "Committed"), "committed save survives abrupt termination");
        for (int i = 0; i < 100; i++) v.Upsert(new Credential { Title = "Load-" + i, Password = "SYNTHETIC-TEST-" + i });
        Check(v.Credentials.Count == 102, "100 transactional credential writes");
        var priorEnvelope = VaultDatabase.Read(path);
        var priorRevision = VaultDatabase.ReadRevision(path);
        v.Upsert(new Credential { Title = "Post-snapshot", Password = "SYNTHETIC-NEWER" });
        var currentEnvelope = VaultDatabase.Read(path);
        var currentRevision = VaultDatabase.ReadRevision(path);
        ReplaceState(path, priorEnvelope, priorRevision);
        Rejected(() => v.CreateEncryptedBackup(), "backup rejects externally replaced stale primary");
        ReplaceState(path, currentEnvelope, currentRevision);
        var backup = v.CreateEncryptedBackup();
        var shortBackup = Path.Combine(directory, "truncated.ksbackup");
        File.WriteAllBytes(shortBackup, File.ReadAllBytes(backup).Take(100).ToArray());
        var before = SHA256.HashData(File.ReadAllBytes(path));
        Rejected(() => v.RestoreEncryptedBackup(shortBackup, password), "truncated backup rejected");
        Check(before.SequenceEqual(SHA256.HashData(File.ReadAllBytes(path))), "failed restore leaves primary byte-for-byte unchanged");
    }
    using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
    {
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE snapshots SET encrypted_envelope='not-a-blob' WHERE id=(SELECT max(id) FROM snapshots)";
        command.ExecuteNonQuery();
    }
    using (var v = new VaultStore(path))
    {
        v.Unlock(password);
        _ = v.VerifiedSnapshotRevisions();
        Check(true, "malformed snapshot storage class is safely ignored");
    }
    var lifecyclePath = Path.Combine(directory, "lifecycle.ksv");
    using (var v = new VaultStore(lifecyclePath))
    {
        v.Create(password); v.TakeNewRecoveryKeys(); v.Lock();
        using var started = new ManualResetEventSlim();
        var unlock = Task.Run(() => { started.Set(); v.Unlock(password); });
        started.Wait(); Thread.Sleep(25);
        v.Lock();
        unlock.GetAwaiter().GetResult();
        Check(!v.IsUnlocked, "lock serializes with an in-flight background unlock");
    }
    using (var holder = StartChild("hold", path))
    {
        var wait = Stopwatch.StartNew();
        while (!File.Exists(path + ".ready") && wait.Elapsed < TimeSpan.FromSeconds(10)) Thread.Sleep(20);
        Check(File.Exists(path + ".ready"), "independent child process holds vault lease");
        using var contender = new VaultStore(path);
        Rejected(() => contender.Unlock(password), "second process cannot open leased vault");
        var alias = Path.Combine(directory, "synthetic-hardlink.ksv");
        if (!NativeMethods.CreateHardLink(alias, path, IntPtr.Zero)) throw new IOException("Hard-link test setup failed: " + Marshal.GetLastWin32Error());
        using var aliasContender = new VaultStore(alias);
        Rejected(() => aliasContender.Unlock(password), "hard-link alias cannot bypass vault identity lease");
        File.WriteAllText(path + ".release", "release");
        Check(holder.WaitForExit(10000) && holder.ExitCode == 0, "vault lease released on clean process exit");
    }
    using (var v = new VaultStore(path))
    {
        v.Unlock(password);
        v.Upsert(new Credential { Title = "After lease", Password = "SYNTHETIC" });
        Check(v.Credentials.Any(c => c.Title == "After lease"), "writes succeed after prior process releases lease");
    }
    var beforeLockedWrite = SHA256.HashData(File.ReadAllBytes(path));
    using (var v = new VaultStore(path))
    {
        v.Unlock(password);
        using var externalLock = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Rejected(() => v.Upsert(new Credential { Title = "Blocked by sharing violation", Password = "SYNTHETIC" }), "sharing violation fails closed");
        Check(!v.IsUnlocked, "failed persistence locks the vault");
    }
    Check(beforeLockedWrite.SequenceEqual(SHA256.HashData(File.ReadAllBytes(path))), "sharing violation leaves primary byte-for-byte unchanged");

    var backupFailureDir = Path.Combine(directory, "backup-failure"); Directory.CreateDirectory(backupFailureDir);
    var backupFailurePath = Path.Combine(backupFailureDir, "vault.ksv");
    using (var v = new VaultStore(backupFailurePath))
    {
        v.Create(password); v.TakeNewRecoveryKeys(); v.Upsert(new Credential { Title = "Original", Password = "SYNTHETIC" });
        File.WriteAllText(Path.Combine(backupFailureDir, "backups"), "blocks directory creation");
        Rejected(() => v.CreateEncryptedBackup(), "backup destination failure is reported");
        Check(v.IsUnlocked && v.Credentials.Count == 1, "backup failure preserves unlocked primary state");
    }
    Console.WriteLine($"ALL {checks} RESILIENCE CHECKS PASSED. Only disposable synthetic vaults were used.");
}

finally
{
    // Synthetic data is expendable and the test never touches %LOCALAPPDATA%\KeySafe.
    try { Directory.Delete(directory, true); } catch { }
}

internal static partial class NativeMethods
{
    [LibraryImport("Kernel32.dll", EntryPoint = "CreateHardLinkW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CreateHardLink(string newFileName, string existingFileName, IntPtr securityAttributes);
}
