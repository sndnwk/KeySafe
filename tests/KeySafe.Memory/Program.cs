using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using KeySafe;
using Microsoft.Win32.SafeHandles;

const string password = "Synthetic-Memory-Test-Master-2026";

if (args.Length == 3 && args[0] == "--child")
{
    RunChild(args[1], args[2]);
    return;
}
if (args.Length == 2 && args[0] == "--locked-child")
{
    File.WriteAllText(Path.Combine(args[1], "replacement.ready"), "ready");
    WaitForRequest(Path.Combine(args[1], "replacement-exit.request"));
    return;
}

var folder = Path.Combine(Path.GetTempPath(), "KeySafe-memory-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(folder);
var marker = "KEYSAFE_SYNTHETIC_" + Guid.NewGuid().ToString("N") + "_MEMORY_MARKER";
var markerFile = Path.Combine(folder, "marker.txt");
File.WriteAllText(markerFile, marker, new UTF8Encoding(false));
var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot find test executable.");
var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
start.ArgumentList.Add("--child"); start.ArgumentList.Add(folder); start.ArgumentList.Add(markerFile);
using var child = Process.Start(start) ?? throw new InvalidOperationException("Cannot start memory test child.");

try
{
    WaitFor(Path.Combine(folder, "unlocked.ready"), child);
    var unlockedDump = Path.Combine(folder, "unlocked.dmp");
    WriteFullDump(child, unlockedDump);
    var unlockedUtf8 = Contains(unlockedDump, Encoding.UTF8.GetBytes(marker));
    var unlockedUtf16 = Contains(unlockedDump, Encoding.Unicode.GetBytes(marker));
    if (!unlockedUtf8 && !unlockedUtf16) throw new Exception("FAIL: synthetic unlocked marker was not found in full process dump; test setup is inconclusive.");
    Console.WriteLine($"PASS: unlocked full-memory dump contains synthetic marker (UTF8={unlockedUtf8}, UTF16={unlockedUtf16})");

    File.WriteAllText(Path.Combine(folder, "lock.request"), "lock");
    if (!child.WaitForExit(10000) || child.ExitCode != 0) throw new Exception("FAIL: memory child did not exit cleanly.");
    var postLockDump = Path.Combine(folder, "post-lock.dmp");
    var dumpSucceeded = false;
    try { WriteFullDump(child, postLockDump); dumpSucceeded = true; } catch (Exception) { }
    if (dumpSucceeded) throw new Exception("FAIL: exited unlocked process remained dumpable after secure lock.");
    Console.WriteLine("PASS: secure lock terminated the process; its former managed heap is no longer dumpable.");

    var replacementStart = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
    replacementStart.ArgumentList.Add("--locked-child"); replacementStart.ArgumentList.Add(folder);
    using var replacement = Process.Start(replacementStart) ?? throw new InvalidOperationException("Cannot start replacement process.");
    WaitFor(Path.Combine(folder, "replacement.ready"), replacement);
    var replacementDump = Path.Combine(folder, "replacement.dmp");
    WriteFullDump(replacement, replacementDump);
    var replacementUtf8 = Contains(replacementDump, Encoding.UTF8.GetBytes(marker));
    var replacementUtf16 = Contains(replacementDump, Encoding.Unicode.GetBytes(marker));
    if (replacementUtf8 || replacementUtf16) throw new Exception("FAIL: replacement locked process retained the prior credential marker.");
    Console.WriteLine("PASS: replacement locked-process dump contains no prior marker in UTF-8 or UTF-16.");
    File.WriteAllText(Path.Combine(folder, "replacement-exit.request"), "exit");
    if (!replacement.WaitForExit(10000) || replacement.ExitCode != 0) throw new Exception("FAIL: replacement process did not exit cleanly.");
}
finally
{
    if (!child.HasExited) child.Kill(true);
    try { Directory.Delete(folder, true); } catch { }
}

static void RunChild(string folder, string markerFile)
{
    var marker = File.ReadAllText(markerFile, Encoding.UTF8);
    File.Delete(markerFile);
    var path = Path.Combine(folder, "synthetic.ksv");
    using var vault = new VaultStore(path);
    vault.Create(password);
    vault.TakeNewRecoveryKeys();
    vault.Upsert(new Credential { Title = "Memory test", Password = marker, Notes = marker });
    File.WriteAllText(Path.Combine(folder, "unlocked.ready"), "ready");
    WaitForRequest(Path.Combine(folder, "lock.request"));
    vault.Lock();
    marker = string.Empty;
    Environment.Exit(0);
}

static void WaitFor(string path, Process child)
{
    var timer = Stopwatch.StartNew();
    while (!File.Exists(path) && timer.Elapsed < TimeSpan.FromSeconds(30))
    {
        if (child.HasExited) throw new Exception("FAIL: memory child exited early with " + child.ExitCode);
        Thread.Sleep(25);
    }
    if (!File.Exists(path)) throw new TimeoutException("Timed out waiting for " + Path.GetFileName(path));
}

static void WaitForRequest(string path)
{
    var timer = Stopwatch.StartNew();
    while (!File.Exists(path) && timer.Elapsed < TimeSpan.FromSeconds(30)) Thread.Sleep(25);
    if (!File.Exists(path)) throw new TimeoutException("Timed out waiting for parent request.");
}

static void WriteFullDump(Process process, string path)
{
    using var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
    if (!MiniDumpWriteDump(process.Handle, (uint)process.Id, file.SafeFileHandle, 0x00000002, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "MiniDumpWriteDump failed.");
    file.Flush(true);
}

static bool Contains(string path, byte[] needle)
{
    const int blockSize = 1024 * 1024;
    var buffer = new byte[blockSize + needle.Length - 1];
    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, blockSize, FileOptions.SequentialScan);
    var carry = 0;
    while (true)
    {
        var read = stream.Read(buffer, carry, blockSize);
        if (read == 0) return false;
        var total = carry + read;
        if (buffer.AsSpan(0, total).IndexOf(needle) >= 0) return true;
        carry = Math.Min(needle.Length - 1, total);
        buffer.AsSpan(total - carry, carry).CopyTo(buffer);
    }
}

[DllImport("Dbghelp.dll", SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
static extern bool MiniDumpWriteDump(IntPtr processHandle, uint processId, SafeFileHandle fileHandle,
    uint dumpType, IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam);
