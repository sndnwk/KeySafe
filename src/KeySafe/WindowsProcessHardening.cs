using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace KeySafe;

internal static class WindowsProcessHardening
{
    private const uint LoadLibrarySearchApplicationDir = 0x00000200;
    private const uint LoadLibrarySearchSystem32 = 0x00000800;
    private const string ExpectedSqliteX64Hash = "B7385D722C83FB52142A00477A726723745916D22A555711EE89834C1111FB2E";

    internal static void Apply()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("KeySafe v1.1.0 supports Windows x64 only.");
        if (!SetDefaultDllDirectories(LoadLibrarySearchApplicationDir | LoadLibrarySearchSystem32))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to harden the native DLL search path.");
        VerifyPinnedNativeFile("e_sqlite3.dll", ExpectedSqliteX64Hash);
        SodiumNative.EnsureInitialized();
    }

    private static void VerifyPinnedNativeFile(string fileName, string expectedHex)
    {
        var path = new[] {
            Path.Combine(AppContext.BaseDirectory, fileName),
            Path.Combine(AppContext.BaseDirectory, "runtimes", "win-x64", "native", fileName)
        }.FirstOrDefault(File.Exists)
            ?? throw new DllNotFoundException($"The pinned {fileName} is missing from the application directory.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actual = SHA256.HashData(stream);
        var expected = Convert.FromHexString(expectedHex);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
                throw new BadImageFormatException($"{fileName} failed its pinned SHA-256 integrity check.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDefaultDllDirectories(uint directoryFlags);
}
