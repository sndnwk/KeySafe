using System.IO;
using System.Security.Cryptography;

namespace KeySafe;

public static class PlaintextExport
{
    public static void WriteVerified(string path, byte[] data)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(data);
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath) ?? throw new IOException("Export directory is unavailable.");
        var temporaryPath = Path.Combine(directory, "." + Path.GetFileName(fullPath) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536,
                       FileOptions.WriteThrough))
            {
                stream.Write(data);
                stream.Flush(true);
            }
            var written = File.ReadAllBytes(temporaryPath);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(data, written))
                    throw new IOException("Export read-back verification failed.");
            }
            finally { Security.Clear(written); }
            if (File.Exists(fullPath)) File.Replace(temporaryPath, fullPath, null, false);
            else File.Move(temporaryPath, fullPath);
        }
        finally
        {
            try { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); } catch { }
            Security.Clear(data);
        }
    }
}
