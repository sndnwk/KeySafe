using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace KeySafe;

public sealed class SodiumException : CryptographicException
{
    public SodiumException(string message) : base(message) { }
}

internal static class SodiumNative
{
    internal const int KeyBytes = 32;
    internal const int NonceBytes = 24;
    internal const int TagBytes = 16;
    private const int Argon2Id13 = 2;
    private const string ExpectedWindowsX64Hash = "64A1F143868309069F0A0A3C8141C0853C4F17243DDF734E92B11C5411739771";

    static SodiumNative()
    {
        NativeLibrary.SetDllImportResolver(typeof(SodiumNative).Assembly, ResolveLibrary);
        if (sodium_init() < 0) throw new SodiumException("libsodium initialization failed.");
        var version = Marshal.PtrToStringAnsi(sodium_version_string());
        if (version != "1.0.22") throw new SodiumException($"Unsupported libsodium version: {version ?? "unknown"}.");
    }

    internal static void EnsureInitialized() { }

    private static IntPtr ResolveLibrary(string libraryName, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!libraryName.Equals("libsodium", StringComparison.Ordinal)) return IntPtr.Zero;
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("KeySafe v1.1.0 supports Windows x64 only.");
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "libsodium.dll"),
            Path.Combine(AppContext.BaseDirectory, "runtimes", "win-x64", "native", "libsodium.dll")
        };
        var path = candidates.FirstOrDefault(File.Exists)
            ?? throw new DllNotFoundException("The pinned libsodium.dll is missing from the application directory.");
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var actual = SHA256.HashData(stream);
            var expected = Convert.FromHexString(ExpectedWindowsX64Hash);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(actual, expected))
                    throw new BadImageFormatException("libsodium.dll failed its pinned SHA-256 integrity check.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
                CryptographicOperations.ZeroMemory(expected);
            }
            // Keep write/delete sharing denied across verification and image loading.
            return NativeLibrary.Load(path);
        }
    }

    internal static byte[] DeriveKey(string password, byte[] salt, int iterations, int memory)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var output = new byte[KeyBytes];
        try
        {
            if (crypto_pwhash(output, (ulong)output.Length, passwordBytes, (ulong)passwordBytes.Length, salt,
                    (ulong)iterations, (nuint)memory, Argon2Id13) != 0)
                throw new SodiumException("Argon2id key derivation failed.");
            return output;
        }
        catch { CryptographicOperations.ZeroMemory(output); throw; }
        finally { CryptographicOperations.ZeroMemory(passwordBytes); }
    }

    internal static unsafe byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad)
    {
        var message = plaintext.ToArray();
        var associated = aad.ToArray();
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var body = new byte[checked(message.Length + TagBytes)];
        try
        {
            fixed (byte* keyPointer = key)
            {
                if (crypto_aead_xchacha20poly1305_ietf_encrypt(body, out var bodyLength, message, (ulong)message.Length,
                        associated, (ulong)associated.Length, IntPtr.Zero, nonce, (IntPtr)keyPointer) != 0 || bodyLength != (ulong)body.Length)
                    throw new SodiumException("Authenticated encryption failed.");
            }
            var combined = new byte[NonceBytes + body.Length];
            nonce.CopyTo(combined, 0);
            body.CopyTo(combined, NonceBytes);
            return combined;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            CryptographicOperations.ZeroMemory(associated); CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(body);
        }
    }

    internal static unsafe byte[] Decrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad)
    {
        var nonce = encrypted[..NonceBytes].ToArray();
        var body = encrypted[NonceBytes..].ToArray();
        var associated = aad.ToArray();
        var plaintext = new byte[body.Length - TagBytes];
        try
        {
            fixed (byte* keyPointer = key)
            {
                if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext, out var plaintextLength, IntPtr.Zero,
                        body, (ulong)body.Length, associated, (ulong)associated.Length, nonce, (IntPtr)keyPointer) != 0 ||
                    plaintextLength != (ulong)plaintext.Length)
                    throw new SodiumException("Authentication failed.");
            }
            return plaintext;
        }
        catch { CryptographicOperations.ZeroMemory(plaintext); throw; }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(body);
            CryptographicOperations.ZeroMemory(associated);
        }
    }

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)] private static extern int sodium_init();
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)] private static extern IntPtr sodium_version_string();
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_pwhash(byte[] output, ulong outputLength, byte[] password, ulong passwordLength,
        byte[] salt, ulong operations, nuint memory, int algorithm);
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_aead_xchacha20poly1305_ietf_encrypt(byte[] ciphertext, out ulong ciphertextLength,
        byte[] message, ulong messageLength, byte[] associatedData, ulong associatedDataLength, IntPtr secretNonce,
        byte[] publicNonce, IntPtr key);
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
    private static extern int crypto_aead_xchacha20poly1305_ietf_decrypt(byte[] message, out ulong messageLength,
        IntPtr secretNonce, byte[] ciphertext, ulong ciphertextLength, byte[] associatedData,
        ulong associatedDataLength, byte[] publicNonce, IntPtr key);
}

internal sealed unsafe class SodiumSecureBuffer : IDisposable
{
    private IntPtr _pointer;
    public int Length { get; }
    public bool IsReadOnly { get; private set; }

    public SodiumSecureBuffer(int length)
    {
        SodiumNative.EnsureInitialized();
        Length = length;
        _pointer = sodium_malloc((nuint)length);
        if (_pointer == IntPtr.Zero) throw new SodiumException("libsodium secure-memory allocation failed.");
        new Span<byte>((void*)_pointer, Length).Clear();
    }

    public Span<byte> AsSpan()
    {
        var pointer = _pointer;
        if (pointer == IntPtr.Zero) throw new ObjectDisposedException(nameof(SodiumSecureBuffer));
        if (IsReadOnly && sodium_mprotect_readwrite(pointer) != 0) throw new SodiumException("Secure-memory protection change failed.");
        IsReadOnly = false;
        return new Span<byte>((void*)pointer, Length);
    }

    public ReadOnlySpan<byte> AsReadOnlySpan()
    {
        var pointer = _pointer;
        if (pointer == IntPtr.Zero) throw new ObjectDisposedException(nameof(SodiumSecureBuffer));
        return new ReadOnlySpan<byte>((void*)pointer, Length);
    }

    public void ProtectReadOnly()
    {
        if (_pointer == IntPtr.Zero || sodium_mprotect_readonly(_pointer) != 0) throw new SodiumException("Secure-memory protection change failed.");
        IsReadOnly = true;
    }

    public void Dispose()
    {
        var pointer = Interlocked.Exchange(ref _pointer, IntPtr.Zero);
        if (pointer == IntPtr.Zero) return;
        if (sodium_mprotect_readwrite(pointer) == 0)
            sodium_memzero(pointer, (nuint)Length);
        sodium_free(pointer);
        GC.SuppressFinalize(this);
    }

    ~SodiumSecureBuffer() => Dispose();

    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)] private static extern IntPtr sodium_malloc(nuint size);
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)] private static extern void sodium_free(IntPtr pointer);
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)] private static extern void sodium_memzero(IntPtr pointer, nuint size);
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)] private static extern int sodium_mprotect_readonly(IntPtr pointer);
    [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)] private static extern int sodium_mprotect_readwrite(IntPtr pointer);
}
