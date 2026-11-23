using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace KeySafe;
public static class Security
{
    public const int KeyBytes = 32;
    public const int MinimumPasswordCharacters = 12;
    public const int MaximumPasswordCharacters = 1024;
    public static byte[] Random(int count) => RandomNumberGenerator.GetBytes(count);
    public static byte[] DeriveMasterKey(string password, byte[] salt, int memory, int iterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        if (password.Length > MaximumPasswordCharacters || salt.Length != 16 ||
            memory is < 67108864 or > 536870912 || iterations is < 2 or > 6)
            throw new InvalidDataException("Unsupported key derivation settings.");
        return SodiumNative.DeriveKey(password, salt, iterations, memory);
    }
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad)
    {
        if (key.Length != KeyBytes) throw new ArgumentException("Invalid encryption key.");
        return SodiumNative.Encrypt(plaintext, key, aad);
    }
    public static byte[] Decrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad)
    {
        if (key.Length != KeyBytes || encrypted.Length < SodiumNative.NonceBytes + SodiumNative.TagBytes)
            throw new InvalidDataException("Vault data is invalid or truncated.");
        return SodiumNative.Decrypt(encrypted, key, aad);
    }
    public static byte[] Aad(Guid vaultId, string purpose, int version) => Encoding.UTF8.GetBytes($"KeySafe|{version}|{vaultId:D}|{purpose}");
    public static string GeneratePassword(int length, bool symbols)
    {
        const string letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        const string extra = "!@#$%^&*-_=+?";
        string alphabet = symbols ? letters + extra : letters;
        if (length is < 12 or > 128) throw new ArgumentOutOfRangeException(nameof(length));
        char[] output = new char[length];
        for (int i = 0; i < output.Length; i++) output[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        return new string(output);
    }
    public static string PasswordGuidance(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.Length == 0) return "Use a unique generated password or a long, randomly selected multiword passphrase.";
        var lower = password.ToLowerInvariant();
        var common = new[] { "password", "qwerty", "letmein", "welcome", "admin", "keysafe", "123456" };
        var predictable = common.Any(lower.Contains) || password.Distinct().Count() < Math.Min(6, password.Length / 2);
        var classes = (password.Any(char.IsLower) ? 1 : 0) + (password.Any(char.IsUpper) ? 1 : 0) +
            (password.Any(char.IsDigit) ? 1 : 0) + (password.Any(c => !char.IsLetterOrDigit(c)) ? 1 : 0);
        var rating = !predictable && password.Length >= 20 && classes >= 2 ? "Strong local estimate" :
            !predictable && password.Length >= 14 && classes >= 2 ? "Moderate local estimate" : "Weak/predictable local estimate";
        return rating + ". Length and uniqueness matter most; this estimate does not check online breach databases.";
    }
    public static void Clear(byte[]? secret)
    {
        if (secret != null) CryptographicOperations.ZeroMemory(secret);
    }
}
