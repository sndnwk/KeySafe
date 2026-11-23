using System.Security.Cryptography;
using System.Text;

namespace KeySafe;

public sealed record TotpConfiguration(byte[] Secret, int Digits, int Period, string Algorithm);

public static class Totp
{
    public static TotpConfiguration Parse(string input)
    {
        if (string.IsNullOrWhiteSpace(input) || input.Length > 2048)
            throw new ArgumentException("A TOTP secret or otpauth URI is required.");
        string secret = input.Trim();
        int digits = 6, period = 30;
        string algorithm = "SHA1";
        if (secret.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(secret, UriKind.Absolute, out var uri) ||
                !uri.Scheme.Equals("otpauth", StringComparison.OrdinalIgnoreCase) ||
                !uri.Host.Equals("totp", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Only otpauth://totp URIs are supported.");
            var fields = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries);
            var args = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in fields)
            {
                int sep = item.IndexOf('=');
                if (sep <= 0) continue;
                var name = Uri.UnescapeDataString(item[..sep].Replace('+', ' '));
                var value = Uri.UnescapeDataString(item[(sep + 1)..].Replace('+', ' '));
                if (!args.TryAdd(name, value)) throw new ArgumentException("Duplicate OTP parameter.");
            }
            if (!args.TryGetValue("secret", out var parsedSecret)) throw new ArgumentException("Missing OTP secret.");
            secret = parsedSecret;
            if (args.TryGetValue("digits", out var d) && !int.TryParse(d, out digits)) throw new ArgumentException("Invalid OTP digits.");
            if (args.TryGetValue("period", out var p) && !int.TryParse(p, out period)) throw new ArgumentException("Invalid OTP period.");
            if (args.TryGetValue("algorithm", out var a)) algorithm = a.ToUpperInvariant().Replace("-", "");
        }
        if (digits is < 6 or > 8 || period is < 15 or > 120 || algorithm is not ("SHA1" or "SHA256" or "SHA512"))
            throw new ArgumentException("Unsupported OTP settings (6–8 digits, 15–120 seconds, SHA1/256/512).");
        var key = DecodeBase32(secret);
        if (key.Length < 10 || key.Length > 128) throw new ArgumentException("OTP secret must contain 10–128 bytes.");
        return new TotpConfiguration(key, digits, period, algorithm);
    }

    private static byte[] DecodeBase32(string text)
    {
        string normalized = new(text.Where(c => !char.IsWhiteSpace(c) && c != '-').ToArray());
        normalized = normalized.TrimEnd('=').ToUpperInvariant();
        if (normalized.Length is < 16 or > 205) throw new ArgumentException("Invalid Base32 secret length.");
        var result = new List<byte>();
        uint buffer = 0;
        int bits = 0;
        foreach (var c in normalized)
        {
            int digit = c switch { >= 'A' and <= 'Z' => c - 'A', >= '2' and <= '7' => c - '2' + 26, _ => -1 };
            if (digit < 0) throw new ArgumentException("TOTP secret is not valid Base32.");
            buffer = (buffer << 5) | (uint)digit;
            bits += 5;
            if (bits >= 8) { bits -= 8; result.Add((byte)(buffer >> bits)); buffer &= (uint)((1 << bits) - 1); }
        }
        if (bits > 0 && buffer != 0) throw new ArgumentException("Invalid Base32 padding bits.");
        return result.ToArray();
    }

    public static string Generate(TotpConfiguration config, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(config);
        long step = now.ToUnixTimeSeconds() / config.Period;
        Span<byte> counter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, step);
        byte[] mac = config.Algorithm switch
        {
            "SHA256" => HMACSHA256.HashData(config.Secret, counter),
            "SHA512" => HMACSHA512.HashData(config.Secret, counter),
#pragma warning disable CA5350 // RFC 6238 interoperability requires HMAC-SHA1; this is a keyed MAC, not a password hash.
            _ => HMACSHA1.HashData(config.Secret, counter)
#pragma warning restore CA5350
        };
        try
        {
            int offset = mac[^1] & 15;
            uint value = ((uint)(mac[offset] & 127) << 24) | ((uint)mac[offset + 1] << 16) |
                         ((uint)mac[offset + 2] << 8) | mac[offset + 3];
            int modulus = config.Digits switch { 6 => 1000000, 7 => 10000000, _ => 100000000 };
            return (value % modulus).ToString("D" + config.Digits);
        }
        finally { CryptographicOperations.ZeroMemory(mac); }
    }

    public static int SecondsRemaining(TotpConfiguration config, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(config);
        return config.Period - (int)(now.ToUnixTimeSeconds() % config.Period);
    }
}
