using System.Text.Json.Serialization;
namespace KeySafe;
public sealed class Credential
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Title { get; set; } = "";
    public string Username { get; set; } = "";
    public string Email { get; set; } = "";
    public string Password { get; set; } = "";
    public string Website { get; set; } = "";
    public string Notes { get; set; } = "";
    public string Category { get; set; } = "";
    public bool Favorite { get; set; }
    public bool IsSecureNote { get; set; }
    public string TotpSecret { get; set; } = "";
    public List<EncryptedAttachment> Attachments { get; set; } = new();
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime ModifiedUtc { get; set; } = DateTime.UtcNow;
    [JsonIgnore] public string Avatar => IsSecureNote ? "✎" : string.IsNullOrWhiteSpace(Title) ? "?" : Title.Trim()[0].ToString().ToUpperInvariant();
    [JsonIgnore] public string Subtitle => IsSecureNote ? "Secure note" :
        !string.IsNullOrWhiteSpace(Username) ? Username : !string.IsNullOrWhiteSpace(Email) ? Email :
        !string.IsNullOrWhiteSpace(Website) ? Website : "No username or email";
    [JsonIgnore] public string CategoryDisplay => string.IsNullOrWhiteSpace(Category) ? "Uncategorized" : Category;
}
public sealed class EncryptedAttachment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string FileName { get; set; } = "";
    public string ContentType { get; set; } = "application/octet-stream";
    public byte[] Data { get; set; } = Array.Empty<byte>();
    public DateTime AddedUtc { get; set; } = DateTime.UtcNow;
    [JsonIgnore] public string Display => $"{FileName} ({Data.Length / 1024.0:F1} KB)";
}
public sealed class CredentialVersion
{
    public Guid CredentialId { get; set; }
    public DateTime SavedUtc { get; set; }
    public Credential Previous { get; set; } = new();
}
public sealed class VaultPayload
{
    public int SchemaVersion { get; set; } = 1;
    public long Revision { get; set; }
    public List<string> Categories { get; set; } = new();
    public List<CredentialVersion> PasswordHistory { get; set; } = new();
    public List<Credential> Credentials { get; set; } = new();
}
public sealed class RecoverySlot
{
    public Guid Id { get; set; }
    public string WrappedKey { get; set; } = "";
}
public sealed class VaultFile
{
    public string Magic { get; set; } = "KEYSAFE-VAULT";
    public int Version { get; set; } = KeySafeInfo.VaultFormatVersion;
    public Guid VaultId { get; set; }
    public int KdfMemoryBytes { get; set; } = 268435456;
    public int KdfIterations { get; set; } = 3;
    public string Salt { get; set; } = "";
    public string WrappedKey { get; set; } = "";
    public string EncryptedPayload { get; set; } = "";
    public List<RecoverySlot> RecoverySlots { get; set; } = new();
}

public sealed class VaultBackup
{
    public string Magic { get; set; } = "KEYSAFE-BACKUP";
    public int Version { get; set; } = KeySafeInfo.VaultFormatVersion;
    public Guid VaultId { get; set; }
    public DateTime CreatedUtc { get; set; }
    public long SourceRevision { get; set; }
    public string VaultEnvelope { get; set; } = "";
    public string EncryptedVerification { get; set; } = "";
}
