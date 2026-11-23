using System.IO;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace KeySafe;

public sealed class VaultStore : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false, PropertyNameCaseInsensitive = false, MaxDepth = 32, AllowDuplicateProperties = false };
    private const long MaximumVaultBytes = 32 * 1024 * 1024;
    private const int RecoveryKeyCount = 10;
    private const int MemoryBytes = 268435456;
    private const int Iterations = 3;
    public const int MaximumCategoryLength = 64;
    public const int MaximumCategories = 100;
    public string PathOnDisk { get; }
    private SodiumSecureBuffer? _rootKey;
    private readonly object _lifecycleSync = new();
    private FileStream? _vaultLease;
    private FileStream? _vaultIdentityLease;
    private const long IdentityLockOffset = long.MaxValue - 1;
    private VaultFile? _file;
    private VaultPayload? _payload;
    private List<string>? _newRecoveryKeys;
    public bool IsUnlocked => _rootKey != null;
    public int RecoveryKeysRemaining => _file?.RecoverySlots.Count ?? 0;
    public IReadOnlyList<Credential> Credentials => _payload?.Credentials ?? new List<Credential>();
    public IReadOnlyList<string> Categories => _payload?.Categories.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList() ?? new List<string>();
    public const int MaximumAttachmentBytes = 2 * 1024 * 1024;
    public const int MaximumTotalAttachmentBytes = 8 * 1024 * 1024;
    public VaultStore(string path) => PathOnDisk = path;
    public bool Exists => File.Exists(PathOnDisk);
    public IReadOnlyList<CredentialVersion> PasswordHistory => _payload?.PasswordHistory ?? new List<CredentialVersion>();
    public string BackupFolder => System.IO.Path.Combine(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(PathOnDisk))!, "backups");


    public void Create(string password)
    {
        lock (_lifecycleSync)
        {
        if (Exists) throw new IOException("A vault already exists. It will not be overwritten.");
        ValidatePassword(password);
        AcquireLease();
        var salt = Security.Random(16);
        var masterKey = Security.DeriveMasterKey(password, salt, MemoryBytes, Iterations);
        var root = Security.Random(Security.KeyBytes);
        var file = new VaultFile { VaultId = Guid.NewGuid(), Salt = Convert.ToBase64String(salt) };
        try
        {
            file.WrappedKey = Convert.ToBase64String(Security.Encrypt(root, masterKey, Security.Aad(file.VaultId, "root-wrap", file.Version)));
            SetRootKey(root);
            _file = file;
            _payload = new VaultPayload();
            _newRecoveryKeys = GenerateSlots(file, root);
            Save();
            AcquireIdentityLeaseIfPresent();
        }
        catch { Lock(); throw; }
        finally { Security.Clear(masterKey); Security.Clear(root); }
        }
    }

    public void Unlock(string password)
    {
        lock (_lifecycleSync)
        {
        Lock();
        AcquireLease();
        try { UnlockCore(password); }
        catch { Lock(); throw; }
        }
    }

    private void UnlockCore(string password)
    {
        var file = ReadFile();
        var salt = Convert.FromBase64String(file.Salt);
        var masterKey = Security.DeriveMasterKey(password, salt, file.KdfMemoryBytes, file.KdfIterations);
        byte[]? root = null;
        try
        {
            root = Security.Decrypt(Convert.FromBase64String(file.WrappedKey), masterKey, Security.Aad(file.VaultId, "root-wrap", file.Version));
            OpenWithRoot(file, root);
            root = null; // OpenWithRoot copied and cleared the temporary root.
        }
        finally { Security.Clear(root); Security.Clear(masterKey); }
    }

    public IReadOnlyList<string> Recover(string recoveryCode, string newPassword)
    {
        lock (_lifecycleSync)
        {
        Lock();
        ValidatePassword(newPassword);
        AcquireLease();
        try { return RecoverCore(recoveryCode, newPassword); }
        catch { Lock(); throw; }
        }
    }

    private IReadOnlyList<string> RecoverCore(string recoveryCode, string newPassword)
    {
        var file = ReadFile();
        if (file.Version != KeySafeInfo.VaultFormatVersion) throw new InvalidOperationException("This vault does not have v1.1 recovery keys.");
        var codeKey = ParseRecoveryCode(recoveryCode);
        byte[]? root = null;
        try
        {
            RecoverySlot? matched = null;
            foreach (var slot in file.RecoverySlots)
            {
                try
                {
                    var candidate = Security.Decrypt(Convert.FromBase64String(slot.WrappedKey), codeKey, Security.Aad(file.VaultId, "recovery:" + slot.Id.ToString("D"), file.Version));
                    if (candidate.Length == Security.KeyBytes) { matched = slot; root = candidate; break; }
                    Security.Clear(candidate);
                }
                catch (SodiumException) { }
            }
            if (matched == null || root == null) throw new CryptographicException("Invalid or previously consumed recovery key.");
            OpenWithRoot(file, root);
            root = null; // OpenWithRoot copied and cleared the temporary root.
            try
            {
                var freshRoot = Security.Random(Security.KeyBytes);
                try
                {
                    SetRootKey(freshRoot);
                    SetMasterWrapping(newPassword, file, freshRoot);
                    file.RecoverySlots.Clear();
                    _newRecoveryKeys = GenerateSlots(file, freshRoot);
                }
                finally { Security.Clear(freshRoot); }
                Save(retainPrevious: false, clearSnapshots: true);
                return TakeNewRecoveryKeys();
            }
            catch { Lock(); throw; }
        }
        finally { Security.Clear(root); Security.Clear(codeKey); }
    }

    public IReadOnlyList<string> ChangeMasterPassword(string currentPassword, string newPassword)
    {
        RequireUnlock();
        ValidatePassword(newPassword);
        // Verify the CURRENT password, not just the fact that the vault is unlocked.
        var currentKey = Security.DeriveMasterKey(currentPassword, Convert.FromBase64String(_file!.Salt), _file.KdfMemoryBytes, _file.KdfIterations);
        byte[]? candidate = null;
        try
        {
            candidate = Security.Decrypt(Convert.FromBase64String(_file.WrappedKey), currentKey, Security.Aad(_file.VaultId, "root-wrap", _file.Version));
            if (!CryptographicOperations.FixedTimeEquals(candidate, RootKey)) throw new CryptographicException("Master password verification failed.");
            var freshRoot = Security.Random(Security.KeyBytes);
            try
            {
                SetRootKey(freshRoot);
                SetMasterWrapping(newPassword, _file, freshRoot);
                _file.RecoverySlots.Clear();
                _newRecoveryKeys = GenerateSlots(_file, freshRoot);
                SaveOrLock(retainPrevious: false, clearSnapshots: true);
                return TakeNewRecoveryKeys();
            }
            catch { Lock(); throw; }
            finally { Security.Clear(freshRoot); }
        }
        finally { Security.Clear(candidate); Security.Clear(currentKey); }
    }

    public IReadOnlyList<string> RotateVaultKey(string currentPassword)
    {
        RequireUnlock();
        // Rotating the root invalidates ALL previous recovery keys. New ones must be saved.
        var currentKey = Security.DeriveMasterKey(currentPassword, Convert.FromBase64String(_file!.Salt), _file.KdfMemoryBytes, _file.KdfIterations);
        byte[]? candidate = null;
        try
        {
            candidate = Security.Decrypt(Convert.FromBase64String(_file.WrappedKey), currentKey, Security.Aad(_file.VaultId, "root-wrap", _file.Version));
            if (!CryptographicOperations.FixedTimeEquals(candidate, RootKey)) throw new CryptographicException("Master password verification failed.");
            var freshRoot = Security.Random(Security.KeyBytes);
            try
            {
                SetRootKey(freshRoot);
                SetMasterWrapping(currentPassword, _file, freshRoot);
                _file.RecoverySlots.Clear();
                _newRecoveryKeys = GenerateSlots(_file, freshRoot);
                SaveOrLock(retainPrevious: false, clearSnapshots: true);
                return TakeNewRecoveryKeys();
            }
            catch { Lock(); throw; }
            finally { Security.Clear(freshRoot); }
        }
        finally { Security.Clear(candidate); Security.Clear(currentKey); }
    }

    public IReadOnlyList<string> TakeNewRecoveryKeys()
    {
        var result = _newRecoveryKeys ?? new List<string>();
        _newRecoveryKeys = null;
        return result;
    }

    public static void ValidatePassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (string.IsNullOrWhiteSpace(password) || password.Length < Security.MinimumPasswordCharacters ||
            password.Length > Security.MaximumPasswordCharacters)
            throw new ArgumentException($"Use a unique master password containing {Security.MinimumPasswordCharacters}â€“{Security.MaximumPasswordCharacters} characters.");
    }

    private static byte[] ParseRecoveryCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);
        if (code.Length > 128) throw new ArgumentException("Recovery key input is too long.");
        var clean = new string(code.Where(c => c != '-' && !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
        if (clean.StartsWith(KeySafeInfo.RecoveryKeyPrefix, StringComparison.Ordinal))
        {
            clean = clean[3..];
            if (clean.Length != 72 || !clean.All(Uri.IsHexDigit))
                throw new ArgumentException("The versioned recovery key has an invalid length or character.");
            var decoded = Convert.FromHexString(clean);
            try
            {
                var secret = decoded.AsSpan(0, Security.KeyBytes).ToArray();
                var expected = SHA256.HashData(secret).AsSpan(0, 4);
                if (!CryptographicOperations.FixedTimeEquals(expected, decoded.AsSpan(Security.KeyBytes, 4)))
                {
                    Security.Clear(secret);
                    throw new ArgumentException("The recovery key checksum is invalid. Check the transcription.");
                }
                return secret;
            }
            finally { Security.Clear(decoded); }
        }
        throw new ArgumentException($"Recovery key must be a {KeySafeInfo.RecoveryKeyPrefix} key generated by KeySafe v1.1.0.");
    }

    public static bool IsRecoveryCodeWellFormed(string code)
    {
        byte[]? parsed = null;
        try { parsed = ParseRecoveryCode(code); return true; }
        catch (ArgumentException) { return false; }
        finally { Security.Clear(parsed); }
    }

    private static List<string> GenerateSlots(VaultFile file, ReadOnlySpan<byte> root)
    {
        var output = new List<string>();
        for (int i = 0; i < RecoveryKeyCount; i++)
        {
            var secret = Security.Random(Security.KeyBytes);
            var slot = new RecoverySlot { Id = Guid.NewGuid() };
            try
            {
                slot.WrappedKey = Convert.ToBase64String(Security.Encrypt(root, secret, Security.Aad(file.VaultId, "recovery:" + slot.Id.ToString("D"), file.Version)));
                file.RecoverySlots.Add(slot);
                var checksum = SHA256.HashData(secret).AsSpan(0, 4);
                var encoded = Convert.ToHexString(secret) + Convert.ToHexString(checksum);
                output.Add(KeySafeInfo.RecoveryKeyPrefix + "-" + string.Join("-", Enumerable.Range(0, 9).Select(x => encoded.Substring(x * 8, 8))));
            }
            finally { Security.Clear(secret); }
        }
        return output;
    }

    private static void SetMasterWrapping(string password, VaultFile file, ReadOnlySpan<byte> root)
    {
        var salt = Security.Random(16);
        var masterKey = Security.DeriveMasterKey(password, salt, MemoryBytes, Iterations);
        try
        {
            file.KdfMemoryBytes = MemoryBytes;
            file.KdfIterations = Iterations;
            file.Salt = Convert.ToBase64String(salt);
            file.WrappedKey = Convert.ToBase64String(Security.Encrypt(root, masterKey, Security.Aad(file.VaultId, "root-wrap", file.Version)));
        }
        finally { Security.Clear(masterKey); }
    }

    private void OpenWithRoot(VaultFile file, byte[] root)
    {
        if (root.Length != Security.KeyBytes) throw new InvalidDataException("Invalid vault key.");
        var bytes = Security.Decrypt(Convert.FromBase64String(file.EncryptedPayload), root, Security.Aad(file.VaultId, "payload", file.Version));
        try
        {
            var payload = JsonSerializer.Deserialize<VaultPayload>(bytes, JsonOptions) ?? throw new InvalidDataException("Vault content is empty.");
            ValidatePayload(payload);
            if (VaultDatabase.ReadRevision(PathOnDisk) != payload.Revision)
                throw new InvalidDataException("Authenticated payload revision does not match the database revision.");
            _file = file; _payload = payload; SetRootKey(root);
        }
        finally { Security.Clear(bytes); Security.Clear(root); }
    }

    public void Upsert(Credential credential)
    {
        RequireUnlock();
        ValidateCredential(credential);
        if (credential.Category.Length != 0)
        {
            var canonical = _payload!.Categories.FirstOrDefault(x => x.Equals(credential.Category, StringComparison.OrdinalIgnoreCase));
            if (canonical == null)
            {
                if (_payload.Categories.Count >= MaximumCategories) throw new ArgumentException($"A vault supports at most {MaximumCategories} categories.");
                _payload.Categories.Add(credential.Category);
            }
            else credential.Category = canonical;
        }
        if (_payload!.Credentials.Where(c => c.Id != credential.Id).Sum(c => c.Attachments.Sum(a => (long)a.Data.Length)) +
            credential.Attachments.Sum(a => (long)a.Data.Length) > MaximumTotalAttachmentBytes)
            throw new ArgumentException("Vault attachment limit is 8 MiB.");
        var items = _payload!.Credentials;
        var existing = items.FindIndex(x => x.Id == credential.Id);
        if (existing < 0) items.Add(credential);
        else
        {
            var prior = items[existing];
            if (prior.Password != credential.Password)
            {
                _payload.PasswordHistory.Add(new CredentialVersion { CredentialId = credential.Id, SavedUtc = DateTime.UtcNow, Previous = new Credential { Id = prior.Id, Password = prior.Password } });
                _payload.PasswordHistory = _payload.PasswordHistory.OrderByDescending(h => h.SavedUtc)
                    .GroupBy(h => h.CredentialId).SelectMany(g => g.Take(10)).ToList();
            }
            items[existing] = credential;
        }
        SaveOrLock();
    }
    public void Delete(Guid id)
    {
        RequireUnlock();
        if (!_payload!.Credentials.Any(x => x.Id == id)) return;
        _payload.Credentials.RemoveAll(x => x.Id == id);
        _payload.PasswordHistory.RemoveAll(x => x.CredentialId == id);
        SaveOrLock();
    }

    public string AddCategory(string name)
    {
        RequireUnlock();
        var normalized = NormalizeCategory(name);
        if (_payload!.Categories.Any(x => x.Equals(normalized, StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("That category already exists.");
        if (_payload.Categories.Count >= MaximumCategories)
            throw new ArgumentException($"A vault supports at most {MaximumCategories} categories.");
        _payload.Categories.Add(normalized);
        SaveOrLock();
        return normalized;
    }

    public void DeleteCategory(string name)
    {
        RequireUnlock();
        var existing = _payload!.Categories.SingleOrDefault(x => x.Equals(name, StringComparison.OrdinalIgnoreCase))
            ?? throw new ArgumentException("Category not found.");
        _payload.Categories.Remove(existing);
        foreach (var credential in _payload.Credentials.Where(x => x.Category.Equals(existing, StringComparison.OrdinalIgnoreCase)))
            credential.Category = "";
        SaveOrLock();
    }
    private static Credential CloneCredential(Credential item) => new()
    {
        Id = item.Id, Title = item.Title, Username = item.Username, Email = item.Email, Password = item.Password, Category = item.Category,
        Website = item.Website, Notes = item.Notes, Favorite = item.Favorite,
        IsSecureNote = item.IsSecureNote, TotpSecret = item.TotpSecret,
        Attachments = item.Attachments.Select(a => new EncryptedAttachment {
            Id = a.Id, FileName = a.FileName, ContentType = a.ContentType,
            Data = (byte[])a.Data.Clone(), AddedUtc = a.AddedUtc }).ToList(),
        CreatedUtc = item.CreatedUtc, ModifiedUtc = item.ModifiedUtc
    };

    public IReadOnlyList<CredentialVersion> GetPasswordHistory(Guid credentialId)
    {
        RequireUnlock();
        return _payload!.PasswordHistory.Where(h => h.CredentialId == credentialId)
            .OrderByDescending(h => h.SavedUtc).ToList();
    }

    public void RestorePassword(Guid credentialId, int index)
    {
        RequireUnlock();
        var versions = GetPasswordHistory(credentialId);
        if (index < 0 || index >= versions.Count) throw new ArgumentOutOfRangeException(nameof(index));
        var current = _payload!.Credentials.SingleOrDefault(c => c.Id == credentialId)
            ?? throw new InvalidOperationException("Credential no longer exists.");
        var restored = CloneCredential(current);
        restored.Password = versions[index].Previous.Password;
        restored.ModifiedUtc = DateTime.UtcNow;
        Upsert(restored);
    }

    public string CreateEncryptedBackup()
    {
        RequireUnlock();
        var envelope = VaultDatabase.Read(PathOnDisk);
        ValidateLiveEnvelopeForBackup(envelope);
        var encrypted = Security.Encrypt(envelope, RootKey, Security.Aad(_file!.VaultId, "backup-snapshot", _file.Version));
        var backup = new VaultBackup { VaultId = _file.VaultId, CreatedUtc = DateTime.UtcNow,
            SourceRevision = _payload!.Revision, VaultEnvelope = Convert.ToBase64String(envelope),
            EncryptedVerification = Convert.ToBase64String(encrypted) };
        var data = JsonSerializer.SerializeToUtf8Bytes(backup, JsonOptions);
        try
        {
            Directory.CreateDirectory(BackupFolder);
            var name = $"keysafe-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid():N}.ksbackup";
            var destination = System.IO.Path.Combine(BackupFolder, name);
            WriteNewFile(destination, data);
            try
            {
                var onDisk = File.ReadAllBytes(destination);
                if (!CryptographicOperations.FixedTimeEquals(data, onDisk))
                    throw new IOException("Backup read-back verification failed.");
            }
            catch
            {
                File.Delete(destination);
                throw;
            }
            return destination;
        }
        finally { Security.Clear(envelope); Security.Clear(encrypted); Security.Clear(data); }
    }

    private void ValidateLiveEnvelopeForBackup(byte[] envelope)
    {
        var diskFile = JsonSerializer.Deserialize<VaultFile>(envelope, JsonOptions)
            ?? throw new InvalidDataException("Vault envelope is missing.");
        ValidateFileShape(diskFile);
        if (diskFile.VaultId != _file!.VaultId || diskFile.KdfMemoryBytes != _file.KdfMemoryBytes ||
            diskFile.KdfIterations != _file.KdfIterations || diskFile.Salt != _file.Salt ||
            diskFile.WrappedKey != _file.WrappedKey || diskFile.EncryptedPayload != _file.EncryptedPayload ||
            diskFile.RecoverySlots.Count != _file.RecoverySlots.Count ||
            !diskFile.RecoverySlots.Zip(_file.RecoverySlots).All(pair =>
                pair.First.Id == pair.Second.Id && pair.First.WrappedKey == pair.Second.WrappedKey))
            throw new IOException("The vault changed on disk. Lock and unlock it before creating a backup.");
        var plaintext = Security.Decrypt(Convert.FromBase64String(diskFile.EncryptedPayload), RootKey,
            Security.Aad(diskFile.VaultId, "payload", diskFile.Version));
        try
        {
            var payload = JsonSerializer.Deserialize<VaultPayload>(plaintext, JsonOptions)
                ?? throw new InvalidDataException("Vault payload is missing.");
            ValidatePayload(payload);
            var diskRevision = VaultDatabase.ReadRevision(PathOnDisk);
            if (payload.Revision != _payload!.Revision || diskRevision != _payload.Revision)
                throw new IOException("The vault revision changed on disk. Lock and unlock it before creating a backup.");
        }
        finally { Security.Clear(plaintext); }
    }

    private static void WriteNewFile(string path, byte[] data)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough);
        stream.Write(data);
        stream.Flush(true);
    }

    // Backups are intentionally self-contained: a lost original vault can be recovered using
    // its master password, while an unlocked vault may only restore the SAME vault identity.
    public void RestoreEncryptedBackup(string backupPath, string password)
    {
        AcquireLease();
        var backupBytes = ReadBoundedFile(backupPath, MaximumVaultBytes * 4, 16);
        VaultBackup backup;
        try
        {
            backup = JsonSerializer.Deserialize<VaultBackup>(backupBytes, JsonOptions)
                ?? throw new InvalidDataException("Invalid backup.");
        }
        finally { Security.Clear(backupBytes); }
        if (backup.Magic != "KEYSAFE-BACKUP" || backup.Version != KeySafeInfo.VaultFormatVersion || backup.VaultId == Guid.Empty)
            throw new InvalidDataException("Unsupported backup format.");
        var envelope = Convert.FromBase64String(backup.VaultEnvelope);
        if (envelope.Length < 64 || (long)envelope.Length > MaximumVaultBytes) throw new InvalidDataException("Invalid backup envelope size.");
        var source = JsonSerializer.Deserialize<VaultFile>(envelope, JsonOptions)
            ?? throw new InvalidDataException("Backup vault missing.");
        ValidateFileShape(source);
        if (source.VaultId != backup.VaultId || backup.SourceRevision < 1)
            throw new InvalidDataException("Backup vault identifier or format mismatch.");
        if (IsUnlocked && _file!.VaultId != source.VaultId)
            throw new InvalidOperationException("This backup belongs to a different vault.");
        var masterKey = Security.DeriveMasterKey(password, Convert.FromBase64String(source.Salt), source.KdfMemoryBytes, source.KdfIterations);
        byte[]? root = null;
        byte[]? verified = null;
        try
        {
            root = Security.Decrypt(Convert.FromBase64String(source.WrappedKey), masterKey,
                Security.Aad(source.VaultId, "root-wrap", source.Version));
            verified = Security.Decrypt(Convert.FromBase64String(backup.EncryptedVerification), root,
                Security.Aad(source.VaultId, "backup-snapshot", source.Version));
            if (!CryptographicOperations.FixedTimeEquals(envelope, verified))
                throw new CryptographicException("Encrypted backup authentication failed.");
            // Authenticate the actual encrypted payload before changing any disk file.
            var payload = Security.Decrypt(Convert.FromBase64String(source.EncryptedPayload), root,
                Security.Aad(source.VaultId, "payload", source.Version));
            try
            {
                var restored = JsonSerializer.Deserialize<VaultPayload>(payload, JsonOptions)
                    ?? throw new InvalidDataException("Backup payload missing.");
                ValidatePayload(restored);
                if (restored.Revision != backup.SourceRevision)
                    throw new InvalidDataException("Backup records invalid.");
            }
            finally { Security.Clear(payload); }
            // A restore must not silently overwrite a newer state. Explicit operator action required.
            ClearUnlockedState(releaseLease: false);
            VaultDatabase.ReplaceDamagedDatabase(PathOnDisk, envelope, backup.SourceRevision);
            UnlockCore(password);
        }
        finally { Security.Clear(root); Security.Clear(masterKey); Security.Clear(verified); Security.Clear(envelope); }
    }

    private static byte[] ReadBoundedFile(string path, long maximumBytes, int minimumBytes)
    {
        if (!File.Exists(path)) throw new InvalidDataException("File is missing.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536,
            FileOptions.SequentialScan);
        if (stream.Length < minimumBytes || stream.Length > maximumBytes || stream.Length > int.MaxValue)
            throw new InvalidDataException("File exceeds the permitted size range.");
        var data = new byte[checked((int)stream.Length)];
        try { stream.ReadExactly(data); return data; }
        catch { Security.Clear(data); throw; }
    }

    public IReadOnlyList<long> VerifiedSnapshotRevisions()
    {
        RequireUnlock();
        var revisions = new List<long>();
        foreach (var bytes in VaultDatabase.ReadSnapshots(PathOnDisk))
        {
            try
            {
                var file = JsonSerializer.Deserialize<VaultFile>(bytes, JsonOptions);
                if (file == null || file.VaultId != _file!.VaultId) continue;
                ValidateFileShape(file);
                var plaintext = Security.Decrypt(Convert.FromBase64String(file.EncryptedPayload), RootKey,
                    Security.Aad(file.VaultId, "payload", file.Version));
                try
                {
                    var payload = JsonSerializer.Deserialize<VaultPayload>(plaintext, JsonOptions);
                    if (payload != null) { ValidatePayload(payload); revisions.Add(payload.Revision); }
                }
                finally { Security.Clear(plaintext); }
            }
            catch (SodiumException) { }
            catch (InvalidDataException) { }
            catch (FormatException) { }
            catch (JsonException) { }
        }
        return revisions;
    }


    private static void ValidateCredential(Credential item)
    {
        if (item == null || item.Id == Guid.Empty || item.Title == null || item.Username == null || item.Email == null ||
            item.Password == null || item.Website == null || item.Notes == null || item.Category == null || item.TotpSecret == null ||
            string.IsNullOrWhiteSpace(item.Title) || item.Title.Length > 2048 || item.Username.Length > 4096 ||
            item.Email.Length > 4096 || item.Password.Length > 65536 || item.Website.Length > 4096 || item.Notes.Length > 524288 ||
            item.CreatedUtc == default || item.ModifiedUtc == default ||
            (item.IsSecureNote && (item.Category.Length != 0 || item.Username.Length != 0 || item.Email.Length != 0 ||
                item.Password.Length != 0 || item.Website.Length != 0 || item.TotpSecret.Length != 0)) ||
            item.Attachments == null ||
            !IsValidCategory(item.Category, allowEmpty: true) || (item.IsSecureNote && item.Category.Length != 0) || item.Attachments.Count > 24 ||
            item.Attachments.Any(a => a == null || a.Id == Guid.Empty || a.Data == null || a.ContentType == null ||
                a.ContentType.Length > 255 || a.AddedUtc == default || a.Data.Length > MaximumAttachmentBytes || !IsSafeAttachmentFileName(a.FileName)) ||
            item.Attachments.Select(a => a.Id).Distinct().Count() != item.Attachments.Count)
            throw new ArgumentException("Invalid credential record.");
        if (item.TotpSecret.Length > 2048) throw new ArgumentException("TOTP configuration exceeds length limit.");
        if (!string.IsNullOrWhiteSpace(item.TotpSecret))
        {
            var configuration = Totp.Parse(item.TotpSecret);
            Security.Clear(configuration.Secret);
        }
    }

    private static void ValidatePayload(VaultPayload payload)
    {
        if (payload.SchemaVersion != 1 || payload.Revision < 1 || payload.Credentials == null || payload.Credentials.Count > 100000 ||
            payload.Categories == null || payload.Categories.Count > MaximumCategories ||
            payload.Categories.Any(x => x == null || !IsValidCategory(x, allowEmpty: false)) ||
            payload.Categories.Distinct(StringComparer.OrdinalIgnoreCase).Count() != payload.Categories.Count ||
            payload.PasswordHistory == null || payload.PasswordHistory.Count > 100000)
            throw new InvalidDataException("Invalid vault payload structure.");

        var credentialIds = new HashSet<Guid>();
        long attachmentBytes = 0;
        foreach (var item in payload.Credentials)
        {
            if (item == null || !credentialIds.Add(item.Id) || item.Category == null ||
                (item.Category.Length != 0 && !payload.Categories.Contains(item.Category, StringComparer.OrdinalIgnoreCase)))
                throw new InvalidDataException("Invalid credential record.");
            try { ValidateCredential(item); }
            catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
            { throw new InvalidDataException("Invalid credential record.", ex); }
            attachmentBytes = checked(attachmentBytes + item.Attachments.Sum(a => (long)a.Data.Length));
            if (attachmentBytes > MaximumTotalAttachmentBytes) throw new InvalidDataException("Vault attachment limit exceeded.");
        }

        var historyCounts = new Dictionary<Guid, int>();
        foreach (var version in payload.PasswordHistory)
        {
            if (version == null || version.Previous == null || version.CredentialId == Guid.Empty ||
                !credentialIds.Contains(version.CredentialId) || version.Previous.Id != version.CredentialId ||
                version.Previous.Password == null || version.Previous.Password.Length > 65536 || version.SavedUtc == default)
                throw new InvalidDataException("Invalid password history record.");
            historyCounts[version.CredentialId] = historyCounts.GetValueOrDefault(version.CredentialId) + 1;
            if (historyCounts[version.CredentialId] > 10) throw new InvalidDataException("Password history limit exceeded.");
        }
    }

    public static string NormalizeCategory(string name)
    {
        var normalized = name?.Trim() ?? "";
        if (!IsValidCategory(normalized, allowEmpty: false))
            throw new ArgumentException($"Category names must contain 1–{MaximumCategoryLength} visible characters.");
        return normalized;
    }

    private static bool IsValidCategory(string value, bool allowEmpty)
    {
        if (value.Length == 0) return allowEmpty;
        return value.Length <= MaximumCategoryLength && value == value.Trim() && !value.Any(char.IsControl);
    }

    public void AddAttachment(Guid credentialId, string fileName, byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        RequireUnlock();
        var existing = _payload!.Credentials.SingleOrDefault(c => c.Id == credentialId) ?? throw new InvalidOperationException("Entry not found.");
        if (content.Length > MaximumAttachmentBytes) throw new ArgumentException("Attachments are limited to 2 MiB each.");
        if (!IsSafeAttachmentFileName(fileName))
            throw new ArgumentException("Invalid attachment filename.");
        var updated = CloneCredential(existing);
        updated.Attachments.Add(new EncryptedAttachment { FileName = fileName, Data = (byte[])content.Clone() });
        updated.ModifiedUtc = DateTime.UtcNow;
        Upsert(updated);
    }

    private static bool IsSafeAttachmentFileName(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName) || fileName.Length > 255 ||
            System.IO.Path.IsPathRooted(fileName) || System.IO.Path.IsPathFullyQualified(fileName) ||
            fileName != System.IO.Path.GetFileName(fileName) || fileName.EndsWith(' ') || fileName.EndsWith('.') ||
            fileName.Normalize(NormalizationForm.FormC) != fileName) return false;
        const string invalid = "<>:\"/\\|?*";
        if (fileName.Any(c => char.IsControl(c) || invalid.Contains(c) ||
            CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.Format)) return false;
        var stem = fileName.Split('.')[0].TrimEnd(' ', '.');
        string[] reserved = ["CON", "PRN", "AUX", "NUL", "CLOCK$", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"];
        return !reserved.Contains(stem, StringComparer.OrdinalIgnoreCase);
    }

    public byte[] ReadAttachment(Guid credentialId, Guid attachmentId)
    {
        RequireUnlock();
        var attachment = _payload!.Credentials.Single(c => c.Id == credentialId).Attachments.Single(a => a.Id == attachmentId);
        return (byte[])attachment.Data.Clone();
    }

    public void RemoveAttachment(Guid credentialId, Guid attachmentId)
    {
        RequireUnlock();
        var original = _payload!.Credentials.Single(c => c.Id == credentialId);
        var updated = CloneCredential(original);
        if (updated.Attachments.RemoveAll(a => a.Id == attachmentId) != 1) throw new InvalidOperationException("Attachment not found.");
        updated.ModifiedUtc = DateTime.UtcNow;
        Upsert(updated);
    }

    public void ImportCredentials(IReadOnlyList<Credential> incoming)
    {
        ArgumentNullException.ThrowIfNull(incoming);
        RequireUnlock();
        if (incoming.Count is < 1 or > 5000) throw new ArgumentException("Import requires 1–5000 entries.");
        var ids = new HashSet<Guid>(_payload!.Credentials.Select(x => x.Id));
        foreach (var item in incoming)
        {
            ValidateCredential(item);
            if (!ids.Add(item.Id)) throw new ArgumentException("Repeated entry identifier.");
        }
        var incomingCategories = incoming.Select(x => x.Category).Where(x => x.Length != 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (_payload.Categories.Concat(incomingCategories).Distinct(StringComparer.OrdinalIgnoreCase).Count() > MaximumCategories)
            throw new ArgumentException($"A vault supports at most {MaximumCategories} categories.");
        foreach (var category in incomingCategories)
        {
            var canonical = _payload.Categories.FirstOrDefault(x => x.Equals(category, StringComparison.OrdinalIgnoreCase));
            if (canonical == null) _payload.Categories.Add(category);
            else foreach (var item in incoming.Where(x => x.Category.Equals(category, StringComparison.OrdinalIgnoreCase))) item.Category = canonical;
        }
        _payload.Credentials.AddRange(incoming);
        SaveOrLock();
    }

    private void SaveOrLock(bool retainPrevious = true, bool clearSnapshots = false)
    {
        try { Save(retainPrevious, clearSnapshots); }
        catch { Lock(); throw; }
    }
    private void RequireUnlock()
    {
        if (_rootKey == null || _file == null || _payload == null) throw new InvalidOperationException("Vault is locked.");
    }
    private VaultFile ReadFile()
    {
        var length = new FileInfo(PathOnDisk).Length;
        if (length is < 64 or > MaximumVaultBytes * 4) throw new InvalidDataException("Invalid vault file size.");
        var envelope = VaultDatabase.Read(PathOnDisk);
        var file = JsonSerializer.Deserialize<VaultFile>(envelope, JsonOptions) ?? throw new InvalidDataException("Invalid vault file.");
        ValidateFileShape(file);
        return file;
    }

    private static void ValidateFileShape(VaultFile file)
    {
        if (file.Magic != "KEYSAFE-VAULT" || file.Version != KeySafeInfo.VaultFormatVersion || file.VaultId == Guid.Empty ||
            file.KdfMemoryBytes != MemoryBytes || file.KdfIterations != Iterations ||
            file.EncryptedPayload == null || file.EncryptedPayload.Length > MaximumVaultBytes ||
            file.WrappedKey == null || file.WrappedKey.Length > 1024 || file.Salt == null || file.Salt.Length > 128 ||
            file.RecoverySlots == null || file.RecoverySlots.Count > RecoveryKeyCount ||
            file.RecoverySlots.Any(x => x == null || x.Id == Guid.Empty || x.WrappedKey == null || x.WrappedKey.Length > 1024) ||
            file.RecoverySlots.Select(x => x.Id).Distinct().Count() != file.RecoverySlots.Count)
            throw new InvalidDataException("Unsupported or malformed vault format.");
        try
        {
            if (Convert.FromBase64String(file.Salt).Length != 16 ||
                Convert.FromBase64String(file.WrappedKey).Length != SodiumNative.NonceBytes + SodiumNative.TagBytes + Security.KeyBytes ||
                Convert.FromBase64String(file.EncryptedPayload).Length < SodiumNative.NonceBytes + SodiumNative.TagBytes ||
                file.RecoverySlots.Any(x => Convert.FromBase64String(x.WrappedKey).Length != SodiumNative.NonceBytes + SodiumNative.TagBytes + Security.KeyBytes))
                throw new InvalidDataException("Unsupported or malformed vault encoding.");
        }
        catch (FormatException ex) { throw new InvalidDataException("Unsupported or malformed vault encoding.", ex); }
    }
    private void Save(bool retainPrevious = true, bool clearSnapshots = false)
    {
        RequireUnlock();
        _payload!.Revision++;
        ValidatePayload(_payload);
        var content = JsonSerializer.SerializeToUtf8Bytes(_payload, JsonOptions);
        byte[]? ciphertext = null;
        try
        {
            if (content.Length > MaximumVaultBytes / 2) throw new IOException("Vault exceeds the current storage limit.");
            ciphertext = Security.Encrypt(content, RootKey, Security.Aad(_file!.VaultId, "payload", _file.Version));
            _file.EncryptedPayload = Convert.ToBase64String(ciphertext);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(_file, JsonOptions);
            try { VaultDatabase.Write(PathOnDisk, bytes, _payload.Revision, retainPrevious, clearSnapshots); }
            finally { Security.Clear(bytes); }
        }
        finally { Security.Clear(content); Security.Clear(ciphertext); }
    }
    public void Lock()
    {
        lock (_lifecycleSync) ClearUnlockedState(releaseLease: true);
    }

    private ReadOnlySpan<byte> RootKey
    {
        get
        {
            if (_rootKey == null) throw new InvalidOperationException("Vault is locked.");
            return _rootKey.AsReadOnlySpan();
        }
    }

    private void SetRootKey(ReadOnlySpan<byte> source)
    {
        var replacement = new SodiumSecureBuffer(Security.KeyBytes);
        try
        {
            source.CopyTo(replacement.AsSpan());
            replacement.ProtectReadOnly();
        }
        catch { replacement.Dispose(); throw; }
        Interlocked.Exchange(ref _rootKey, replacement)?.Dispose();
    }

    private void AcquireLease()
    {
        if (_vaultLease != null) return;
        var fullPath = System.IO.Path.GetFullPath(PathOnDisk);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(fullPath)!);
        try
        {
            _vaultLease = new FileStream(fullPath + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite,
                FileShare.Read, 1, FileOptions.WriteThrough);
            AcquireIdentityLeaseIfPresent();
        }
        catch (IOException ex)
        {
            throw new IOException("This vault is already open in another KeySafe instance.", ex);
        }
    }

    private void AcquireIdentityLeaseIfPresent()
    {
        if (_vaultIdentityLease != null || !File.Exists(PathOnDisk)) return;
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("KeySafe v1.1.0 supports Windows only.");
        FileStream? candidate = null;
        try
        {
            candidate = new FileStream(PathOnDisk, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.None);
            candidate.Lock(IdentityLockOffset, 1);
            _vaultIdentityLease = candidate;
        }
        catch (IOException ex)
        {
            candidate?.Dispose();
            throw new IOException("This vault file is already open through this path or another filesystem alias.", ex);
        }
    }

    private void ClearUnlockedState(bool releaseLease)
    {
        _rootKey?.Dispose();
        _rootKey = null;
        if (_payload != null)
        {
            foreach (var item in _payload.Credentials) { item.Password = ""; item.Notes = ""; item.TotpSecret = ""; item.Category = ""; item.Email = "";
                foreach (var a in item.Attachments) Security.Clear(a.Data); item.Attachments.Clear(); }
            _payload.Credentials.Clear();
            foreach (var version in _payload.PasswordHistory) { version.Previous.Password = ""; version.Previous.Notes = ""; version.Previous.TotpSecret = ""; version.Previous.Email = "";
                foreach (var a in version.Previous.Attachments) Security.Clear(a.Data); version.Previous.Attachments.Clear(); }
            _payload.PasswordHistory.Clear();
            _payload.Categories.Clear();
        }
        _payload = null;
        _file = null;
        _newRecoveryKeys = null;
        if (releaseLease)
        {
            _vaultIdentityLease?.Dispose();
            _vaultIdentityLease = null;
            _vaultLease?.Dispose();
            _vaultLease = null;
        }
    }
    public void Dispose() => Lock();
}
