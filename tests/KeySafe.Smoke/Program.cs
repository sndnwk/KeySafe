using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KeySafe;

var folder = Path.Combine(Path.GetTempPath(), "KeySafe-v110-test-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(folder);
const string master = "Strong-Unique-KeySafe-Test-Master-2026";
const string changed = "New-Long-Strong-Master-2026";
int passed = 0;
void Check(bool condition, string label)
{
    if (!condition) throw new Exception("FAIL: " + label);
    Console.WriteLine("PASS: " + label);
    passed++;
}
void MustReject(Action action, string label)
{
    var rejected = false;
    try { action(); }
    catch (Exception e) when (e is CryptographicException or SodiumException or InvalidDataException or IOException or UnauthorizedAccessException or JsonException or ArgumentException) { rejected = true; }
    Check(rejected, label);
}
try
{
    Check(new VaultPayload().SchemaVersion == 1 && KeySafeInfo.VaultFormatVersion == 5, "v1.1 payload schema and vault format are explicit");
    var path = Path.Combine(folder, "primary.ksv");
    string[] keys;
    using (var vault = new VaultStore(path))
    {
        vault.Create(master);
        var rootField = typeof(VaultStore).GetField("_rootKey", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        Check(rootField.GetValue(vault) is SodiumSecureBuffer secureRoot && secureRoot.IsReadOnly && secureRoot.Length == Security.KeyBytes,
            "vault root key held in libsodium protected secure memory");
        keys = vault.TakeNewRecoveryKeys().ToArray();
        Check(keys.Length == 10 && keys.Distinct().Count() == 10 && keys.All(k => k.StartsWith("KS2-") && VaultStore.IsRecoveryCodeWellFormed(k)), "ten independent v1.1 checksum-protected recovery keys");
        Check(!VaultStore.IsRecoveryCodeWellFormed("KS1-" + new string('A', 72)) && !VaultStore.IsRecoveryCodeWellFormed(new string('A', 64)), "v1.1 rejects legacy recovery-key encodings");
        var damagedRecovery = keys[0].ToCharArray();
        damagedRecovery[^1] = damagedRecovery[^1] == 'A' ? 'B' : 'A';
        Check(!VaultStore.IsRecoveryCodeWellFormed(new string(damagedRecovery)), "recovery checksum detects transcription error");
        Check(VaultDatabase.IsSqlite(path), "SQLite primary file created");
        Check(vault.AddCategory("  Work  ") == "Work" && vault.AddCategory("Personal") == "Personal", "encrypted categories created and whitespace normalized");
        MustReject(() => vault.AddCategory("work"), "duplicate category rejected case-insensitively");
        MustReject(() => vault.AddCategory("bad\ncategory"), "control character in category rejected");
        MustReject(() => vault.AddCategory(new string('A', VaultStore.MaximumCategoryLength + 1)), "oversized category rejected");
        MustReject(() => vault.Upsert(new Credential { Title = "Bad note", IsSecureNote = true, Category = "Work" }), "secure notes cannot be assigned password categories");
        MustReject(() => vault.Upsert(new Credential { Title = "Hidden secret", IsSecureNote = true, Password = "must-not-hide" }), "secure notes reject hidden credential fields");
        MustReject(() => vault.Upsert(new Credential { Title = "Oversized email", Email = new string('e', 4097) }), "oversized email rejected");
        vault.Upsert(new Credential { Title = "Private Site", Username = "example-user", Email = "private@example.test", Password = "ORIGINAL-SECRET", Notes = "Top Secret", Category = "Work" });
        Check(vault.Credentials.Count == 1, "credential created");
        Check(vault.VerifiedSnapshotRevisions().Count >= 1, "authenticated SQLite snapshots");
        vault.Lock();
    }
    var data = File.ReadAllBytes(path);
    var raw = Encoding.UTF8.GetString(data);
    Check(!raw.Contains("ORIGINAL-SECRET") && !raw.Contains("Private Site") && !raw.Contains("private@example.test") && !raw.Contains("Work") && !raw.Contains(keys[0]), "no plaintext credentials, email, categories, or recovery codes in SQLite");
    using (var vault = new VaultStore(path))
    {
        MustReject(() => vault.Unlock("wrong-password"), "wrong master rejected");
        Check(File.ReadAllBytes(path).SequenceEqual(data), "failed authentication leaves SQLite source byte-for-byte unchanged");
        vault.Unlock(master);
        Check(File.ReadAllBytes(path).SequenceEqual(data), "successful authentication reads SQLite source without mutation");
        Check(vault.Credentials.Single().Password == "ORIGINAL-SECRET" && vault.Credentials.Single().Username == "example-user" && vault.Credentials.Single().Email == "private@example.test" && vault.Credentials.Single().Category == "Work" && vault.Categories.Count == 2, "separate username, email, password, and categories roundtrip");
        var current = vault.Credentials.Single();
        vault.Upsert(new Credential { Id = current.Id, Title = current.Title, Username = current.Username, Email = current.Email, Password = "REPLACED-SECRET", Notes = current.Notes, Category = current.Category });
        Check(vault.GetPasswordHistory(current.Id).Count == 1, "password history on update");
        vault.RestorePassword(current.Id, 0);
        Check(vault.Credentials.Single().Password == "ORIGINAL-SECRET", "restore previous password");
        Check(vault.GetPasswordHistory(current.Id).Count == 2, "history includes restored prior version");
        var backup = vault.CreateEncryptedBackup();
        Check(File.Exists(backup), "verified backup created");
        var backupText = File.ReadAllText(backup);
        Check(!backupText.Contains("ORIGINAL-SECRET") && !backupText.Contains(keys[1]), "backup contains no plaintext secrets");
        vault.Upsert(new Credential { Title = "Added Later", Password = "LATER-SECRET" });
        Check(vault.Credentials.Count == 2, "writes after backup");
        vault.RestoreEncryptedBackup(backup, master);
        Check(vault.Credentials.Count == 1 && vault.Credentials.Single().Password == "ORIGINAL-SECRET" && vault.Credentials.Single().Category == "Work" && vault.Categories.Contains("Personal"), "backup and empty-category restoration roundtrip");
        var changedKeys = vault.ChangeMasterPassword(master, changed).ToArray();
        Check(changedKeys.Length == 10, "master change rotates root and recovery keys");
        Check(VaultDatabase.SnapshotCount(path) == 0, "master change purges retired unlock envelopes");
        vault.Lock();
        MustReject(() => vault.Unlock(master), "old master rejected after change");
        vault.Unlock(changed);
        Check(vault.Credentials.Single().Password == "ORIGINAL-SECRET", "master change retained credentials");
        var newKeys = vault.RotateVaultKey(changed).ToArray();
        Check(newKeys.Length == 10, "key rotation generates ten new keys");
        Check(VaultDatabase.SnapshotCount(path) == 0, "root rotation purges pre-rotation snapshots");
        vault.Lock();
        MustReject(() => vault.Recover(keys[1], "Another-Long-Master-2026"), "obsolete recovery code rejected");
        var recoveryKeys = vault.Recover(newKeys[0], "Recovery-Now-New-Master-2026").ToArray();
        Check(recoveryKeys.Length == 10 && vault.RecoveryKeysRemaining == 10 && vault.Credentials.Count == 1, "recovery rotates root and replaces all keys");
        Check(VaultDatabase.SnapshotCount(path) == 0, "recovery rotation purges snapshots containing retired keys");
        vault.Lock();
        MustReject(() => vault.Recover(newKeys[0], "Repeat-Recovery-Key-2026"), "recovery code reuse rejected");
    }
    // Verify repeated recovery rotations preserve data and revoke each preceding key set.
    var tenPath = Path.Combine(folder, "ten.ksv");
    using (var vault = new VaultStore(tenPath)) { vault.Create(master); keys = vault.TakeNewRecoveryKeys().ToArray(); vault.Upsert(new Credential { Title = "permanent", Password = "SAME" }); }
    for (int i = 0; i < 10; i++)
    {
        using var vault = new VaultStore(tenPath);
        var used = keys[0];
        keys = vault.Recover(used, "New-Master-Recovery-" + i + "-2026").ToArray();
        Check(vault.RecoveryKeysRemaining == 10 && keys.Length == 10 && vault.Credentials.Single().Password == "SAME", $"recovery rotation {i+1}/10 retained data and issued replacement keys");
        vault.Lock();
        MustReject(() => vault.Recover(used, "Rejected-Old-Recovery-" + i + "-2026"), $"recovery rotation {i+1}/10 revoked prior key");
    }
    // Strict isolation: an older/non-SQLite vault is rejected and never migrated or rewritten.
    var unsupportedPath = Path.Combine(folder, "unsupported.ksv");
    var unsupportedBytes = Encoding.UTF8.GetBytes("{\"Magic\":\"KEYSAFE-VAULT\",\"Version\":2}");
    File.WriteAllBytes(unsupportedPath, unsupportedBytes);
    using (var vault = new VaultStore(unsupportedPath))
    {
        MustReject(() => vault.Unlock(master), "non-SQLite vault rejected without migration");
    }
    Check(File.ReadAllBytes(unsupportedPath).SequenceEqual(unsupportedBytes), "unsupported vault remains byte-for-byte untouched");
    Check(!File.Exists(unsupportedPath + ".pre-sqlite.ksv"), "no migration artifacts created");
    // Corruption and backup restore from locked state.
    var damagedPath = Path.Combine(folder, "damaged.ksv");
    string recoveryBackup;
    using (var vault = new VaultStore(damagedPath))
    {
        vault.Create(master);
        vault.Upsert(new Credential { Title = "repair", Password = "RESTORABLE" });
        recoveryBackup = vault.CreateEncryptedBackup();
    }
    var corrupted = File.ReadAllBytes(damagedPath);
    corrupted[0] ^= 0x40;
    File.WriteAllBytes(damagedPath, corrupted);
    using (var vault = new VaultStore(damagedPath))
    {
        MustReject(() => vault.Unlock(master), "corrupt SQLite header rejected");
        MustReject(() => vault.RestoreEncryptedBackup(recoveryBackup, "incorrect-master"), "incorrect backup password rejected");
        Check(File.ReadAllBytes(damagedPath)[0] == corrupted[0], "failed restore did not overwrite damaged source");
        vault.RestoreEncryptedBackup(recoveryBackup, master);
        Check(vault.Credentials.Single().Password == "RESTORABLE", "disaster recovery after corrupt primary");
        Check(Directory.GetFiles(folder, "damaged.ksv.damaged-*").Length == 1, "damaged database quarantined");
    }
    // Backup authentication and tamper test without changing current vault.
    using (var vault = new VaultStore(damagedPath))
    {
        vault.Unlock(master);
        var oversizedBackup = Path.Combine(folder, "oversized.ksbackup");
        using (var oversized = new FileStream(oversizedBackup, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            oversized.SetLength(128L * 1024 * 1024 + 1);
        MustReject(() => vault.RestoreEncryptedBackup(oversizedBackup, master), "oversized backup rejected before unbounded allocation");
        var backup = vault.CreateEncryptedBackup();
        var tampered = JsonSerializer.Deserialize<VaultBackup>(File.ReadAllText(backup))!;
        var cipher = Convert.FromBase64String(tampered.EncryptedVerification);
        cipher[^1] ^= 0x01;
        tampered.EncryptedVerification = Convert.ToBase64String(cipher);
        File.WriteAllText(backup, JsonSerializer.Serialize(tampered));
        MustReject(() => vault.RestoreEncryptedBackup(backup, master), "altered backup authentication tag rejected");
        Check(vault.IsUnlocked && vault.Credentials.Single().Password == "RESTORABLE", "failed restore preserves unlocked vault");

        // An attacker who already knows the password/root can create an authenticated but
        // structurally invalid backup. Restore must validate it fully before replacing the
        // current database, otherwise malformed relationships can destroy a good primary.
        var malformedBackupPath = vault.CreateEncryptedBackup();
        var malformedBackup = JsonSerializer.Deserialize<VaultBackup>(File.ReadAllText(malformedBackupPath))!;
        var malformedEnvelopeBytes = Convert.FromBase64String(malformedBackup.VaultEnvelope);
        var malformedEnvelope = JsonSerializer.Deserialize<VaultFile>(malformedEnvelopeBytes)!;
        var rootField = typeof(VaultStore).GetField("_rootKey", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        var secureRoot = (SodiumSecureBuffer)rootField.GetValue(vault)!;
        var root = secureRoot.AsReadOnlySpan().ToArray();
        byte[]? malformedPlaintext = null;
        byte[]? malformedCiphertext = null;
        byte[]? malformedVerification = null;
        try
        {
            malformedPlaintext = Security.Decrypt(Convert.FromBase64String(malformedEnvelope.EncryptedPayload), root,
                Security.Aad(malformedEnvelope.VaultId, "payload", malformedEnvelope.Version));
            var malformedPayload = JsonSerializer.Deserialize<VaultPayload>(malformedPlaintext)!;
            malformedPayload.Credentials.Single().Category = "missing-authenticated-category";
            Security.Clear(malformedPlaintext);
            malformedPlaintext = JsonSerializer.SerializeToUtf8Bytes(malformedPayload);
            malformedCiphertext = Security.Encrypt(malformedPlaintext, root,
                Security.Aad(malformedEnvelope.VaultId, "payload", malformedEnvelope.Version));
            malformedEnvelope.EncryptedPayload = Convert.ToBase64String(malformedCiphertext);
            malformedEnvelopeBytes = JsonSerializer.SerializeToUtf8Bytes(malformedEnvelope);
            malformedBackup.VaultEnvelope = Convert.ToBase64String(malformedEnvelopeBytes);
            malformedVerification = Security.Encrypt(malformedEnvelopeBytes, root,
                Security.Aad(malformedEnvelope.VaultId, "backup-snapshot", malformedEnvelope.Version));
            malformedBackup.EncryptedVerification = Convert.ToBase64String(malformedVerification);
            File.WriteAllText(malformedBackupPath, JsonSerializer.Serialize(malformedBackup));
        }
        finally
        {
            Security.Clear(root); Security.Clear(malformedPlaintext); Security.Clear(malformedCiphertext);
            Security.Clear(malformedVerification); Security.Clear(malformedEnvelopeBytes);
        }
        var primaryBeforeMalformedRestore = File.ReadAllBytes(damagedPath);
        MustReject(() => vault.RestoreEncryptedBackup(malformedBackupPath, master), "authenticated malformed backup payload rejected before replacement");
        Check(File.ReadAllBytes(damagedPath).SequenceEqual(primaryBeforeMalformedRestore), "malformed authenticated restore leaves primary byte-for-byte unchanged");
        Check(vault.IsUnlocked && vault.Credentials.Single().Password == "RESTORABLE", "malformed authenticated restore preserves unlocked state");
    }
    var probeKey = Security.Random(32);
    var aad = Encoding.UTF8.GetBytes("KeySafe 0.4 AEAD test");
    var message = Encoding.UTF8.GetBytes("encrypted message");
    try
    {
        var encrypted = Security.Encrypt(message, probeKey, aad);
        Check(Security.Decrypt(encrypted, probeKey, aad).SequenceEqual(message), "AEAD roundtrip");
        foreach (int pos in new[] { 0, SodiumNative.NonceBytes, encrypted.Length - 1 })
        {
            var mutated = (byte[])encrypted.Clone(); mutated[pos] ^= 1;
            MustReject(() => Security.Decrypt(mutated, probeKey, aad), "AEAD byte flip rejected at " + pos);
        }
        var nonces = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < 10000; i++)
        {
            var sample = Security.Encrypt(message, probeKey, aad);
            if (!nonces.Add(Convert.ToHexString(sample.AsSpan(0, SodiumNative.NonceBytes))))
                throw new Exception("FAIL: random AEAD nonce collision");
            Security.Clear(sample);
        }
        Check(nonces.Count == 10000, "10,000 generated AEAD nonces are unique");
    }
    finally { Security.Clear(probeKey); Security.Clear(message); }
    // Official libsodium XChaCha20-Poly1305 vector:
    // test/default/aead_xchacha20poly1305.c and .exp.
    var katKey = Enumerable.Range(0x80, 32).Select(i => (byte)i).ToArray();
    var katNonce = Convert.FromHexString("07000000404142434445464748494A4B4C4D4E4F50515253");
    var katAad = Convert.FromHexString("50515253C0C1C2C3C4C5C6C7");
    var katMessage = Encoding.ASCII.GetBytes("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
    var katExpected = Convert.FromHexString(
        "F8EBEA4875044066FC162A0604E171FEECFB3D20425248563BCFD5A155DCC47B" +
        "BDA70B86E5AB9B55002BD1274C02DB35321ACD7AF8B2E2D25015E136B7679458" +
        "E9F43243BF719D639BADB5FEAC03F80A19A96EF10CB1D15333A837B90946BA38" +
        "54EE74DA3F2585EFC7E1E170E17E15E563E77601F4F85CAFA8E5877614E143E6" +
        "8420");
    var katCombined = katNonce.Concat(katExpected).ToArray();
    var katActual = Security.Decrypt(katCombined, katKey, katAad);
    Check(katActual.SequenceEqual(katMessage), "official libsodium XChaCha20-Poly1305 known-answer vector");
    Security.Clear(katKey); Security.Clear(katMessage); Security.Clear(katActual); Security.Clear(katExpected); Security.Clear(katCombined);
    // RFC 6238 reference vectors, with the standard RFC 4226 ASCII secret.
    var otp = Totp.Parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    var otp8 = Totp.Parse("otpauth://totp/KeySafe:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1");
    Check(Totp.Generate(otp8, DateTimeOffset.FromUnixTimeSeconds(59)) == "94287082", "RFC 6238 SHA1 TOTP vector 59 seconds");
    Check(Totp.Generate(otp8, DateTimeOffset.FromUnixTimeSeconds(1111111109)) == "07081804", "RFC 6238 SHA1 TOTP vector 1111111109 seconds");
    Check(Totp.Generate(otp8, DateTimeOffset.FromUnixTimeSeconds(1234567890)) == "89005924", "RFC 6238 SHA1 TOTP vector 1234567890 seconds");
    var otp256 = Totp.Parse("otpauth://totp/key?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&digits=8&algorithm=SHA256");
    Check(Totp.Generate(otp256, DateTimeOffset.FromUnixTimeSeconds(59)) == "46119246", "RFC 6238 SHA256 TOTP vector");
    var otp512 = Totp.Parse("otpauth://totp/key?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&digits=8&algorithm=SHA512");
    Check(Totp.Generate(otp512, DateTimeOffset.FromUnixTimeSeconds(59)) == "90693936", "RFC 6238 SHA512 TOTP vector");
    Security.Clear(otp256.Secret); Security.Clear(otp512.Secret);
    Check(Totp.Generate(otp, DateTimeOffset.FromUnixTimeSeconds(59)).Length == 6, "TOTP default six digits");
    Check(Totp.SecondsRemaining(otp, DateTimeOffset.FromUnixTimeSeconds(59)) == 1, "TOTP countdown boundary");
    MustReject(() => Totp.Parse("otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), "HOTP rejected without counter state");
    MustReject(() => Totp.Parse("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=9"), "TOTP invalid length rejected");
    MustReject(() => Totp.Parse("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5"), "TOTP invalid hash rejected");
    Security.Clear(otp.Secret); Security.Clear(otp8.Secret);
    var fuzzRandom = new Random(0x4B455953);
    var parserFuzzTimer = Stopwatch.StartNew();
    for (var fuzzCase = 0; fuzzCase < 2000; fuzzCase++)
    {
        var length = fuzzRandom.Next(0, 4097);
        var chars = new char[length];
        for (var i = 0; i < chars.Length; i++) chars[i] = (char)fuzzRandom.Next(0, 128);
        var fuzz = new string(chars);
        try { CsvTransfer.Import(fuzz); }
        catch (Exception e) when (e is ArgumentException or InvalidDataException or FormatException) { }
        try
        {
            var fuzzTotp = Totp.Parse(fuzz);
            Security.Clear(fuzzTotp.Secret);
        }
        catch (Exception e) when (e is ArgumentException or InvalidDataException or FormatException or UriFormatException or OverflowException) { }
    }
    parserFuzzTimer.Stop();
    Check(true, $"2,000 deterministic bounded CSV/TOTP parser fuzz cases completed without crash (seed 0x4B455953, {parserFuzzTimer.ElapsedMilliseconds} ms)");
    var importText = "title,username,email,password,website,notes,favorite,type,totp,category\r\n" +
        "\"Example, quoted\",example-user,test@example.com,secret123,https://example.com,\"Line 1\nLine 2 with \"\"quotes\"\"\",true,password,,Imported Work\r\n" +
        "Secure note,,,,,\"Long, detailed note\",false,note,,\r\n";
    var imported = CsvTransfer.Import(importText);
    Check(imported.Count == 2 && imported[0].Title == "Example, quoted" && imported[0].Username == "example-user" && imported[0].Email == "test@example.com" && imported[0].Notes.Contains("\"quotes\"") && imported[0].Category == "Imported Work" && imported[1].IsSecureNote,
        "CSV RFC4180 quoted multiline and note import");
    var exported = CsvTransfer.Export(imported);
    var roundtrip = CsvTransfer.Import(exported);
    Check(roundtrip.Count == 2 && roundtrip[0].Username == imported[0].Username && roundtrip[0].Email == imported[0].Email && roundtrip[0].Notes == imported[0].Notes && roundtrip[0].Category == "Imported Work" && roundtrip[1].IsSecureNote,
        "CSV import-export lossless roundtrip");
    var oldCsv = CsvTransfer.Import("title,username,password\nLegacy,old-user,secret");
    Check(oldCsv.Single().Username == "old-user" && oldCsv.Single().Email == "", "older CSV files without email remain compatible");
    var formulaSafe = CsvTransfer.Export(new[] { new Credential { Title = "=CMD()", Username = "+attack", Email = "=mail", Password = "@payload", Notes = "-1+2", Category = "+group" } }, formulaSafe: true);
    Check(formulaSafe.Contains("\"'=CMD()\"") && formulaSafe.Contains("\"'+attack\"") && formulaSafe.Contains("\"'=mail\"") && formulaSafe.Contains("\"'@payload\"") && formulaSafe.Contains("\"'-1+2\"") && formulaSafe.Contains("\"'+group\""),
        "formula-safe CSV neutralizes spreadsheet trigger prefixes");
    var whitespaceFormula = CsvTransfer.Export(new[] { new Credential { Title = "\t=CMD()" } }, formulaSafe: true);
    Check(whitespaceFormula.Contains("\"'\t=CMD()\""), "formula-safe CSV neutralizes leading-whitespace spreadsheet formulas");
    MustReject(() => CsvTransfer.Import("title,username\n\"unterminated,x"), "CSV rejects unterminated quoted field");
    MustReject(() => CsvTransfer.Import("username,password\nx,y"), "CSV requires title column");
    MustReject(() => CsvTransfer.Import("title,title\na,b"), "CSV rejects duplicate headers");
    MustReject(() => CsvTransfer.Import("title,type,category\nNote,note,Work"), "CSV rejects categories on secure notes");
    var richPath = Path.Combine(folder, "rich.ksv");
    byte[] fileContent = Encoding.UTF8.GetBytes("attachment binary content with SECRET-TEST-ATTACHMENT");
    Guid attachmentId;
    using (var vault = new VaultStore(richPath))
    {
        vault.Create(master); vault.TakeNewRecoveryKeys();
        vault.ImportCredentials(imported);
        Check(vault.Credentials.Count == 2 && vault.Categories.SequenceEqual(new[] { "Imported Work" }), "batch import saves entries and categories atomically");
        var id = vault.Credentials.Single(c => !c.IsSecureNote).Id;
        vault.AddAttachment(id, "safe-file.txt", fileContent);
        var selected = vault.Credentials.Single(c => c.Id == id);
        attachmentId = selected.Attachments.Single().Id;
        Check(vault.ReadAttachment(id, attachmentId).SequenceEqual(fileContent), "encrypted attachment readback");
        MustReject(() => vault.AddAttachment(id, "../unsafe.txt", fileContent), "attachment path traversal rejected");
        MustReject(() => vault.AddAttachment(id, "CON.txt", fileContent), "Windows reserved attachment filename rejected");
        MustReject(() => vault.AddAttachment(id, "CON.archive.txt", fileContent), "multi-extension Windows reserved attachment filename rejected");
        MustReject(() => vault.AddAttachment(id, "report.txt:stream", fileContent), "NTFS alternate data stream filename rejected");
        MustReject(() => vault.AddAttachment(id, "bad?.txt", fileContent), "Windows wildcard attachment filename rejected");
        MustReject(() => vault.AddAttachment(id, "e\u0301.txt", fileContent), "non-canonical Unicode attachment filename rejected");
        MustReject(() => vault.AddAttachment(id, "zero\u200Bwidth.txt", fileContent), "invisible Unicode format attachment filename rejected");
        MustReject(() => vault.AddAttachment(id, "invoice\u202Etxt.exe", fileContent), "bidi override attachment filename rejected");
        MustReject(() => vault.AddAttachment(id, "trailing. ", fileContent), "ambiguous trailing-dot/space filename rejected");
        MustReject(() => vault.AddAttachment(id, "huge.bin", new byte[VaultStore.MaximumAttachmentBytes + 1]), "oversized attachment rejected");
        var backup = vault.CreateEncryptedBackup();
        vault.Lock();
        var disk = Encoding.UTF8.GetString(File.ReadAllBytes(richPath));
        Check(!disk.Contains("SECRET-TEST-ATTACHMENT") && !disk.Contains("Long, detailed note") &&
              !disk.Contains("test@example.com") && !disk.Contains("secret123"), "SQLite never contains plaintext imported or attached secrets");
        Check(!File.ReadAllText(backup).Contains("SECRET-TEST-ATTACHMENT"), "backup never contains plaintext attachments");
    }
    using (var vault = new VaultStore(richPath))
    {
        vault.Unlock(master);
        var entry = vault.Credentials.Single(c => !c.IsSecureNote);
        Check(entry.Attachments.Count == 1 && vault.ReadAttachment(entry.Id, attachmentId).SequenceEqual(fileContent),
            "attachment persists after application reopen");
        Check(vault.Credentials.Single(c => c.IsSecureNote).Notes == "Long, detailed note", "secure note persists encrypted");
        vault.RemoveAttachment(entry.Id, attachmentId);
        Check(vault.Credentials.Single(c => !c.IsSecureNote).Attachments.Count == 0, "attachment deletion committed");
    }
    using (var vault = new VaultStore(richPath))
    {
        vault.Unlock(master);
        Check(vault.Credentials.Single(c => !c.IsSecureNote).Attachments.Count == 0, "attachment deletion survives relock/reopen");
        var ids = vault.Credentials.Select(x => x.Id).ToHashSet();
        var invalidImport = new[] { new Credential { Id = ids.First(), Title = "Duplicate" } };
        MustReject(() => vault.ImportCredentials(invalidImport), "batch import rejects duplicate IDs without writing");
        Check(vault.Credentials.Count == 2, "failed import preserves existing entries");
        vault.DeleteCategory("Imported Work");
        Check(vault.Categories.Count == 0 && vault.Credentials.Single(c => !c.IsSecureNote).Category == "", "category deletion safely unassigns passwords");
    }
    void RejectEnvelopeMutation(string label, Action<VaultFile> mutate)
    {
        var candidate = JsonSerializer.Deserialize<VaultFile>(VaultDatabase.Read(richPath))!;
        mutate(candidate);
        var candidatePath = Path.Combine(folder, "mutated-" + Guid.NewGuid().ToString("N") + ".ksv");
        VaultDatabase.Write(candidatePath, JsonSerializer.SerializeToUtf8Bytes(candidate), VaultDatabase.ReadRevision(richPath));
        using var candidateVault = new VaultStore(candidatePath);
        MustReject(() => candidateVault.Unlock(master), label);
    }
    RejectEnvelopeMutation("mutated vault identifier rejected", f => f.VaultId = Guid.NewGuid());
    RejectEnvelopeMutation("invalid low KDF memory rejected", f => f.KdfMemoryBytes = 1024);
    RejectEnvelopeMutation("hostile high KDF memory rejected before derivation", f => f.KdfMemoryBytes = 1073741824);
    RejectEnvelopeMutation("invalid KDF iteration count rejected", f => f.KdfIterations = 99);
    RejectEnvelopeMutation("invalid salt rejected", f => f.Salt = Convert.ToBase64String(new byte[15]));
    RejectEnvelopeMutation("tampered wrapped root rejected", f => { var b = Convert.FromBase64String(f.WrappedKey); b[^1] ^= 1; f.WrappedKey = Convert.ToBase64String(b); });
    RejectEnvelopeMutation("tampered payload rejected", f => { var b = Convert.FromBase64String(f.EncryptedPayload); b[^1] ^= 1; f.EncryptedPayload = Convert.ToBase64String(b); });
    RejectEnvelopeMutation("duplicate recovery slot identifiers rejected", f => f.RecoverySlots.Add(new RecoverySlot { Id = f.RecoverySlots[0].Id, WrappedKey = f.RecoverySlots[0].WrappedKey }));
    var aeadFuzzTimer = Stopwatch.StartNew();
    for (var mutation = 0; mutation < 256; mutation++)
    {
        var mutationKey = Security.Random(32);
        var ciphertext = Security.Encrypt(Encoding.UTF8.GetBytes("native-fuzz-marker"), mutationKey, Encoding.UTF8.GetBytes("native-fuzz"));
        ciphertext[fuzzRandom.Next(ciphertext.Length)] ^= (byte)(1 << fuzzRandom.Next(8));
        try { Security.Decrypt(ciphertext, mutationKey, Encoding.UTF8.GetBytes("native-fuzz")); throw new Exception("mutated native ciphertext was accepted"); }
        catch (SodiumException) { }
        finally { Security.Clear(ciphertext); Security.Clear(mutationKey); }
    }
    aeadFuzzTimer.Stop();
    Check(true, $"256 randomized native AEAD mutation cases rejected without crash (PRNG stream seed 0x4B455953, {aeadFuzzTimer.ElapsedMilliseconds} ms)");

    var duplicateJsonPath = Path.Combine(folder, "duplicate-json.ksv");
    var rawEnvelope = Encoding.UTF8.GetString(VaultDatabase.Read(richPath));
    var duplicateJson = rawEnvelope.Replace("\"Magic\":\"KEYSAFE-VAULT\"", "\"Magic\":\"EVIL\",\"Magic\":\"KEYSAFE-VAULT\"", StringComparison.Ordinal);
    VaultDatabase.Write(duplicateJsonPath, Encoding.UTF8.GetBytes(duplicateJson), VaultDatabase.ReadRevision(richPath));
    using (var duplicateVault = new VaultStore(duplicateJsonPath)) MustReject(() => duplicateVault.Unlock(master), "duplicate JSON properties rejected");

    var invalidUtf8Path = Path.Combine(folder, "invalid-utf8.ksv");
    var invalidUtf8 = VaultDatabase.Read(richPath); invalidUtf8[20] = 0xFF;
    VaultDatabase.Write(invalidUtf8Path, invalidUtf8, VaultDatabase.ReadRevision(richPath));
    using (var invalidVault = new VaultStore(invalidUtf8Path)) MustReject(() => invalidVault.Unlock(master), "invalid UTF-8 vault JSON rejected");

    var revisionPath = Path.Combine(folder, "revision-mismatch.ksv");
    File.Copy(richPath, revisionPath);
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + revisionPath))
    { connection.Open(); using var command = connection.CreateCommand(); command.CommandText = "UPDATE vault_state SET revision=revision+100 WHERE id=1"; command.ExecuteNonQuery(); }
    using (var revisionVault = new VaultStore(revisionPath)) MustReject(() => revisionVault.Unlock(master), "unauthenticated database revision change rejected");

    var triggerPath = Path.Combine(folder, "unexpected-trigger.ksv");
    File.Copy(richPath, triggerPath);
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + triggerPath))
    { connection.Open(); using var command = connection.CreateCommand(); command.CommandText = "CREATE TRIGGER hostile AFTER UPDATE ON vault_state BEGIN SELECT 1; END"; command.ExecuteNonQuery(); }
    using (var triggerVault = new VaultStore(triggerPath)) MustReject(() => triggerVault.Unlock(master), "unexpected SQLite trigger rejected");

    var typePath = Path.Combine(folder, "sqlite-type-confusion.ksv");
    File.Copy(richPath, typePath);
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + typePath))
    { connection.Open(); using var command = connection.CreateCommand(); command.CommandText = "UPDATE vault_state SET encrypted_envelope='not-a-blob' WHERE id=1"; command.ExecuteNonQuery(); }
    using (var typeVault = new VaultStore(typePath)) MustReject(() => typeVault.Unlock(master), "SQLite storage-class confusion rejected");
    // No implicit upgrades: v1.0.0 format-4 envelopes are rejected by the public v1.1 reader.
    var envelope11 = JsonSerializer.Deserialize<VaultFile>(VaultDatabase.Read(richPath))!;
    Check(envelope11.Version == KeySafeInfo.VaultFormatVersion, "v1.1 vault format is version 5");
    envelope11.Version = 4;
    var olderPath = Path.Combine(folder, "manual-older-format.ksv");
    VaultDatabase.Write(olderPath, JsonSerializer.SerializeToUtf8Bytes(envelope11), 1);
    using (var vault = new VaultStore(olderPath))
        MustReject(() => vault.Unlock(master), "manually supplied v1.0.0 format-4 envelope rejected without conversion");
    Check(Security.GeneratePassword(32, true).Length == 32, "cryptographic password generator");
    MustReject(() => Security.GeneratePassword(0, true), "password generator rejects invalid minimum");
    MustReject(() => Security.GeneratePassword(129, true), "password generator rejects oversized length");
    MustReject(() => Security.DeriveMasterKey("TEST", new byte[15], 268435456, 3), "KDF rejects invalid salt size");
    MustReject(() => Security.DeriveMasterKey("TEST", new byte[16], 1024, 3), "KDF rejects unsafe memory cost");
    MustReject(() => Security.DeriveMasterKey(new string('x', Security.MaximumPasswordCharacters + 1), new byte[16], 268435456, 3), "KDF rejects oversized password");
    MustReject(() => Security.DeriveMasterKey("TEST", new byte[16], 1073741824, 8), "KDF rejects hostile maximum settings");
    var unicodeKdf = Security.DeriveMasterKey("p\u00E4ssphrase-\U0001F510-\u6F22\u5B57", Enumerable.Range(0, 16).Select(i => (byte)i).ToArray(), 67108864, 2);
    Check(Convert.ToHexString(unicodeKdf) == "30B1ABA932D825B1EAD2574D3803A0C06FAC9DBECA113890A847E24ED716119A",
        "pinned Argon2id UTF-8 Unicode password derivation vector");
    Security.Clear(unicodeKdf);
    MustReject(() => Security.Decrypt(new byte[8], Security.Random(32), Encoding.UTF8.GetBytes("purpose")), "AEAD rejects truncated ciphertext");
    using (var vault = new VaultStore(richPath))
    {
        MustReject(() => vault.Recover(new string('A', 1024), "Recovery-New-Master-2026"), "recovery rejects excessive input before cryptography");
        MustReject(() => vault.Create(master), "cannot overwrite existing vault");
    }
    var prunePath = Path.Combine(folder, "snapshot-prune.ksv");
    using (var vault = new VaultStore(prunePath))
    {
        vault.Create(master); vault.TakeNewRecoveryKeys();
        for (var i = 0; i < 40; i++) vault.Upsert(new Credential { Title = "Snapshot-" + i, Password = "SYNTHETIC" });
        Check(VaultDatabase.SnapshotCount(prunePath) == 25, "snapshot history pruned to configured limit");
        Check(vault.VerifiedSnapshotRevisions().Count == 25, "all retained snapshots authenticate");
    }
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = prunePath, Pooling = false }.ToString()))
    {
        connection.Open();
        using var vacuum = connection.CreateCommand(); vacuum.CommandText = "VACUUM"; vacuum.ExecuteNonQuery();
    }
    Check(VaultDatabase.SecureDeleteIsEnabled(prunePath), "SQLite secure_delete enabled on KeySafe connections");
    Check(!Encoding.UTF8.GetString(File.ReadAllBytes(prunePath)).Contains("SYNTHETIC"), "VACUUMed SQLite file contains no synthetic plaintext");
    var exportPath = Path.Combine(folder, "verified-export.csv");
    var exportBytes = Encoding.UTF8.GetBytes("synthetic,plaintext,export");
    PlaintextExport.WriteVerified(exportPath, exportBytes);
    Check(File.ReadAllText(exportPath) == "synthetic,plaintext,export" && exportBytes.All(b => b == 0), "plaintext export is durably written, verified, and caller buffer cleared");
    File.WriteAllText(exportPath, "ORIGINAL");
    using (var heldExport = new FileStream(exportPath, FileMode.Open, FileAccess.Read, FileShare.None))
        MustReject(() => PlaintextExport.WriteVerified(exportPath, Encoding.UTF8.GetBytes("REPLACEMENT")), "locked export destination fails closed");
    Check(File.ReadAllText(exportPath) == "ORIGINAL" && !Directory.EnumerateFiles(folder, ".verified-export.csv.*.tmp").Any(),
        "failed plaintext export preserves destination and removes staging file");
    Console.WriteLine($"ALL {passed} CHECKS PASSED.");
    return 0;
}
catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
finally { try { Directory.Delete(folder, true); } catch { } }
