using System.IO;
using Microsoft.Data.Sqlite;
namespace KeySafe;

public static class VaultDatabase
{
    private const int MaximumEnvelopeBytes = 48 * 1024 * 1024;
    private const string Schema = """
        CREATE TABLE IF NOT EXISTS vault_state (
            id INTEGER PRIMARY KEY CHECK(id=1),
            encrypted_envelope BLOB NOT NULL,
            revision INTEGER NOT NULL CHECK(revision>=1)
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            revision INTEGER NOT NULL,
            created_utc TEXT NOT NULL,
            encrypted_envelope BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_revision ON snapshots(revision);
        """;

    private static SqliteConnection OpenWrite(string path)
    {
        var builder = new SqliteConnectionStringBuilder {
            DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private, Pooling = false
        };
        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var options = connection.CreateCommand();
        options.CommandText = "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=3000; PRAGMA secure_delete=ON;";
        options.ExecuteNonQuery();
        return connection;
    }

    // Authentication and inspection must not create a missing database, change its
    // journal settings, or perform recovery writes.
    private static SqliteConnection OpenReadOnly(string path)
    {
        var builder = new SqliteConnectionStringBuilder {
            DataSource = path, Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private, Pooling = false
        };
        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var options = connection.CreateCommand();
        options.CommandText = "PRAGMA query_only=ON; PRAGMA busy_timeout=3000;";
        options.ExecuteNonQuery();
        return connection;
    }

    public static bool IsSqlite(string path)
    {
        if (!File.Exists(path)) return false;
        using var stream = File.OpenRead(path);
        if (stream.Length < 16) return false;
        Span<byte> header = stackalloc byte[16];
        stream.ReadExactly(header);
        return header.SequenceEqual("SQLite format 3\0"u8);
    }

    public static byte[] Read(string path)
    {
        if (!IsSqlite(path)) throw new InvalidDataException("Vault database header is damaged or unsupported.");
        using var connection = OpenReadOnly(path);
        ValidateSchema(connection);
        using var integrity = connection.CreateCommand();
        integrity.CommandText = "PRAGMA quick_check;";
        if ((string?)integrity.ExecuteScalar() != "ok") throw new InvalidDataException("SQLite integrity check failed.");
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT encrypted_envelope FROM vault_state WHERE id=1;";
        var data = command.ExecuteScalar() as byte[] ?? throw new InvalidDataException("Vault state missing.");
        if (data.Length is < 64 or > MaximumEnvelopeBytes) throw new InvalidDataException("Invalid vault envelope length.");
        return data;
    }

    public static long ReadRevision(string path)
    {
        if (!IsSqlite(path)) throw new InvalidDataException("Vault database header is damaged or unsupported.");
        using var connection = OpenReadOnly(path);
        ValidateSchema(connection);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT revision FROM vault_state WHERE id=1";
        return command.ExecuteScalar() is long revision ? revision : throw new InvalidDataException("Vault revision missing.");
    }

    public static void Write(string path, byte[] envelope, long revision, bool retainPrevious = true, bool clearSnapshots = false)
    {
        if (envelope.Length is < 64 or > MaximumEnvelopeBytes) throw new IOException("Vault envelope too large.");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        if (File.Exists(path) && !IsSqlite(path))
            throw new InvalidDataException("Unsupported vault format. KeySafe v1.1.0 only accepts its own SQLite vaults; no migration is performed.");
        WriteDb(path, envelope, revision, retainPrevious, clearSnapshots);
    }

    private static void WriteDb(string path, byte[] envelope, long revision, bool retainPrevious = true, bool clearSnapshots = false)
    {
        using var connection = OpenWrite(path);
        using (var setup = connection.CreateCommand()) { setup.CommandText = Schema; setup.ExecuteNonQuery(); }
        ValidateSchema(connection);
        using var transaction = connection.BeginTransaction();
        byte[]? previous = null;
        long previousRevision = 0;
        using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = "SELECT encrypted_envelope, revision FROM vault_state WHERE id=1";
            using var reader = read.ExecuteReader();
            if (reader.Read()) { previous = (byte[])reader[0]; previousRevision = reader.GetInt64(1); }
        }
        if (previous != null && revision <= previousRevision)
            throw new IOException("Stale vault revision. Refusing to overwrite newer data.");
        if (clearSnapshots)
        {
            using var clear = connection.CreateCommand();
            clear.Transaction = transaction;
            clear.CommandText = "DELETE FROM snapshots";
            clear.ExecuteNonQuery();
        }
        if (previous != null && retainPrevious)
        {
            using var snapshot = connection.CreateCommand();
            snapshot.Transaction = transaction;
            snapshot.CommandText = "INSERT INTO snapshots(revision,created_utc,encrypted_envelope) VALUES($rev,$time,$data)";
            snapshot.Parameters.AddWithValue("$rev", previousRevision);
            snapshot.Parameters.AddWithValue("$time", DateTime.UtcNow.ToString("O"));
            snapshot.Parameters.AddWithValue("$data", previous);
            snapshot.ExecuteNonQuery();
        }
        using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "INSERT INTO vault_state(id,revision,encrypted_envelope) VALUES(1,$rev,$data) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, encrypted_envelope=excluded.encrypted_envelope";
            update.Parameters.AddWithValue("$rev", revision);
            update.Parameters.AddWithValue("$data", envelope);
            update.ExecuteNonQuery();
        }
        using (var prune = connection.CreateCommand())
        {
            prune.Transaction = transaction;
            prune.CommandText = "DELETE FROM snapshots WHERE id NOT IN (SELECT id FROM snapshots ORDER BY id DESC LIMIT 25)";
            prune.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    public static IReadOnlyList<byte[]> ReadSnapshots(string path)
    {
        if (!IsSqlite(path)) return Array.Empty<byte[]>();
        using var connection = OpenReadOnly(path);
        ValidateSchema(connection);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT encrypted_envelope FROM snapshots WHERE typeof(encrypted_envelope)='blob' AND length(encrypted_envelope) BETWEEN 64 AND $max ORDER BY id DESC LIMIT 25";
        command.Parameters.AddWithValue("$max", MaximumEnvelopeBytes);
        using var reader = command.ExecuteReader();
        var snapshots = new List<byte[]>();
        long total = 0;
        while (reader.Read())
        {
            if (reader[0] is not byte[] bytes) continue;
            total += bytes.Length;
            if (total > MaximumEnvelopeBytes * 2L) break;
            snapshots.Add(bytes);
        }
        return snapshots;
    }

    public static int SnapshotCount(string path)
    {
        if (!IsSqlite(path)) return 0;
        using var connection = OpenReadOnly(path);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM snapshots";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    public static bool SecureDeleteIsEnabled(string path)
    {
        using var connection = OpenWrite(path);
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA secure_delete";
        return Convert.ToInt32(command.ExecuteScalar()) == 1;
    }

    private static void ValidateSchema(SqliteConnection connection)
    {
        using var objects = connection.CreateCommand();
        objects.CommandText = "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name";
        using var reader = objects.ExecuteReader();
        var found = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read()) found.Add(reader.GetString(0) + ":" + reader.GetString(1));
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            "table:snapshots", "table:vault_state", "index:idx_snapshots_revision"
        };
        if (!found.SetEquals(expected)) throw new InvalidDataException("Vault database contains an unexpected or missing schema object.");
    }

    public static void ReplaceDamagedDatabase(string path, byte[] envelope, long revision)
    {
        var staged = path + ".restore-pending";
        if (File.Exists(staged)) File.Delete(staged);
        try
        {
            WriteDb(staged, envelope, revision);
            if (File.Exists(path))
            {
                var quarantine = path + ".damaged-" + DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
                File.Replace(staged, path, quarantine, true);
            }
            else File.Move(staged, path);
        }
        finally { if (File.Exists(staged)) File.Delete(staged); }
    }
}
