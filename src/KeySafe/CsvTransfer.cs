using System.IO;
using System.Text;

namespace KeySafe;

public static class CsvTransfer
{
    public const int MaximumCsvBytes = 8 * 1024 * 1024;
    private static readonly string[] Headers = { "title", "username", "email", "password", "website", "notes", "favorite", "type", "totp", "category" };

    public static IReadOnlyList<Credential> Import(string csv)
    {
        ArgumentNullException.ThrowIfNull(csv);
        if (Encoding.UTF8.GetByteCount(csv) > MaximumCsvBytes) throw new InvalidDataException("CSV exceeds 8 MiB.");
        var rows = ParseRows(csv);
        if (rows.Count < 2) throw new InvalidDataException("CSV must contain a header and at least one entry.");
        var header = rows[0].Select(h => h.Trim().TrimStart('\uFEFF').ToLowerInvariant()).ToArray();
        if (header.Distinct().Count() != header.Length || !(header.Contains("title") || header.Contains("name")))
            throw new InvalidDataException("CSV needs a 'title' or 'name' column and distinct headers.");
        int col(string name)
        {
            string[] aliases = name switch
            {
                "title" => new[] { "title", "name" },
                "username" => new[] { "username", "login_username", "login name", "account" },
                "email" => new[] { "email", "e-mail", "mail" },
                "password" => new[] { "password", "login_password" },
                "website" => new[] { "website", "login_uri", "url", "web site" },
                "notes" => new[] { "notes", "comments" },
                "totp" => new[] { "totp", "login_totp" },
                "category" => new[] { "category", "folder", "group" },
                _ => new[] { name }
            };
            return Array.FindIndex(header, h => aliases.Contains(h));
        }
        string get(string[] row, string name) => col(name) < 0 ? "" : row[col(name)];
        if (rows.Count - 1 > 5000) throw new InvalidDataException("Import limited to 5000 entries.");
        var output = new List<Credential>();
        foreach (var row in rows.Skip(1))
        {
            if (row.Length != header.Length) throw new InvalidDataException("CSV has inconsistent column count.");
            if (row.All(string.IsNullOrWhiteSpace)) continue;
            var title = get(row, "title");
            if (string.IsNullOrWhiteSpace(title) || title.Length > 2048 || get(row, "username").Length > 4096 || get(row, "email").Length > 4096 ||
                get(row, "password").Length > 65536 || get(row, "website").Length > 4096 || get(row, "notes").Length > 524288)
                throw new InvalidDataException("CSV entry contains invalid field lengths or missing title.");
            var type = get(row, "type");
            if (type.Length != 0 && !type.Equals("note", StringComparison.OrdinalIgnoreCase) &&
                !type.Equals("password", StringComparison.OrdinalIgnoreCase) &&
                !type.Equals("login", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Unsupported CSV entry type.");
            var category = get(row, "category").Trim();
            if (category.Length > VaultStore.MaximumCategoryLength || category.Any(char.IsControl) ||
                (type.Equals("note", StringComparison.OrdinalIgnoreCase) && category.Length != 0))
                throw new InvalidDataException("CSV category is invalid or cannot be assigned to a secure note.");
            var favorite = get(row, "favorite");
            if (favorite.Length != 0 && !new[] { "true", "false", "1", "0" }.Contains(favorite.ToLowerInvariant()))
                throw new InvalidDataException("Invalid CSV favorite flag.");
            var totp = get(row, "totp");
            if (totp.Length != 0)
            {
                var configuration = Totp.Parse(totp);
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(configuration.Secret);
            }
            output.Add(new Credential { Title = title, Username = get(row, "username"), Email = get(row, "email"),
                Password = get(row, "password"), Website = get(row, "website"), Notes = get(row, "notes"),
                Favorite = favorite.Equals("true", StringComparison.OrdinalIgnoreCase) || favorite == "1",
                IsSecureNote = type.Equals("note", StringComparison.OrdinalIgnoreCase), TotpSecret = totp, Category = category });
        }
        if (output.Count == 0) throw new InvalidDataException("No entries to import.");
        return output;
    }

    public static string Export(IEnumerable<Credential> items, bool formulaSafe = false)
    {
        ArgumentNullException.ThrowIfNull(items);
        var builder = new StringBuilder();
        builder.AppendLine(string.Join(",", Headers));
        foreach (var c in items)
        {
            string[] row = { c.Title, c.Username, c.Email, c.Password, c.Website, c.Notes,
                c.Favorite ? "true" : "false", c.IsSecureNote ? "note" : "password", c.TotpSecret, c.Category };
            builder.AppendLine(string.Join(",", row.Select(value => Escape(formulaSafe ? NeutralizeFormula(value) : value))));
        }
        if (Encoding.UTF8.GetByteCount(builder.ToString()) > MaximumCsvBytes)
            throw new InvalidDataException("CSV export exceeds 8 MiB.");
        return builder.ToString();
    }

    private static string Escape(string value) => "\"" + value.Replace("\"", "\"\"") + "\"";
    private static string NeutralizeFormula(string value)
    {
        var candidate = value.AsSpan().TrimStart();
        return candidate.Length > 0 && candidate[0] is '=' or '+' or '-' or '@' ? "'" + value : value;
    }

    private static List<string[]> ParseRows(string content)
    {
        var rows = new List<string[]>();
        var fields = new List<string>();
        var field = new StringBuilder();
        bool quoted = false, endedQuote = false, atStart = true;
        void addField() { fields.Add(field.ToString()); field.Clear(); endedQuote = false; atStart = true; }
        void addRow() { addField(); rows.Add(fields.ToArray()); fields.Clear(); if (rows.Count > 5002) throw new InvalidDataException("Too many CSV records."); }
        for (int i = 0; i < content.Length; i++)
        {
            char c = content[i];
            if (quoted)
            {
                if (c == '"') { if (i + 1 < content.Length && content[i + 1] == '"') { field.Append('"'); i++; } else { quoted = false; endedQuote = true; } }
                else field.Append(c);
            }
            else if (c == ',' ) addField();
            else if (c == '\r' || c == '\n')
            {
                if (c == '\r' && i + 1 < content.Length && content[i + 1] == '\n') i++;
                addRow();
            }
            else if (c == '"' && atStart) { quoted = true; atStart = false; }
            else if (endedQuote || c == '"') throw new InvalidDataException("Malformed CSV quoting.");
            else { atStart = false; field.Append(c); }
        }
        if (quoted) throw new InvalidDataException("Unterminated CSV field.");
        if (field.Length > 0 || fields.Count > 0 || endedQuote) addRow();
        return rows;
    }
}
