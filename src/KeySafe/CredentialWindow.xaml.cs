using System.Windows;
using System.Windows.Controls;
namespace KeySafe;
public partial class CredentialWindow : Window
{
    private readonly Credential? _source;
    private bool _syncing;
    private bool _revealed;
    private readonly bool _isNote;
    private sealed record CategoryChoice(string Value, string Label)
    {
        public override string ToString() => Label;
    }
    public Credential? Result { get; private set; }
    public CredentialWindow(Credential? source, bool note = false, IReadOnlyList<string>? categories = null, string? defaultCategory = null)
    {
        InitializeComponent();
        _source = source;
        _isNote = source?.IsSecureNote ?? note;
        CredentialFields.Visibility = _isNote ? Visibility.Collapsed : Visibility.Visible;
        CategoryFields.Visibility = _isNote ? Visibility.Collapsed : Visibility.Visible;
        var choices = new List<CategoryChoice> { new("", "Uncategorized") };
        choices.AddRange((categories ?? Array.Empty<string>()).OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .Select(x => new CategoryChoice(x, x)));
        CategoryInput.ItemsSource = choices;
        var chosenCategory = source?.Category ?? defaultCategory ?? "";
        CategoryInput.SelectedItem = choices.FirstOrDefault(x => x.Value.Equals(chosenCategory, StringComparison.OrdinalIgnoreCase)) ?? choices[0];
        HeaderText.Text = _isNote ? (source == null ? "New secure note" : "Edit secure note") : (source == null ? "New password" : "Edit password");
        Title = _isNote ? "Secure note · KeySafe" : "Password · KeySafe";
        if (source != null)
        {

            TitleInput.Text = source.Title; UsernameInput.Text = source.Username; EmailInput.Text = source.Email;
            PasswordInput.Password = source.Password; WebsiteInput.Text = source.Website;
            NotesInput.Text = source.Notes; FavoriteInput.IsChecked = source.Favorite; TotpInput.Text = source.TotpSecret;
        }
        Loaded += (_, _) => TitleInput.Focus();
        Closed += (_, _) =>
        {
            PasswordInput.Clear(); VisiblePasswordInput.Clear(); UsernameInput.Clear(); EmailInput.Clear();
            NotesInput.Clear(); TotpInput.Clear();
        };
    }
    private void PasswordInput_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        if (_revealed) { _syncing = true; VisiblePasswordInput.Text = PasswordInput.Password; _syncing = false; }
    }
    private void VisiblePasswordInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_syncing) return;
        _syncing = true; PasswordInput.Password = VisiblePasswordInput.Text; _syncing = false;
    }
    private void Visibility_Click(object sender, RoutedEventArgs e)
    {
        _revealed = !_revealed;
        if (_revealed) VisiblePasswordInput.Text = PasswordInput.Password;
        else VisiblePasswordInput.Clear();
        PasswordInput.Visibility = _revealed ? Visibility.Collapsed : Visibility.Visible;
        VisiblePasswordInput.Visibility = _revealed ? Visibility.Visible : Visibility.Collapsed;
        VisibilityButton.Content = _revealed ? "Hide" : "Show";
    }
    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        PasswordInput.Password = Security.GeneratePassword(24, true);
        GeneratorInfo.Text = "24 characters · letters, numbers, symbols";
    }
    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(TitleInput.Text)) { ErrorText.Text = "Title is required."; return; }
        if (!_isNote && !string.IsNullOrWhiteSpace(TotpInput.Text))
        {
            try { var configuration = Totp.Parse(TotpInput.Text); Security.Clear(configuration.Secret); }
            catch (ArgumentException ex) { ErrorText.Text = ex.Message; return; }
        }
        Result = new Credential
        {
            Id = _source?.Id ?? Guid.NewGuid(), Title = TitleInput.Text.Trim(), Username = UsernameInput.Text, Email = EmailInput.Text,
            Password = PasswordInput.Password, Website = WebsiteInput.Text.Trim(), Notes = NotesInput.Text,
            Favorite = FavoriteInput.IsChecked == true, IsSecureNote = _isNote,
            Category = _isNote ? "" : (CategoryInput.SelectedItem as CategoryChoice)?.Value ?? "",
            TotpSecret = _isNote ? "" : TotpInput.Text.Trim(),
            Attachments = _source?.Attachments.Select(a => new EncryptedAttachment {
                Id = a.Id, FileName = a.FileName, ContentType = a.ContentType,
                Data = (byte[])a.Data.Clone(), AddedUtc = a.AddedUtc }).ToList() ?? new(), CreatedUtc = _source?.CreatedUtc ?? DateTime.UtcNow, ModifiedUtc = DateTime.UtcNow
        };
        DialogResult = true;
    }
    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
