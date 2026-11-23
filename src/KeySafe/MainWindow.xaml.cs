using System.IO;
using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
namespace KeySafe;
public partial class MainWindow : Window
{
    private readonly VaultStore _vault;
    private readonly DispatcherTimer _idleTimer;
    private readonly DispatcherTimer _clipboardTimer;
    private DateTime _lastInteractionUtc = DateTime.UtcNow;
    private Credential? _selected;
    private bool _favoritesOnly;
    private bool _notesOnly;
    private string? _selectedCategory;
    private bool _refreshingCategories;
    private sealed record CategoryListItem(string Name, int Count);
    private readonly DispatcherTimer _otpTimer;
    private bool _passwordRevealed;
    private string? _clipboardOwnedValue;
    private int _failedUnlockAttempts;
    private DateTime _unlockAllowedUtc = DateTime.MinValue;
    private bool _secureLockRestarting;
    public MainWindow()
    {
        InitializeComponent();
        var directory = StorageSecurity.EnsurePrivateApplicationDirectory();
        _vault = new VaultStore(System.IO.Path.Combine(directory, "vault.ksv"));
        VaultPathLabel.Text = _vault.PathOnDisk;
        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _idleTimer.Tick += (_, _) => { if (_vault.IsUnlocked && DateTime.UtcNow - _lastInteractionUtc > TimeSpan.FromMinutes(5)) LockVault(); };
        _idleTimer.Start();
        _otpTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _otpTimer.Tick += (_, _) => UpdateTotp();
        _otpTimer.Start();
        InputManager.Current.PreProcessInput += TrackGlobalInput;
        SystemEvents.SessionSwitch += SessionChanged;
        SystemEvents.PowerModeChanged += PowerChanged;
        _clipboardTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _clipboardTimer.Tick += (_, _) => ClearOwnedClipboard();
        PreviewMouseDown += (_, _) => _lastInteractionUtc = DateTime.UtcNow;
        PreviewKeyDown += Window_PreviewKeyDown;
        MasterPasswordInput.PasswordChanged += (_, _) =>
        {
            if (MasterPasswordGuidance != null) MasterPasswordGuidance.Text = Security.PasswordGuidance(MasterPasswordInput.Password);
        };
        Deactivated += (_, _) => { if (_vault.IsUnlocked) HidePassword(); };
        Closed += (_, _) => { _otpTimer.Stop(); _idleTimer.Stop(); _clipboardTimer.Stop(); InputManager.Current.PreProcessInput -= TrackGlobalInput; SystemEvents.SessionSwitch -= SessionChanged; SystemEvents.PowerModeChanged -= PowerChanged; ClearOwnedClipboard(); _vault.Dispose(); };
        ShowWelcome();
    }
    private void ShowWelcome()
    {
        bool create = !_vault.Exists;
        WelcomePanel.Visibility = Visibility.Visible;
        VaultPanel.Visibility = Visibility.Collapsed;
        ConfirmationFields.Visibility = create ? Visibility.Visible : Visibility.Collapsed;
        RecoveryAction.Visibility = create ? Visibility.Collapsed : Visibility.Visible;
        WelcomeSubtitle.Text = create ? "Create your private, encrypted local vault." : "Welcome back. Unlock your local vault.";
        FirstPasswordLabel.Text = create ? "Create master password" : "Master password";
        WelcomeAction.Content = create ? "Create encrypted vault" : "Unlock vault";
        MasterPasswordInput.Clear(); ConfirmPasswordInput.Clear(); WelcomeError.Text = "";
        Dispatcher.BeginInvoke(() => MasterPasswordInput.Focus());
    }
    private async void WelcomeAction_Click(object sender, RoutedEventArgs e)
    {
        var password = MasterPasswordInput.Password;
        var confirmation = ConfirmPasswordInput.Password;
        bool create = !_vault.Exists;
        WelcomeError.Text = "";
        if (!create && DateTime.UtcNow < _unlockAllowedUtc)
        {
            WelcomeError.Text = $"Wait {Math.Ceiling((_unlockAllowedUtc - DateTime.UtcNow).TotalSeconds)} seconds before another attempt. This local delay does not prevent offline guessing.";
            return;
        }
        if (create && password != confirmation) { WelcomeError.Text = "Passwords do not match."; return; }
        if (create && (password.Length < Security.MinimumPasswordCharacters || password.Length > Security.MaximumPasswordCharacters || string.IsNullOrWhiteSpace(password))) { WelcomeError.Text = $"Use a master password of {Security.MinimumPasswordCharacters}â€“{Security.MaximumPasswordCharacters} characters."; return; }
        WelcomeAction.IsEnabled = false;
        WelcomeAction.Content = create ? "Creating vault…" : "Unlocking…";
        try
        {
            await Task.Run(() => { if (create) _vault.Create(password); else _vault.Unlock(password); });
            IReadOnlyList<string> generated = create ? _vault.TakeNewRecoveryKeys() : Array.Empty<string>();
            MasterPasswordInput.Clear(); ConfirmPasswordInput.Clear();
            _lastInteractionUtc = DateTime.UtcNow;
            _failedUnlockAttempts = 0; _unlockAllowedUtc = DateTime.MinValue;
            WelcomePanel.Visibility = Visibility.Collapsed;
            VaultPanel.Visibility = Visibility.Visible;
            RefreshList();
            if (generated.Count > 0) new RecoveryKeysWindow(this, generated).ShowDialog();
        }
        catch (Exception ex)
        {
            if (!create)
            {
                _failedUnlockAttempts = Math.Min(_failedUnlockAttempts + 1, 6);
                _unlockAllowedUtc = DateTime.UtcNow.AddSeconds(Math.Min(30, 1 << (_failedUnlockAttempts - 1)));
            }
            WelcomeError.Text = ex is FileNotFoundException ? "Vault file was not found." :
                ex is ArgumentException ? ex.Message :
                create ? "Could not create the vault. Check the data folder and available disk space." :
                "Unable to unlock. The password may be incorrect, or the vault may be damaged.";
        }
        finally { WelcomeAction.IsEnabled = true; WelcomeAction.Content = create ? "Create encrypted vault" : "Unlock vault"; }
    }
    private void MasterPasswordInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { e.Handled = true; WelcomeAction_Click(sender, new RoutedEventArgs()); }
    }
    private void RefreshList(Guid? select = null)
    {
        if (!_vault.IsUnlocked) { LockVault(); return; }
        var query = SearchInput.Text.Trim();
        var list = _vault.Credentials.Where(x => (!_favoritesOnly || x.Favorite) && (_favoritesOnly || x.IsSecureNote == _notesOnly) &&
            (_selectedCategory == null || (!x.IsSecureNote && x.Category.Equals(_selectedCategory, StringComparison.OrdinalIgnoreCase))) &&
            (query.Length == 0 || x.Title.Contains(query, StringComparison.OrdinalIgnoreCase) || x.Username.Contains(query, StringComparison.OrdinalIgnoreCase) || x.Email.Contains(query, StringComparison.OrdinalIgnoreCase) || x.Website.Contains(query, StringComparison.OrdinalIgnoreCase) || x.Category.Contains(query, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(x => x.Favorite).ThenBy(x => x.Title, StringComparer.OrdinalIgnoreCase).ToList();
        CredentialsList.ItemsSource = list;
        PageTitle.Text = _selectedCategory == null ? (_favoritesOnly ? "Favorites" : _notesOnly ? "Secure notes" : "Passwords") :
            _selectedCategory.Length == 0 ? "Uncategorized" : _selectedCategory;
        ItemCount.Text = $"{list.Count} {(list.Count == 1 ? "credential" : "credentials")}";
        RefreshCategories();
        if (select.HasValue) CredentialsList.SelectedItem = list.FirstOrDefault(x => x.Id == select.Value);
        if (CredentialsList.SelectedItem == null) ShowDetails(null);
        FooterStatus.Text = $"Encrypted locally  •  {_vault.Credentials.Count} total entries  •  Auto-lock: 5 minutes  •  KeySafe {KeySafeInfo.ApplicationVersion}";
        RecoveryStatus.Text = $"Recovery keys remaining: {_vault.RecoveryKeysRemaining} / 10";
    }

    private void RefreshCategories()
    {
        _refreshingCategories = true;
        try
        {
            var items = _vault.Categories.Select(name => new CategoryListItem(name,
                _vault.Credentials.Count(x => !x.IsSecureNote && x.Category.Equals(name, StringComparison.OrdinalIgnoreCase)))).ToList();
            CategoriesList.ItemsSource = items;
            CategoriesList.SelectedItem = _selectedCategory is { Length: > 0 }
                ? items.FirstOrDefault(x => x.Name.Equals(_selectedCategory, StringComparison.OrdinalIgnoreCase)) : null;
            AllCategoriesButton.FontWeight = _selectedCategory == null ? FontWeights.SemiBold : FontWeights.Normal;
            UncategorizedButton.FontWeight = _selectedCategory == "" ? FontWeights.SemiBold : FontWeights.Normal;
        }
        finally { _refreshingCategories = false; }
    }
    private void ShowDetails(Credential? credential)
    {
        _selected = credential;
        HidePassword();
        EmptyDetails.Visibility = credential == null ? Visibility.Visible : Visibility.Collapsed;
        DetailsPanel.Visibility = credential == null ? Visibility.Collapsed : Visibility.Visible;
        if (credential == null) { OtpDetails.Visibility = Visibility.Collapsed; AttachmentsList.ItemsSource = null; return; }
        DetailTitle.Text = credential.Title;
        DetailCategory.Text = credential.CategoryDisplay;
        DetailCategoryBadge.Visibility = credential.IsSecureNote ? Visibility.Collapsed : Visibility.Visible;
        DetailUsername.Text = string.IsNullOrWhiteSpace(credential.Username) ? "—" : credential.Username;
        DetailEmail.Text = string.IsNullOrWhiteSpace(credential.Email) ? "—" : credential.Email;
        DetailWebsite.Text = string.IsNullOrWhiteSpace(credential.Website) ? "—" : credential.Website;
        DetailNotes.Text = string.IsNullOrWhiteSpace(credential.Notes) ? "—" : credential.Notes;
        FavoriteGlyph.Visibility = credential.Favorite ? Visibility.Visible : Visibility.Collapsed;
        CredentialDetails.Visibility = credential.IsSecureNote ? Visibility.Collapsed : Visibility.Visible;
        HistoryButton.Visibility = credential.IsSecureNote ? Visibility.Collapsed : Visibility.Visible;
        EditEntryButton.Content = credential.IsSecureNote ? "Edit secure note" : "Edit credential";
        AttachmentsList.ItemsSource = credential.Attachments.ToList();
        UpdateTotp();
    }
    private void HidePassword()
    {
        _passwordRevealed = false;
        if (DetailPassword != null) DetailPassword.Text = "••••••••••••";
        if (RevealButton != null) RevealButton.Content = "Reveal";
    }
    private void CredentialsList_SelectionChanged(object sender, SelectionChangedEventArgs e) => ShowDetails(CredentialsList.SelectedItem as Credential);
    private void SearchInput_TextChanged(object sender, TextChangedEventArgs e) { if (_vault != null && _vault.IsUnlocked) RefreshList(); }
    private void AllNav_Click(object sender, RoutedEventArgs e) { _favoritesOnly = false; _notesOnly = false; _selectedCategory = null; RefreshList(); }
    private void NotesNav_Click(object sender, RoutedEventArgs e) { _favoritesOnly = false; _notesOnly = true; _selectedCategory = null; RefreshList(); }
    private void FavoritesNav_Click(object sender, RoutedEventArgs e) { _favoritesOnly = true; _selectedCategory = null; RefreshList(); }
    private void AllCategories_Click(object sender, RoutedEventArgs e)
    {
        _favoritesOnly = false; _notesOnly = false; _selectedCategory = null; RefreshList();
    }
    private void Uncategorized_Click(object sender, RoutedEventArgs e)
    {
        _favoritesOnly = false; _notesOnly = false; _selectedCategory = ""; RefreshList();
    }
    private void CategoriesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_refreshingCategories || CategoriesList.SelectedItem is not CategoryListItem item) return;
        _favoritesOnly = false; _notesOnly = false; _selectedCategory = item.Name; RefreshList();
    }
    private void CategoryNameInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) { e.Handled = true; AddCategory_Click(sender, new RoutedEventArgs()); }
    }
    private void AddCategory_Click(object sender, RoutedEventArgs e)
    {
        if (!_vault.IsUnlocked) return;
        try
        {
            var category = _vault.AddCategory(CategoryNameInput.Text);
            CategoryNameInput.Clear();
            _favoritesOnly = false; _notesOnly = false; _selectedCategory = category;
            RefreshList();
            FooterStatus.Text = $"Category '{category}' added to the encrypted vault.";
        }
        catch (ArgumentException ex) { MessageBox.Show(this, ex.Message, "Category", MessageBoxButton.OK, MessageBoxImage.Information); }
        catch (Exception) { MessageBox.Show(this, "The category could not be saved. The vault has been locked.", "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); LockVault(); }
    }
    private void DeleteCategory_Click(object sender, RoutedEventArgs e)
    {
        if (!_vault.IsUnlocked || CategoriesList.SelectedItem is not CategoryListItem item) return;
        var assigned = _vault.Credentials.Count(x => x.Category.Equals(item.Name, StringComparison.OrdinalIgnoreCase));
        var message = assigned == 0 ? $"Delete the empty category '{item.Name}'?" :
            $"Delete '{item.Name}'? {assigned} password{(assigned == 1 ? "" : "s")} will become uncategorized.";
        if (MessageBox.Show(this, message, "Delete category", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            _vault.DeleteCategory(item.Name); _selectedCategory = null; RefreshList();
            FooterStatus.Text = "Category deleted. Assigned passwords are now uncategorized.";
        }
        catch (Exception) { MessageBox.Show(this, "The category could not be deleted. The vault has been locked.", "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); LockVault(); }
    }
    private void Add_Click(object sender, RoutedEventArgs e) { _favoritesOnly = false; _notesOnly = false; EditCredential(null, false); }
    private void AddNote_Click(object sender, RoutedEventArgs e) { _favoritesOnly = false; _notesOnly = true; _selectedCategory = null; EditCredential(null, true); }
    private void Edit_Click(object sender, RoutedEventArgs e) { if (_selected != null) EditCredential(_selected); }
    private void EditCredential(Credential? source, bool note = false)
    {
        if (!_vault.IsUnlocked) return;
        var editor = new CredentialWindow(source, note, _vault.Categories, source == null ? _selectedCategory : source.Category) { Owner = this };
        _lastInteractionUtc = DateTime.UtcNow;
        if (editor.ShowDialog() != true || editor.Result == null) return;
        try { _vault.Upsert(editor.Result); RefreshList(editor.Result.Id); }
        catch (Exception) { MessageBox.Show(this, "Saving failed. For your safety, the vault has been locked. Reopen it and verify the last saved entry.", "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); LockVault(); }
    }
    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (_selected == null) return;
        if (MessageBox.Show(this, $"Permanently delete '{_selected.Title}'?", "Delete credential", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try { _vault.Delete(_selected.Id); RefreshList(); }
        catch (Exception) { MessageBox.Show(this, "Deletion could not be saved. The vault was locked to prevent showing uncommitted changes.", "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); LockVault(); }
    }
    private void CopyUsername_Click(object sender, RoutedEventArgs e) { if (_selected != null) CopySecret(_selected.Username); }
    private void CopyEmail_Click(object sender, RoutedEventArgs e) { if (_selected != null) CopySecret(_selected.Email); }
    private void CopyPassword_Click(object sender, RoutedEventArgs e) { if (_selected != null) CopySecret(_selected.Password); }
    private void CopySecret(string value)
    {
        if (ClipboardEnabled.IsChecked != true)
        {
            FooterStatus.Text = "Clipboard copying is disabled. Reveal and type the value manually if needed.";
            return;
        }
        try
        {
            SecureClipboard.SetSecret(value);
            _clipboardOwnedValue = value;
            _clipboardTimer.Stop(); _clipboardTimer.Start();
            FooterStatus.Text = "Copied. KeySafe will clear this clipboard value after 30 seconds if unchanged.";
        }
        catch { FooterStatus.Text = "Clipboard unavailable. Try again."; }
    }
    private void ClearOwnedClipboard()
    {
        _clipboardTimer.Stop();
        try { SecureClipboard.ClearIfUnchanged(_clipboardOwnedValue); }
        catch { }
        _clipboardOwnedValue = null;
    }
    private void Reveal_Click(object sender, RoutedEventArgs e)
    {
        if (_selected == null) return;
        _passwordRevealed = !_passwordRevealed;
        DetailPassword.Text = _passwordRevealed ? _selected.Password : "••••••••••••";
        RevealButton.Content = _passwordRevealed ? "Hide" : "Reveal";
    }
    private void TrackGlobalInput(object sender, PreProcessInputEventArgs e)
    {
        if (e.StagingItem.Input is KeyEventArgs or MouseEventArgs) _lastInteractionUtc = DateTime.UtcNow;
    }
    private void SessionChanged(object? sender, SessionSwitchEventArgs e)
    {
        if (e.Reason == SessionSwitchReason.SessionLock) Dispatcher.BeginInvoke(() => LockVault());
    }
    private void PowerChanged(object? sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend) Dispatcher.BeginInvoke(() => LockVault());
    }
    private void Recover_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new RecoverVaultWindow(this);
        if (dialog.ShowDialog() != true) return;
        try
        {
            var replacementCodes = _vault.Recover(dialog.Code, dialog.NewPassword);
            MasterPasswordInput.Clear(); ConfirmPasswordInput.Clear();
            _lastInteractionUtc = DateTime.UtcNow;
            WelcomePanel.Visibility = Visibility.Collapsed;
            VaultPanel.Visibility = Visibility.Visible;
            RefreshList();
            MessageBox.Show(this, "Recovery succeeded. The encryption key was rotated, so ALL previous recovery keys are now invalid. Save the new set that follows.", "KeySafe recovery", MessageBoxButton.OK, MessageBoxImage.Information);
            new RecoveryKeysWindow(this, replacementCodes).ShowDialog();
        }
        catch (Exception) { _vault.Lock(); WelcomeError.Text = "Recovery failed. The key may be incorrect, already used, or the vault may be damaged."; }
    }
    private void ChangeMaster_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new PasswordActionWindow(this, "Change master password", true, true, "Changing the master password also rotates encryption and invalidates ALL previous recovery keys. You must save a new set.");
        if (dialog.ShowDialog() != true) return;
        try { var codes = _vault.ChangeMasterPassword(dialog.OldPassword, dialog.NewPassword); RefreshList(); MessageBox.Show(this, "Master password and encryption key updated. ALL previous recovery keys are invalid; save the new set that follows.", "KeySafe", MessageBoxButton.OK, MessageBoxImage.Information); new RecoveryKeysWindow(this, codes).ShowDialog(); }
        catch (Exception) { MessageBox.Show(this, "Password update failed. Verify the current master password and vault state.", "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); if (!_vault.IsUnlocked) LockVault(); }
    }
    private void Rotate_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Rotate the vault encryption key? ALL 10 previous recovery keys will be invalidated in the current vault. You must save a NEW set of 10 keys.", "Rotate encryption key", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        var dialog = new PasswordActionWindow(this, "Rotate vault key", true, false, "Enter your current master password to rotate the root encryption key and issue 10 new recovery keys.");
        if (dialog.ShowDialog() != true) return;
        try { var codes = _vault.RotateVaultKey(dialog.OldPassword); RefreshList(); new RecoveryKeysWindow(this, codes).ShowDialog(); }
        catch (Exception) { MessageBox.Show(this, "Vault-key rotation failed. Verify your password and vault integrity.", "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); if (!_vault.IsUnlocked) LockVault(); }
    }
    private void Lock_Click(object sender, RoutedEventArgs e) => LockVault();
    private void LockVault()
    {
        if (_secureLockRestarting) return;
        _secureLockRestarting = true;
        foreach (Window window in Application.Current.Windows.Cast<Window>().ToArray())
            if (window != this && window.Owner == this) window.Close();
        HidePassword(); ClearOwnedClipboard();
        DetailUsername.Text = "";
        DetailEmail.Text = "";
        DetailWebsite.Text = "";
        DetailNotes.Text = "";
        DetailTitle.Text = "";
        TotpCodeText.Text = "";
        TotpCountdownText.Text = "";
        OtpDetails.Visibility = Visibility.Collapsed;
        AttachmentsList.ItemsSource = null;
        SearchInput.Clear();
        CategoryNameInput.Clear();
        CategoriesList.ItemsSource = null;
        _selectedCategory = null;
        CredentialsList.ItemsSource = null;
        _selected = null;
        _vault.Lock();
        MasterPasswordInput.Clear();
        ConfirmPasswordInput.Clear();
        try
        {
            var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate KeySafe executable.");
            Process.Start(new ProcessStartInfo(executable) { UseShellExecute = true });
            Application.Current.Shutdown();
        }
        catch
        {
            // Security takes precedence over preserving the window. If replacement
            // cannot start, exit so the unlocked managed heap is still destroyed.
            Application.Current.Shutdown(1);
        }
    }
    private void UpdateTotp()
    {
        if (_selected == null || !_vault.IsUnlocked || _selected.IsSecureNote || string.IsNullOrWhiteSpace(_selected.TotpSecret))
        {
            OtpDetails.Visibility = Visibility.Collapsed;
            TotpCodeText.Text = "";
            TotpCountdownText.Text = "";
            return;
        }
        TotpConfiguration? config = null;
        try
        {
            config = Totp.Parse(_selected.TotpSecret);
            var now = DateTimeOffset.UtcNow;
            TotpCodeText.Text = Totp.Generate(config, now);
            TotpCountdownText.Text = $"{Totp.SecondsRemaining(config, now)}s left";
            OtpDetails.Visibility = Visibility.Visible;
        }
        catch { OtpDetails.Visibility = Visibility.Collapsed; TotpCodeText.Text = ""; }
        finally { if (config != null) Security.Clear(config.Secret); }
    }

    private void CopyTotp_Click(object sender, RoutedEventArgs e)
    {
        if (_selected == null || !_vault.IsUnlocked || string.IsNullOrWhiteSpace(_selected.TotpSecret)) return;
        var config = Totp.Parse(_selected.TotpSecret);
        try { CopySecret(Totp.Generate(config, DateTimeOffset.UtcNow)); }
        finally { Security.Clear(config.Secret); }
    }

    private void AddAttachment_Click(object sender, RoutedEventArgs e)
    {
        if (_selected == null || !_vault.IsUnlocked) return;
        var picker = new OpenFileDialog { Title = "Attach a file to the encrypted vault", Filter = "All files (*.*)|*.*" };
        if (picker.ShowDialog(this) != true) return;
        byte[]? content = null;
        try
        {
            content = ReadBoundedFile(picker.FileName, VaultStore.MaximumAttachmentBytes, requireContent: true);
            var selectedId = _selected.Id;
            _vault.AddAttachment(selectedId, Path.GetFileName(picker.FileName), content);
            RefreshList(selectedId);
            FooterStatus.Text = "File encrypted into the vault. The original file was not deleted.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Attachment failed: " + ex.Message, "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error);
            if (!_vault.IsUnlocked) LockVault();
        }
        finally { Security.Clear(content); }
    }

    private void SaveAttachment_Click(object sender, RoutedEventArgs e)
    {
        if (_selected == null || AttachmentsList.SelectedItem is not EncryptedAttachment attachment) return;
        var picker = new SaveFileDialog { Title = "Export decrypted attachment", FileName = attachment.FileName,
            Filter = "All files (*.*)|*.*", OverwritePrompt = true };
        if (picker.ShowDialog(this) != true) return;
        if (MessageBox.Show(this, "The exported file will be PLAINTEXT on disk and will no longer be protected by KeySafe. Continue?",
            "Export unencrypted attachment", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        byte[]? data = null;
        try
        {
            data = _vault.ReadAttachment(_selected.Id, attachment.Id);
            PlaintextExport.WriteVerified(picker.FileName, data);
            data = null; // WriteVerified clears the caller buffer.
            FooterStatus.Text = "Attachment exported as plaintext. Securely protect the destination file.";
        }
        catch (Exception ex) { MessageBox.Show(this, "Cannot export attachment: " + ex.Message, "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); }
        finally { Security.Clear(data); }
    }

    private void RemoveAttachment_Click(object sender, RoutedEventArgs e)
    {
        if (_selected == null || AttachmentsList.SelectedItem is not EncryptedAttachment attachment) return;
        if (MessageBox.Show(this, $"Remove '{attachment.FileName}' from this encrypted entry?", "Remove attachment",
            MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try { var id = _selected.Id; _vault.RemoveAttachment(id, attachment.Id); RefreshList(id); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); if (!_vault.IsUnlocked) LockVault(); }
    }

    private void Import_Click(object sender, RoutedEventArgs e)
    {
        if (!_vault.IsUnlocked) return;
        var picker = new OpenFileDialog { Title = "Import credentials from CSV", Filter = "CSV files (*.csv)|*.csv" };
        if (picker.ShowDialog(this) != true) return;
        if (MessageBox.Show(this, "CSV files are UNENCRYPTED. KeySafe will import their contents into your vault, but will not securely delete the source CSV. Make sure the source is trusted. Continue?",
            "Import plaintext credentials", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            var csvBytes = ReadBoundedFile(picker.FileName, CsvTransfer.MaximumCsvBytes, requireContent: true);
            string csv;
            try { csv = new UTF8Encoding(false, true).GetString(csvBytes); }
            finally { Security.Clear(csvBytes); }
            var incoming = CsvTransfer.Import(csv);
            _vault.CreateEncryptedBackup();
            _vault.ImportCredentials(incoming);
            _favoritesOnly = false; _notesOnly = false;
            RefreshList();
            MessageBox.Show(this, $"Imported {incoming.Count} encrypted entries. A pre-import encrypted backup was created.\n\nRemember to securely handle the original CSV file.",
                "Import complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Import failed: " + ex.Message, "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error);
            if (!_vault.IsUnlocked) LockVault();
        }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (!_vault.IsUnlocked) return;
        if (MessageBox.Show(this, "WARNING: This creates a PLAINTEXT CSV containing passwords, notes and TOTP secrets. Attachments cannot be exported to CSV. Anyone with access to that file can read the secrets. Continue?",
            "Unencrypted export", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        var picker = new SaveFileDialog { Title = "Export plaintext CSV", FileName = "KeySafe-export.csv", Filter = "CSV files (*.csv)|*.csv", OverwritePrompt = true };
        if (picker.ShowDialog(this) != true) return;
        try
        {
            var csv = CsvTransfer.Export(_vault.Credentials, formulaSafe: true);
            PlaintextExport.WriteVerified(picker.FileName, new UTF8Encoding(false).GetBytes(csv));
            MessageBox.Show(this, "The CSV was exported UNENCRYPTED. Move it to a secure destination and remove unnecessary copies. Opening it in a spreadsheet may interpret cells as formulas.",
                "Export complete", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex) { MessageBox.Show(this, "Export failed: " + ex.Message, "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        _lastInteractionUtc = DateTime.UtcNow;
        if (!_vault.IsUnlocked) return;
        if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.N) { _favoritesOnly = false; _notesOnly = false; EditCredential(null); e.Handled = true; }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.L) { LockVault(); e.Handled = true; }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.F) { SearchInput.Focus(); SearchInput.SelectAll(); e.Handled = true; }
    }

    private static byte[] ReadBoundedFile(string path, int maximumBytes, bool requireContent)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536,
            FileOptions.SequentialScan);
        if (stream.Length > maximumBytes || stream.Length > int.MaxValue || (requireContent && stream.Length == 0))
            throw new InvalidDataException($"File must be between 1 byte and {maximumBytes} bytes.");
        var data = new byte[checked((int)stream.Length)];
        try { stream.ReadExactly(data); return data; }
        catch { Security.Clear(data); throw; }
    }
    private void Backup_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var file = _vault.CreateEncryptedBackup();
            MessageBox.Show(this, $"Encrypted backup successfully verified and saved to:\n{file}\n\nKeep a separate offline copy.",
                "Backup created", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show(this, "Backup failed: " + ex.Message, "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void RestoreBackup_Click(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog { Title = "Select KeySafe encrypted backup", Filter = "KeySafe backups (*.ksbackup)|*.ksbackup" };
        if (picker.ShowDialog(this) != true) return;
        if (MessageBox.Show(this, "This replaces the active vault with the chosen backup and preserves a quarantined copy of the current vault. Old recovery keys and old master-password state may become valid again. Rotate all recovery keys after restore. Continue?",
            "Confirm vault restoration", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        var dialog = new PasswordActionWindow(this, "Verify backup master password", true, false,
            "Enter the master password that was active when this backup was created.");
        if (dialog.ShowDialog() != true) return;
        try
        {
            _vault.RestoreEncryptedBackup(picker.FileName, dialog.OldPassword);
            RefreshList();
            MessageBox.Show(this, "Backup restored and cryptographically verified. Older recovery-key states may have been restored. Rotate keys if needed.",
                "Restore successful", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { MessageBox.Show(this, "Restore failed: " + ex.Message, "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); if (!_vault.IsUnlocked) LockVault(); }
    }

    private void History_Click(object sender, RoutedEventArgs e)
    {
        if (_selected == null) return;
        var versions = _vault.GetPasswordHistory(_selected.Id);
        if (versions.Count == 0)
        {
            MessageBox.Show(this, "No previous passwords are available for this credential.", "Password history", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var items = versions.Select((x, i) => $"{i + 1}: {x.SavedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}").ToArray();
        var window = new Window { Title = "Restore a previous password", Owner = this, Icon = (ImageSource)Application.Current.Resources["ApplicationIcon"], Width = 450, Height = 300,
            WindowStartupLocation = WindowStartupLocation.CenterOwner };
        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock { Text = "Select an earlier password version to restore.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
        var list = new ListBox { ItemsSource = items, SelectedIndex = 0, Height = 155 };
        panel.Children.Add(list);
        var restore = new Button { Content = "Restore selected version", Margin = new Thickness(0, 12, 0, 0), Height = 35 };
        restore.Click += (_, _) => { if (list.SelectedIndex >= 0) { window.DialogResult = true; window.Close(); } };
        panel.Children.Add(restore);
        window.Content = panel;
        if (window.ShowDialog() != true || list.SelectedIndex < 0) return;
        try { _vault.RestorePassword(_selected.Id, list.SelectedIndex); RefreshList(_selected.Id); }
        catch (Exception ex) { MessageBox.Show(this, "History restore failed: " + ex.Message, "KeySafe", MessageBoxButton.OK, MessageBoxImage.Error); if (!_vault.IsUnlocked) LockVault(); }
    }

}
