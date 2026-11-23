using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
namespace KeySafe;

internal static class DialogElements
{
    public static TextBlock Label(string text) => new() { Text = text, Margin = new Thickness(0, 12, 0, 6), FontWeight = FontWeights.SemiBold };
    public static Button Button(string text, bool primary = false) => new() { Content = text, Height = 40, Margin = new Thickness(0, 14, 0, 0), Style = primary ? (Style)Application.Current.Resources["AccentButton"] : null };
    public static Window Create(Window owner, string title, int width, int height) => new() { Title = title, Owner = owner, Icon = (ImageSource)Application.Current.Resources["ApplicationIcon"], Width = width, Height = height, MinWidth = width, WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = (Brush)Application.Current.Resources["Bg"], Foreground = (Brush)Application.Current.Resources["TextPrimary"], ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false };
}

public sealed class RecoveryKeysWindow : Window
{
    public RecoveryKeysWindow(Window owner, IReadOnlyList<string> codes)
    {
        var setup = DialogElements.Create(owner, "KeySafe - Save recovery keys", 780, 650);
        Title = setup.Title; Owner = owner; Icon = setup.Icon; Width = setup.Width; Height = setup.Height; MinWidth = setup.MinWidth;
        WindowStartupLocation = setup.WindowStartupLocation; Background = setup.Background; Foreground = setup.Foreground;
        ResizeMode = ResizeMode.NoResize; ShowInTaskbar = false;
        var panel = new StackPanel { Margin = new Thickness(26) };
        panel.Children.Add(new TextBlock { Text = "Save your 10 emergency recovery keys", FontWeight = FontWeights.Bold, FontSize = 23 });
        panel.Children.Add(new TextBlock { Text = "Each key works once in the current vault. Print or hand-copy these and keep them somewhere secure. They will not be displayed again. Never store them unencrypted on the same computer.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 14) });
        var codesBox = new TextBox { Text = string.Join(Environment.NewLine, codes.Select((code, i) => $"{i+1:D2}  {code}")), FontFamily = new FontFamily("Consolas"), FontSize = 13, IsReadOnly = true, TextWrapping = TextWrapping.NoWrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Height = 350, Padding = new Thickness(12) };
        panel.Children.Add(codesBox);
        panel.Children.Add(new TextBlock { Text = "Warning: older .bak files and copied vaults may still accept previously used keys. Offline storage cannot guarantee rollback resistance.", TextWrapping = TextWrapping.Wrap, Foreground = Brushes.Orange, Margin = new Thickness(0, 10, 0, 0) });
        panel.Children.Add(new TextBlock { Text = "Verification: enter the final 8 characters (ignoring hyphens) of keys 3 and 8.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 12, 0, 0) });
        var verify3 = new TextBox { Height = 34, MaxLength = 8, Margin = new Thickness(0, 6, 0, 0) };
        var verify8 = new TextBox { Height = 34, MaxLength = 8, Margin = new Thickness(0, 6, 0, 0) };
        panel.Children.Add(verify3); panel.Children.Add(verify8);
        var acknowledgment = new CheckBox { Content = "I have securely recorded all 10 recovery keys.", Margin = new Thickness(0, 12, 0, 0) };
        panel.Children.Add(acknowledgment);
        var close = DialogElements.Button("Continue", true);
        close.IsEnabled = false;
        void validate() => close.IsEnabled = acknowledgment.IsChecked == true &&
            verify3.Text.Equals(new string(codes[2].Where(Uri.IsHexDigit).ToArray())[^8..], StringComparison.OrdinalIgnoreCase) &&
            verify8.Text.Equals(new string(codes[7].Where(Uri.IsHexDigit).ToArray())[^8..], StringComparison.OrdinalIgnoreCase);
        acknowledgment.Checked += (_, _) => validate();
        acknowledgment.Unchecked += (_, _) => validate();
        verify3.TextChanged += (_, _) => validate(); verify8.TextChanged += (_, _) => validate();
        close.Click += (_, _) => Close();
        panel.Children.Add(close);
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Closed += (_, _) => { codesBox.Clear(); verify3.Clear(); verify8.Clear(); };
    }
}

public sealed class PasswordActionWindow : Window
{
    private readonly PasswordBox _old = new() { Height = 42 };
    private readonly PasswordBox _new = new() { Height = 42 };
    private readonly PasswordBox _confirm = new() { Height = 42 };
    private readonly TextBlock _error = new() { Foreground = Brushes.OrangeRed, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0) };
    private readonly TextBlock _strength = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0), FontSize = 11 };
    public string OldPassword => _old.Password;
    public string NewPassword => _new.Password;
    public PasswordActionWindow(Window owner, string title, bool needsOldPassword, bool needsNewPassword, string description)
    {
        var basic = DialogElements.Create(owner, "KeySafe - " + title, 475, 435);
        Title = basic.Title; Owner = owner; Icon = basic.Icon; Width = basic.Width; Height = needsNewPassword ? 435 : 295;
        WindowStartupLocation = basic.WindowStartupLocation; Background = basic.Background; Foreground = basic.Foreground;
        ResizeMode = ResizeMode.NoResize; ShowInTaskbar = false;
        var panel = new StackPanel { Margin = new Thickness(25) };
        panel.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.Bold, FontSize = 22 });
        panel.Children.Add(new TextBlock { Text = description, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 9, 0, 7) });
        if (needsOldPassword) { panel.Children.Add(DialogElements.Label("Current master password")); panel.Children.Add(_old); }
        if (needsNewPassword)
        {
            panel.Children.Add(DialogElements.Label("New master password (12+ characters)")); panel.Children.Add(_new);
            panel.Children.Add(_strength);
            panel.Children.Add(DialogElements.Label("Confirm new master password")); panel.Children.Add(_confirm);
            _new.PasswordChanged += (_, _) => _strength.Text = Security.PasswordGuidance(_new.Password);
        }
        panel.Children.Add(_error);
        var apply = DialogElements.Button("Confirm", true);
        apply.Click += (_, _) =>
        {
            if (needsOldPassword && string.IsNullOrEmpty(_old.Password)) { _error.Text = "Enter your current master password."; return; }
            if (needsNewPassword && (_new.Password.Length < Security.MinimumPasswordCharacters || _new.Password.Length > Security.MaximumPasswordCharacters || string.IsNullOrWhiteSpace(_new.Password))) { _error.Text = $"Use a master password of {Security.MinimumPasswordCharacters}â€“{Security.MaximumPasswordCharacters} characters."; return; }
            if (needsNewPassword && _new.Password != _confirm.Password) { _error.Text = "New passwords do not match."; return; }
            DialogResult = true;
        };
        panel.Children.Add(apply);
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Closed += (_, _) => { _old.Clear(); _new.Clear(); _confirm.Clear(); };
    }
}

public sealed class RecoverVaultWindow : Window
{
    private readonly TextBox _code = new() { Height = 42, FontFamily = new FontFamily("Consolas") };
    private readonly PasswordBox _new = new() { Height = 42 };
    private readonly PasswordBox _confirm = new() { Height = 42 };
    private readonly TextBlock _error = new() { Foreground = Brushes.OrangeRed, Margin = new Thickness(0, 10, 0, 0) };
    private readonly TextBlock _strength = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 0), FontSize = 11 };
    public string Code => _code.Text;
    public string NewPassword => _new.Password;
    public RecoverVaultWindow(Window owner)
    {
        var basic = DialogElements.Create(owner, "KeySafe - Emergency recovery", 550, 475);
        Title = basic.Title; Owner = owner; Icon = basic.Icon; Width = basic.Width; Height = basic.Height;
        WindowStartupLocation = basic.WindowStartupLocation; Background = basic.Background; Foreground = basic.Foreground;
        ResizeMode = ResizeMode.NoResize; ShowInTaskbar = false;
        var panel = new StackPanel { Margin = new Thickness(26) };
        panel.Children.Add(new TextBlock { Text = "Emergency vault recovery", FontWeight = FontWeights.Bold, FontSize = 23 });
        panel.Children.Add(new TextBlock { Text = "Enter one UNUSED recovery key and set a new master password. Recovery rotates vault encryption and invalidates ALL previous recovery keys; you must save the new set.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 10) });
        panel.Children.Add(DialogElements.Label("Recovery key")); panel.Children.Add(_code);
        panel.Children.Add(DialogElements.Label("New master password")); panel.Children.Add(_new);
        panel.Children.Add(_strength);
        panel.Children.Add(DialogElements.Label("Confirm new master password")); panel.Children.Add(_confirm);
        _new.PasswordChanged += (_, _) => _strength.Text = Security.PasswordGuidance(_new.Password);
        panel.Children.Add(_error);
        var button = DialogElements.Button("Recover vault", true);
        button.Click += (_, _) =>
        {
            if (!VaultStore.IsRecoveryCodeWellFormed(_code.Text)) { _error.Text = "Enter a complete recovery key with a valid checksum."; return; }
            if (_new.Password.Length < Security.MinimumPasswordCharacters || _new.Password.Length > Security.MaximumPasswordCharacters || string.IsNullOrWhiteSpace(_new.Password)) { _error.Text = $"Master password must have {Security.MinimumPasswordCharacters}â€“{Security.MaximumPasswordCharacters} characters."; return; }
            if (_new.Password != _confirm.Password) { _error.Text = "Passwords do not match."; return; }
            DialogResult = true;
        };
        panel.Children.Add(button);
        Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Closed += (_, _) => { _code.Clear(); _new.Clear(); _confirm.Clear(); };
    }
}
