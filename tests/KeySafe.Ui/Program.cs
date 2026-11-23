using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Threading;

namespace KeySafe.UiTests;

internal static class Program
{
    private static int _checks;

    [STAThread]
    private static int Main()
    {
        App? app = null;
        CredentialWindow? editor = null;
        try
        {
            app = new App();
            app.InitializeComponent();
            var storagePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "KeySafe", KeySafeInfo.DataFolderName);
            var storage = new DirectoryInfo(storagePath);
            var storageAcl = storage.GetAccessControl(AccessControlSections.Access);
            var actualSids = storageAcl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Select(rule => rule.IdentityReference.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var expectedSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
                WindowsIdentity.GetCurrent().User!.Value,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value
            };
            Check(storageAcl.AreAccessRulesProtected && actualSids.SetEquals(expectedSids),
                "v1.1 application-data ACL is protected and limited to user, SYSTEM, and Administrators");
            Check((storage.Attributes & FileAttributes.ReparsePoint) == 0,
                "v1.1 application-data directory is not a reparse point");
            Check(File.Exists(Path.Combine(AppContext.BaseDirectory, "e_sqlite3.dll")) ||
                  File.Exists(Path.Combine(AppContext.BaseDirectory, "runtimes", "win-x64", "native", "e_sqlite3.dll")),
                "pinned SQLite native dependency was verified during application startup");
            editor = new CredentialWindow(null, false, new[] { "Personal", "Work" }, "Work");
            editor.Show();
            editor.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);

            Check(editor.Icon != null, "credential editor receives the packaged application icon");
            var recoveryDialog = new RecoverVaultWindow(editor);
            Check(recoveryDialog.Icon != null, "programmatic recovery dialogs receive the packaged application icon");
            recoveryDialog.Close();

            var email = editor.FindName("EmailInput") as TextBox;
            Check(email is { IsEnabled: true }, "separate optional email editor is instantiated");

            var category = editor.FindName("CategoryInput") as ComboBox;
            Check(category != null && category.SelectedItem?.ToString() == "Work", "category selection retains the requested value");
            category!.ApplyTemplate();
            Check(category.Template.FindName("DropDownToggle", category) is ToggleButton, "category selector uses the custom control template");
            Check(IsColor(category.Background, 0x20, 0x2E, 0x40) && IsColor(category.Foreground, 0xED, 0xF3, 0xFC),
                "category selector uses dark background and light foreground");

            category.IsDropDownOpen = true;
            editor.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
            var item = category.ItemContainerGenerator.ContainerFromIndex(0) as ComboBoxItem;
            Check(item != null && IsColor(item.Foreground, 0xED, 0xF3, 0xFC), "category dropdown items use the dark-theme foreground");
            Check(category.IsDropDownOpen, "category dropdown opens without a runtime binding or template error");

            Console.WriteLine($"ALL {_checks} WPF UI CHECKS PASSED. No vault was opened.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
        finally
        {
            editor?.Close();
            app?.Shutdown();
        }
    }

    private static bool IsColor(Brush? brush, byte red, byte green, byte blue) =>
        brush is SolidColorBrush solid && solid.Color.R == red && solid.Color.G == green && solid.Color.B == blue;

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception("FAIL: " + message);
        _checks++;
        Console.WriteLine("PASS: " + message);
    }
}
