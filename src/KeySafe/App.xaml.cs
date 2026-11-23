using System.IO;
using System.Windows;
using System.Windows.Threading;
namespace KeySafe;
public partial class App : Application
{
    public App()
    {
        WindowsProcessHardening.Apply();
        StorageSecurity.EnsurePrivateApplicationDirectory();
        DispatcherUnhandledException += HandleStartupError;
    }
    private void HandleStartupError(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            var directory = Path.Combine(StorageSecurity.EnsurePrivateApplicationDirectory(), "logs");
            Directory.CreateDirectory(directory);
            File.AppendAllText(Path.Combine(directory, "startup.log"), $"{DateTime.UtcNow:O} | {e.Exception.GetType().FullName}\n");
        }
        catch { }
        MessageBox.Show($"KeySafe encountered an unexpected error and must close. Check %LOCALAPPDATA%\\KeySafe\\{KeySafeInfo.DataFolderName}\\logs\\startup.log for the exception type. Vault data was not intentionally modified by this error handler.", "KeySafe application error", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
        Shutdown(1);
    }
}
