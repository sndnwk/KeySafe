using System.Runtime.InteropServices;
using System.Windows;

namespace KeySafe.ClipboardTests;

internal static class Program
{
    private static int _checks;

    [STAThread]
    private static int Main()
    {
        try
        {
            const string secret = "SYNTHETIC-CLIPBOARD-SECRET";
            SecureClipboard.SetSecret(secret);
            Check(WaitUntil(() => Clipboard.ContainsText() && Clipboard.GetText() == secret), "secret copied as Unicode text");
            IDataObject? data = null;
            Check(WaitUntil(() => (data = Clipboard.GetDataObject()) != null), "clipboard data object available");
            Check(data!.GetDataPresent("ExcludeClipboardContentFromMonitorProcessing"), "clipboard-history exclusion format present");
            Check(data.GetDataPresent("CanIncludeInClipboardHistory"), "local-history opt-out format present");
            Check(data.GetDataPresent("CanUploadToCloudClipboard"), "cloud-clipboard opt-out format present");
            Check(SecureClipboard.ClearIfUnchanged(secret) && !Clipboard.ContainsText(), "unchanged owned clipboard is cleared");

            SecureClipboard.SetSecret(secret);
            Clipboard.SetText("UNRELATED-CONTENT");
            Check(!SecureClipboard.ClearIfUnchanged(secret) && Clipboard.GetText() == "UNRELATED-CONTENT", "changed clipboard is never overwritten");

            var nonText = new DataObject(); nonText.SetData(DataFormats.Bitmap, new object());
            Clipboard.SetDataObject(nonText, false);
            Check(!SecureClipboard.ClearIfUnchanged(secret), "non-text clipboard is not cleared as owned text");

            Clipboard.Clear();
            Console.WriteLine($"ALL {_checks} CLIPBOARD CHECKS PASSED. Windows history/cloud formats were asserted; policy enforcement remains OS-controlled.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
        finally { try { Clipboard.Clear(); } catch { } }
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception("FAIL: " + message);
        _checks++; Console.WriteLine("PASS: " + message);
    }

    private static bool WaitUntil(Func<bool> predicate)
    {
        for (var attempt = 0; attempt < 40; attempt++)
        {
            try { if (predicate()) return true; }
            catch (ExternalException) { }
            Thread.Sleep(25);
        }
        return false;
    }
}
