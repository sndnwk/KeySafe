using System.Runtime.InteropServices;
using System.Windows;

namespace KeySafe;

public static class SecureClipboard
{
    public static void SetSecret(string value)
    {
        var data = new DataObject();
        data.SetData(DataFormats.UnicodeText, value);
        data.SetData("ExcludeClipboardContentFromMonitorProcessing", new byte[] { 0 });
        data.SetData("CanIncludeInClipboardHistory", new byte[4]);
        data.SetData("CanUploadToCloudClipboard", new byte[4]);
        Retry(() => Clipboard.SetDataObject(data, false));
    }

    public static bool ClearIfUnchanged(string? ownedValue)
    {
        if (ownedValue == null) return false;
        var cleared = false;
        Retry(() =>
        {
            if (Clipboard.ContainsText() && Clipboard.GetText() == ownedValue)
            {
                Clipboard.Clear();
                cleared = true;
            }
        });
        return cleared;
    }

    private static void Retry(Action action)
    {
        for (var attempt = 0; ; attempt++)
        {
            try { action(); return; }
            catch (ExternalException) when (attempt < 5) { Thread.Sleep(25 * (attempt + 1)); }
        }
    }
}
