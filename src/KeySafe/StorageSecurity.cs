using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace KeySafe;

internal static class StorageSecurity
{
    internal static string EnsurePrivateApplicationDirectory()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("KeySafe v1.1.0 supports Windows only.");
        var local = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        var keySafe = Path.Combine(local, "KeySafe");
        var version = Path.Combine(keySafe, KeySafeInfo.DataFolderName);
        RejectReparsePoint(local);
        Directory.CreateDirectory(keySafe);
        RejectReparsePoint(keySafe);
        Directory.CreateDirectory(version);
        RejectReparsePoint(version);
        ApplyPrivateAcl(version);
        RejectReparsePoint(version);
        return version;
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException($"Refusing redirected application-data directory: {path}");
    }

    private static void ApplyPrivateAcl(string path)
    {
        var user = WindowsIdentity.GetCurrent().User
            ?? throw new UnauthorizedAccessException("The current Windows user SID is unavailable.");
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        acl.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, inheritance,
            PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(acl);
    }
}
