using System.Buffers;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace Sbroenne.WindowsMcp.Hosting;

/// <summary>
/// One audited tool call.
/// </summary>
/// <param name="TimestampIso">When the call finished, ISO 8601 with an offset.</param>
/// <param name="Login">The caller's tailnet login, or "anonymous" when the transport carries no identity.</param>
/// <param name="Node">The caller's node name, or an empty string when it is not known.</param>
/// <param name="Tool">The tool that was called.</param>
/// <param name="Success">True when the tool returned a non-error result.</param>
/// <param name="DurationMs">How long the call took, in milliseconds.</param>
/// <remarks>
/// Deliberately holds no argument values. The audit trail answers who did what and when; the arguments to these
/// tools are keystrokes, clipboard contents, and file paths, which must not be written to a log file.
/// </remarks>
public sealed record AuditRecord(
    string TimestampIso,
    string Login,
    string Node,
    string Tool,
    bool Success,
    long DurationMs);

/// <summary>
/// Receives one <see cref="AuditRecord"/> per tool call.
/// </summary>
public interface IAuditSink
{
    /// <summary>
    /// Records one tool call. Implementations must not throw: a broken sink may not break a tool call.
    /// </summary>
    /// <param name="record">The record to persist.</param>
    void Write(AuditRecord record);
}

/// <summary>
/// Discards audit records. Used when no --audit-file was given, so the log remains the only audit trail.
/// </summary>
public sealed class NullAuditSink : IAuditSink
{
    /// <summary>The shared instance. The type holds no state.</summary>
    public static readonly NullAuditSink Instance = new();

    /// <inheritdoc/>
    public void Write(AuditRecord record)
    {
        // Nothing to do; the logger already carries the same information.
    }
}

/// <summary>
/// Appends one JSON object per line to a file whose permissions are locked to this user and Administrators.
/// </summary>
/// <remarks>
/// <para>
/// The audit trail says which tailnet user drove this desktop. That is only worth something if a third party
/// cannot rewrite it, so the file is created with an explicit DACL that grants this user and the local
/// Administrators group and nobody else, with inheritance from the parent directory switched off.
/// </para>
/// <para>
/// Permissions on a file cannot protect it from someone who can replace or delete it through the directory,
/// so a directory that grants Everyone write access is refused outright at construction.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class AuditFileSink : IAuditSink, IDisposable
{
    private static readonly byte[] LineSeparator = "\r\n"u8.ToArray();

    private readonly FileStream _stream;
    private readonly Lock _writeLock = new();
    private bool _disposed;

    /// <summary>
    /// Opens or creates the audit file.
    /// </summary>
    /// <param name="path">Path to the JSON-lines audit file.</param>
    /// <exception cref="ArgumentException"><paramref name="path"/> is empty or has no directory.</exception>
    /// <exception cref="UnauthorizedAccessException">The containing directory grants Everyone write access.</exception>
    public AuditFileSink(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException($"Audit path '{path}' has no directory.", nameof(path));

        Directory.CreateDirectory(directory);
        ThrowIfWorldWritable(directory);

        FilePath = fullPath;
        _stream = OpenRestricted(fullPath);
    }

    /// <summary>The full path being appended to.</summary>
    public string FilePath { get; }

    /// <inheritdoc/>
    public void Write(AuditRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        var buffer = new ArrayBufferWriter<byte>(256);
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("timestamp", record.TimestampIso);
            writer.WriteString("login", record.Login);
            writer.WriteString("node", record.Node);
            writer.WriteString("tool", record.Tool);
            writer.WriteBoolean("success", record.Success);
            writer.WriteNumber("durationMs", record.DurationMs);
            writer.WriteEndObject();
        }

        lock (_writeLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _stream.Write(buffer.WrittenSpan);
            _stream.Write(LineSeparator);
            _stream.Flush();
        }
    }

    /// <summary>Formats an instant the way <see cref="AuditRecord.TimestampIso"/> expects.</summary>
    /// <param name="instant">The instant to format.</param>
    /// <returns>An ISO 8601 timestamp with milliseconds and an offset.</returns>
    public static string FormatTimestamp(DateTimeOffset instant) =>
        instant.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK", CultureInfo.InvariantCulture);

    /// <inheritdoc/>
    public void Dispose()
    {
        lock (_writeLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _stream.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Creates the file with a restrictive DACL, or opens an existing one and tightens it.
    /// </summary>
    /// <param name="fullPath">Full path to the audit file.</param>
    /// <returns>A stream positioned at the end of the file.</returns>
    private static FileStream OpenRestricted(string fullPath)
    {
        var security = BuildFileSecurity();
        var file = new FileInfo(fullPath);

        try
        {
            // CreateNew applies the DACL as part of the create, so the file is never briefly world readable.
            var stream = file.Create(
                FileMode.CreateNew,
                FileSystemRights.AppendData | FileSystemRights.WriteData | FileSystemRights.ReadData | FileSystemRights.Synchronize,
                FileShare.Read,
                4096,
                FileOptions.None,
                security);
            return stream;
        }
        catch (IOException)
        {
            // The file already exists. Open it for append, then replace whatever DACL it carried.
            var stream = new FileStream(fullPath, FileMode.Append, FileAccess.Write, FileShare.Read);
            try
            {
                file.SetAccessControl(security);
            }
            catch (UnauthorizedAccessException)
            {
                stream.Dispose();
                throw;
            }

            return stream;
        }
    }

    private static FileSecurity BuildFileSecurity()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User
            ?? throw new UnauthorizedAccessException("The current Windows identity has no user SID, so the audit file cannot be secured.");
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.Modify | FileSystemRights.Synchronize, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, AccessControlType.Allow));
        return security;
    }

    /// <summary>
    /// Refuses a directory that grants Everyone write access.
    /// </summary>
    /// <param name="directory">The directory that will hold the audit file.</param>
    /// <remarks>
    /// Only the Everyone SID is checked. Groups such as Authenticated Users legitimately hold write access on
    /// shared locations, and deciding whether that is acceptable belongs to the operator, not to this process.
    /// </remarks>
    private static void ThrowIfWorldWritable(string directory)
    {
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        const FileSystemRights WriteRights =
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete | FileSystemRights.ChangePermissions;

        DirectorySecurity security;
        try
        {
            security = new DirectoryInfo(directory).GetAccessControl(AccessControlSections.Access);
        }
        catch (UnauthorizedAccessException)
        {
            // The ACL cannot be read, so it cannot be judged. Continue: the file DACL is still applied.
            // PrivilegeNotHeldException derives from this, so both cases land here.
            return;
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow
                && rule.IdentityReference is SecurityIdentifier sid
                && sid == everyone
                && (rule.FileSystemRights & WriteRights) != 0)
            {
                throw new UnauthorizedAccessException(
                    $"Refusing to write the audit file in '{directory}': it grants Everyone write access. Choose a directory only you can write to.");
            }
        }
    }
}
