using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sbroenne.WindowsMcp.Native;

/// <summary>
/// P/Invoke declarations for Windows session APIs. The server drives the interactive desktop, so it has to be
/// able to tell whether it is running in the console session or somewhere that has no desktop at all, such as
/// a service or an SSH session.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class SessionNativeMethods
{
    /// <summary>Value WTSGetActiveConsoleSessionId returns when there is no attached console session.</summary>
    internal const uint NoActiveConsoleSession = 0xFFFFFFFF;

    /// <summary>
    /// Retrieves the session identifier of the console session, the session the physical keyboard, mouse,
    /// and display are attached to. See the Win32 API WTSGetActiveConsoleSessionId in kernel32.dll.
    /// </summary>
    /// <returns>The console session id, or 0xFFFFFFFF when there is no console session.</returns>
    [LibraryImport("kernel32.dll")]
    internal static partial uint WTSGetActiveConsoleSessionId();

    /// <summary>
    /// Retrieves the terminal services session a process belongs to.
    /// See the Win32 API ProcessIdToSessionId in kernel32.dll.
    /// </summary>
    /// <param name="dwProcessId">The process identifier to look up.</param>
    /// <param name="pSessionId">Receives the session identifier.</param>
    /// <returns>True on success, false otherwise.</returns>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    /// <summary>
    /// Determines whether this process runs in the interactive console session.
    /// </summary>
    /// <returns>True when this process shares the session the physical desktop is attached to.</returns>
    internal static bool IsInteractiveConsoleSession()
    {
        var consoleSession = WTSGetActiveConsoleSessionId();
        return consoleSession != NoActiveConsoleSession
            && ProcessIdToSessionId((uint)Environment.ProcessId, out var ownSession)
            && ownSession == consoleSession;
    }
}
