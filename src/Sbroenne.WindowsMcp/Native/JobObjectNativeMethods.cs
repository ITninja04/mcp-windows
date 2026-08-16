using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Sbroenne.WindowsMcp.Native;

/// <summary>
/// P/Invoke declarations for Windows Job Objects. A job with the kill-on-close limit guarantees that a
/// supervised child process dies with this process even if this process is force-killed, which is how the
/// Tailscale Serve route is prevented from outliving the server.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class JobObjectNativeMethods
{
    /// <summary>Information class for JOBOBJECT_EXTENDED_LIMIT_INFORMATION, used with SetInformationJobObject.</summary>
    internal const int JobObjectExtendedLimitInformation = 9;

    /// <summary>Kills every process in the job when the last handle to the job is closed.</summary>
    internal const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;

    /// <summary>
    /// Creates or opens a job object (Win32 CreateJobObjectW).
    /// </summary>
    /// <param name="lpJobAttributes">Security attributes, or IntPtr.Zero for the defaults.</param>
    /// <param name="lpName">Name of the job, or null for an unnamed job.</param>
    /// <returns>A raw handle to the job. The handle is NULL, not -1, when the call fails.</returns>
    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial nint CreateJobObjectW(nint lpJobAttributes, string? lpName);

    /// <summary>
    /// Sets limits on a job object (Win32 SetInformationJobObject).
    /// </summary>
    /// <param name="hJob">Handle to the job.</param>
    /// <param name="jobObjectInformationClass">Information class, e.g. <see cref="JobObjectExtendedLimitInformation"/>.</param>
    /// <param name="lpJobObjectInformation">The limit structure to apply.</param>
    /// <param name="cbJobObjectInformationLength">Size of the limit structure in bytes.</param>
    /// <returns>True on success, false otherwise.</returns>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetInformationJobObject(
        SafeJobHandle hJob,
        int jobObjectInformationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInformation,
        int cbJobObjectInformationLength);

    /// <summary>
    /// Assigns a process to a job object (Win32 AssignProcessToJobObject).
    /// </summary>
    /// <param name="hJob">Handle to the job.</param>
    /// <param name="hProcess">Handle to the process, needing PROCESS_SET_QUOTA and PROCESS_TERMINATE rights.</param>
    /// <returns>True on success, false otherwise.</returns>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool AssignProcessToJobObject(SafeJobHandle hJob, SafeProcessHandle hProcess);

    /// <summary>
    /// Closes an open object handle (Win32 CloseHandle).
    /// </summary>
    /// <param name="hObject">The handle to close.</param>
    /// <returns>True on success, false otherwise.</returns>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(nint hObject);
}

/// <summary>
/// Owns a job object handle. Closing the last handle to a kill-on-close job terminates every process
/// assigned to it, so this handle must be held in a field for as long as the child should live.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SafeJobHandle"/> class, taking ownership of a raw handle
    /// returned by <see cref="JobObjectNativeMethods.CreateJobObjectW"/>.
    /// </summary>
    /// <param name="existingHandle">The raw job handle to own.</param>
    internal SafeJobHandle(nint existingHandle)
        : base(true)
    {
        SetHandle(existingHandle);
    }

    /// <summary>Closes the job handle, killing every process still assigned to the job.</summary>
    /// <returns>True when the handle was closed.</returns>
    protected override bool ReleaseHandle() => JobObjectNativeMethods.CloseHandle(handle);
}

/// <summary>
/// Win32 IO_COUNTERS. Present so the extended limit structure has the right size and layout; the server
/// never reads the counters.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct IO_COUNTERS
{
    /// <summary>Number of read operations performed.</summary>
    public ulong ReadOperationCount;

    /// <summary>Number of write operations performed.</summary>
    public ulong WriteOperationCount;

    /// <summary>Number of I/O operations performed other than read and write.</summary>
    public ulong OtherOperationCount;

    /// <summary>Number of bytes read.</summary>
    public ulong ReadTransferCount;

    /// <summary>Number of bytes written.</summary>
    public ulong WriteTransferCount;

    /// <summary>Number of bytes transferred during operations other than read and write.</summary>
    public ulong OtherTransferCount;
}

/// <summary>
/// Win32 JOBOBJECT_BASIC_LIMIT_INFORMATION. This server sets only <see cref="LimitFlags"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
{
    /// <summary>Per-process user-mode execution time limit, in 100-nanosecond ticks.</summary>
    public long PerProcessUserTimeLimit;

    /// <summary>Per-job user-mode execution time limit, in 100-nanosecond ticks.</summary>
    public long PerJobUserTimeLimit;

    /// <summary>Which of the other members are in effect, e.g. JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.</summary>
    public uint LimitFlags;

    /// <summary>Minimum working set size for each process.</summary>
    public nuint MinimumWorkingSetSize;

    /// <summary>Maximum working set size for each process.</summary>
    public nuint MaximumWorkingSetSize;

    /// <summary>Maximum number of processes that can run concurrently in the job.</summary>
    public uint ActiveProcessLimit;

    /// <summary>Processor affinity mask for the job.</summary>
    public nuint Affinity;

    /// <summary>Priority class for each process in the job.</summary>
    public uint PriorityClass;

    /// <summary>Scheduling class for the job, from 0 to 9.</summary>
    public uint SchedulingClass;
}

/// <summary>
/// Win32 JOBOBJECT_EXTENDED_LIMIT_INFORMATION, the structure passed with
/// <see cref="JobObjectNativeMethods.JobObjectExtendedLimitInformation"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
{
    /// <summary>The basic limits, including the limit flags.</summary>
    public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;

    /// <summary>I/O accounting for the job. Not used by this server.</summary>
    public IO_COUNTERS IoInfo;

    /// <summary>Per-process committed memory limit, in bytes.</summary>
    public nuint ProcessMemoryLimit;

    /// <summary>Job-wide committed memory limit, in bytes.</summary>
    public nuint JobMemoryLimit;

    /// <summary>Peak committed memory used by any process in the job.</summary>
    public nuint PeakProcessMemoryUsed;

    /// <summary>Peak committed memory used by the job.</summary>
    public nuint PeakJobMemoryUsed;
}
