using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Sbroenne.WindowsMcp.Native;

namespace Sbroenne.WindowsMcp.Tailscale;

/// <summary>
/// A Windows Job Object configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. Every process assigned to the
/// job is terminated when the job handle closes, which happens on <see cref="Dispose"/> and also when this
/// process dies for any reason, including a force kill.
/// </summary>
/// <remarks>
/// This is how the Tailscale Serve route is guaranteed not to outlive the server. A foreground
/// <c>tailscale serve</c> child keeps the route alive only while it runs, so killing it with the job removes
/// the route. Only the kill-on-close flag is set: breakaway flags would let a child leave the job, which is
/// exactly what must not happen.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class KillOnCloseJob : IDisposable
{
    // Holding the handle in an instance field is load bearing. A SafeHandle left in a local can be finalized
    // once the constructor returns, and closing the last handle to a kill-on-close job kills the child.
    private readonly SafeJobHandle _handle;

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="KillOnCloseJob"/> class, creating an unnamed job object
    /// and applying the kill-on-close limit before any process is assigned to it.
    /// </summary>
    /// <exception cref="Win32Exception">The job could not be created or the limit could not be set.</exception>
    public KillOnCloseJob()
    {
        // CreateJobObject returns NULL, not -1, when it fails.
        var rawHandle = JobObjectNativeMethods.CreateJobObjectW(nint.Zero, null);
        if (rawHandle == nint.Zero)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "CreateJobObject failed, so the Tailscale Serve child cannot be contained.");
        }

        var handle = new SafeJobHandle(rawHandle);

        var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JobObjectNativeMethods.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
        };

        // The limit has to be in place before the first process joins, otherwise a child assigned in the gap
        // would survive a crash of this process.
        if (!JobObjectNativeMethods.SetInformationJobObject(
                handle,
                JobObjectNativeMethods.JobObjectExtendedLimitInformation,
                ref limits,
                Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()))
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "SetInformationJobObject failed, so the job would not kill its children on close.");
        }

        _handle = handle;
    }

    /// <summary>
    /// Assigns a running process to the job. The process handle returned by <see cref="Process.Start()"/>
    /// already carries the PROCESS_SET_QUOTA and PROCESS_TERMINATE rights this needs.
    /// </summary>
    /// <param name="process">The started process to contain.</param>
    /// <exception cref="Win32Exception">The process could not be assigned to the job.</exception>
    public void Assign(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!JobObjectNativeMethods.AssignProcessToJobObject(_handle, process.SafeHandle))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "AssignProcessToJobObject failed, so the child would outlive this server. Kill it before continuing.");
        }
    }

    /// <summary>
    /// Closes the job handle. Every process still assigned to the job is terminated by the kernel.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _handle.Dispose();
        GC.SuppressFinalize(this);
    }
}
