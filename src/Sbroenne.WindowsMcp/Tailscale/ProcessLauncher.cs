using System.Diagnostics;
using System.Runtime.Versioning;

namespace Sbroenne.WindowsMcp.Tailscale;

/// <summary>
/// Starts child processes inside a kill-on-close Job Object so a child cannot outlive this server.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProcessLauncher : IChildProcessLauncher
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ProcessLauncher"/> class.
    /// </summary>
    public ProcessLauncher()
    {
    }

    /// <inheritdoc/>
    public IChildProcess Start(string fileName, IReadOnlyList<string> arguments, string workingDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);

        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        var job = new KillOnCloseJob();
        Process? process = null;
        try
        {
            process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            _ = process.Start();

            // Process.Start cannot create a suspended process, so a grandchild spawned in the window between
            // Start and AssignProcessToJobObject would escape the job. tailscale.exe does not fork helpers on
            // this path, so the window is accepted rather than papered over with a CreateProcess rewrite.
            job.Assign(process);

            var child = new JobChildProcess(process, job);
            child.BeginDrainingStandardError();
            return child;
        }
        catch
        {
            // Disposing the job kills anything already assigned to it.
            job.Dispose();
            process?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// A started process that owns the job it was assigned to. Standard error is drained continuously,
    /// because a full pipe buffer would block the child.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private sealed class JobChildProcess : IChildProcess, IDisposable
    {
        private const int MaxCapturedLines = 200;

        private readonly Process _process;
        private readonly KillOnCloseJob _job;
        private readonly Queue<string> _standardErrorLines = new();
        private readonly Lock _standardErrorLock = new();

        private int _jobReleased;
        private int _disposed;

        internal JobChildProcess(Process process, KillOnCloseJob job)
        {
            _process = process;
            _job = job;
        }

        /// <inheritdoc/>
        public int Id => _process.Id;

        /// <inheritdoc/>
        public bool HasExited => _process.HasExited;

        /// <inheritdoc/>
        public int ExitCode => _process.ExitCode;

        /// <inheritdoc/>
        public async Task WaitForExitAsync(CancellationToken cancellationToken)
        {
            await _process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            ReleaseJob();
        }

        /// <inheritdoc/>
        public string DrainStandardError()
        {
            lock (_standardErrorLock)
            {
                return string.Join(Environment.NewLine, _standardErrorLines);
            }
        }

        /// <inheritdoc/>
        public void Kill()
        {
            try
            {
                _process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // The process already exited, which is the outcome the caller wanted.
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // The process is exiting concurrently; the job close below is the backstop.
            }

            ReleaseJob();
        }

        /// <summary>Releases the job handle and the process handle.</summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1)
            {
                return;
            }

            ReleaseJob();
            _process.Dispose();
        }

        /// <summary>Starts the asynchronous standard-error reader. Called once, right after the process starts.</summary>
        internal void BeginDrainingStandardError()
        {
            _process.ErrorDataReceived += OnErrorDataReceived;
            _process.BeginErrorReadLine();
        }

        private void OnErrorDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data is null)
            {
                return;
            }

            lock (_standardErrorLock)
            {
                _standardErrorLines.Enqueue(e.Data);
                while (_standardErrorLines.Count > MaxCapturedLines)
                {
                    _ = _standardErrorLines.Dequeue();
                }
            }
        }

        private void ReleaseJob()
        {
            if (Interlocked.Exchange(ref _jobReleased, 1) == 0)
            {
                _job.Dispose();
            }
        }
    }
}
