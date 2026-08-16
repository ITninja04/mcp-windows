namespace Sbroenne.WindowsMcp.Tailscale;

/// <summary>
/// A running child process the supervisor owns. Abstracted so the supervisor can be tested against a fake
/// launcher without spawning a real process.
/// </summary>
public interface IChildProcess
{
    /// <summary>The operating-system process id.</summary>
    int Id { get; }

    /// <summary>True once the process has exited.</summary>
    bool HasExited { get; }

    /// <summary>The exit code. Only valid after <see cref="HasExited"/> is true.</summary>
    int ExitCode { get; }

    /// <summary>Completes when the process exits.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes on process exit.</returns>
    Task WaitForExitAsync(CancellationToken cancellationToken);

    /// <summary>Reads the most recent standard-error lines the process produced, for diagnostics after a failure.</summary>
    /// <returns>The captured standard-error text.</returns>
    string DrainStandardError();

    /// <summary>Kills the process and its children.</summary>
    void Kill();
}

/// <summary>
/// Starts child processes. The real implementation places each child in a kill-on-close Job Object so the
/// child cannot outlive this server; the fake implementation is used in tests.
/// </summary>
public interface IChildProcessLauncher
{
    /// <summary>
    /// Starts a process with the given executable and argument vector.
    /// </summary>
    /// <param name="fileName">Full path to the executable.</param>
    /// <param name="arguments">Argument vector, never a joined string.</param>
    /// <param name="workingDirectory">Working directory for the child, chosen so the current directory is never on its DLL search path.</param>
    /// <returns>The started child process.</returns>
    IChildProcess Start(string fileName, IReadOnlyList<string> arguments, string workingDirectory);
}
