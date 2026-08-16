using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Sbroenne.WindowsMcp.Hosting;

namespace Sbroenne.WindowsMcp.Tailscale;

/// <summary>
/// Owns the foreground <c>tailscale serve</c> child that publishes this server on the tailnet. The child runs
/// inside a kill-on-close Job Object, so the route exists only while this process lives.
/// </summary>
/// <remarks>
/// This is a plain class the host starts and stops, not a hosted service. The server deliberately has no DI
/// container or generic host, and the supervisor must be startable before Kestrel accepts a request and
/// stoppable with a bounded wait for the route to disappear.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed partial class ServeSupervisor : IAsyncDisposable
{
    /// <summary>How long to wait for our Serve listener to show up after starting the child.</summary>
    private static readonly TimeSpan RouteAppearTimeout = TimeSpan.FromSeconds(10);

    /// <summary>How long to wait for our Serve listener to disappear after killing the child.</summary>
    private static readonly TimeSpan RouteDisappearTimeout = TimeSpan.FromSeconds(5);

    /// <summary>How often the serve status is polled while waiting for a route to appear or disappear.</summary>
    private static readonly TimeSpan RoutePollInterval = TimeSpan.FromMilliseconds(250);

    /// <summary>How often the backend state and the funnel guard are re-checked.</summary>
    private static readonly TimeSpan HealthPollInterval = TimeSpan.FromSeconds(30);

    /// <summary>Restart backoff. The last entry is the cap and repeats for every further attempt.</summary>
    private static readonly TimeSpan[] RestartBackoff =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(4),
        TimeSpan.FromSeconds(8),
        TimeSpan.FromSeconds(16),
        TimeSpan.FromSeconds(30),
    ];

    private readonly ITailscaleCli _cli;
    private readonly IChildProcessLauncher _launcher;
    private readonly ServerOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<ServeSupervisor> _logger;
    private readonly CancellationTokenSource _stopSignal = new();
    private readonly string _proxyTarget;
    private readonly string _workingDirectory;
    private readonly IReadOnlyList<string> _serveArguments;
    private readonly Lock _childLock = new();

    private IChildProcess? _child;
    private Task? _supervisionTask;
    private Task? _healthTask;
    private volatile bool _lastKnownHealthy;
    private int _restartCount;
    private int _stopping;
    private int _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="ServeSupervisor"/> class.
    /// </summary>
    /// <param name="cli">The Tailscale CLI used to confirm the route exists and stays free of funnel.</param>
    /// <param name="launcher">Launcher that starts the Serve child inside a kill-on-close job.</param>
    /// <param name="options">Parsed server options, supplying the serve port and the MCP route.</param>
    /// <param name="loopbackPort">The loopback port Kestrel is actually listening on.</param>
    /// <param name="timeProvider">Clock used for every wait, so tests can drive time instead of sleeping.</param>
    /// <param name="logger">Logger for restarts, health failures, and the funnel guard.</param>
    public ServeSupervisor(
        ITailscaleCli cli,
        IChildProcessLauncher launcher,
        ServerOptions options,
        int loopbackPort,
        TimeProvider timeProvider,
        ILogger<ServeSupervisor> logger)
    {
        ArgumentNullException.ThrowIfNull(cli);
        ArgumentNullException.ThrowIfNull(launcher);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentOutOfRangeException.ThrowIfLessThan(loopbackPort, 1);

        _cli = cli;
        _launcher = launcher;
        _options = options;
        _timeProvider = timeProvider;
        _logger = logger;

        _proxyTarget = string.Create(
            CultureInfo.InvariantCulture,
            $"http://127.0.0.1:{loopbackPort}{options.Path}");

        // The target carries the path on purpose: without it Serve strips the prefix before forwarding.
        _serveArguments =
        [
            "serve",
            "--https",
            options.ServePort.ToString(CultureInfo.InvariantCulture),
            "--set-path",
            options.Path,
            "--yes",
            _proxyTarget,
        ];

        // Running the child from the Tailscale install directory keeps the server's current directory off the
        // child's DLL search path.
        _workingDirectory = System.IO.Path.GetDirectoryName(cli.ExecutablePath)
            ?? Environment.GetFolderPath(Environment.SpecialFolder.System);
    }

    /// <summary>True when the Serve route was confirmed present at the last check and no restart is pending.</summary>
    public bool LastKnownHealthy => _lastKnownHealthy;

    /// <summary>How many times the Serve child had to be restarted after an unexpected exit.</summary>
    public int RestartCount => Volatile.Read(ref _restartCount);

    /// <summary>The proxy target this supervisor claims in <c>tailscale serve status</c>.</summary>
    public string ProxyTarget => _proxyTarget;

    /// <summary>
    /// Starts the Serve child and waits until our own listener appears in <c>tailscale serve status --json</c>.
    /// On success a supervision loop and a health loop keep running until <see cref="StopAsync"/>.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes once the route is confirmed.</returns>
    /// <exception cref="InvalidOperationException">
    /// The route never appeared, or a listener on our port and path proxies somewhere else.
    /// </exception>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);

        if (_supervisionTask is not null)
        {
            throw new InvalidOperationException("The Serve supervisor is already started.");
        }

        _ = await StartChildAndConfirmRouteAsync(cancellationToken).ConfigureAwait(false);
        _lastKnownHealthy = true;

        _supervisionTask = Task.Run(() => SuperviseAsync(_stopSignal.Token), CancellationToken.None);
        _healthTask = Task.Run(() => PollHealthAsync(_stopSignal.Token), CancellationToken.None);
    }

    /// <summary>
    /// Kills the Serve child and waits, with a bound, for our listener to disappear from the serve status.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes once the child is gone and the route was observed to disappear.</returns>
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        await ShutdownAsync(cancellationToken).ConfigureAwait(false);

        var supervisionTask = _supervisionTask;
        var healthTask = _healthTask;
        if (supervisionTask is not null)
        {
            await supervisionTask.ConfigureAwait(false);
        }

        if (healthTask is not null)
        {
            await healthTask.ConfigureAwait(false);
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        try
        {
            await StopAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _stopSignal.Dispose();
        }
    }

    private static bool MatchesPortAndPath(TailscaleServeListener listener, int servePort, string path) =>
        listener.Port == servePort && string.Equals(listener.Path, path, StringComparison.Ordinal);

    private async Task<IChildProcess> StartChildAndConfirmRouteAsync(CancellationToken cancellationToken)
    {
        var child = _launcher.Start(_cli.ExecutablePath, _serveArguments, _workingDirectory);
        lock (_childLock)
        {
            _child = child;
        }

        LogServeChildStarted(_logger, child.Id, _options.ServePort, _proxyTarget);

        try
        {
            await ConfirmRouteAsync(child, cancellationToken).ConfigureAwait(false);
            return child;
        }
        catch
        {
            child.Kill();
            (child as IDisposable)?.Dispose();
            lock (_childLock)
            {
                if (ReferenceEquals(_child, child))
                {
                    _child = null;
                }
            }

            throw;
        }
    }

    private async Task ConfirmRouteAsync(IChildProcess child, CancellationToken cancellationToken)
    {
        var deadline = _timeProvider.GetUtcNow() + RouteAppearTimeout;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var status = await _cli.GetServeStatusAsync(cancellationToken).ConfigureAwait(false);
            if (status is not null)
            {
                foreach (var listener in status.Listeners)
                {
                    if (!MatchesPortAndPath(listener, _options.ServePort, _options.Path))
                    {
                        continue;
                    }

                    if (!string.Equals(listener.ProxyTarget, _proxyTarget, StringComparison.Ordinal))
                    {
                        // Someone else already owns this port and path. Adopting it would hand tailnet traffic
                        // to a backend this server does not control, so refuse instead.
                        LogForeignListener(_logger, _options.ServePort, _options.Path, listener.ProxyTarget, _proxyTarget);
                        throw new InvalidOperationException(
                            $"A Tailscale Serve listener on port {_options.ServePort.ToString(CultureInfo.InvariantCulture)} path {_options.Path} already proxies to {listener.ProxyTarget}. Remove it or pick another --serve-port.");
                    }

                    if (listener.AllowFunnel)
                    {
                        LogFunnelDetected(_logger, _options.ServePort);
                        throw new InvalidOperationException(
                            $"The Serve listener on port {_options.ServePort.ToString(CultureInfo.InvariantCulture)} is exposed by Funnel. This server must never be reachable from the public internet; remove the funnel and restart.");
                    }

                    return;
                }
            }

            if (child.HasExited)
            {
                throw new InvalidOperationException(
                    $"The tailscale serve child exited with code {child.ExitCode.ToString(CultureInfo.InvariantCulture)} before the route appeared: {child.DrainStandardError()}");
            }

            if (_timeProvider.GetUtcNow() >= deadline)
            {
                throw new InvalidOperationException(
                    $"The Tailscale Serve route for port {_options.ServePort.ToString(CultureInfo.InvariantCulture)} path {_options.Path} did not appear within {RouteAppearTimeout.TotalSeconds.ToString(CultureInfo.InvariantCulture)} seconds. Run 'tailscale serve status' to see what is configured.");
            }

            await Task.Delay(RoutePollInterval, _timeProvider, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task SuperviseAsync(CancellationToken stopToken)
    {
        var attempt = 0;

        while (!stopToken.IsCancellationRequested)
        {
            IChildProcess? child;
            lock (_childLock)
            {
                child = _child;
            }

            if (child is null)
            {
                return;
            }

            try
            {
                await child.WaitForExitAsync(stopToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (IsStopping)
            {
                return;
            }

            _lastKnownHealthy = false;
            LogServeChildExited(_logger, SafeExitCode(child), child.DrainStandardError());
            (child as IDisposable)?.Dispose();

            var delay = RestartBackoff[Math.Min(attempt, RestartBackoff.Length - 1)];
            attempt++;

            try
            {
                await Task.Delay(delay, _timeProvider, stopToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (IsStopping)
            {
                return;
            }

            try
            {
                _ = await StartChildAndConfirmRouteAsync(stopToken).ConfigureAwait(false);
                _ = Interlocked.Increment(ref _restartCount);
                _lastKnownHealthy = true;
                LogServeChildRestarted(_logger, RestartCount);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or System.IO.IOException)
            {
                // Keep backing off and try again. The health surface stays false so /healthz reports the outage.
                LogServeRestartFailed(_logger, exception);
            }
        }
    }

    private async Task PollHealthAsync(CancellationToken stopToken)
    {
        while (!stopToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(HealthPollInterval, _timeProvider, stopToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (IsStopping)
            {
                return;
            }

            TailscaleStatus? status;
            TailscaleServeStatus? serveStatus;
            try
            {
                status = await _cli.GetStatusAsync(stopToken).ConfigureAwait(false);
                serveStatus = await _cli.GetServeStatusAsync(stopToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (status is null || !status.IsRunning)
            {
                _lastKnownHealthy = false;
                LogBackendNotRunning(_logger, status?.BackendState ?? "unknown");
                continue;
            }

            if (serveStatus is not null
                && serveStatus.Listeners.Any(listener => listener.Port == _options.ServePort && listener.AllowFunnel))
            {
                // Funnel would publish desktop control to the public internet. Tear the route down rather than
                // keep serving on a listener someone widened.
                LogFunnelDetected(_logger, _options.ServePort);
                _lastKnownHealthy = false;
                await ShutdownAsync(CancellationToken.None).ConfigureAwait(false);
                return;
            }

            var routePresent = serveStatus is not null
                && serveStatus.Listeners.Any(listener =>
                    MatchesPortAndPath(listener, _options.ServePort, _options.Path)
                    && string.Equals(listener.ProxyTarget, _proxyTarget, StringComparison.Ordinal));

            if (!routePresent)
            {
                _lastKnownHealthy = false;
                LogRouteMissing(_logger, _options.ServePort, _options.Path);
                continue;
            }

            _lastKnownHealthy = true;
        }
    }

    /// <summary>
    /// Signals stop, kills the child, and waits for the route to disappear. Safe to call from the health loop,
    /// because unlike <see cref="StopAsync"/> it never awaits the loop tasks.
    /// </summary>
    private async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _stopping, 1) == 1)
        {
            return;
        }

        await _stopSignal.CancelAsync().ConfigureAwait(false);

        IChildProcess? child;
        lock (_childLock)
        {
            child = _child;
            _child = null;
        }

        _lastKnownHealthy = false;

        if (child is null)
        {
            return;
        }

        child.Kill();

        var gone = await WaitForRouteGoneAsync(cancellationToken).ConfigureAwait(false);
        if (!gone)
        {
            LogRouteStillPresentAfterStop(_logger, _options.ServePort, _options.Path);
        }

        (child as IDisposable)?.Dispose();
    }

    private async Task<bool> WaitForRouteGoneAsync(CancellationToken cancellationToken)
    {
        var deadline = _timeProvider.GetUtcNow() + RouteDisappearTimeout;

        while (true)
        {
            TailscaleServeStatus? status;
            try
            {
                status = await _cli.GetServeStatusAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return false;
            }

            var present = status is not null
                && status.Listeners.Any(listener =>
                    MatchesPortAndPath(listener, _options.ServePort, _options.Path)
                    && string.Equals(listener.ProxyTarget, _proxyTarget, StringComparison.Ordinal));

            if (!present)
            {
                return true;
            }

            if (_timeProvider.GetUtcNow() >= deadline)
            {
                return false;
            }

            try
            {
                await Task.Delay(RoutePollInterval, _timeProvider, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return false;
            }
        }
    }

    private static int SafeExitCode(IChildProcess child)
    {
        try
        {
            return child.ExitCode;
        }
        catch (InvalidOperationException)
        {
            return -1;
        }
    }

    private bool IsStopping => Volatile.Read(ref _stopping) == 1;

    [LoggerMessage(Level = LogLevel.Information, Message = "Started tailscale serve child {ProcessId} on port {ServePort} proxying to {ProxyTarget}")]
    private static partial void LogServeChildStarted(ILogger logger, int processId, int servePort, string proxyTarget);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The tailscale serve child exited unexpectedly with code {ExitCode}: {StandardError}")]
    private static partial void LogServeChildExited(ILogger logger, int exitCode, string standardError);

    [LoggerMessage(Level = LogLevel.Information, Message = "Restarted the tailscale serve child (restart {RestartCount})")]
    private static partial void LogServeChildRestarted(ILogger logger, int restartCount);

    [LoggerMessage(Level = LogLevel.Error, Message = "Restarting the tailscale serve child failed; backing off and retrying")]
    private static partial void LogServeRestartFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "A Serve listener on port {ServePort} path {Path} proxies to {ActualTarget}, not to {ExpectedTarget}; refusing to adopt it")]
    private static partial void LogForeignListener(ILogger logger, int servePort, string path, string actualTarget, string expectedTarget);

    [LoggerMessage(Level = LogLevel.Critical, Message = "Funnel is enabled on Serve port {ServePort}; stopping so this desktop is not reachable from the public internet")]
    private static partial void LogFunnelDetected(ILogger logger, int servePort);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The Tailscale backend is not running (state {BackendState}); the tailnet route is down")]
    private static partial void LogBackendNotRunning(ILogger logger, string backendState);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The Serve route for port {ServePort} path {Path} is missing from serve status")]
    private static partial void LogRouteMissing(ILogger logger, int servePort, string path);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The Serve route for port {ServePort} path {Path} was still present after the child was killed; run 'tailscale serve status' to check")]
    private static partial void LogRouteStillPresentAfterStop(ILogger logger, int servePort, string path);
}
