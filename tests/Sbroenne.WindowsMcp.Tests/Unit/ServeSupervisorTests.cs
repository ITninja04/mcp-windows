using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;
using Sbroenne.WindowsMcp.Hosting;
using Sbroenne.WindowsMcp.Tailscale;

namespace Sbroenne.WindowsMcp.Tests.Unit;

public sealed class ServeSupervisorTests
{
    private static readonly string[] ExpectedServeArguments =
        ["serve", "--https", "8443", "--set-path", "/mcp", "--yes", "http://127.0.0.1:8765/mcp"];

    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(20);

    [Fact]
    public async Task StartAsync_ConfirmsRoute_WhenMatchingListenerAppears()
    {
        await using var harness = new Harness();
        harness.SetListeners(Harness.OwnListener());

        await harness.Supervisor.StartAsync(CancellationToken.None);

        Assert.True(harness.Supervisor.LastKnownHealthy);
        Assert.Equal(1, harness.Launcher.StartCount);
        Assert.Equal(Harness.TailscaleExecutable, harness.Launcher.LastFileName);
        Assert.Equal(ExpectedServeArguments, harness.Launcher.LastArguments);
    }

    [Fact]
    public async Task StartAsync_KillsChildAndFails_WhenListenerProxiesElsewhere()
    {
        await using var harness = new Harness();
        harness.SetListeners(new TailscaleServeListener(
            Harness.ServePort,
            "host:8443",
            Harness.RoutePath,
            "http://127.0.0.1:9999/mcp",
            Foreground: true,
            AllowFunnel: false));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.Supervisor.StartAsync(CancellationToken.None));

        Assert.Contains("http://127.0.0.1:9999/mcp", exception.Message, StringComparison.Ordinal);
        Assert.True(harness.Launcher.Current.Killed);
        Assert.False(harness.Supervisor.LastKnownHealthy);
    }

    [Fact]
    public async Task SupervisionLoop_RestartsChild_AfterFirstBackoffInterval()
    {
        await using var harness = new Harness();
        harness.SetListeners(Harness.OwnListener());
        await harness.Supervisor.StartAsync(CancellationToken.None);
        var first = harness.Launcher.Current;

        first.Exit(1);

        Assert.True(await TestWait.UntilAsync(
            () => !harness.Supervisor.LastKnownHealthy,
            Patience,
            PollInterval));
        Assert.Equal(1, harness.Launcher.StartCount);

        Assert.True(await TestWait.UntilAsync(
            () =>
            {
                harness.Time.Advance(TimeSpan.FromSeconds(1));
                return harness.Launcher.StartCount >= 2;
            },
            Patience,
            PollInterval));
        Assert.True(await TestWait.UntilAsync(
            () => harness.Supervisor.RestartCount == 1 && harness.Supervisor.LastKnownHealthy,
            Patience,
            PollInterval));
    }

    [Fact]
    public async Task StopAsync_KillsChildAndWaitsForRouteToDisappear()
    {
        await using var harness = new Harness();
        harness.SetListeners(Harness.OwnListener());
        await harness.Supervisor.StartAsync(CancellationToken.None);
        var child = harness.Launcher.Current;

        var stopTask = harness.Supervisor.StopAsync(CancellationToken.None);

        Assert.True(await TestWait.UntilAsync(() => child.Killed, Patience, PollInterval));
        Assert.False(stopTask.IsCompleted);

        harness.SetListeners();

        Assert.True(await TestWait.UntilAsync(
            () =>
            {
                harness.Time.Advance(TimeSpan.FromMilliseconds(250));
                return stopTask.IsCompleted;
            },
            Patience,
            PollInterval));
        await stopTask;
        Assert.False(harness.Supervisor.LastKnownHealthy);
    }

    [Fact]
    public async Task HealthPoll_StopsTheChild_WhenFunnelAppearsOnOurPort()
    {
        await using var harness = new Harness();
        harness.SetListeners(Harness.OwnListener());
        await harness.Supervisor.StartAsync(CancellationToken.None);
        var child = harness.Launcher.Current;

        harness.SetListeners(new TailscaleServeListener(
            Harness.ServePort,
            "host:8443",
            Harness.RoutePath,
            harness.Supervisor.ProxyTarget,
            Foreground: true,
            AllowFunnel: true));

        Assert.True(await TestWait.UntilAsync(
            () =>
            {
                harness.Time.Advance(TimeSpan.FromSeconds(30));
                return child.Killed;
            },
            Patience,
            PollInterval));
        Assert.False(harness.Supervisor.LastKnownHealthy);
    }

    private sealed class Harness : IAsyncDisposable
    {
        internal const string TailscaleExecutable = @"C:\Program Files\Tailscale\tailscale.exe";
        internal const string RoutePath = "/mcp";
        internal const int ServePort = 8443;
        internal const int LoopbackPort = 8765;

        private readonly Lock _listenersLock = new();
        private IReadOnlyList<TailscaleServeListener> _listeners = [];

        internal Harness()
        {
            Cli = Substitute.For<ITailscaleCli>();
            Cli.ExecutablePath.Returns(TailscaleExecutable);
            Cli.GetServeStatusAsync(Arg.Any<CancellationToken>())
                .Returns(_ => Task.FromResult<TailscaleServeStatus?>(new TailscaleServeStatus(CurrentListeners)));
            Cli.GetStatusAsync(Arg.Any<CancellationToken>())
                .Returns(_ => Task.FromResult<TailscaleStatus?>(
                    new TailscaleStatus("Running", "host.tailnet.ts.net", ["100.64.0.1"], "tailnet.ts.net", ["host.tailnet.ts.net"], HttpsEnabled: true)));

            Time = new FakeTimeProvider();
            Launcher = new FakeChildProcessLauncher();
            Supervisor = new ServeSupervisor(
                Cli,
                Launcher,
                new ServerOptions
                {
                    Transport = ServerTransport.Http,
                    Tailscale = true,
                    ServePort = ServePort,
                    Path = RoutePath,
                    AllowedLogins = ["someone@example.com"],
                },
                LoopbackPort,
                Time,
                NullLogger<ServeSupervisor>.Instance);
        }

        internal ITailscaleCli Cli { get; }

        internal FakeTimeProvider Time { get; }

        internal FakeChildProcessLauncher Launcher { get; }

        internal ServeSupervisor Supervisor { get; }

        private IReadOnlyList<TailscaleServeListener> CurrentListeners
        {
            get
            {
                lock (_listenersLock)
                {
                    return _listeners;
                }
            }
        }

        internal void SetListeners(params TailscaleServeListener[] listeners)
        {
            lock (_listenersLock)
            {
                _listeners = listeners;
            }
        }

        internal static TailscaleServeListener OwnListener() => new(
            ServePort,
            "host:8443",
            RoutePath,
            $"http://127.0.0.1:{LoopbackPort}{RoutePath}",
            Foreground: true,
            AllowFunnel: false);

        public async ValueTask DisposeAsync()
        {
            // Clearing the listeners first lets the bounded stop wait finish without advancing the fake clock.
            SetListeners();
            await Supervisor.DisposeAsync();
        }
    }

    private sealed class FakeChildProcessLauncher : IChildProcessLauncher
    {
        private readonly List<FakeChildProcess> _started = [];
        private readonly Lock _startedLock = new();

        internal string? LastFileName { get; private set; }

        internal IReadOnlyList<string>? LastArguments { get; private set; }

        internal string? LastWorkingDirectory { get; private set; }

        internal int StartCount
        {
            get
            {
                lock (_startedLock)
                {
                    return _started.Count;
                }
            }
        }

        internal FakeChildProcess Current
        {
            get
            {
                lock (_startedLock)
                {
                    return _started[^1];
                }
            }
        }

        public IChildProcess Start(string fileName, IReadOnlyList<string> arguments, string workingDirectory)
        {
            LastFileName = fileName;
            LastArguments = arguments;
            LastWorkingDirectory = workingDirectory;

            var child = new FakeChildProcess();
            lock (_startedLock)
            {
                _started.Add(child);
            }

            return child;
        }
    }

    private sealed class FakeChildProcess : IChildProcess
    {
        private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int Id => 4321;

        public bool HasExited { get; private set; }

        public int ExitCode { get; private set; }

        internal bool Killed { get; private set; }

        public Task WaitForExitAsync(CancellationToken cancellationToken) => _exited.Task.WaitAsync(cancellationToken);

        public string DrainStandardError() => "fake serve stderr";

        public void Kill()
        {
            Killed = true;
            Exit(-1);
        }

        internal void Exit(int exitCode)
        {
            if (HasExited)
            {
                return;
            }

            ExitCode = exitCode;
            HasExited = true;
            _ = _exited.TrySetResult();
        }
    }
}
