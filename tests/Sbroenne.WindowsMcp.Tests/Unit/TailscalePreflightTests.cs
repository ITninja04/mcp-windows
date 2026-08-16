using NSubstitute;
using Sbroenne.WindowsMcp.Hosting;
using Sbroenne.WindowsMcp.Tailscale;

namespace Sbroenne.WindowsMcp.Tests.Unit;

public sealed class TailscalePreflightTests
{
    private const string ExecutablePath = @"C:\Program Files\Tailscale\tailscale.exe";
    private const string HostPort = "msiwin11.taila0594.ts.net:443";

    [Fact]
    public async Task RunAsync_PassesEveryCheckOnAHealthyMachine()
    {
        var preflight = CreatePreflight(CreateCli());

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.True(report.Passed, report.Format());
        Assert.All(report.Checks, check => Assert.True(check.Passed));
        Assert.All(report.Checks, check => Assert.Null(check.FixHint));
        Assert.Equal(8, report.Checks.Count);
    }

    [Fact]
    public async Task RunAsync_ReportsTheVerifiedExecutablePath()
    {
        var preflight = CreatePreflight(CreateCli());

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        var check = FindCheck(report, TailscalePreflight.ExecutableCheck);
        Assert.True(check.Passed);
        Assert.Contains(ExecutablePath, check.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void ResolutionFailed_ProducesASingleFailedExecutableCheck()
    {
        var report = TailscalePreflight.ResolutionFailed("tailscale.exe was not found.");

        Assert.False(report.Passed);
        var check = Assert.Single(report.Checks);
        Assert.Equal(TailscalePreflight.ExecutableCheck, check.Name);
        Assert.False(check.Passed);
        Assert.Contains("--tailscale-exe", check.FixHint, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(TooOldVersions))]
    public async Task RunAsync_FailsWhenTheClientIsOlderThanTheMinimum(Version? version)
    {
        var cli = CreateCli();
        cli.GetVersionAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(version));
        var preflight = CreatePreflight(cli);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.False(report.Passed);
        var check = FindCheck(report, TailscalePreflight.VersionCheck);
        Assert.False(check.Passed);
        Assert.Contains("Update Tailscale to 1.60.0 or newer", check.FixHint, StringComparison.Ordinal);
    }

    public static TheoryData<Version?> TooOldVersions => new()
    {
        new Version(1, 58, 2),
        new Version(1, 0, 0),
        null,
    };

    [Theory]
    [InlineData("Stopped")]
    [InlineData("NeedsLogin")]
    [InlineData("NoState")]
    public async Task RunAsync_FailsWhenTheBackendIsNotRunning(string backendState)
    {
        var cli = CreateCli();
        cli.GetStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleStatus?>(
            new TailscaleStatus(backendState, null, [], null, [], false)));
        var preflight = CreatePreflight(cli);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.False(report.Passed);
        var check = FindCheck(report, TailscalePreflight.BackendCheck);
        Assert.False(check.Passed);
        Assert.Contains("tailscale up", check.FixHint, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_FailsWhenTheStatusCommandCannotBeRead()
    {
        var cli = CreateCli();
        cli.GetStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleStatus?>(null));
        var preflight = CreatePreflight(cli);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.False(report.Passed);
        Assert.False(FindCheck(report, TailscalePreflight.BackendCheck).Passed);
        Assert.False(FindCheck(report, TailscalePreflight.HttpsCheck).Passed);
    }

    [Fact]
    public async Task RunAsync_FailsWhenTheTailnetDoesNotIssueCertificates()
    {
        var cli = CreateCli();
        cli.GetStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleStatus?>(
            new TailscaleStatus("Running", "msiwin11.taila0594.ts.net", ["100.1.2.3"], "taila0594.ts.net", [], false)));
        var preflight = CreatePreflight(cli);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.False(report.Passed);
        var check = FindCheck(report, TailscalePreflight.HttpsCheck);
        Assert.False(check.Passed);
        Assert.Contains("Enable MagicDNS and HTTPS certificates", check.FixHint, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_FailsWhenThereIsNoInteractiveDesktopSession()
    {
        var preflight = CreatePreflight(CreateCli(), interactiveSession: false);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.False(report.Passed);
        var check = FindCheck(report, TailscalePreflight.SessionCheck);
        Assert.False(check.Passed);
        Assert.Contains("Start the server in the console session", check.FixHint, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_FailsWhenAnotherServeListenerHoldsTheServePort()
    {
        var cli = CreateCli();
        cli.GetServeStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleServeStatus?>(
            new TailscaleServeStatus([new TailscaleServeListener(443, HostPort, "/", "http://127.0.0.1:3000", false, false)])));
        var preflight = CreatePreflight(cli);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.False(report.Passed);
        var check = FindCheck(report, TailscalePreflight.ServePortCheck);
        Assert.False(check.Passed);
        Assert.Contains("tailscale serve --https=443 off", check.FixHint, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_AcceptsAServeListenerThatPointsBackAtThisServer()
    {
        var cli = CreateCli();
        cli.GetServeStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleServeStatus?>(
            new TailscaleServeStatus([new TailscaleServeListener(443, HostPort, "/mcp", "http://127.0.0.1:8765/mcp", true, false)])));
        var preflight = CreatePreflight(cli);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.True(report.Passed, report.Format());
        Assert.True(FindCheck(report, TailscalePreflight.ServePortCheck).Passed);
    }

    [Fact]
    public async Task RunAsync_IgnoresAServeListenerOnAnotherPort()
    {
        var cli = CreateCli();
        cli.GetServeStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleServeStatus?>(
            new TailscaleServeStatus([new TailscaleServeListener(8443, "msiwin11.taila0594.ts.net:8443", "/", "http://127.0.0.1:3000", false, false)])));
        var preflight = CreatePreflight(cli);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.True(report.Passed, report.Format());
    }

    [Fact]
    public async Task RunAsync_FailsWhenAnyFunnelRouteExists()
    {
        var cli = CreateCli();
        cli.GetServeStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleServeStatus?>(
            new TailscaleServeStatus([new TailscaleServeListener(8443, "msiwin11.taila0594.ts.net:8443", "/", "http://127.0.0.1:3000", false, true)])));
        var preflight = CreatePreflight(cli);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.False(report.Passed);
        var check = FindCheck(report, TailscalePreflight.FunnelCheck);
        Assert.False(check.Passed);
        Assert.Contains("tailscale funnel off", check.FixHint, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_FailsWhenTheServeStatusCommandCannotBeRead()
    {
        var cli = CreateCli();
        cli.GetServeStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleServeStatus?>(null));
        var preflight = CreatePreflight(cli);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.False(report.Passed);
        Assert.False(FindCheck(report, TailscalePreflight.ServePortCheck).Passed);
        Assert.False(FindCheck(report, TailscalePreflight.FunnelCheck).Passed);
    }

    [Fact]
    public async Task RunAsync_FailsWhenTheLoopbackPortIsTaken()
    {
        var preflight = CreatePreflight(CreateCli(), loopbackFailure: "Only one usage of each socket address is normally permitted.");

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);

        Assert.False(report.Passed);
        var check = FindCheck(report, TailscalePreflight.LoopbackPortCheck);
        Assert.False(check.Passed);
        Assert.Contains("Stop whatever is listening on 127.0.0.1:8765", check.FixHint, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_SkipsTheLoopbackPortProbeWhenTheOperatingSystemPicksThePort()
    {
        var probed = false;
        var preflight = new TailscalePreflight(
            CreateCli(),
            () => true,
            _ =>
            {
                probed = true;
                return "should not be called";
            });

        var report = await preflight.RunAsync(CreateOptions() with { Port = 0 }, CancellationToken.None);

        Assert.False(probed);
        Assert.True(FindCheck(report, TailscalePreflight.LoopbackPortCheck).Passed);
    }

    [Fact]
    public async Task RunAsync_FormatsAFailedReportWithTheFixHint()
    {
        var preflight = CreatePreflight(CreateCli(), interactiveSession: false);

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);
        var text = report.Format();

        Assert.Contains("FAIL  Interactive session", text, StringComparison.Ordinal);
        Assert.Contains("      fix: Start the server in the console session", text, StringComparison.Ordinal);
        Assert.Contains("Tailscale preflight failed.", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ToJson_WritesEveryCheck()
    {
        var preflight = CreatePreflight(CreateCli());

        var report = await preflight.RunAsync(CreateOptions(), CancellationToken.None);
        var json = report.ToJson();

        Assert.Contains("\"passed\": true", json, StringComparison.Ordinal);
        Assert.Contains("\"name\": \"Funnel\"", json, StringComparison.Ordinal);
    }

    private static ServerOptions CreateOptions() => new()
    {
        Transport = ServerTransport.Http,
        Tailscale = true,
        Host = ServerOptions.DefaultHttpHost,
        Port = 8765,
        Path = "/mcp",
        ServePort = 443,
        AllowedLogins = ["ozzie@github"],
    };

    private static ITailscaleCli CreateCli()
    {
        var cli = Substitute.For<ITailscaleCli>();
        cli.ExecutablePath.Returns(ExecutablePath);
        cli.GetVersionAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<Version?>(new Version(1, 102, 2)));
        cli.GetStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleStatus?>(
            new TailscaleStatus(
                "Running",
                "msiwin11.taila0594.ts.net",
                ["100.1.2.3"],
                "taila0594.ts.net",
                ["msiwin11.taila0594.ts.net"],
                true)));
        cli.GetServeStatusAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult<TailscaleServeStatus?>(
            new TailscaleServeStatus([])));
        return cli;
    }

    private static TailscalePreflight CreatePreflight(
        ITailscaleCli cli,
        bool interactiveSession = true,
        string? loopbackFailure = null) =>
        new(cli, () => interactiveSession, _ => loopbackFailure);

    private static PreflightCheck FindCheck(PreflightReport report, string name) =>
        Assert.Single(report.Checks, check => check.Name == name);
}
