using System.Diagnostics;
using Sbroenne.WindowsMcp.Tailscale;

namespace Sbroenne.WindowsMcp.Tests.Unit;

public sealed class KillOnCloseJobTests
{
    [Fact]
    public async Task Dispose_KillsTheAssignedChildProcess()
    {
        // timeout is used rather than pause: pause returns immediately once stdin reaches end of file, which
        // would make the child exit on its own and prove nothing about the job.
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c timeout /t 30 /nobreak >NUL",
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };

        try
        {
            var job = new KillOnCloseJob();
            Assert.True(process.Start());
            job.Assign(process);
            Assert.False(process.HasExited);

            job.Dispose();

            Assert.True(await TestWait.UntilAsync(
                () => process.HasExited,
                TimeSpan.FromSeconds(5),
                TimeSpan.FromMilliseconds(50)));
        }
        finally
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException)
            {
                // The process was never started or is already gone.
            }
        }
    }

    [Fact]
    public void Constructor_CreatesIndependentJobs_AndDisposeIsIdempotent()
    {
        using var first = new KillOnCloseJob();
        using var second = new KillOnCloseJob();

        first.Dispose();
        first.Dispose();
        second.Dispose();

        Assert.NotSame(first, second);
    }
}
