using Sbroenne.WindowsMcp.Models;
using Sbroenne.WindowsMcp.Tools;

namespace Sbroenne.WindowsMcp.Tests.Tools;

/// <summary>
/// Verifies that the best-effort target window attachment distinguishes caller cancellation from
/// the internal timeout: the former must propagate so mouse_control reports a cancelled request,
/// the latter must never turn an already-successful input result into a fabricated failure.
/// </summary>
public class MouseControlToolCancellationTests
{
    [Fact]
    [Trait("Category", "RequiresDesktop")]
    public async Task AttachTargetWindowInfo_CallerCancellation_Propagates()
    {
        // A pre-cancelled token makes the window lookup's Task.Run return a canceled task without
        // running, so the only question is whether the helper swallows or rethrows it.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var success = MouseControlResult.CreateSuccess(new Coordinates(0, 0));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => MouseControlTool.AttachTargetWindowInfoAsync(success, cts.Token, cts.Token));
    }

    [Fact]
    public async Task AttachTargetWindowInfo_InternalTimeoutOnly_ReturnsResultUnchanged()
    {
        // The linked token is cancelled (internal timeout) while the caller's is not: the attach is
        // best-effort decoration, so the successful input result must come back untouched.
        using var callerCts = new CancellationTokenSource();
        using var timeoutCts = new CancellationTokenSource();
        timeoutCts.Cancel();
        var success = MouseControlResult.CreateSuccess(new Coordinates(0, 0));

        var result = await MouseControlTool.AttachTargetWindowInfoAsync(success, timeoutCts.Token, callerCts.Token);

        Assert.True(result.Success);
        Assert.Null(result.TargetWindow);
    }
}
