using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Sbroenne.WindowsMcp.Native;

namespace Sbroenne.WindowsMcp.Input;

/// <summary>
/// Waits until a marked, injected mouse input sequence has been dequeued by system input processing.
/// </summary>
/// <remarks>
/// SendInput only places events on the system input queue; it says nothing about when they are
/// consumed. For a multi-event sequence such as a double-click that gap is a race: a caller that
/// continues after SendInput can inject new input that interleaves ahead of the tail of the
/// sequence. This barrier closes the gap with a WH_MOUSE_LL hook, which the system invokes for each
/// mouse event as it is dequeued, before the event is posted to the target thread. Events are
/// matched by the caller's marker in <c>MOUSEINPUT.DwExtraInfo</c>, so once the expected number of
/// marked button-up events has passed the hook, the whole sequence has cleared system input
/// processing and any input injected afterwards is ordered strictly behind it.
/// <para>
/// The hook runs on a dedicated background thread with its own message loop, installed before the
/// caller sends the input (await <see cref="WaitForInstallAsync"/>) and removed on dispose. The
/// barrier is per-call: markers are unique per instance, so overlapping barriers observe only their
/// own events.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class InjectedInputBarrier : IDisposable
{
    /// <summary>
    /// High bits of every marker this process emits, so our injected events are recognizable and
    /// do not collide with the zero extra-info of ordinary input.
    /// </summary>
    private const uint MarkerBase = 0x574D0000; // 'WM'

    private static int _markerCounter;

    private readonly int _expectedButtonUps;
    private readonly TaskCompletionSource _installed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _completed = new(TaskCreationOptions.RunContinuationsAsynchronously);

    // Rooted for the lifetime of the hook: the native side holds only the unmanaged thunk, which
    // does not keep the delegate alive for the GC.
    private readonly LowLevelMouseProc _callback;
    private readonly Thread _thread;

    private nint _hookHandle;
    private uint _threadId;
    private int _observedButtonUps;

    private InjectedInputBarrier(int expectedButtonUps)
    {
        _expectedButtonUps = expectedButtonUps;
        Marker = MarkerBase | (ushort)Interlocked.Increment(ref _markerCounter);
        _callback = HookCallback;
        _thread = new Thread(RunHookThread)
        {
            Name = "InjectedInputBarrier",
            IsBackground = true,
        };
    }

    /// <summary>The value the caller must place in <c>MOUSEINPUT.DwExtraInfo</c> of every event in the sequence.</summary>
    public nuint Marker { get; }

    /// <summary>
    /// Creates a barrier and starts installing its hook. Await <see cref="WaitForInstallAsync"/>
    /// before sending the input the barrier is supposed to observe.
    /// </summary>
    /// <param name="expectedButtonUps">Number of marked WM_LBUTTONUP events that completes the barrier.</param>
    public static InjectedInputBarrier Start(int expectedButtonUps)
    {
        var barrier = new InjectedInputBarrier(expectedButtonUps);
        barrier._thread.Start();
        return barrier;
    }

    /// <summary>
    /// Completes true once the hook is live, false if it could not be installed within
    /// <paramref name="timeout"/> (in which case the caller proceeds without ordering insurance).
    /// </summary>
    public async Task<bool> WaitForInstallAsync(TimeSpan timeout)
    {
        try
        {
            await _installed.Task.WaitAsync(timeout);
        }
        catch (TimeoutException)
        {
            return false;
        }

        return _hookHandle != 0;
    }

    /// <summary>
    /// Completes true once the expected number of marked button-up events has passed the hook,
    /// false when <paramref name="timeout"/> elapses first.
    /// </summary>
    public async Task<bool> WaitForCompletionAsync(TimeSpan timeout)
    {
        try
        {
            await _completed.Task.WaitAsync(timeout);
        }
        catch (TimeoutException)
        {
            return false;
        }

        return true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        // The thread id is published before _installed completes, so wait for that first; without
        // it there is no queue to post WM_QUIT to and the join below would hang out its timeout.
        try
        {
            _installed.Task.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
            // Install failed; the thread has already exited on its own.
        }

        if (_threadId != 0)
        {
            _ = NativeMethods.PostThreadMessageW(_threadId, NativeMethods.WM_QUIT, 0, 0);
        }

        _thread.Join(TimeSpan.FromSeconds(2));
    }

    /// <summary>
    /// Hook thread body: install the hook, signal readiness, pump until WM_QUIT, then unhook.
    /// The unhook happens here rather than in Dispose so install and remove are on the same thread.
    /// </summary>
    private void RunHookThread()
    {
        _threadId = NativeMethods.GetCurrentThreadId();
        _hookHandle = NativeMethods.SetWindowsHookExW(
            NativeMethods.WH_MOUSE_LL,
            Marshal.GetFunctionPointerForDelegate(_callback),
            0,
            0);
        _installed.TrySetResult();

        if (_hookHandle == 0)
        {
            return;
        }

        try
        {
            // No dispatching needed: the loop exists so the system can call the hook on this thread.
            while (NativeMethods.GetMessageW(out _, 0, 0, 0) > 0)
            {
            }
        }
        finally
        {
            _ = NativeMethods.UnhookWindowsHookEx(_hookHandle);
        }
    }

    /// <summary>
    /// Counts marked button-up events. Must stay trivial: the system removes low-level hooks that
    /// exceed the LowLevelHooksTimeout budget, silently disabling the barrier.
    /// </summary>
    private nint HookCallback(int nCode, nint wParam, nint lParam)
    {
        if (nCode == NativeMethods.HC_ACTION && wParam == (nint)NativeMethods.WM_LBUTTONUP)
        {
            var info = Marshal.PtrToStructure<MSLLHOOKSTRUCT>(lParam);
            if (info.DwExtraInfo == Marker && Interlocked.Increment(ref _observedButtonUps) >= _expectedButtonUps)
            {
                _completed.TrySetResult();
            }
        }

        return NativeMethods.CallNextHookEx(0, nCode, wParam, lParam);
    }
}
