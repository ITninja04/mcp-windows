using System.Runtime.InteropServices;

namespace Sbroenne.WindowsMcp.Native;

/// <summary>
/// Delegate for a low-level mouse hook procedure (LowLevelMouseProc).
/// </summary>
/// <remarks>
/// Declared as a delegate rather than a function pointer so the hook can carry per-instance state;
/// the installer must keep the delegate instance rooted for the lifetime of the hook, because the
/// native side holds only the unmanaged thunk and the GC cannot see that reference.
/// </remarks>
internal delegate nint LowLevelMouseProc(int nCode, nint wParam, nint lParam);

/// <summary>
/// P/Invoke declarations for low-level input hooks. Used to observe injected mouse events as the
/// system dequeues them, which is the only reliable signal that a multi-event SendInput sequence
/// has fully cleared system input processing.
/// </summary>
internal static partial class NativeMethods
{
    /// <summary>Hook id for a low-level mouse hook.</summary>
    internal const int WH_MOUSE_LL = 14;

    /// <summary>Hook code indicating the callback carries a real event that may be processed.</summary>
    internal const int HC_ACTION = 0;

    /// <summary>Left mouse button up message, as delivered in a mouse hook's wParam.</summary>
    internal const uint WM_LBUTTONUP = 0x0202;

    /// <summary>Posted to a thread's message queue to end its message loop.</summary>
    internal const uint WM_QUIT = 0x0012;

    /// <summary>
    /// Installs a hook procedure. For WH_MOUSE_LL the hook runs in the context of the installing
    /// thread, which must pump messages for the callback to be invoked.
    /// </summary>
    [LibraryImport("user32.dll", EntryPoint = "SetWindowsHookExW", SetLastError = true)]
    internal static partial nint SetWindowsHookExW(int idHook, nint lpfn, nint hMod, uint dwThreadId);

    /// <summary>Removes a hook installed by <see cref="SetWindowsHookExW"/>.</summary>
    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool UnhookWindowsHookEx(nint hhk);

    /// <summary>Passes the hook information to the next hook procedure in the chain.</summary>
    [LibraryImport("user32.dll")]
    internal static partial nint CallNextHookEx(nint hhk, int nCode, nint wParam, nint lParam);

    /// <summary>
    /// Retrieves the next message for the calling thread, blocking until one arrives. Returns 0 for
    /// WM_QUIT, -1 on error, and a positive value otherwise.
    /// </summary>
    [LibraryImport("user32.dll", EntryPoint = "GetMessageW", SetLastError = true)]
    internal static partial int GetMessageW(out MSG lpMsg, nint hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    /// <summary>Posts a message to the message queue of the specified thread.</summary>
    [LibraryImport("user32.dll", EntryPoint = "PostThreadMessageW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool PostThreadMessageW(uint idThread, uint msg, nuint wParam, nint lParam);
}

/// <summary>
/// Message structure returned by <see cref="NativeMethods.GetMessageW"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MSG
{
    /// <summary>Window handle the message is for, or zero for a thread message.</summary>
    public nint Hwnd;

    /// <summary>The message identifier.</summary>
    public uint Message;

    /// <summary>Additional message information.</summary>
    public nuint WParam;

    /// <summary>Additional message information.</summary>
    public nint LParam;

    /// <summary>The time at which the message was posted.</summary>
    public uint Time;

    /// <summary>The cursor position, in screen coordinates, when the message was posted.</summary>
    public POINT Pt;
}

/// <summary>
/// Event data delivered to a WH_MOUSE_LL hook procedure through its lParam.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MSLLHOOKSTRUCT
{
    /// <summary>The cursor position, in screen coordinates.</summary>
    public POINT Pt;

    /// <summary>Button or wheel data, depending on the message.</summary>
    public uint MouseData;

    /// <summary>Event flags; bit 0 (LLMHF_INJECTED) is set for events injected with SendInput.</summary>
    public uint Flags;

    /// <summary>The time stamp for this message.</summary>
    public uint Time;

    /// <summary>The extra information supplied in <c>MOUSEINPUT.DwExtraInfo</c> when the event was injected.</summary>
    public nuint DwExtraInfo;
}
