using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sbroenne.WindowsMcp.Native;

/// <summary>
/// P/Invoke declarations for the WinTrust Authenticode API. The server uses these to confirm that an
/// executable it is about to launch is signed and that the signature chains to a trusted root, so a file
/// dropped into the expected location by something else is refused instead of run.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class AuthenticodeNativeMethods
{
    /// <summary>WINTRUST_ACTION_GENERIC_VERIFY_V2: the standard Authenticode verification policy.</summary>
    internal static readonly Guid GenericVerifyV2 = new("00aac56b-cd44-11d0-8cc2-00c04fc295ee");

    /// <summary>WTD_UI_NONE: never display a user interface during verification.</summary>
    internal const uint WTD_UI_NONE = 2;

    /// <summary>WTD_REVOKE_NONE: do not perform revocation checking, which would need the network.</summary>
    internal const uint WTD_REVOKE_NONE = 0;

    /// <summary>WTD_CHOICE_FILE: the union member in WINTRUST_DATA is a WINTRUST_FILE_INFO.</summary>
    internal const uint WTD_CHOICE_FILE = 1;

    /// <summary>WTD_STATEACTION_VERIFY: run the verification and keep the state handle open.</summary>
    internal const uint WTD_STATEACTION_VERIFY = 1;

    /// <summary>WTD_STATEACTION_CLOSE: release the state handle allocated by a verify call.</summary>
    internal const uint WTD_STATEACTION_CLOSE = 2;

    /// <summary>WTD_SAFER_FLAG: use the policy WinVerifyTrust applies for software restriction checks.</summary>
    internal const uint WTD_SAFER_FLAG = 0x00000100;

    /// <summary>WTD_CACHE_ONLY_URL_RETRIEVAL: never go to the network for chain material.</summary>
    internal const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    /// <summary>
    /// Verifies the embedded Authenticode signature of a file with the generic verify policy.
    /// </summary>
    /// <param name="filePath">Full path to the file to verify.</param>
    /// <param name="status">The value WinVerifyTrust returned. Zero means trusted.</param>
    /// <returns>True when the file carries a valid signature that chains to a trusted root.</returns>
    /// <remarks>
    /// Revocation checking is off and URL retrieval is cache only, because this runs at startup on a machine
    /// whose network may not be up yet and a hung certificate fetch would block the server from starting.
    /// </remarks>
    internal static bool TryVerifyEmbeddedSignature(string filePath, out int status)
    {
        var fileInfoSize = Marshal.SizeOf<WINTRUST_FILE_INFO>();
        var filePathBuffer = Marshal.StringToHGlobalUni(filePath);
        var fileInfoBuffer = Marshal.AllocHGlobal(fileInfoSize);
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)fileInfoSize,
                pcwszFilePath = filePathBuffer,
                hFile = nint.Zero,
                pgKnownSubject = nint.Zero,
            };
            Marshal.StructureToPtr(fileInfo, fileInfoBuffer, false);

            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoBuffer,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
            };

            var action = GenericVerifyV2;
            status = WinVerifyTrust(nint.Zero, ref action, ref trustData);

            // A verify call allocates provider state that has to be handed back or the process leaks it.
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            _ = WinVerifyTrust(nint.Zero, ref action, ref trustData);

            return status == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoBuffer);
            Marshal.FreeHGlobal(filePathBuffer);
        }
    }

    /// <summary>
    /// Performs a trust verification action on an object. See the Win32 API WinVerifyTrust in wintrust.dll.
    /// </summary>
    /// <param name="hwnd">Owner window for any user interface, or zero for none.</param>
    /// <param name="pgActionID">The action GUID that selects the trust provider policy.</param>
    /// <param name="pWVTData">The WINTRUST_DATA describing what to verify.</param>
    /// <returns>Zero when the object is trusted, otherwise a trust provider error code.</returns>
    [LibraryImport("wintrust.dll")]
    private static partial int WinVerifyTrust(nint hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);
}

/// <summary>
/// Native WINTRUST_FILE_INFO: identifies the file a trust verification applies to.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WINTRUST_FILE_INFO
{
    /// <summary>Size of this structure in bytes.</summary>
    internal uint cbStruct;

    /// <summary>Pointer to the null terminated wide file path.</summary>
    internal nint pcwszFilePath;

    /// <summary>Optional open handle to the file, or zero.</summary>
    internal nint hFile;

    /// <summary>Optional pointer to a known subject GUID, or zero.</summary>
    internal nint pgKnownSubject;
}

/// <summary>
/// Native WINTRUST_DATA: the request passed to WinVerifyTrust.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WINTRUST_DATA
{
    /// <summary>Size of this structure in bytes.</summary>
    internal uint cbStruct;

    /// <summary>Optional policy provider data, or zero.</summary>
    internal nint pPolicyCallbackData;

    /// <summary>Optional subject interface package data, or zero.</summary>
    internal nint pSIPClientData;

    /// <summary>Which user interface to display, one of the WTD_UI_* values.</summary>
    internal uint dwUIChoice;

    /// <summary>Which revocation checks to perform, one of the WTD_REVOKE_* values.</summary>
    internal uint fdwRevocationChecks;

    /// <summary>Which union member is supplied, one of the WTD_CHOICE_* values.</summary>
    internal uint dwUnionChoice;

    /// <summary>The union member itself. Always a WINTRUST_FILE_INFO pointer here.</summary>
    internal nint pFile;

    /// <summary>Which state action to perform, one of the WTD_STATEACTION_* values.</summary>
    internal uint dwStateAction;

    /// <summary>Handle to state allocated by a verify call, released by a close call.</summary>
    internal nint hWVTStateData;

    /// <summary>Reserved. Always zero.</summary>
    internal nint pwszURLReference;

    /// <summary>Trust provider flags, a combination of the WTD_* flag values.</summary>
    internal uint dwProvFlags;

    /// <summary>The context the verification runs in, one of the WTD_UICONTEXT_* values.</summary>
    internal uint dwUIContext;

    /// <summary>Optional signature settings for multiply signed files, or zero.</summary>
    internal nint pSignatureSettings;
}
