using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sbroenne.WindowsMcp.Native;

namespace Sbroenne.WindowsMcp.Tailscale;

/// <summary>
/// Runs the Tailscale CLI and parses the JSON the server relies on.
/// </summary>
/// <remarks>
/// The executable is never resolved from PATH. A caller obtains an instance through <see cref="Resolve"/>,
/// which accepts an explicit override or the Program Files install and refuses anything that is not
/// Authenticode signed by Tailscale. Every invocation passes an argument vector rather than a command line,
/// so nothing a caller supplies can turn into extra arguments, and the working directory is the Tailscale
/// install directory so the server's own current directory is never on the child's DLL search path.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed partial class TailscaleCli : ITailscaleCli
{
    /// <summary>The organization the Tailscale CLI is signed by. Anything else is refused.</summary>
    public const string ExpectedSignerOrganization = "O=Tailscale Inc.";

    /// <summary>How long a Tailscale CLI call may run before it is killed.</summary>
    public static readonly TimeSpan DefaultCommandTimeout = TimeSpan.FromSeconds(10);

    private readonly string _workingDirectory;

    private TailscaleCli(string executablePath, string workingDirectory)
    {
        ExecutablePath = executablePath;
        _workingDirectory = workingDirectory;
    }

    /// <inheritdoc/>
    public string ExecutablePath { get; }

    /// <summary>
    /// Resolves the Tailscale executable from a trusted location and verifies its Authenticode signature.
    /// </summary>
    /// <param name="overridePath">An explicit path to tailscale.exe, or null to use the Program Files install.</param>
    /// <param name="error">A one line reason the executable was rejected, or null on success.</param>
    /// <returns>A usable client, or null when the executable is missing or not trusted.</returns>
    /// <remarks>
    /// PATH is deliberately not searched. The server hands full desktop control to whatever this executable
    /// reports, so a tailscale.exe earlier on PATH than the real one would be a complete bypass.
    /// </remarks>
    public static TailscaleCli? Resolve(string? overridePath, out string? error)
    {
        string candidate;
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            try
            {
                candidate = Path.GetFullPath(overridePath);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
                error = $"'{overridePath}' is not a usable path for tailscale.exe: {exception.Message}";
                return null;
            }
        }
        else
        {
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (string.IsNullOrEmpty(programFiles))
            {
                error = "The Program Files directory could not be determined; pass --tailscale-exe with the full path to tailscale.exe.";
                return null;
            }

            candidate = Path.Combine(programFiles, "Tailscale", "tailscale.exe");
        }

        if (!File.Exists(candidate))
        {
            error = $"tailscale.exe was not found at '{candidate}'; install Tailscale or pass --tailscale-exe with the full path.";
            return null;
        }

        if (!AuthenticodeNativeMethods.TryVerifyEmbeddedSignature(candidate, out var trustStatus))
        {
            error = $"'{candidate}' has no valid Authenticode signature (WinVerifyTrust returned 0x{trustStatus:X8}); refusing to run it.";
            return null;
        }

        if (!TryReadSignerSubject(candidate, out var subject))
        {
            error = $"The Authenticode signer of '{candidate}' could not be read; refusing to run it.";
            return null;
        }

        if (!subject.Contains(ExpectedSignerOrganization, StringComparison.OrdinalIgnoreCase))
        {
            error = $"'{candidate}' is signed by '{subject}' rather than {ExpectedSignerOrganization}; refusing to run it.";
            return null;
        }

        var directory = Path.GetDirectoryName(candidate);
        if (string.IsNullOrEmpty(directory))
        {
            error = $"'{candidate}' has no parent directory to run from; pass --tailscale-exe with a full path.";
            return null;
        }

        error = null;
        return new TailscaleCli(candidate, directory);
    }

    /// <inheritdoc/>
    public async Task<TailscaleCommandResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        var startInfo = new ProcessStartInfo
        {
            FileName = ExecutablePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = _workingDirectory,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };

        try
        {
            if (!process.Start())
            {
                return new TailscaleCommandResult(-1, string.Empty, $"'{ExecutablePath}' could not be started.");
            }
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new TailscaleCommandResult(-1, string.Empty, $"'{ExecutablePath}' could not be started: {exception.Message}");
        }

        // Read both pipes before waiting; a full pipe would otherwise deadlock the child.
        var standardOutputTask = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var standardErrorTask = process.StandardError.ReadToEndAsync(CancellationToken.None);

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException)
        {
            KillQuietly(process);
            cancellationToken.ThrowIfCancellationRequested();

            var seconds = timeout.TotalSeconds.ToString("0.#", CultureInfo.InvariantCulture);
            return new TailscaleCommandResult(
                -1,
                string.Empty,
                $"'tailscale {string.Join(' ', arguments)}' did not finish within {seconds} s and was killed.");
        }

        var standardOutput = await ReadOrEmptyAsync(standardOutputTask);
        var standardError = await ReadOrEmptyAsync(standardErrorTask);
        return new TailscaleCommandResult(process.ExitCode, standardOutput, standardError);
    }

    /// <inheritdoc/>
    public async Task<TailscaleStatus?> GetStatusAsync(CancellationToken cancellationToken)
    {
        var result = await RunAsync(["status", "--json"], DefaultCommandTimeout, cancellationToken);
        return result.Succeeded ? ParseStatus(result.StandardOutput) : null;
    }

    /// <inheritdoc/>
    public async Task<TailscaleServeStatus?> GetServeStatusAsync(CancellationToken cancellationToken)
    {
        var result = await RunAsync(["serve", "status", "--json"], DefaultCommandTimeout, cancellationToken);
        return result.Succeeded ? ParseServeStatus(result.StandardOutput) : null;
    }

    /// <inheritdoc/>
    public async Task<TailscaleWhois?> WhoisAsync(IPAddress address, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);

        var result = await RunAsync(["whois", "--json", address.ToString()], DefaultCommandTimeout, cancellationToken);
        return result.Succeeded ? ParseWhois(result.StandardOutput) : null;
    }

    /// <inheritdoc/>
    public async Task<Version?> GetVersionAsync(CancellationToken cancellationToken)
    {
        var result = await RunAsync(["version"], DefaultCommandTimeout, cancellationToken);
        return result.Succeeded ? ParseVersion(result.StandardOutput) : null;
    }

    /// <summary>
    /// Parses the output of <c>tailscale status --json</c>.
    /// </summary>
    /// <param name="json">The raw JSON document.</param>
    /// <returns>The parsed status, or null when the text is not a status document.</returns>
    internal static TailscaleStatus? ParseStatus(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("BackendState", out var backendStateElement)
                || backendStateElement.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            var backendState = backendStateElement.GetString() ?? string.Empty;

            string? dnsName = null;
            var tailscaleIps = new List<string>();
            var hasHttpsCapability = false;

            if (root.TryGetProperty("Self", out var self) && self.ValueKind == JsonValueKind.Object)
            {
                // The status document reports a fully qualified name with a trailing dot; callers build URLs
                // from this, so the dot goes away here rather than in every caller.
                dnsName = ReadString(self, "DNSName")?.TrimEnd('.');
                if (string.IsNullOrEmpty(dnsName))
                {
                    dnsName = null;
                }

                if (self.TryGetProperty("TailscaleIPs", out var ips) && ips.ValueKind == JsonValueKind.Array)
                {
                    foreach (var ip in ips.EnumerateArray())
                    {
                        if (ip.ValueKind == JsonValueKind.String)
                        {
                            tailscaleIps.Add(ip.GetString() ?? string.Empty);
                        }
                    }
                }

                hasHttpsCapability = self.TryGetProperty("CapMap", out var capabilities)
                    && capabilities.ValueKind == JsonValueKind.Object
                    && capabilities.TryGetProperty("https", out _);
            }

            var magicDnsSuffix = ReadString(root, "MagicDNSSuffix");
            if (string.IsNullOrEmpty(magicDnsSuffix))
            {
                magicDnsSuffix = null;
            }

            var certDomains = new List<string>();
            if (root.TryGetProperty("CertDomains", out var domains) && domains.ValueKind == JsonValueKind.Array)
            {
                foreach (var domain in domains.EnumerateArray())
                {
                    if (domain.ValueKind == JsonValueKind.String)
                    {
                        certDomains.Add(domain.GetString() ?? string.Empty);
                    }
                }
            }

            return new TailscaleStatus(
                backendState,
                dnsName,
                tailscaleIps,
                magicDnsSuffix,
                certDomains,
                certDomains.Count > 0 && hasHttpsCapability);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses the output of <c>tailscale serve status --json</c>.
    /// </summary>
    /// <param name="json">The raw JSON document. An empty configuration is the object <c>{}</c>.</param>
    /// <returns>The parsed serve status, or null when the text is not JSON.</returns>
    /// <remarks>
    /// The top level object is the background configuration, and a top level "Foreground" object maps each
    /// foreground session id to a configuration of the same shape. Funnel detection is deliberately loose:
    /// any property whose name mentions funnel and is true marks the matching host and port, and a funnel
    /// flag that cannot be tied to one host marks the whole configuration. Guessing high here is safe,
    /// because the only thing the server does with the answer is refuse to start.
    /// </remarks>
    internal static TailscaleServeStatus? ParseServeStatus(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var listeners = new List<TailscaleServeListener>();
            AddListeners(root, foreground: false, listeners);

            if (root.TryGetProperty("Foreground", out var foreground) && foreground.ValueKind == JsonValueKind.Object)
            {
                foreach (var session in foreground.EnumerateObject())
                {
                    if (session.Value.ValueKind == JsonValueKind.Object)
                    {
                        AddListeners(session.Value, foreground: true, listeners);
                    }
                }
            }

            return new TailscaleServeStatus(listeners);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses the output of <c>tailscale whois --json</c>.
    /// </summary>
    /// <param name="json">The raw JSON document.</param>
    /// <returns>The parsed identity, or null when the text is not a whois document.</returns>
    internal static TailscaleWhois? ParseWhois(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var hasNode = root.TryGetProperty("Node", out var node) && node.ValueKind == JsonValueKind.Object;
            var hasProfile = root.TryGetProperty("UserProfile", out var profile) && profile.ValueKind == JsonValueKind.Object;
            if (!hasNode && !hasProfile)
            {
                return null;
            }

            // A tagged node has no user behind it, so an empty login is a normal answer rather than an error.
            var loginName = hasProfile ? ReadString(profile, "LoginName") ?? string.Empty : string.Empty;
            var displayName = hasProfile ? ReadString(profile, "DisplayName") : null;
            if (string.IsNullOrEmpty(displayName))
            {
                displayName = null;
            }

            var nodeName = (hasNode ? ReadString(node, "Name") : null)?.TrimEnd('.') ?? string.Empty;

            var tags = new List<string>();
            if (hasNode && node.TryGetProperty("Tags", out var tagArray) && tagArray.ValueKind == JsonValueKind.Array)
            {
                foreach (var tag in tagArray.EnumerateArray())
                {
                    if (tag.ValueKind == JsonValueKind.String)
                    {
                        tags.Add(tag.GetString() ?? string.Empty);
                    }
                }
            }

            return new TailscaleWhois(loginName, displayName, nodeName, tags);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses the leading version number from the output of <c>tailscale version</c>.
    /// </summary>
    /// <param name="output">The raw command output; only the first line is considered.</param>
    /// <returns>The parsed version, or null when the first line does not start with one.</returns>
    internal static Version? ParseVersion(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return null;
        }

        var firstLine = output.Split('\n', 2)[0].Trim();
        var match = LeadingVersion().Match(firstLine);
        return match.Success && Version.TryParse(match.Value, out var version) ? version : null;
    }

    private static void AddListeners(JsonElement config, bool foreground, List<TailscaleServeListener> listeners)
    {
        var funnelHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var configWideFunnel = false;
        CollectFunnelFlags(config, currentHostPort: null, funnelHosts, ref configWideFunnel);

        if (!config.TryGetProperty("Web", out var web) || web.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var hostEntry in web.EnumerateObject())
        {
            if (hostEntry.Value.ValueKind != JsonValueKind.Object
                || !hostEntry.Value.TryGetProperty("Handlers", out var handlers)
                || handlers.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var hostPort = hostEntry.Name;
            var port = ParsePort(hostPort);
            var allowFunnel = configWideFunnel || funnelHosts.Contains(hostPort);

            foreach (var handler in handlers.EnumerateObject())
            {
                var proxyTarget = handler.Value.ValueKind == JsonValueKind.Object
                    ? ReadString(handler.Value, "Proxy") ?? string.Empty
                    : string.Empty;

                listeners.Add(new TailscaleServeListener(port, hostPort, handler.Name, proxyTarget, foreground, allowFunnel));
            }
        }
    }

    private static void CollectFunnelFlags(JsonElement element, string? currentHostPort, HashSet<string> funnelHosts, ref bool configWideFunnel)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var property in element.EnumerateObject())
        {
            if (property.Name.Contains("funnel", StringComparison.OrdinalIgnoreCase))
            {
                if (property.Value.ValueKind == JsonValueKind.True)
                {
                    if (currentHostPort is null)
                    {
                        configWideFunnel = true;
                    }
                    else
                    {
                        funnelHosts.Add(currentHostPort);
                    }
                }
                else if (property.Value.ValueKind == JsonValueKind.Object)
                {
                    foreach (var host in property.Value.EnumerateObject())
                    {
                        if (host.Value.ValueKind == JsonValueKind.True)
                        {
                            funnelHosts.Add(host.Name);
                        }
                    }
                }

                continue;
            }

            var nextHostPort = LooksLikeHostPort(property.Name) ? property.Name : currentHostPort;
            CollectFunnelFlags(property.Value, nextHostPort, funnelHosts, ref configWideFunnel);
        }
    }

    private static bool LooksLikeHostPort(string name)
    {
        var separator = name.LastIndexOf(':');
        return separator > 0
            && separator < name.Length - 1
            && int.TryParse(name.AsSpan(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out _);
    }

    private static int ParsePort(string hostPort)
    {
        var separator = hostPort.LastIndexOf(':');
        return separator >= 0
            && int.TryParse(hostPort.AsSpan(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            ? port
            : 0;
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool TryReadSignerSubject(string path, out string subject)
    {
        try
        {
            // X509CertificateLoader, the replacement the obsoletion points at, reads certificate files. It has
            // no equivalent for pulling the signer out of a signed PE, so this stays until one exists.
#pragma warning disable SYSLIB0057
            using var certificate = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            subject = certificate.Subject;
            return !string.IsNullOrEmpty(subject);
        }
        catch (Exception exception) when (exception is System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException)
        {
            subject = string.Empty;
            return false;
        }
    }

    private static void KillQuietly(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            // The process exited between the timeout and the kill; nothing left to do.
        }
    }

    private static async Task<string> ReadOrEmptyAsync(Task<string> readTask)
    {
        try
        {
            // The pipes close when the child dies, so this only guards against a grandchild holding them open.
            return await readTask.WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch (Exception exception) when (exception is TimeoutException or IOException or ObjectDisposedException)
        {
            return string.Empty;
        }
    }

    [GeneratedRegex(@"^\d+(\.\d+){1,3}")]
    private static partial Regex LeadingVersion();
}
