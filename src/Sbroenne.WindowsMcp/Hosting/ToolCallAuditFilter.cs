using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Sbroenne.WindowsMcp.Tailscale;

namespace Sbroenne.WindowsMcp.Hosting;

/// <summary>
/// Builds the call-tool filter that writes one audit line per tool call.
/// </summary>
/// <remarks>
/// <para>
/// Invariant I8: every tool call over HTTP is recorded with the caller's login, the tool name, and the outcome.
/// The filter wraps the whole call so a tool that throws is still audited.
/// </para>
/// <para>
/// Argument values are never recorded. The arguments to these tools are keystrokes, clipboard contents, and file
/// paths, so an audit log that included them would be a keylogger. Only argument names, and for most tools their
/// value kind and length, are written. The tools listed in <see cref="SensitiveTools"/> get names only.
/// </para>
/// </remarks>
public static partial class ToolCallAudit
{
    /// <summary>Login recorded when the transport carries no identity, for example plain stdio.</summary>
    public const string AnonymousLogin = "anonymous";

    /// <summary>Tool name recorded when the request did not name one.</summary>
    public const string UnknownTool = "(unknown)";

    /// <summary>Argument detail recorded when a call carried no arguments.</summary>
    public const string NoArguments = "none";

    /// <summary>
    /// Tools whose arguments are secrets by nature. Their audit line lists argument names and nothing else,
    /// because even the length of a typed string leaks something about a password.
    /// </summary>
    public static readonly IReadOnlySet<string> SensitiveTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "keyboard_control",
        "ui_type",
        "clipboard",
        "file_save",
        "file_open",
    };

    // Argument names come from the client, so they are capped and stripped before they reach a log line.
    private const int MaxArgumentNameLength = 64;
    private const int MaxArgumentsDescribed = 32;

    /// <summary>
    /// Creates the call-tool filter to register with <c>WithRequestFilters(f =&gt; f.AddCallToolFilter(filter))</c>.
    /// </summary>
    /// <param name="logger">Logger that receives the audit line.</param>
    /// <param name="sink">Sink that receives the structured record; use <see cref="NullAuditSink.Instance"/> for none.</param>
    /// <param name="timeProvider">Clock used for the record timestamp; defaults to <see cref="TimeProvider.System"/>.</param>
    /// <returns>The filter delegate.</returns>
    public static McpRequestFilter<CallToolRequestParams, CallToolResult> CreateFilter(
        ILogger logger,
        IAuditSink sink,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(sink);

        var clock = timeProvider ?? TimeProvider.System;

        return next => async (context, cancellationToken) =>
        {
            var login = context.User?.Identity?.Name ?? AnonymousLogin;
            var node = context.User?.FindFirst(TailscaleIdentity.NodeClaimType)?.Value ?? string.Empty;
            var toolName = context.Params?.Name ?? UnknownTool;
            var argumentDetail = DescribeArguments(toolName, context.Params?.Arguments);
            var startedAt = Stopwatch.GetTimestamp();
            var success = false;

            try
            {
                var result = await next(context, cancellationToken);
                success = result.IsError != true;
                return result;
            }
            finally
            {
                Record(
                    logger,
                    sink,
                    clock,
                    login,
                    node,
                    toolName,
                    argumentDetail,
                    success,
                    (long)Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);
            }
        };
    }

    /// <summary>
    /// Writes one audit line to the logger and one record to the sink.
    /// </summary>
    /// <param name="logger">Logger that receives the audit line.</param>
    /// <param name="sink">Sink that receives the structured record.</param>
    /// <param name="timeProvider">Clock used for the record timestamp.</param>
    /// <param name="login">The caller's login.</param>
    /// <param name="node">The caller's node name, or an empty string.</param>
    /// <param name="tool">The tool that was called.</param>
    /// <param name="argumentDetail">The redacted argument description from <see cref="DescribeArguments"/>.</param>
    /// <param name="success">True when the tool returned a non-error result.</param>
    /// <param name="durationMs">How long the call took, in milliseconds.</param>
    internal static void Record(
        ILogger logger,
        IAuditSink sink,
        TimeProvider timeProvider,
        string login,
        string node,
        string tool,
        string argumentDetail,
        bool success,
        long durationMs)
    {
        ToolCallAudited(logger, login, node, tool, success, durationMs, argumentDetail);

        try
        {
            sink.Write(new AuditRecord(
                AuditFileSink.FormatTimestamp(timeProvider.GetUtcNow()),
                login,
                node,
                tool,
                success,
                durationMs));
        }
#pragma warning disable CA1031 // A failing audit file must not turn into a failed tool call; the log line already went out.
        catch (Exception exception)
        {
            AuditSinkFailed(logger, exception);
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Describes a call's arguments without revealing any value.
    /// </summary>
    /// <param name="toolName">The tool being called; decides how much detail is safe.</param>
    /// <param name="arguments">The raw arguments, or null when there were none.</param>
    /// <returns>A one-line description containing argument names only, or names with kinds and lengths.</returns>
    internal static string DescribeArguments(string toolName, IDictionary<string, JsonElement>? arguments)
    {
        if (arguments is null || arguments.Count == 0)
        {
            return NoArguments;
        }

        var namesOnly = SensitiveTools.Contains(toolName);
        var builder = new StringBuilder();
        var described = 0;

        foreach (var name in arguments.Keys.Order(StringComparer.Ordinal))
        {
            if (described == MaxArgumentsDescribed)
            {
                builder.Append(CultureInfo.InvariantCulture, $",+{arguments.Count - described}more");
                break;
            }

            if (described > 0)
            {
                builder.Append(',');
            }

            builder.Append(SanitizeName(name));
            if (!namesOnly)
            {
                var value = arguments[name];
                builder.Append(CultureInfo.InvariantCulture, $":{value.ValueKind}({MeasureLength(value)})");
            }

            described++;
        }

        return builder.ToString();
    }

    /// <summary>
    /// Measures a value without reading it, so the audit line carries a size and never the content.
    /// </summary>
    /// <param name="value">The argument value.</param>
    /// <returns>The character length of the value's text form.</returns>
    private static int MeasureLength(JsonElement value) =>
        value.ValueKind switch
        {
            JsonValueKind.String => value.GetString()?.Length ?? 0,
            JsonValueKind.Null or JsonValueKind.Undefined => 0,
            _ => value.GetRawText().Length,
        };

    /// <summary>
    /// Reduces a client-supplied argument name to something that cannot forge or split a log line.
    /// </summary>
    /// <param name="name">The raw argument name.</param>
    /// <returns>A printable, length-capped name.</returns>
    private static string SanitizeName(string name)
    {
        var builder = new StringBuilder(Math.Min(name.Length, MaxArgumentNameLength));
        foreach (var character in name)
        {
            if (builder.Length == MaxArgumentNameLength)
            {
                break;
            }

            builder.Append(character is >= ' ' and <= '~' && character != ',' && character != ':' ? character : '_');
        }

        return builder.Length == 0 ? "_" : builder.ToString();
    }

    [LoggerMessage(
        EventId = 4501,
        Level = LogLevel.Information,
        Message = "audit tool={Tool} login={Login} node={Node} success={Success} durationMs={DurationMs} args={ArgumentDetail}")]
    private static partial void ToolCallAudited(
        ILogger logger,
        string login,
        string node,
        string tool,
        bool success,
        long durationMs,
        string argumentDetail);

    [LoggerMessage(EventId = 4502, Level = LogLevel.Error, Message = "Could not append to the audit file; the log line above is the only record of this call.")]
    private static partial void AuditSinkFailed(ILogger logger, Exception exception);
}
