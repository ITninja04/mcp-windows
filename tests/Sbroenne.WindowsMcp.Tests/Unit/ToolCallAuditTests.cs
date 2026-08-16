using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Sbroenne.WindowsMcp.Hosting;

namespace Sbroenne.WindowsMcp.Tests.Unit;

public sealed class ToolCallAuditTests
{
    private const string Secret = "correct-horse-batt";
    private const string Login = "ITninja04@github";

    [Fact]
    public void DescribeArguments_ForSensitiveToolListsNamesOnly()
    {
        var arguments = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["action"] = JsonSerializer.SerializeToElement("type"),
            ["text"] = JsonSerializer.SerializeToElement(Secret + "er"),
        };

        var detail = ToolCallAudit.DescribeArguments("keyboard_control", arguments);

        Assert.Equal("action,text", detail);
        Assert.DoesNotContain("correct", detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("horse", detail, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("keyboard_control")]
    [InlineData("ui_type")]
    [InlineData("clipboard")]
    [InlineData("file_save")]
    [InlineData("file_open")]
    public void DescribeArguments_ForEverySensitiveToolOmitsValueLengths(string toolName)
    {
        var arguments = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["text"] = JsonSerializer.SerializeToElement(Secret + "er"),
        };

        var detail = ToolCallAudit.DescribeArguments(toolName, arguments);

        Assert.Equal("text", detail);
    }

    [Fact]
    public void DescribeArguments_ForOrdinaryToolRecordsKindAndLengthButNoValue()
    {
        var arguments = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["title"] = JsonSerializer.SerializeToElement("Untitled - Notepad"),
            ["timeoutMs"] = JsonSerializer.SerializeToElement(2500),
        };

        var detail = ToolCallAudit.DescribeArguments("window_activate", arguments);

        Assert.Equal("timeoutMs:Number(4),title:String(18)", detail);
        Assert.DoesNotContain("Notepad", detail, StringComparison.Ordinal);
    }

    [Fact]
    public void DescribeArguments_ReportsNoneWhenThereAreNoArguments()
    {
        Assert.Equal(ToolCallAudit.NoArguments, ToolCallAudit.DescribeArguments("screenshot", null));
        Assert.Equal(ToolCallAudit.NoArguments, ToolCallAudit.DescribeArguments("screenshot", new Dictionary<string, JsonElement>(StringComparer.Ordinal)));
    }

    [Fact]
    public void DescribeArguments_StripsSeparatorsFromClientSuppliedNames()
    {
        var arguments = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["bad\r\nname:with,separators"] = JsonSerializer.SerializeToElement("x"),
        };

        var detail = ToolCallAudit.DescribeArguments("keyboard_control", arguments);

        Assert.Equal("bad__name_with_separators", detail);
    }

    [Fact]
    public void Record_WritesLoginAndToolButNoArgumentValue()
    {
        var logger = new CapturingLogger();
        var sink = new CapturingSink();
        var arguments = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["action"] = JsonSerializer.SerializeToElement("type"),
            ["text"] = JsonSerializer.SerializeToElement(Secret + "er"),
        };
        var detail = ToolCallAudit.DescribeArguments("keyboard_control", arguments);

        ToolCallAudit.Record(
            logger,
            sink,
            new FakeTimeProvider(DateTimeOffset.Parse("2026-08-16T10:11:12Z", null)),
            Login,
            "laptop.taila0594.ts.net",
            "keyboard_control",
            detail,
            success: true,
            durationMs: 42);

        var line = Assert.Single(logger.Messages);
        Assert.Contains("keyboard_control", line, StringComparison.Ordinal);
        Assert.Contains(Login, line, StringComparison.Ordinal);
        Assert.Contains("durationMs=42", line, StringComparison.Ordinal);
        foreach (var fragment in SubstringsOf(Secret + "er", 6))
        {
            Assert.DoesNotContain(fragment, line, StringComparison.OrdinalIgnoreCase);
        }

        var record = Assert.Single(sink.Records);
        Assert.Equal(Login, record.Login);
        Assert.Equal("keyboard_control", record.Tool);
        Assert.True(record.Success);
        Assert.Equal(42, record.DurationMs);
        Assert.Equal("2026-08-16T10:11:12.000+00:00", record.TimestampIso);
    }

    [Fact]
    public void Record_SurvivesASinkThatThrows()
    {
        var logger = new CapturingLogger();

        ToolCallAudit.Record(
            logger,
            new ThrowingSink(),
            TimeProvider.System,
            Login,
            string.Empty,
            "screenshot",
            ToolCallAudit.NoArguments,
            success: false,
            durationMs: 7);

        Assert.Equal(2, logger.Messages.Count);
    }

    private static IEnumerable<string> SubstringsOf(string value, int length)
    {
        for (var start = 0; start + length <= value.Length; start++)
        {
            yield return value.Substring(start, length);
        }
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);
            Messages.Add(formatter(state, exception));
        }
    }

    private sealed class CapturingSink : IAuditSink
    {
        public List<AuditRecord> Records { get; } = [];

        public void Write(AuditRecord record) => Records.Add(record);
    }

    private sealed class ThrowingSink : IAuditSink
    {
        public void Write(AuditRecord record) => throw new IOException("the audit volume went away");
    }
}
