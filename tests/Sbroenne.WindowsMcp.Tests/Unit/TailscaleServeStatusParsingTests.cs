using Sbroenne.WindowsMcp.Tailscale;

namespace Sbroenne.WindowsMcp.Tests.Unit;

public sealed class TailscaleServeStatusParsingTests
{
    private const string ForegroundServeJson = """
        {
          "Foreground": {
            "sess-8f2a": {
              "TCP": { "8443": { "HTTPS": true } },
              "Web": {
                "msiwin11.taila0594.ts.net:8443": {
                  "Handlers": {
                    "/mcp": { "Proxy": "http://127.0.0.1:8765/mcp" }
                  }
                }
              }
            }
          }
        }
        """;

    private const string BackgroundServeJson = """
        {
          "TCP": { "443": { "HTTPS": true } },
          "Web": {
            "msiwin11.taila0594.ts.net:443": {
              "Handlers": {
                "/": { "Proxy": "http://127.0.0.1:3000" },
                "/api": { "Proxy": "http://127.0.0.1:3001/api" }
              }
            }
          }
        }
        """;

    private const string FunnelServeJson = """
        {
          "TCP": { "443": { "HTTPS": true } },
          "Web": {
            "msiwin11.taila0594.ts.net:443": {
              "Handlers": {
                "/": { "Proxy": "http://127.0.0.1:3000" }
              }
            }
          },
          "AllowFunnel": { "msiwin11.taila0594.ts.net:443": true }
        }
        """;

    [Fact]
    public void ParseServeStatus_ReadsForegroundSession()
    {
        var status = TailscaleCli.ParseServeStatus(ForegroundServeJson);

        Assert.NotNull(status);
        var listener = Assert.Single(status.Listeners);
        Assert.Equal(8443, listener.Port);
        Assert.Equal("msiwin11.taila0594.ts.net:8443", listener.HostPort);
        Assert.Equal("/mcp", listener.Path);
        Assert.Equal("http://127.0.0.1:8765/mcp", listener.ProxyTarget);
        Assert.True(listener.Foreground);
        Assert.False(listener.AllowFunnel);
        Assert.False(status.AnyFunnel);
    }

    [Fact]
    public void ParseServeStatus_ReadsBackgroundHandlers()
    {
        var status = TailscaleCli.ParseServeStatus(BackgroundServeJson);

        Assert.NotNull(status);
        Assert.Equal(2, status.Listeners.Count);
        Assert.All(status.Listeners, listener => Assert.False(listener.Foreground));
        Assert.All(status.Listeners, listener => Assert.Equal(443, listener.Port));
        Assert.Contains(status.Listeners, listener => listener.Path == "/" && listener.ProxyTarget == "http://127.0.0.1:3000");
        Assert.Contains(status.Listeners, listener => listener.Path == "/api" && listener.ProxyTarget == "http://127.0.0.1:3001/api");
    }

    [Fact]
    public void ParseServeStatus_ReadsEmptyConfigurationAsNoListeners()
    {
        var status = TailscaleCli.ParseServeStatus("{}");

        Assert.NotNull(status);
        Assert.Empty(status.Listeners);
        Assert.False(status.AnyFunnel);
    }

    [Fact]
    public void ParseServeStatus_FlagsFunnelForTheMatchingHost()
    {
        var status = TailscaleCli.ParseServeStatus(FunnelServeJson);

        Assert.NotNull(status);
        var listener = Assert.Single(status.Listeners);
        Assert.True(listener.AllowFunnel);
        Assert.True(status.AnyFunnel);
    }

    [Fact]
    public void ParseServeStatus_FlagsFunnelDeclaredInsideAHostEntry()
    {
        const string json = """
            {
              "Web": {
                "host.example.ts.net:443": {
                  "AllowFunnel": true,
                  "Handlers": { "/": { "Proxy": "http://127.0.0.1:3000" } }
                }
              }
            }
            """;

        var status = TailscaleCli.ParseServeStatus(json);

        Assert.NotNull(status);
        Assert.True(Assert.Single(status.Listeners).AllowFunnel);
    }

    [Fact]
    public void ParseServeStatus_TreatsAnUnattributedFunnelFlagAsCoveringEveryListener()
    {
        const string json = """
            {
              "TCP": { "443": { "HTTPS": true, "Funnel": true } },
              "Web": {
                "host.example.ts.net:443": {
                  "Handlers": { "/": { "Proxy": "http://127.0.0.1:3000" } }
                }
              }
            }
            """;

        var status = TailscaleCli.ParseServeStatus(json);

        Assert.NotNull(status);
        Assert.True(status.AnyFunnel);
    }

    [Fact]
    public void ParseServeStatus_CombinesBackgroundAndForegroundConfigurations()
    {
        const string json = """
            {
              "Web": {
                "host.example.ts.net:443": {
                  "Handlers": { "/": { "Proxy": "http://127.0.0.1:3000" } }
                }
              },
              "Foreground": {
                "sess-1": {
                  "Web": {
                    "host.example.ts.net:8443": {
                      "Handlers": { "/mcp": { "Proxy": "http://127.0.0.1:8765/mcp" } }
                    }
                  }
                }
              }
            }
            """;

        var status = TailscaleCli.ParseServeStatus(json);

        Assert.NotNull(status);
        Assert.Equal(2, status.Listeners.Count);
        Assert.Single(status.Listeners, listener => listener.Foreground);
        Assert.Single(status.Listeners, listener => !listener.Foreground);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json")]
    [InlineData("[]")]
    public void ParseServeStatus_ReturnsNullForUnusableOutput(string json)
    {
        Assert.Null(TailscaleCli.ParseServeStatus(json));
    }

    [Fact]
    public void ParseStatus_ReadsSelfAndCertificateDomains()
    {
        const string json = """
            {
              "BackendState": "Running",
              "MagicDNSSuffix": "taila0594.ts.net",
              "CertDomains": ["msiwin11.taila0594.ts.net"],
              "Self": {
                "DNSName": "msiwin11.taila0594.ts.net.",
                "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::1"],
                "CapMap": { "https": null }
              }
            }
            """;

        var status = TailscaleCli.ParseStatus(json);

        Assert.NotNull(status);
        Assert.Equal("Running", status.BackendState);
        Assert.True(status.IsRunning);
        Assert.Equal("msiwin11.taila0594.ts.net", status.DnsName);
        Assert.Equal(["100.101.102.103", "fd7a:115c:a1e0::1"], status.TailscaleIps);
        Assert.Equal("taila0594.ts.net", status.MagicDnsSuffix);
        Assert.Equal(["msiwin11.taila0594.ts.net"], status.CertDomains);
        Assert.True(status.HttpsEnabled);
    }

    [Fact]
    public void ParseStatus_ReportsHttpsDisabledWithoutCertificateDomains()
    {
        const string json = """
            {
              "BackendState": "Running",
              "CertDomains": [],
              "Self": { "DNSName": "host.example.ts.net.", "CapMap": { "https": null } }
            }
            """;

        var status = TailscaleCli.ParseStatus(json);

        Assert.NotNull(status);
        Assert.False(status.HttpsEnabled);
    }

    [Fact]
    public void ParseStatus_ReportsHttpsDisabledWithoutTheHttpsCapability()
    {
        const string json = """
            {
              "BackendState": "Running",
              "CertDomains": ["host.example.ts.net"],
              "Self": { "DNSName": "host.example.ts.net.", "CapMap": {} }
            }
            """;

        var status = TailscaleCli.ParseStatus(json);

        Assert.NotNull(status);
        Assert.False(status.HttpsEnabled);
    }

    [Fact]
    public void ParseStatus_ReadsAStoppedBackend()
    {
        var status = TailscaleCli.ParseStatus("""{ "BackendState": "Stopped" }""");

        Assert.NotNull(status);
        Assert.False(status.IsRunning);
        Assert.Null(status.DnsName);
        Assert.Empty(status.TailscaleIps);
        Assert.Empty(status.CertDomains);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{}")]
    public void ParseStatus_ReturnsNullForUnusableOutput(string json)
    {
        Assert.Null(TailscaleCli.ParseStatus(json));
    }

    [Fact]
    public void ParseWhois_ReadsUserProfileAndNode()
    {
        const string json = """
            {
              "Node": { "Name": "laptop.taila0594.ts.net.", "Tags": null },
              "UserProfile": { "LoginName": "ozzie@github", "DisplayName": "Ozzie" }
            }
            """;

        var whois = TailscaleCli.ParseWhois(json);

        Assert.NotNull(whois);
        Assert.Equal("ozzie@github", whois.LoginName);
        Assert.Equal("Ozzie", whois.DisplayName);
        Assert.Equal("laptop.taila0594.ts.net", whois.NodeName);
        Assert.Empty(whois.Tags);
    }

    [Fact]
    public void ParseWhois_ReadsATaggedNodeWithNoLogin()
    {
        const string json = """
            {
              "Node": { "Name": "ci.taila0594.ts.net.", "Tags": ["tag:ci", "tag:build"] },
              "UserProfile": { "LoginName": "", "DisplayName": "" }
            }
            """;

        var whois = TailscaleCli.ParseWhois(json);

        Assert.NotNull(whois);
        Assert.Equal("", whois.LoginName);
        Assert.Null(whois.DisplayName);
        Assert.Equal(["tag:ci", "tag:build"], whois.Tags);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{}")]
    public void ParseWhois_ReturnsNullForUnusableOutput(string json)
    {
        Assert.Null(TailscaleCli.ParseWhois(json));
    }

    [Theory]
    [InlineData("1.102.2\r\n  tailscale commit: abc\r\n", "1.102.2")]
    [InlineData("1.60.0", "1.60.0")]
    [InlineData("1.58.2-t1234abcd\n", "1.58.2")]
    public void ParseVersion_ReadsTheLeadingVersionOfTheFirstLine(string output, string expected)
    {
        Assert.Equal(Version.Parse(expected), TailscaleCli.ParseVersion(output));
    }

    [Theory]
    [InlineData("")]
    [InlineData("unknown")]
    [InlineData("v1.60.0")]
    public void ParseVersion_ReturnsNullWhenTheFirstLineDoesNotStartWithAVersion(string output)
    {
        Assert.Null(TailscaleCli.ParseVersion(output));
    }
}
