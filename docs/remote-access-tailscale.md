# Remote access over Tailscale

The HTTP transport lets an MCP client on another machine drive this desktop. Exposing that to a network is dangerous, so the recommended way to reach it from another machine is Tailscale: the server runs behind `tailscale serve`, only tailnet peers can reach it, and every request carries a verified tailnet identity.

`--tailscale` mode does four things:

1. Binds Kestrel to loopback only and never anything else.
2. Starts and supervises a foreground `tailscale serve` child, so the tailnet route exists only while the server runs. Kill the server and the route disappears.
3. Requires every request to carry a Tailscale identity header, cross-checks it against `tailscale whois`, and matches it against your `--allow` list.
4. Logs every tool call with the caller's login.

Funnel (public internet exposure) is refused. The server will not start if the command line mentions it, and preflight fails if a funnel config is found on the serve port.

## Requirements

- Tailscale installed and signed in on this machine, backend Running.
- MagicDNS and HTTPS certificates enabled for the tailnet (Tailscale admin console, DNS page).
- The server must run in the interactive desktop session. A service or SSH session cannot see the desktop, so UI automation would find no windows. Preflight fails in that case.

## Check readiness

```powershell
Sbroenne.WindowsMcp.exe --tailscale --allow you@github --tailscale-check
```

This runs the preflight checks and exits. Each failing check prints one line naming the fix. Exit code 0 means ready.

## Run it

```powershell
Sbroenne.WindowsMcp.exe --tailscale --allow you@github
```

On success it prints the tailnet URL and the exact command to add it on the client:

```
Windows MCP is available on your tailnet:
  https://thishost.your-tailnet.ts.net/mcp
Add it on another machine:
  claude mcp add --transport http windows https://thishost.your-tailnet.ts.net/mcp
Allowed logins: you@github
```

Add more `--allow <login>` flags for more users. Every allowed login can fully control this desktop, so keep the list tight.

Options specific to this mode:

| Option | Default | Description |
|--------|---------|-------------|
| `--tailscale` | off | Serve behind Tailscale Serve, tailnet-only |
| `--allow <login>` | (required) | A tailnet login allowed to connect; repeat for more |
| `--serve-port <n>` | `443` | Tailnet-facing HTTPS port |
| `--no-verify-identity` | off | Skip the whois cross-check. This reduces authentication to a header the peer sends. Do not use it unless you understand the risk |
| `--audit-file <path>` | none | Append a JSON-lines audit record per tool call |
| `--tailscale-exe <path>` | Program Files | Path to `tailscale.exe` |
| `--tailscale-check` | off | Run preflight and exit |

## Connect from another machine

On the client (Mac, Linux, another Windows box) with Tailscale signed in as an allowed login:

```
claude mcp add --transport http windows https://thishost.your-tailnet.ts.net/mcp
```

That is the whole client setup. The server drives the desktop of the machine it runs on.

## Run it at logon (Task Scheduler)

The server has to run in your interactive session, so a normal Windows service will not work. Use a scheduled task that runs at logon, only when you are logged on:

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\bin\Sbroenne.WindowsMcp.exe" -Argument "--tailscale --allow you@github"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
Register-ScheduledTask -TaskName "WindowsMcp" -Action $action -Trigger $trigger -Settings $settings -RunLevel Limited
```

Keep `-RunLevel Limited` (not elevated): the server cannot drive elevated windows anyway, and running it unelevated keeps its reach the same as yours.

## Check that it is healthy

- `Sbroenne.WindowsMcp.exe --tailscale --allow you@github --tailscale-check` reports each precondition.
- `GET http://127.0.0.1:8765/healthz` on the machine itself returns status, version, and uptime. It needs no identity because it is loopback only and returns nothing sensitive.
- With `--audit-file`, the audit log shows every tool call with its caller.

## When something breaks

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Tailscale is not running` | backend stopped or signed out | open the Tailscale app and sign in |
| `HTTPS certificates are not enabled` | MagicDNS/HTTPS off for the tailnet | enable both in the admin console DNS page |
| `not running in the interactive desktop session` | started as a service or over SSH | run it from a logon task in your session |
| `port 443 is already served` | another serve config owns it | `tailscale serve reset` or pass `--serve-port` |
| client gets a certificate error | client Tailscale not signed in, or clock skew | sign the client in, check the time |
| every call is 403 | client login not in `--allow`, or identity mismatch | add the login to `--allow`, confirm the client is that user |
| route gone after a crash | expected: the route lives only while the server runs | restart the server |

## Why this shape

Serve terminates TLS with a real tailnet certificate and forwards to the server on loopback, injecting the caller's verified identity. Because the server runs the Serve child in the foreground inside a job that dies with it, there is never a tailnet URL pointing at a port nothing is listening on. Because the server binds loopback and checks the identity header against `whois`, a stray local process cannot use the port either. The tailnet is the authentication boundary, so there are no tokens to manage or leak.
