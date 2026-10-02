# Contributor guide

## Build from source

The CLI uses the published `MLVScan.Core` package when no sibling Core checkout is
available. In the MLVScan workspace, it uses the sibling Core project by default.

Build against the published package:

```bash
dotnet restore -p:UseLocalCoreProject=false
dotnet build -c Release --no-restore -p:UseLocalCoreProject=false
```

Build against a sibling Core checkout:

```bash
dotnet build -c Release -p:UseLocalCoreProject=true
```

Run the CLI with `dotnet run -- --help` or `dotnet run -- info --format json`.

## Publish to NuGet

The `publish-nuget` job in `auto-release.yml` uses `NuGet/login@v1` to obtain a
short-lived API key. The job requires `id-token: write` and does not use the
`NUGET_API_KEY` repository secret.

The trusted publishing policy under the `ifBars` NuGet account must match:

- Package owner: `ifBars`
- Repository owner: `ifBars`
- Repository: `MLVScan.DevCLI`
- Workflow file: `auto-release.yml`
- Environment: empty
- Scope: push only new package versions
- Package: `MLVScan.DevCLI` (exact match)

The job saves its `.nupkg` artifact before authentication and upload. If publishing
fails, inspect the publishing job and the retained package. After a successful
upload, wait for NuGet validation and indexing, then verify installation from the
public feed. A successful build or pack does not confirm publication.
