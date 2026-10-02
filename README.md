# MLVScan.DevCLI

Scan .NET mod assemblies from the command line or during a build. MLVScan reports
suspicious behavior, known malware families, and guidance for reviewing findings.

## Install

### .NET tool

Install the CLI globally:

```bash
dotnet tool install --global MLVScan.DevCLI
```

To update it:

```bash
dotnet tool update --global MLVScan.DevCLI
```

For a project-local installation, create a tool manifest if your project does not
already have one, then install the tool:

```bash
dotnet new tool-manifest
dotnet tool install MLVScan.DevCLI
```

Run a local installation with `dotnet tool run mlvscan --` followed by the scan
arguments. Use `dotnet tool restore` after cloning a project with a tool manifest.

### Windows executable

Download `mlvscan-win-x64.zip` from [GitHub Releases](https://github.com/ifBars/MLVScan.DevCLI/releases/latest),
extract it, and run `mlvscan.exe` from the extracted folder:

```powershell
.\mlvscan.exe info --format json
```

## Scan an assembly

```bash
mlvscan MyMod.dll
```

The console report shows the overall disposition, findings, and any matched threat
families. Findings may include remediation advice, documentation links, call
chains, or data-flow evidence.

Use `--verbose` to include advanced diagnostics:

```bash
mlvscan MyMod.dll --verbose
```

### JSON output

Use the schema format for scripts and CI:

```bash
mlvscan MyMod.dll --format schema > scan-results.json
```

The report includes `disposition`, `threatFamilies`, `findings`, and scan metadata.
The legacy JSON format remains available with `--format json` or `--json`.

### Deeper analysis

If a scan reaches an analysis limit, use `retry` to run deeper analysis when needed:

```bash
mlvscan MyMod.dll --scan-mode retry --format schema
```

Use `--scan-mode deep` to apply the larger analysis budgets from the start.
Deeper scans can take longer and may still need manual review if an analysis
limit is reached.

## Use in a build

To fail a build when the disposition is `Suspicious` or `KnownThreat`:

```bash
mlvscan MyMod.dll --fail-on-disposition Suspicious
```

The command returns exit code `1` when the threshold is met. Without a failure
threshold, a completed scan returns `0` even if it reports findings. Scan errors
also return `1`.

For workflows that use finding severity, `--fail-on High` fails on `High` or
`Critical` findings.

### MSBuild

Install MLVScan as a local tool in your project, then add this target to your
`.csproj`:

```xml
<Target Name="MLVScanCheck" AfterTargets="Build">
  <Exec Command="dotnet tool run mlvscan -- &quot;$(TargetPath)&quot; --fail-on-disposition Suspicious" />
</Target>
```

Run `dotnet tool restore` before building on a new machine or in CI.

### GitHub Actions

This example builds a project and scans its assembly. Replace `MyMod.csproj` and
the DLL path with your project's paths.

```yaml
name: Build and scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-dotnet@v5
        with:
          dotnet-version: '8.0.x'
      - name: Install MLVScan
        run: dotnet tool install --global MLVScan.DevCLI
      - name: Build
        run: dotnet build MyMod.csproj -c Release
      - name: Scan
        run: mlvscan ./bin/Release/netstandard2.1/MyMod.dll --format schema --fail-on-disposition Suspicious > scan-results.json
      - name: Save report
        if: always()
        uses: actions/upload-artifact@v6
        with:
          name: scan-results
          path: scan-results.json
```

## Command reference

```text
mlvscan <assembly-path> [options]
mlvscan info [--format text|json]
mlvscan --schema-version
```

| Option | Behavior |
| --- | --- |
| `--format`, `-o` | Output `console` (default), `schema`, or legacy `json`. |
| `--json`, `-j` | Use legacy JSON output. |
| `--fail-on-disposition` | Return `1` at or above `Clean`, `Suspicious`, or `KnownThreat`. |
| `--fail-on`, `-f` | Return `1` at or above `Low`, `Medium`, `High`, or `Critical` severity. |
| `--verbose`, `-v` | Include advanced diagnostics. |
| `--scan-mode` | Use `standard` (default), `retry`, or `deep` analysis. |
| `--help`, `-h` | Show command help. |
| `--version` | Show the CLI version. |

## Review a result

Start with the disposition and any threat-family matches, then read the supporting
findings. Severity describes individual findings; it is not the overall verdict.
Review incomplete analysis and uncertain findings before deciding what to do
with an assembly.

The CLI scans compiled assemblies, so source code is not required. If you suspect
a false positive, report it with the scan output and enough context to explain
the assembly's intended behavior.

## Support

- [Report an issue](https://github.com/ifBars/MLVScan.DevCLI/issues)
- [Join the Discord](https://discord.gg/UD4K4chKak)

## License

[GPL-3.0-or-later](LICENSE).
