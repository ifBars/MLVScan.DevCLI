# MLVScan.DevCLI

Developer CLI tool for MLVScan - scan .NET mod assemblies during development with remediation guidance and known malware family verdicts.

## Installation

Install as a global .NET tool:

```bash
dotnet tool install --global MLVScan.DevCLI
```

Or install locally in your project:

```bash
dotnet new tool-manifest  # if you don't have one already
dotnet tool install MLVScan.DevCLI
```

## Building from Source

The DevCLI can be built using either the published NuGet package (default) or a local copy of MLVScan.Core for development.

### Default Build (NuGet Package)

By default, the build uses the published `MLVScan.Core` package from NuGet:

```bash
dotnet build -c Release
```

### Local Development Build

To use a local copy of MLVScan.Core (e.g., when developing new features or testing changes):

```bash
dotnet build -c Release -p:LocalCoreBuild=true
```

This switches the reference from the NuGet package to a local project reference at `../MLVScan.Core/MLVScan.Core.csproj`.

**Note:** The NuGet package build requires a published version of MLVScan.Core that includes the DTOs (v1.1.5+). Until then, use `-p:LocalCoreBuild=true` for local development.

## Updating

If installed as a global .NET tool:

```bash
dotnet tool update --global MLVScan.DevCLI
```

Or if installed locally in your project:

```bash
dotnet tool update MLVScan.DevCLI
```

## Usage

### Basic Scan

Scan a mod DLL and get developer-friendly output:

```bash
mlvscan-dev MyMod.dll
```

### JSON Output (for CI/CD)

Get machine-readable JSON output in legacy format:

```bash
mlvscan-dev MyMod.dll --json
```

Or use the new standardized schema format (recommended):

```bash
mlvscan-dev MyMod.dll --format schema
```

The schema format follows MLVScan Schema v1.0.0, which is compatible with the web UI and other MLVScan tools, including threat family matches when a sample maps to a known malware cluster.

### Fail Build on High Severity

Exit with error code 1 if findings of High or Critical severity are found:

```bash
mlvscan-dev MyMod.dll --fail-on High
```

### Verbose Mode

Show all findings, even those without developer guidance:

```bash
mlvscan-dev MyMod.dll --verbose
```

## MSBuild Integration

Add MLVScan checks to your build process by adding this to your `.csproj`:

Note: The output of the DevCLI may be hidden when using the dotnet CLI. Use an IDE like Visual Studio or Rider to see the full output of the DevCLI.

### Option 1: Post-Build Check (Recommended for Development)

```xml
<Target Name="MLVScanCheck" AfterTargets="Build">
  <Exec Command="dotnet mlvscan-dev $(TargetPath)" />
</Target>
```

### Option 2: Fail Build on Issues

```xml
<Target Name="MLVScanCheck" AfterTargets="Build">
  <Exec Command="dotnet mlvscan-dev $(TargetPath) --fail-on High" />
</Target>
```

### Option 3: JSON Output for CI/CD

```xml
<Target Name="MLVScanCheck" AfterTargets="Build">
  <Exec Command="dotnet mlvscan-dev $(TargetPath) --format schema > mlvscan-report.json" />
</Target>
```

Note: Use `--format schema` for the standardized output format, or `--json` for the legacy format.

## Complete Example Project Configuration

Here's a complete example of a mod project with MLVScan integration:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>netstandard2.1</TargetFramework>
    <AssemblyName>MyAwesomeMod</AssemblyName>
  </PropertyGroup>

  <!-- Your mod dependencies -->
  <ItemGroup>
    <PackageReference Include="MelonLoader" Version="0.6.1" />
  </ItemGroup>

  <!-- MLVScan Developer Tool -->
  <ItemGroup>
    <PackageReference Include="MLVScan.DevCLI" Version="1.0.0">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
    </PackageReference>
  </ItemGroup>

  <!-- Run MLVScan after every build -->
  <Target Name="MLVScanCheck" AfterTargets="Build" Condition="'$(Configuration)' == 'Debug'">
    <Exec Command="dotnet mlvscan-dev &quot;$(TargetPath)&quot;" 
          ContinueOnError="true" 
          IgnoreExitCode="true" />
  </Target>

  <!-- Fail release builds if critical issues found -->
  <Target Name="MLVScanCheckRelease" AfterTargets="Build" Condition="'$(Configuration)' == 'Release'">
    <Exec Command="dotnet mlvscan-dev &quot;$(TargetPath)&quot; --fail-on Critical" />
  </Target>
</Project>
```

## Command-Line Options

```
Usage:
  mlvscan-dev <assembly-path> [options]

Arguments:
  <assembly-path>  Path to the .dll file to scan

Options:
  -o, --format <format>   Output format: console (default), json (legacy), schema (MLVScan Schema v1.0.0)
  -j, --json              Output results as JSON (legacy format, use --format schema for new format)
  -f, --fail-on <value>   Exit with error code 1 if findings >= severity (Low/Medium/High/Critical)
  -v, --verbose           Show all findings, not just those with developer guidance
  -h, --help              Show help information
  --version               Show version information
```

## Output Examples

### Console Output

```
MLVScan Developer Report
========================
Assembly: MyMod.dll
Findings: 2

Known malware family match
Family: Embedded resource ShellExecute temp CMD dropper
Match: BehaviorVariant
Confidence: 99%
Summary: Embedded payload materialized to a temporary .cmd file and launched with hidden native shell execution.
Matched Rules: DllImportRule

[High] Detected executable write near persistence-prone directory
  Rule: PersistenceRule
  Occurrences: 1

  Developer Guidance:
  For mod settings, use MelonPreferences. For save data, use the game's
  save system or Application.persistentDataPath with .json extension.
  📚 https://melonwiki.xyz/#/modders/preferences
  Suggested APIs: MelonPreferences.CreateEntry<T>

  Locations:
    • MyMod.SaveManager.SaveSettings:42

─────────────────────────────────────────
```

### JSON Output (Legacy)

```json
{
  "assemblyName": "MyMod.dll",
  "totalFindings": 2,
  "findings": [
    {
      "ruleId": "PersistenceRule",
      "description": "Detected executable write near persistence-prone directory",
      "severity": "High",
      "location": "MyMod.SaveManager.SaveSettings:42",
      "codeSnippet": "...",
      "guidance": {
        "remediation": "For mod settings, use MelonPreferences...",
        "documentationUrl": "https://melonwiki.xyz/#/modders/preferences",
        "alternativeApis": ["MelonPreferences.CreateEntry<T>"],
        "isRemediable": true
      }
    }
  ]
}
```

### Schema Output (New, Recommended)

Using `--format schema` outputs the standardized MLVScan Schema v1.0.0 format:

```json
{
  "schemaVersion": "1.0.0",
  "metadata": {
    "scannerVersion": "1.1.5",
    "timestamp": "2026-01-29T12:34:56.789Z",
    "scanMode": "developer",
    "platform": "cli"
  },
  "input": {
    "fileName": "MyMod.dll",
    "sizeBytes": 45678,
    "sha256Hash": "a1b2c3d4..."
  },
  "summary": {
    "totalFindings": 2,
    "countBySeverity": {
      "High": 2
    },
    "triggeredRules": ["PersistenceRule"]
  },
  "threatFamilies": [
    {
      "familyId": "family-resource-shell32-tempcmd-v1",
      "variantId": "resource-shell32-tempcmd-hidden",
      "displayName": "Embedded resource ShellExecute temp CMD dropper",
      "summary": "Embedded payload materialized to a temporary .cmd file and launched with hidden native shell execution.",
      "matchKind": "BehaviorVariant",
      "confidence": 0.99,
      "exactHashMatch": false,
      "matchedRules": ["DllImportRule"],
      "advisorySlugs": ["2025-12-malware-customtv-il2cpp"],
      "evidence": [
        {
          "kind": "api",
          "value": "ShellExecuteEx"
        }
      ]
    }
  ],
  "findings": [
    {
      "id": "f1a2b3c4d5e6",
      "ruleId": "PersistenceRule",
      "description": "Detected executable write near persistence-prone directory",
      "severity": "High",
      "location": "MyMod.SaveManager.SaveSettings:42",
      "codeSnippet": "..."
    }
  ],
  "developerGuidance": [
    {
      "ruleId": "PersistenceRule",
      "remediation": "For mod settings, use MelonPreferences...",
      "documentationUrl": "https://melonwiki.xyz/#/modders/preferences",
      "alternativeApis": ["MelonPreferences.CreateEntry<T>"],
      "isRemediable": true
    }
  ]
}
```

This format is compatible with the MLVScan web UI and other ecosystem tools.

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: Build and Scan

on: [push, pull_request]

jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup .NET
        uses: actions/setup-dotnet@v3
        with:
          dotnet-version: '8.0.x'
      
      - name: Install MLVScan.DevCLI
        run: dotnet tool install --global MLVScan.DevCLI
      
      - name: Build
        run: dotnet build -c Release
      
      - name: Scan for issues
        run: mlvscan-dev ./bin/Release/netstandard2.1/MyMod.dll --json > scan-results.json
      
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: mlvscan-results
          path: scan-results.json
```

### GitLab CI

```yaml
stages:
  - build
  - scan

build:
  stage: build
  script:
    - dotnet build -c Release
  artifacts:
    paths:
      - bin/Release/

scan:
  stage: scan
  script:
    - dotnet tool install --global MLVScan.DevCLI
    - mlvscan-dev ./bin/Release/netstandard2.1/MyMod.dll --json > scan-results.json
    - mlvscan-dev ./bin/Release/netstandard2.1/MyMod.dll --fail-on Critical
  artifacts:
    reports:
      mlvscan: scan-results.json
```

## Understanding the Output

### Severity Levels

- **Critical**: Serious security violations (e.g., shell execution, Discord webhooks)
- **High**: Potentially dangerous patterns (e.g., registry access, DLL imports)
- **Medium**: Suspicious patterns that may be legitimate (e.g., encoded strings)
- **Low**: Informational findings (e.g., Base64 usage)

### Developer Guidance

Each finding may include:
- **Remediation**: Specific advice on how to fix the issue
- **Documentation URL**: Link to relevant MelonLoader documentation
- **Alternative APIs**: Suggested safe APIs to use instead
- **IsRemediable**: Whether a safe alternative exists

If `IsRemediable` is `false`, the pattern has no safe alternative and should not be used in MelonLoader mods.

## FAQ

### Q: Will this slow down my build?

A: The scan typically takes 1-2 seconds for most mods. You can disable it in Debug builds or use `ContinueOnError="true"` to make it non-blocking.

### Q: What if I get false positives?

A: The developer guidance will help you understand why something was flagged and how to fix it. If you believe it's a legitimate false positive, you can:
1. Refactor your code using the suggested alternatives
2. Contact the MLVScan maintainers in the Discord
3. Add your mod's hash to the whitelist after community review

### Q: Can I use this for closed-source mods?

A: Yes! The tool works on compiled DLLs and doesn't require source code access.

## Support

- **Discord**: https://discord.gg/UD4K4chKak
- **GitHub**: Report issues and suggestions

## License

GPL-3.0 License - See [LICENSE] file for details
