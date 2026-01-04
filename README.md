# MLVScan.DevCLI

Developer CLI tool for MLVScan - scan MelonLoader mods during development with remediation guidance.

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

## Usage

### Basic Scan

Scan a mod DLL and get developer-friendly output:

```bash
mlvscan-dev MyMod.dll
```

### JSON Output (for CI/CD)

Get machine-readable JSON output:

```bash
mlvscan-dev MyMod.dll --json
```

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
  <Exec Command="dotnet mlvscan-dev $(TargetPath) --json > mlvscan-report.json" />
</Target>
```

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
  -j, --json              Output results as JSON (useful for CI/CD pipelines)
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

### JSON Output

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

MIT License - See LICENSE file for details
