using System.CommandLine;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using MLVScan;
using MLVScan.DevCLI;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.Models.ThreatIntel;
using MLVScan.Services;

if (TryHandleInfoCommand(args))
{
    return 0;
}

if (TryHandleSchemaVersionCommand(args))
{
    return 0;
}

var assemblyPathArgument = new Argument<FileInfo>(
    "assembly-path",
    "Path to the .dll file to scan");

var formatOption = new Option<string>(
    "--format",
    () => "console",
    "Output format: console (default), json (legacy), schema (new schema v1.2.0)");
formatOption.AddAlias("-o");

var jsonOption = new Option<bool>(
    "--json",
    "Output results as JSON (legacy format, use --format schema for new format)");
jsonOption.AddAlias("-j");

var failOnOption = new Option<string?>(
    "--fail-on",
    "Exit with error code 1 if findings >= specified severity (Low/Medium/High/Critical)");
failOnOption.AddAlias("-f");

var failOnDispositionOption = new Option<string?>(
    "--fail-on-disposition",
    "Exit with error code 1 if disposition >= specified classification (Clean/Suspicious/KnownThreat)");

var verboseOption = new Option<bool>(
    "--verbose",
    "Show advanced diagnostics in addition to default retained findings");
verboseOption.AddAlias("-v");

var rootCommand = new RootCommand("MLVScan CLI - Scan .NET mod assemblies during development and CI");
rootCommand.Add(assemblyPathArgument);
rootCommand.Add(formatOption);
rootCommand.Add(jsonOption);
rootCommand.Add(failOnOption);
rootCommand.Add(failOnDispositionOption);
rootCommand.Add(verboseOption);

rootCommand.SetHandler(
    (FileInfo assemblyPath, string format, bool json, string? failOn, string? failOnDisposition, bool verbose) =>
    {
        if (json && format == "console")
        {
            format = "json";
        }

        var exitCode = ScanAssembly(assemblyPath, format, failOn, failOnDisposition, verbose);
        Environment.Exit(exitCode);
    },
    assemblyPathArgument,
    formatOption,
    jsonOption,
    failOnOption,
    failOnDispositionOption,
    verboseOption);

return await rootCommand.InvokeAsync(args);

static int ScanAssembly(
    FileInfo assemblyPath,
    string format,
    string? failOn,
    string? failOnDisposition,
    bool verbose)
{
    if (!assemblyPath.Exists)
    {
        Console.Error.WriteLine($"Error: File not found: {assemblyPath.FullName}");
        return 1;
    }

    try
    {
        var assemblyBytes = File.ReadAllBytes(assemblyPath.FullName);
        var config = new ScanConfig { DeveloperMode = true };
        var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), config);
        var findings = scanner.Scan(assemblyPath.FullName).ToList();

        var options = ScanResultOptions.ForCli(config.DeveloperMode);
        options.PlatformVersion = GetCliVersion();

        var schemaResult = ScanResultMapper.ToDto(findings, assemblyPath.Name, assemblyBytes, options);
        var findingPairs = findings
            .Zip(schemaResult.Findings, static (finding, dto) => new FindingPair(finding, dto))
            .ToList();
        var displayPairs = verbose
            ? findingPairs
            : findingPairs
                .Where(static pair => !string.Equals(pair.Dto.Visibility, nameof(FindingVisibility.Advanced), StringComparison.Ordinal))
                .ToList();

        switch (format.ToLowerInvariant())
        {
            case "schema":
                OutputSchema(schemaResult);
                break;
            case "json":
                OutputJson(assemblyPath.Name, displayPairs.Select(static pair => pair.Finding).ToList());
                break;
            case "console":
            default:
                OutputConsole(schemaResult, displayPairs.Select(static pair => pair.Dto).ToList(), verbose);
                break;
        }

        if (!string.IsNullOrWhiteSpace(failOnDisposition))
        {
            var failClassification = ParseDispositionClassification(failOnDisposition);
            if (failClassification.HasValue)
            {
                var currentClassification = GetEffectiveDispositionClassification(schemaResult);
                if (currentClassification >= failClassification.Value)
                {
                    if (string.Equals(format, "console", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.Error.WriteLine();
                        Console.Error.WriteLine(
                            $"Build failed: Disposition {currentClassification} meets or exceeds {failClassification.Value}");
                    }

                    return 1;
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(failOn))
        {
            var failSeverity = ParseSeverity(failOn);
            if (failSeverity.HasValue && findings.Any(f => f.Severity >= failSeverity.Value))
            {
                if (string.Equals(format, "console", StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine();
                    Console.Error.WriteLine(
                        $"Build failed: Found {findings.Count(f => f.Severity >= failSeverity.Value)} finding(s) >= {failSeverity.Value}");
                }

                return 1;
            }
        }

        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error scanning assembly: {ex.Message}");
        if (verbose)
        {
            Console.Error.WriteLine(ex.StackTrace);
        }

        return 1;
    }
}

static void OutputSchema(ScanResultDto result)
{
    var jsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    Console.WriteLine(JsonSerializer.Serialize(result, jsonOptions));
}

static void OutputConsole(ScanResultDto schemaResult, List<FindingDto> findings, bool verbose)
{
    Console.WriteLine("MLVScan Developer Report");
    Console.WriteLine("========================");
    Console.WriteLine($"Assembly: {schemaResult.Input.FileName}");
    Console.WriteLine($"Disposition: {schemaResult.Disposition?.Classification ?? GetEffectiveDispositionClassification(schemaResult).ToString()}");
    Console.WriteLine($"Retained Findings: {findings.Count}");

    var advancedCount = schemaResult.Findings.Count(static finding =>
        string.Equals(finding.Visibility, nameof(FindingVisibility.Advanced), StringComparison.Ordinal));
    if (advancedCount > 0)
    {
        Console.WriteLine($"Advanced Diagnostics: {advancedCount}{(verbose ? string.Empty : " (use --verbose to show)")}");
    }

    Console.WriteLine();

    OutputDispositionSummary(schemaResult);
    OutputThreatFamilySummary(schemaResult);

    if (findings.Count == 0)
    {
        Console.WriteLine(advancedCount > 0 && !verbose
            ? "No retained findings. Use --verbose to inspect advanced diagnostics."
            : "No retained findings.");
        return;
    }

    var groupedByRule = findings
        .Where(static finding => finding.RuleId != null)
        .GroupBy(static finding => finding.RuleId!)
        .OrderByDescending(static group => group.Max(finding => ParseSeverity(finding.Severity) ?? Severity.Low))
        .ThenBy(static group => group.Key, StringComparer.Ordinal);

    foreach (var ruleGroup in groupedByRule)
    {
        var firstFinding = ruleGroup.First();
        var count = ruleGroup.Count();

        Console.WriteLine($"[{firstFinding.Severity}] {firstFinding.Description}");
        Console.WriteLine($"  Rule: {firstFinding.RuleId}");
        Console.WriteLine($"  Occurrences: {count}");

        if (firstFinding.DeveloperGuidance != null)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  Developer Guidance:");
            Console.ResetColor();
            Console.WriteLine($"  {firstFinding.DeveloperGuidance.Remediation}");

            if (!string.IsNullOrWhiteSpace(firstFinding.DeveloperGuidance.DocumentationUrl))
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine($"  Docs: {firstFinding.DeveloperGuidance.DocumentationUrl}");
                Console.ResetColor();
            }

            if (firstFinding.DeveloperGuidance.AlternativeApis is { Length: > 0 })
            {
                Console.WriteLine($"  Suggested APIs: {string.Join(", ", firstFinding.DeveloperGuidance.AlternativeApis)}");
            }

            if (!firstFinding.DeveloperGuidance.IsRemediable)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  Warning: No safe alternative - this pattern should not be used");
                Console.ResetColor();
            }
        }
        else if (verbose)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  (No developer guidance available)");
            Console.ResetColor();
        }

        Console.WriteLine();

        if (firstFinding.CallChain != null)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  Call Chain (Attack Path):");
            Console.ResetColor();

            foreach (var node in firstFinding.CallChain.Nodes)
            {
                var indent = node.NodeType switch
                {
                    "EntryPoint" => "    ",
                    "IntermediateCall" => "      -> ",
                    "SuspiciousDeclaration" => "        -> ",
                    _ => "    "
                };

                var nodeTypeLabel = node.NodeType switch
                {
                    "EntryPoint" => "[ENTRY]",
                    "IntermediateCall" => "[CALL]",
                    "SuspiciousDeclaration" => "[DECL]",
                    _ => "[???]"
                };

                Console.WriteLine($"{indent}{nodeTypeLabel} {node.Location}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"{indent}        {node.Description}");
                Console.ResetColor();
            }
        }

        if (firstFinding.DataFlowChain != null)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  Data Flow:");
            Console.ResetColor();
            Console.WriteLine($"    Pattern: {firstFinding.DataFlowChain.Pattern}");
            Console.WriteLine($"    Summary: {firstFinding.DataFlowChain.Description}");

            if (!string.IsNullOrWhiteSpace(firstFinding.DataFlowChain.MethodLocation))
            {
                Console.WriteLine($"    Method: {firstFinding.DataFlowChain.MethodLocation}");
            }
        }

        if (firstFinding.CallChain == null && firstFinding.DataFlowChain == null)
        {
            Console.WriteLine("  Locations:");
            foreach (var finding in ruleGroup.Take(3))
            {
                Console.WriteLine($"    - {finding.Location}");
            }

            if (count > 3)
            {
                Console.WriteLine($"    ... and {count - 3} more");
            }
        }

        Console.WriteLine();
        Console.WriteLine("-----------------------------------------");
        Console.WriteLine();
    }
}

static void OutputDispositionSummary(ScanResultDto schemaResult)
{
    if (schemaResult.Disposition == null)
    {
        return;
    }

    var classification = GetEffectiveDispositionClassification(schemaResult);
    var color = GetDispositionColor(classification);
    if (color.HasValue)
    {
        Console.ForegroundColor = color.Value;
    }

    Console.WriteLine(schemaResult.Disposition.Headline);
    Console.ResetColor();
    Console.WriteLine($"Summary: {schemaResult.Disposition.Summary}");
    Console.WriteLine($"Blocking Recommended: {(schemaResult.Disposition.BlockingRecommended ? "Yes" : "No")}");

    if (!string.IsNullOrWhiteSpace(schemaResult.Disposition.PrimaryThreatFamilyId))
    {
        Console.WriteLine($"Primary Threat Family: {schemaResult.Disposition.PrimaryThreatFamilyId}");
    }

    Console.WriteLine();
}

static void OutputThreatFamilySummary(ScanResultDto schemaResult)
{
    if (schemaResult.ThreatFamilies == null || schemaResult.ThreatFamilies.Count == 0)
    {
        return;
    }

    var primary = schemaResult.ThreatFamilies
        .OrderByDescending(static family => family.ExactHashMatch)
        .ThenByDescending(static family => family.Confidence)
        .ThenBy(static family => family.FamilyId, StringComparer.Ordinal)
        .First();

    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine(primary.ExactHashMatch ? "Known malicious sample match" : "Known malware family match");
    Console.ResetColor();
    Console.WriteLine($"Family: {primary.DisplayName}");
    Console.WriteLine($"Match: {primary.MatchKind}");
    Console.WriteLine($"Confidence: {primary.Confidence:P0}");

    if (!string.IsNullOrWhiteSpace(primary.Summary))
    {
        Console.WriteLine($"Summary: {primary.Summary}");
    }

    if (primary.MatchedRules.Count > 0)
    {
        Console.WriteLine($"Matched Rules: {string.Join(", ", primary.MatchedRules)}");
    }

    if (primary.Evidence.Count > 0)
    {
        Console.WriteLine("Evidence:");
        foreach (var evidence in primary.Evidence.Take(4))
        {
            var kind = string.IsNullOrWhiteSpace(evidence.Kind) ? "evidence" : evidence.Kind;
            Console.WriteLine($"  - {kind}: {evidence.Value}");
        }
    }

    if (primary.AdvisorySlugs.Count > 0)
    {
        Console.WriteLine($"Advisories: {string.Join(", ", primary.AdvisorySlugs)}");
    }

    Console.WriteLine();
}

static void OutputJson(string assemblyName, List<ScanFinding> findings)
{
    var result = new DevScanResult
    {
        AssemblyName = assemblyName,
        TotalFindings = findings.Count,
        Findings = findings.Select(static finding => new DevFindingDto
        {
            RuleId = finding.RuleId,
            Description = finding.Description,
            Severity = finding.Severity.ToString(),
            Location = finding.Location,
            CodeSnippet = finding.CodeSnippet,
            Guidance = finding.DeveloperGuidance != null
                ? new GuidanceDto
                {
                    Remediation = finding.DeveloperGuidance.Remediation,
                    DocumentationUrl = finding.DeveloperGuidance.DocumentationUrl,
                    AlternativeApis = finding.DeveloperGuidance.AlternativeApis,
                    IsRemediable = finding.DeveloperGuidance.IsRemediable
                }
                : null
        }).ToList()
    };

    var options = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    Console.WriteLine(JsonSerializer.Serialize(result, options));
}

static Severity? ParseSeverity(string severity)
{
    return severity.ToLowerInvariant() switch
    {
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => null
    };
}

static ThreatDispositionClassification? ParseDispositionClassification(string classification)
{
    return classification.ToLowerInvariant() switch
    {
        "clean" => ThreatDispositionClassification.Clean,
        "suspicious" => ThreatDispositionClassification.Suspicious,
        "knownthreat" => ThreatDispositionClassification.KnownThreat,
        "known-threat" => ThreatDispositionClassification.KnownThreat,
        _ => null
    };
}

static ThreatDispositionClassification GetEffectiveDispositionClassification(ScanResultDto schemaResult)
{
    var parsed = ParseDispositionClassification(schemaResult.Disposition?.Classification ?? string.Empty);
    if (parsed.HasValue)
    {
        return parsed.Value;
    }

    if (schemaResult.ThreatFamilies is { Count: > 0 })
    {
        return ThreatDispositionClassification.KnownThreat;
    }

    return schemaResult.Summary.TotalFindings > 0
        ? ThreatDispositionClassification.Suspicious
        : ThreatDispositionClassification.Clean;
}

static ConsoleColor? GetDispositionColor(ThreatDispositionClassification classification)
{
    return classification switch
    {
        ThreatDispositionClassification.Clean => ConsoleColor.Green,
        ThreatDispositionClassification.Suspicious => ConsoleColor.Yellow,
        ThreatDispositionClassification.KnownThreat => ConsoleColor.Red,
        _ => null
    };
}

static bool TryHandleInfoCommand(IReadOnlyList<string> arguments)
{
    if (arguments.Count == 0 || !string.Equals(arguments[0], "info", StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    if (arguments.Any(static argument => string.Equals(argument, "--help", StringComparison.OrdinalIgnoreCase)
        || string.Equals(argument, "-h", StringComparison.OrdinalIgnoreCase)))
    {
        OutputInfoHelp();
        return true;
    }

    var format = "text";
    for (var index = 1; index < arguments.Count; index++)
    {
        var argument = arguments[index];
        if (string.Equals(argument, "--format", StringComparison.OrdinalIgnoreCase)
            || string.Equals(argument, "-o", StringComparison.OrdinalIgnoreCase))
        {
            if (index + 1 >= arguments.Count)
            {
                Console.Error.WriteLine("Error: Missing value for --format.");
                Environment.ExitCode = 1;
                return true;
            }

            format = arguments[index + 1];
            index++;
            continue;
        }

        Console.Error.WriteLine($"Error: Unknown info option '{argument}'.");
        Environment.ExitCode = 1;
        return true;
    }

    OutputInfo(format);
    return true;
}

static bool TryHandleSchemaVersionCommand(IReadOnlyList<string> arguments)
{
    if (arguments.Count != 1)
    {
        return false;
    }

    var argument = arguments[0];
    if (!string.Equals(argument, "--schema-version", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(argument, "schema-version", StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    Console.WriteLine(MLVScanVersions.SchemaVersion);
    return true;
}

static void OutputInfo(string format)
{
    var info = new CliInfo
    {
        Command = "mlvscan",
        Platform = "cli",
        PlatformVersion = GetCliVersion(),
        SchemaVersion = MLVScanVersions.SchemaVersion,
        CoreVersion = MLVScanVersions.CoreVersion
    };

    if (string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
    {
        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        Console.WriteLine(JsonSerializer.Serialize(info, jsonOptions));
        return;
    }

    if (!string.Equals(format, "text", StringComparison.OrdinalIgnoreCase))
    {
        Console.Error.WriteLine($"Error: Unsupported info format '{format}'. Use 'text' or 'json'.");
        Environment.ExitCode = 1;
        return;
    }

    Console.WriteLine("MLVScan CLI");
    Console.WriteLine($"Command: {info.Command}");
    Console.WriteLine($"Platform: {info.Platform}");
    Console.WriteLine($"Platform Version: {info.PlatformVersion}");
    Console.WriteLine($"Schema Version: {info.SchemaVersion}");
    Console.WriteLine($"Core Version: {info.CoreVersion}");
}

static void OutputInfoHelp()
{
    Console.WriteLine("Usage:");
    Console.WriteLine("  mlvscan info [--format <text|json>]");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine("  -o, --format <format>   Output format: text (default) or json");
    Console.WriteLine("  -h, --help              Show help information");
}

static string GetCliVersion()
{
    var assembly = Assembly.GetExecutingAssembly();
    var informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
    if (!string.IsNullOrWhiteSpace(informationalVersion))
    {
        return informationalVersion.Split('+', 2)[0];
    }

    return assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}

sealed record FindingPair(ScanFinding Finding, FindingDto Dto);

sealed class CliInfo
{
    public string Command { get; set; } = string.Empty;
    public string Platform { get; set; } = string.Empty;
    public string PlatformVersion { get; set; } = string.Empty;
    public string SchemaVersion { get; set; } = string.Empty;
    public string CoreVersion { get; set; } = string.Empty;
}
