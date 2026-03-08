using System.CommandLine;
using System.Collections;
using System.Text.Json;
using System.Text.Json.Serialization;
using MLVScan;
using MLVScan.DevCLI;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.Services;

var assemblyPathArgument = new Argument<FileInfo>(
    "assembly-path",
    "Path to the .dll file to scan");

var formatOption = new Option<string>(
    "--format",
    () => "console",
    "Output format: console (default), json (legacy), schema (new schema v1.0.0)");
formatOption.AddAlias("-o");

var jsonOption = new Option<bool>(
    "--json",
    "Output results as JSON (legacy format, use --format schema for new format)");
jsonOption.AddAlias("-j");

var failOnOption = new Option<string?>(
    "--fail-on",
    "Exit with error code 1 if findings >= specified severity (Low/Medium/High/Critical)");
failOnOption.AddAlias("-f");

var verboseOption = new Option<bool>(
    "--verbose",
    "Show all findings, not just those with developer guidance");
verboseOption.AddAlias("-v");

var rootCommand = new RootCommand("MLVScan Developer CLI - Scan MelonLoader mods during development");
rootCommand.Add(assemblyPathArgument);
rootCommand.Add(formatOption);
rootCommand.Add(jsonOption);
rootCommand.Add(failOnOption);
rootCommand.Add(verboseOption);

rootCommand.SetHandler((FileInfo assemblyPath, string format, bool json, string? failOn, bool verbose) =>
{
    // Handle legacy --json flag
    if (json && format == "console")
    {
        format = "json";
    }
    
    var exitCode = ScanAssembly(assemblyPath, format, failOn, verbose);
    Environment.Exit(exitCode);
}, assemblyPathArgument, formatOption, jsonOption, failOnOption, verboseOption);

return await rootCommand.InvokeAsync(args);

static int ScanAssembly(FileInfo assemblyPath, string format, string? failOn, bool verbose)
{
    if (!assemblyPath.Exists)
    {
        Console.Error.WriteLine($"Error: File not found: {assemblyPath.FullName}");
        return 1;
    }

    try
    {
        byte[] assemblyBytes = File.ReadAllBytes(assemblyPath.FullName);

        // Create scanner with developer mode enabled
        var config = new ScanConfig { DeveloperMode = true };
        var rules = RuleFactory.CreateDefaultRules();
        var scanner = new AssemblyScanner(rules, config);

        // Scan the assembly
        var findings = scanner.Scan(assemblyPath.FullName).ToList();

        // Filter findings if not verbose (only show those with guidance)
        var displayFindings = verbose
            ? findings
            : findings.Where(f => f.DeveloperGuidance != null).ToList();

        var options = ScanResultOptions.ForCli(config.DeveloperMode);
        options.PlatformVersion = "1.0.2";
        var schemaResult = ScanResultMapper.ToDto(findings, assemblyPath.Name, assemblyBytes, options);

        // Output based on format
        switch (format.ToLower())
        {
            case "schema":
                OutputSchema(schemaResult);
                break;
            case "json":
                OutputJson(assemblyPath.Name, displayFindings);
                break;
            case "console":
            default:
                OutputConsole(assemblyPath.Name, displayFindings, schemaResult, verbose);
                break;
        }

        // Check if we should fail based on severity
        if (!string.IsNullOrEmpty(failOn))
        {
            var failSeverity = ParseSeverity(failOn);
            if (failSeverity.HasValue && findings.Any(f => f.Severity >= failSeverity.Value))
            {
                if (format == "console")
                {
                    Console.Error.WriteLine();
                    Console.Error.WriteLine($"Build failed: Found {findings.Count(f => f.Severity >= failSeverity.Value)} finding(s) >= {failSeverity.Value}");
                }
                return 1;
            }
        }

        return findings.Count > 0 ? 0 : 0; // Always return 0 unless --fail-on is used
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
    // Serialize with indentation for readability
    var jsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    Console.WriteLine(JsonSerializer.Serialize(result, jsonOptions));
}

static void OutputConsole(string assemblyName, List<ScanFinding> findings, ScanResultDto schemaResult, bool verbose)
{
    Console.WriteLine("MLVScan Developer Report");
    Console.WriteLine("========================");
    Console.WriteLine($"Assembly: {assemblyName}");
    Console.WriteLine($"Findings: {findings.Count}");
    Console.WriteLine();

    OutputThreatFamilySummary(schemaResult);

    if (findings.Count == 0)
    {
        Console.WriteLine("✓ No issues found!");
        return;
    }

    var groupedByRule = findings
        .Where(f => f.RuleId != null)
        .GroupBy(f => f.RuleId)
        .OrderByDescending(g => g.Max(f => f.Severity));

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

            if (!string.IsNullOrEmpty(firstFinding.DeveloperGuidance.DocumentationUrl))
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine($"  📚 {firstFinding.DeveloperGuidance.DocumentationUrl}");
                Console.ResetColor();
            }

            if (firstFinding.DeveloperGuidance.AlternativeApis != null &&
                firstFinding.DeveloperGuidance.AlternativeApis.Length > 0)
            {
                Console.WriteLine($"  Suggested APIs: {string.Join(", ", firstFinding.DeveloperGuidance.AlternativeApis)}");
            }

            if (!firstFinding.DeveloperGuidance.IsRemediable)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  ⚠ No safe alternative - this pattern should not be used");
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
        
        // Show call chain if available
        if (firstFinding.HasCallChain)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  Call Chain (Attack Path):");
            Console.ResetColor();
            
            foreach (var node in firstFinding.CallChain!.Nodes)
            {
                var indent = node.NodeType switch
                {
                    CallChainNodeType.EntryPoint => "    ",
                    CallChainNodeType.IntermediateCall => "      → ",
                    CallChainNodeType.SuspiciousDeclaration => "        → ",
                    _ => "    "
                };
                
                var nodeTypeLabel = node.NodeType switch
                {
                    CallChainNodeType.EntryPoint => "[ENTRY]",
                    CallChainNodeType.IntermediateCall => "[CALL]",
                    CallChainNodeType.SuspiciousDeclaration => "[DECL]",
                    _ => "[???]"
                };
                
                Console.WriteLine($"{indent}{nodeTypeLabel} {node.Location}");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"{indent}        {node.Description}");
                Console.ResetColor();
            }
        }
        else
        {
            Console.WriteLine("  Locations:");
            foreach (var finding in ruleGroup.Take(3))
            {
                Console.WriteLine($"    • {finding.Location}");
            }
            if (count > 3)
            {
                Console.WriteLine($"    ... and {count - 3} more");
            }
        }

        Console.WriteLine();
        Console.WriteLine("─────────────────────────────────────────");
        Console.WriteLine();
    }
}

static void OutputThreatFamilySummary(ScanResultDto schemaResult)
{
    var threatFamilies = GetThreatFamilies(schemaResult);
    if (threatFamilies.Count == 0)
    {
        return;
    }

    var primary = threatFamilies
        .OrderByDescending(f => f.ExactHashMatch)
        .ThenByDescending(f => f.Confidence)
        .ThenBy(f => f.FamilyId, StringComparer.Ordinal)
        .First();

    var verdict = primary.ExactHashMatch ? "Known malicious sample match" : "Known malware family match";

    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine(verdict);
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
            Console.WriteLine($"  - {evidence}");
        }
    }

    if (primary.AdvisorySlugs.Count > 0)
    {
        Console.WriteLine($"Advisories: {string.Join(", ", primary.AdvisorySlugs)}");
    }

    Console.WriteLine();
}

static List<ThreatFamilyConsoleView> GetThreatFamilies(ScanResultDto schemaResult)
{
    var property = schemaResult.GetType().GetProperty("ThreatFamilies");
    if (property?.GetValue(schemaResult) is not IEnumerable rawFamilies)
    {
        return new List<ThreatFamilyConsoleView>();
    }

    var results = new List<ThreatFamilyConsoleView>();
    foreach (var rawFamily in rawFamilies)
    {
        if (rawFamily == null)
        {
            continue;
        }

        results.Add(new ThreatFamilyConsoleView
        {
            FamilyId = GetStringProperty(rawFamily, "FamilyId"),
            DisplayName = GetStringProperty(rawFamily, "DisplayName"),
            Summary = GetStringProperty(rawFamily, "Summary"),
            MatchKind = GetStringProperty(rawFamily, "MatchKind"),
            Confidence = GetDoubleProperty(rawFamily, "Confidence"),
            ExactHashMatch = GetBoolProperty(rawFamily, "ExactHashMatch"),
            MatchedRules = GetStringListProperty(rawFamily, "MatchedRules"),
            AdvisorySlugs = GetStringListProperty(rawFamily, "AdvisorySlugs"),
            Evidence = GetEvidenceProperty(rawFamily, "Evidence")
        });
    }

    return results;
}

static string GetStringProperty(object target, string propertyName)
{
    return target.GetType().GetProperty(propertyName)?.GetValue(target) as string ?? string.Empty;
}

static double GetDoubleProperty(object target, string propertyName)
{
    return target.GetType().GetProperty(propertyName)?.GetValue(target) is double value ? value : 0d;
}

static bool GetBoolProperty(object target, string propertyName)
{
    return target.GetType().GetProperty(propertyName)?.GetValue(target) is bool value && value;
}

static List<string> GetStringListProperty(object target, string propertyName)
{
    if (target.GetType().GetProperty(propertyName)?.GetValue(target) is not IEnumerable values)
    {
        return new List<string>();
    }

    return values.Cast<object?>()
        .Select(value => value?.ToString())
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Cast<string>()
        .ToList();
}

static List<string> GetEvidenceProperty(object target, string propertyName)
{
    if (target.GetType().GetProperty(propertyName)?.GetValue(target) is not IEnumerable values)
    {
        return new List<string>();
    }

    var results = new List<string>();
    foreach (var value in values)
    {
        if (value == null)
        {
            continue;
        }

        var kind = GetStringProperty(value, "Kind");
        var content = GetStringProperty(value, "Value");
        results.Add(string.IsNullOrWhiteSpace(kind) ? content : $"{kind}: {content}");
    }

    return results;
}

static void OutputJson(string assemblyName, List<ScanFinding> findings)
{
    var result = new DevScanResult
    {
        AssemblyName = assemblyName,
        TotalFindings = findings.Count,
        Findings = findings.Select(f => new DevFindingDto
        {
            RuleId = f.RuleId,
            Description = f.Description,
            Severity = f.Severity.ToString(),
            Location = f.Location,
            CodeSnippet = f.CodeSnippet,
            Guidance = f.DeveloperGuidance != null ? new GuidanceDto
            {
                Remediation = f.DeveloperGuidance.Remediation,
                DocumentationUrl = f.DeveloperGuidance.DocumentationUrl,
                AlternativeApis = f.DeveloperGuidance.AlternativeApis,
                IsRemediable = f.DeveloperGuidance.IsRemediable
            } : null
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
    return severity.ToLower() switch
    {
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => null
    };
}

sealed class ThreatFamilyConsoleView
{
    public string FamilyId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string MatchKind { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public bool ExactHashMatch { get; set; }
    public List<string> MatchedRules { get; set; } = new();
    public List<string> AdvisorySlugs { get; set; } = new();
    public List<string> Evidence { get; set; } = new();
}

