using System.CommandLine;
using System.Security.Cryptography;
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

        // Output based on format
        switch (format.ToLower())
        {
            case "schema":
                OutputSchema(assemblyPath, findings, config);
                break;
            case "json":
                OutputJson(assemblyPath.Name, displayFindings);
                break;
            case "console":
            default:
                OutputConsole(assemblyPath.Name, displayFindings, verbose);
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

static void OutputSchema(FileInfo assemblyPath, List<ScanFinding> findings, ScanConfig config)
{
    // Read file bytes for SHA256 hash
    byte[] assemblyBytes = File.ReadAllBytes(assemblyPath.FullName);
    
    // Use shared mapper from MLVScan.Core with CLI-specific options
    var options = ScanResultOptions.ForCli(config.DeveloperMode);
    options.PlatformVersion = "1.0.2";
    var result = ScanResultMapper.ToDto(findings, assemblyPath.Name, assemblyBytes, options);
    
    // Serialize with indentation for readability
    var jsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    Console.WriteLine(JsonSerializer.Serialize(result, jsonOptions));
}

static void OutputConsole(string assemblyName, List<ScanFinding> findings, bool verbose)
{
    Console.WriteLine("MLVScan Developer Report");
    Console.WriteLine("========================");
    Console.WriteLine($"Assembly: {assemblyName}");
    Console.WriteLine($"Findings: {findings.Count}");
    Console.WriteLine();

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

