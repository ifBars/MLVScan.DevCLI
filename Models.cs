namespace MLVScan.DevCLI;

/// <summary>
/// Simple scan result model for legacy JSON output format.
/// Used by the --json flag for backward compatibility.
/// For new code, use the schema-compliant DTOs from MLVScan.Models.Dto.
/// </summary>
public class DevScanResult
{
    public string AssemblyName { get; set; } = string.Empty;
    public int TotalFindings { get; set; }
    public List<DevFindingDto> Findings { get; set; } = new();
}

public class DevFindingDto
{
    public string? RuleId { get; set; }
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string? CodeSnippet { get; set; }
    public GuidanceDto? Guidance { get; set; }
}

public class GuidanceDto
{
    public string Remediation { get; set; } = string.Empty;
    public string? DocumentationUrl { get; set; }
    public string[]? AlternativeApis { get; set; }
    public bool IsRemediable { get; set; }
}
