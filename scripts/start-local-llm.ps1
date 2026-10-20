param(
    [switch]$SmokeTest,
    [string]$ConfigPath = ""
)
$ErrorActionPreference = "Stop"
$repoPath = Split-Path -Parent $PSScriptRoot
if (-not $ConfigPath) { $ConfigPath = Join-Path $repoPath ".env.llm.local" }
$allowedNames = @("ARTEX_LLM_PROVIDER", "ARTEX_LLM_BASE_URL", "ARTEX_LLM_MODEL", "ANTHROPIC_API_KEY", "ARTEX_LLM_STREAM")
$previousValues = @{}
try {
    foreach ($entry in Get-Content -LiteralPath $ConfigPath) {
        if (-not $entry.Trim() -or $entry.TrimStart().StartsWith("#")) { continue }
        $pair = $entry.Split("=", 2)
        if ($pair.Length -ne 2 -or $pair[0] -notin $allowedNames) { throw "Unsupported local LLM setting" }
        $envName = $pair[0]
        if (-not $previousValues.ContainsKey($envName)) {
            $previousValues[$envName] = [Environment]::GetEnvironmentVariable($envName, "Process")
        }
        [Environment]::SetEnvironmentVariable($envName, $pair[1], "Process")
    }
    Push-Location -LiteralPath $repoPath
    try {
        if ($SmokeTest) { & go run ./cmd/artex-llm-smoke }
        else { & go run ./cmd/artex }
        $commandExitCode = $LASTEXITCODE
    } finally { Pop-Location }
} finally {
    foreach ($envName in $previousValues.Keys) {
        [Environment]::SetEnvironmentVariable($envName, $previousValues[$envName], "Process")
    }
}
exit $commandExitCode
