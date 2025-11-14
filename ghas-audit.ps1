# ============================================================================
# DISCLAIMER: 
# This script is provided "AS IS" without warranty of any kind, either express or implied,
# including but not limited to the implied warranties of merchantability and/or fitness for a
# particular purpose. The entire risk arising out of the use or performance of the sample scripts
# and documentation remains with you. In no event shall Microsoft, its authors, or anyone else
# involved in the creation, production, or delivery of the script be liable for any damages
# whatsoever (including, without limitation, damages for loss of business profits, business
# interruption, loss of business information, or other pecuniary loss) arising out of the use of
# or inability to use the sample scripts or documentation, even if Microsoft has been advised of
# the possibility of such damages.
# ============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$Organization,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "./ghas-reports",
    
    [Parameter(Mandatory=$false)]
    [switch]$DetailedAudit
)

$ErrorActionPreference = "Stop"

# ============================================================================
# PARAMETER VALIDATION AND PROMPTS
# ============================================================================

# Prompt for Organization if not provided
if ([string]::IsNullOrWhiteSpace($Organization)) {
    Write-Host ""
    Write-Host "GitHub Organization not specified." -ForegroundColor Yellow
    Write-Host "Please enter the name of the GitHub Organization to audit:" -ForegroundColor Cyan
    $Organization = Read-Host "Organization"
    
    if ([string]::IsNullOrWhiteSpace($Organization)) {
        Write-Host "Error: Organization name is required." -ForegroundColor Red
        exit 1
    }
}

# Prompt for DetailedAudit mode if not specified
if (-not $PSBoundParameters.ContainsKey('DetailedAudit')) {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                            AUDIT MODE SELECTION                            ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] BASIC MODE" -ForegroundColor Green
    Write-Host "      • GHAS licensing details (who enabled GHAS, when, and how)" -ForegroundColor Gray
    Write-Host "      • Active committers count per repository" -ForegroundColor Gray
    Write-Host "      • Summary reports (JSON + CSV)" -ForegroundColor Gray
    Write-Host "      • Faster execution, minimal API calls" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] DETAILED MODE" -ForegroundColor Yellow
    Write-Host "      • Everything in BASIC mode, plus:" -ForegroundColor Gray
    Write-Host "      • Repository metadata (creation date, size, language, branch)" -ForegroundColor Gray
    Write-Host "      • GHAS features status (Secret Scanning, Dependabot, Code Scanning)" -ForegroundColor Gray
    Write-Host "      • Detailed commit history for each active committer" -ForegroundColor Gray
    Write-Host "      • Longer execution time, more API calls required" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "Select audit mode (1 or 2) [default: 1]"
    
    if ([string]::IsNullOrWhiteSpace($choice)) {
        $choice = "1"
    }
    
    if ($choice -eq "2") {
        $DetailedAudit = $true
    }
    elseif ($choice -ne "1") {
        Write-Host "Invalid choice. Using BASIC mode." -ForegroundColor Yellow
        $DetailedAudit = $false
    }
}

# ============================================================================
# AUTHENTICATION AND PERMISSIONS CHECK
# ============================================================================

function Test-GitHubCLI {
    Write-Host ""
    Write-Host "Checking GitHub CLI installation..." -ForegroundColor Cyan
    
    try {
        $ghVersion = gh --version 2>&1 | Select-Object -First 1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ GitHub CLI found: $ghVersion" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ✗ GitHub CLI not found" -ForegroundColor Red
            Write-Host ""
            Write-Host "Please install GitHub CLI:" -ForegroundColor Yellow
            Write-Host "  Windows: winget install GitHub.cli" -ForegroundColor Gray
            Write-Host "  Or visit: https://cli.github.com/" -ForegroundColor Gray
            return $false
        }
    } catch {
        Write-Host "  ✗ GitHub CLI not found" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install GitHub CLI:" -ForegroundColor Yellow
        Write-Host "  Windows: winget install GitHub.cli" -ForegroundColor Gray
        Write-Host "  Or visit: https://cli.github.com/" -ForegroundColor Gray
        return $false
    }
}

function Test-GitHubAuthentication {
    Write-Host "Checking GitHub authentication..." -ForegroundColor Cyan
    
    try {
        $authStatus = gh auth status 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Authenticated with GitHub" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ✗ Not authenticated with GitHub" -ForegroundColor Red
            Write-Host ""
            Write-Host "Please authenticate with GitHub CLI:" -ForegroundColor Yellow
            Write-Host "  gh auth login" -ForegroundColor Gray
            return $false
        }
    } catch {
        Write-Host "  ✗ Failed to check authentication status" -ForegroundColor Red
        return $false
    }
}

function Test-OrganizationAccess {
    param([string]$OrgName)
    
    Write-Host "Verifying access to organization '$OrgName'..." -ForegroundColor Cyan
    
    try {
        $response = gh api "/orgs/$OrgName" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Organization found and accessible" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ✗ Cannot access organization '$OrgName'" -ForegroundColor Red
            Write-Host ""
            Write-Host "Possible reasons:" -ForegroundColor Yellow
            Write-Host "  • Organization name is incorrect" -ForegroundColor Gray
            Write-Host "  • You don't have access to this organization" -ForegroundColor Gray
            Write-Host "  • Organization doesn't exist" -ForegroundColor Gray
            return $false
        }
    } catch {
        Write-Host "  ✗ Failed to verify organization access" -ForegroundColor Red
        return $false
    }
}

function Test-BillingPermissions {
    param([string]$OrgName)
    
    Write-Host "Checking billing permissions..." -ForegroundColor Cyan
    
    try {
        $response = gh api "/orgs/$OrgName/settings/billing/advanced-security?advanced_security_product=code_security" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Billing access confirmed" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ⚠ No billing access for organization '$OrgName'" -ForegroundColor Yellow
            Write-Host "  → Script will continue, but some billing data may be incomplete" -ForegroundColor Gray
            return $true
        }
    } catch {
        Write-Host "  ⚠ Failed to verify billing permissions" -ForegroundColor Yellow
        Write-Host "  → Script will continue, but some billing data may be incomplete" -ForegroundColor Gray
        return $true
    }
}

function Test-Prerequisites {
    param([string]$OrgName)
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                       PREREQUISITES VERIFICATION                           ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    $checks = @(
        @{ Name = "GitHub CLI"; Test = { Test-GitHubCLI } },
        @{ Name = "Authentication"; Test = { Test-GitHubAuthentication } },
        @{ Name = "Organization Access"; Test = { Test-OrganizationAccess -OrgName $OrgName } },
        @{ Name = "Billing Permissions"; Test = { Test-BillingPermissions -OrgName $OrgName } }
    )
    
    $allPassed = $true
    
    foreach ($check in $checks) {
        $result = & $check.Test
        if (-not $result) {
            $allPassed = $false
        }
    }
    
    Write-Host ""
    
    if ($allPassed) {
        Write-Host "✓ All prerequisites met. Starting audit..." -ForegroundColor Green
        Write-Host ""
        return $true
    } else {
        Write-Host "✗ Prerequisites check failed. Please resolve the issues above." -ForegroundColor Red
        Write-Host ""
        return $false
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Global rate limit tracking
$script:RateLimitInfo = @{
    Limit = 0
    Remaining = 0
    Used = 0
    Reset = 0
    Resource = ""
    LastCheck = [DateTime]::MinValue
}

# API call counter for this script execution
$script:ApiCallCount = 0

function Update-RateLimitInfo {
    param([string]$ResponseHeaders)
    
    if (-not $ResponseHeaders) { return }
    
    try {
        # Parse headers from gh CLI response
        $headers = @{}
        $ResponseHeaders -split "`n" | ForEach-Object {
            if ($_ -match '^([^:]+):\s*(.+)$') {
                $headers[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        
        if ($headers.ContainsKey('x-ratelimit-limit')) {
            $script:RateLimitInfo.Limit = [int]$headers['x-ratelimit-limit']
        }
        if ($headers.ContainsKey('x-ratelimit-remaining')) {
            $script:RateLimitInfo.Remaining = [int]$headers['x-ratelimit-remaining']
        }
        if ($headers.ContainsKey('x-ratelimit-used')) {
            $script:RateLimitInfo.Used = [int]$headers['x-ratelimit-used']
        }
        if ($headers.ContainsKey('x-ratelimit-reset')) {
            $script:RateLimitInfo.Reset = [int]$headers['x-ratelimit-reset']
        }
        if ($headers.ContainsKey('x-ratelimit-resource')) {
            $script:RateLimitInfo.Resource = $headers['x-ratelimit-resource']
        }
        
        $script:RateLimitInfo.LastCheck = [DateTime]::UtcNow
        
        # Warn if approaching rate limit
        if ($script:RateLimitInfo.Remaining -lt 100 -and $script:RateLimitInfo.Remaining -gt 0) {
            $resetTime = [DateTimeOffset]::FromUnixTimeSeconds($script:RateLimitInfo.Reset).LocalDateTime
            Write-Warning "  Rate limit low: $($script:RateLimitInfo.Remaining) requests remaining (resets at $($resetTime.ToString('HH:mm:ss')))"
        }
        
    } catch {
        Write-Verbose "Failed to parse rate limit headers: $_"
    }
}

function Get-RateLimitStatus {
    try {
        $response = (gh api rate_limit --include 2>&1) -join "`n"
        
        if ($LASTEXITCODE -eq 0) {
            # Split headers and body (separated by double newline)
            $parts = $response -split "`n`n", 2
            if ($parts.Count -ge 2) {
                Update-RateLimitInfo -ResponseHeaders $parts[0]
                $data = $parts[1] | ConvertFrom-Json
                
                # Update with more detailed info from API
                if ($data.resources.core) {
                    $script:RateLimitInfo.Limit = $data.resources.core.limit
                    $script:RateLimitInfo.Remaining = $data.resources.core.remaining
                    $script:RateLimitInfo.Used = $data.resources.core.used
                    $script:RateLimitInfo.Reset = $data.resources.core.reset
                }
            }
        }
    } catch {
        Write-Verbose "Failed to retrieve rate limit status: $_"
    }
    
    return [PSCustomObject]$script:RateLimitInfo
}

function Wait-ForRateLimit {
    param(
        [int]$MinimumRemaining = 10,
        [switch]$Force
    )
    
    $status = Get-RateLimitStatus
    
    if ($Force -or $status.Remaining -lt $MinimumRemaining) {
        if ($status.Reset -gt 0) {
            $resetTime = [DateTimeOffset]::FromUnixTimeSeconds($status.Reset)
            $waitSeconds = ($resetTime - [DateTimeOffset]::UtcNow).TotalSeconds
            
            if ($waitSeconds -gt 0) {
                Write-Warning "Rate limit exceeded. Waiting until $($resetTime.LocalDateTime.ToString('HH:mm:ss')) ($([Math]::Ceiling($waitSeconds)) seconds)..."
                Start-Sleep -Seconds ([Math]::Ceiling($waitSeconds) + 1)
                
                # Verify rate limit has reset
                Get-RateLimitStatus | Out-Null
                Write-Host "  ✓ Rate limit reset. Continuing..." -ForegroundColor Green
            }
        }
    }
}

function Invoke-GitHubAPI {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Endpoint,
        
        [switch]$Paginate
    )
    
    # Increment API call counter
    $script:ApiCallCount++
    
    # Check rate limit before making request
    if ($script:RateLimitInfo.Remaining -lt 10 -and $script:RateLimitInfo.Remaining -gt 0) {
        Wait-ForRateLimit -MinimumRemaining 10
    }
    
    # Execute request
    if ($Paginate) {
        # For paginated requests, get data without headers first, then check rate limit separately
        $response = gh api --paginate $Endpoint 2>&1
        if ($LASTEXITCODE -eq 0 -and $response) {
            # Update rate limit info with a separate call
            $headerResponse = (gh api --include $Endpoint 2>&1) -join "`n"
            if ($LASTEXITCODE -eq 0 -and $headerResponse) {
                $parts = $headerResponse -split "`n`n", 2
                if ($parts.Count -ge 2) {
                    Update-RateLimitInfo -ResponseHeaders $parts[0]
                }
            }
            return $response
        }
    } else {
        # For single requests, get headers and body
        # Join array of lines into single string before splitting
        $response = (gh api --include $Endpoint 2>&1) -join "`n"
        if ($LASTEXITCODE -eq 0 -and $response) {
            # Split headers and body (separated by double newline)
            $parts = $response -split "`n`n", 2
            if ($parts.Count -ge 2) {
                Update-RateLimitInfo -ResponseHeaders $parts[0]
                return $parts[1]
            }
            # If split failed, return as-is (might be already JSON)
            return $response
        }
    }
    
    return $null
}

function Get-NormalizedRepoName {
    param([string]$Name)
    if ($Name -match '/') { 
        return $Name.Split('/')[-1] 
    }
    return $Name
}

function ConvertTo-FormattedTimestamp {
    param($Timestamp)
    
    if (-not $Timestamp -or $Timestamp -eq 0) { return "" }
    
    if ($Timestamp -is [long] -or $Timestamp -is [int]) {
        if ($Timestamp -gt 10000000000) {
            return ([DateTimeOffset]::FromUnixTimeMilliseconds($Timestamp)).DateTime.ToString("yyyy-MM-dd HH:mm:ss")
        } else {
            return ([DateTimeOffset]::FromUnixTimeSeconds($Timestamp)).DateTime.ToString("yyyy-MM-dd HH:mm:ss")
        }
    }
    return $Timestamp.ToString()
}

function ConvertTo-ISO8601 {
    param($DateString)
    
    if (-not $DateString) { return "" }
    try { 
        return ([DateTime]$DateString).ToString("yyyy-MM-dd HH:mm:ss")
    } catch { 
        return $DateString 
    }
}

function Get-FirstEnableEvent {
    param([array]$Events)
    
    if (-not $Events) { return $null }
    
    $sortedEvents = $Events | Sort-Object Timestamp
    
    # Array di pattern in ordine di priorità
    $priorityPatterns = @(
        { $_.Action -eq "repository_security_configuration.applied" -and $_.Actor -and $_.Actor -ne "" },
        { ($_.Action -match "code_security.*enable" -or $_.Action -match "advanced_security.*enabled") -and $_.Actor -and $_.Actor -ne "" },
        { $_.Action -match "secret_scanning.*enable" -and $_.Actor -and $_.Actor -ne "" },
        { $_.Action -match "code_scanning.*enable" -and $_.Actor -and $_.Actor -ne "" },
        { $_.Action -match "enable" -and $_.Actor -and $_.Actor -ne "" },
        { $_.Action -eq "repo.create" -and $_.Actor -and $_.Actor -ne "" }
    )
    
    foreach ($pattern in $priorityPatterns) {
        $matchedEvent = $sortedEvents | Where-Object $pattern | Select-Object -First 1
        if ($matchedEvent) { return $matchedEvent }
    }
    
    return $null
}

# ============================================================================
# CORE API FUNCTIONS
# ============================================================================

function Get-GHASBillingInfo {
    param([string]$Organization)
    
    $combinedData = @{
        total_advanced_security_committers = 0
        total_count = 0
        maximum_advanced_security_committers = 0
        purchased_advanced_security_committers = 0
        repositories = [System.Collections.ArrayList]::new()
        code_security_committers = 0
        code_security_repositories = 0
        secret_protection_committers = 0
        secret_protection_repositories = 0
    }
    
    $products = @("code_security", "secret_protection")
    
    foreach ($product in $products) {
        try {
            Write-Host "  → Fetching billing data for $product..." -ForegroundColor Gray
            $response = Invoke-GitHubAPI -Endpoint "/orgs/$Organization/settings/billing/advanced-security?advanced_security_product=$product"
            if (-not $response) { continue }
            
            $data = $response | ConvertFrom-Json
            
            # Store product-specific metrics
            if ($product -eq "code_security") {
                $combinedData.code_security_committers = $data.total_advanced_security_committers
                $combinedData.code_security_repositories = $data.total_count
                Write-Host "     ✓ Code Security: $($data.total_advanced_security_committers) committers in $($data.total_count) repos" -ForegroundColor Gray
            } elseif ($product -eq "secret_protection") {
                $combinedData.secret_protection_committers = $data.total_advanced_security_committers
                $combinedData.secret_protection_repositories = $data.total_count
                Write-Host "     ✓ Secret Protection: $($data.total_advanced_security_committers) committers in $($data.total_count) repos" -ForegroundColor Gray
            }
            
            $combinedData.total_advanced_security_committers += $data.total_advanced_security_committers
            
            if ($data.maximum_advanced_security_committers -gt $combinedData.maximum_advanced_security_committers) {
                $combinedData.maximum_advanced_security_committers = $data.maximum_advanced_security_committers
            }
            if ($data.purchased_advanced_security_committers -gt $combinedData.purchased_advanced_security_committers) {
                $combinedData.purchased_advanced_security_committers = $data.purchased_advanced_security_committers
            }
            
            # Add repositories with product marker
            foreach ($repo in $data.repositories) {
                $existing = $combinedData.repositories | Where-Object { $_.name -eq $repo.name }
                if (-not $existing) {
                    # Add product type to repository object
                    $repo | Add-Member -NotePropertyName "product_type" -NotePropertyValue $product -Force
                    [void]$combinedData.repositories.Add($repo)
                } else {
                    # Mark existing repo with additional product
                    $existing | Add-Member -NotePropertyName "product_type_additional" -NotePropertyValue $product -Force
                }
            }
        } catch {}
    }
    
    # total_count should be the number of unique repositories, not the sum
    $combinedData.total_count = $combinedData.repositories.Count
    
    return [PSCustomObject]$combinedData
}

function Get-RepositoryDetails {
    param(
        [string]$Organization,
        [array]$RepositoryNames
    )
    
    $details = @{}
    $counter = 0
    
    Write-Host "  → Fetching details for $($RepositoryNames.Count) repositories..." -ForegroundColor Gray
    
    foreach ($repoName in $RepositoryNames) {
        $counter++
        
        if ($counter % 20 -eq 0) {
            Write-Host "     Progress: $counter/$($RepositoryNames.Count)" -ForegroundColor DarkGray
            $rateLimitStatus = Get-RateLimitStatus
            if ($rateLimitStatus.Remaining -lt 30) {
                Wait-ForRateLimit -MinimumRemaining 30
            }
        }
        
        try {
            $repoJson = Invoke-GitHubAPI -Endpoint "/repos/$Organization/$repoName"
            if ($repoJson) {
                $repo = $repoJson | ConvertFrom-Json
                $details[$repoName] = [PSCustomObject]@{
                    Repository = $repo.name
                    IsPrivate = $repo.private
                    CreatedAt = $repo.created_at
                    UpdatedAt = $repo.updated_at
                    PushedAt = $repo.pushed_at
                    Size = $repo.size
                    Language = $repo.language
                    DefaultBranch = $repo.default_branch
                }
            }
        } catch {
            Write-Verbose "Could not fetch details for ${repoName}: $($_.Exception.Message)"
        }
    }
    
    return $details
}

function Get-RepositoryFeatures {
    param(
        [string]$Organization,
        [array]$RepositoryNames
    )
    
    $features = @{}
    $counter = 0
    
    Write-Host "  → Fetching GHAS features for $($RepositoryNames.Count) repositories..." -ForegroundColor Gray
    
    foreach ($repoName in $RepositoryNames) {
        $counter++
        
        Write-Host "  → [$counter/$($RepositoryNames.Count)] Checking $repoName..." -ForegroundColor Gray -NoNewline
        
        if ($counter % 20 -eq 0) {
            Write-Host ""
            $rateLimitStatus = Get-RateLimitStatus
            if ($rateLimitStatus.Remaining -lt 30) {
                Wait-ForRateLimit -MinimumRemaining 30
            }
        }
        
        try {
            $repoJson = Invoke-GitHubAPI -Endpoint "/repos/$Organization/$repoName"
            if (-not $repoJson) { 
                Write-Host " ✗" -ForegroundColor Red
                continue 
            }
            
            $repo = $repoJson | ConvertFrom-Json
            $sec = $repo.security_and_analysis
            
            # Check Code Scanning Default Setup
            $codeScanningState = "not-configured"
            $codeScanningLanguages = ""
            $codeScanningSchedule = ""
            try {
                $csSetupJson = Invoke-GitHubAPI -Endpoint "/repos/$Organization/$repoName/code-scanning/default-setup"
                if ($csSetupJson) {
                    $csSetup = $csSetupJson | ConvertFrom-Json
                    $codeScanningState = $csSetup.state
                    if ($csSetup.state -eq "configured") {
                        $codeScanningLanguages = $csSetup.languages -join ", "
                        $codeScanningSchedule = $csSetup.schedule
                    }
                }
            } catch {
                Write-Verbose "Code scanning setup not available for $repoName"
            }
            
            # Check Dependabot Alerts
            $dependabotAlerts = "disabled"
            try {
                $null = Invoke-GitHubAPI -Endpoint "/repos/$Organization/$repoName/vulnerability-alerts"
                if ($LASTEXITCODE -eq 0) {
                    $dependabotAlerts = "enabled"
                }
            } catch {
                Write-Verbose "Dependabot alerts check failed for $repoName"
            }
            
            $features[$repoName] = [PSCustomObject]@{
                Repository = $repoName
                SecretScanning = $sec.secret_scanning.status
                SecretScanningPushProtection = $sec.secret_scanning_push_protection.status
                DependabotAlerts = $dependabotAlerts
                DependabotSecurityUpdates = if ($sec.PSObject.Properties['dependabot_security_updates']) { 
                    $sec.dependabot_security_updates.status 
                } else { "disabled" }
                CodeScanningDefaultSetup = $codeScanningState
                CodeScanningLanguages = $codeScanningLanguages
                CodeScanningSchedule = $codeScanningSchedule
            }
            
            Write-Host " ✓" -ForegroundColor Green
        } catch {
            Write-Host " ✗" -ForegroundColor Red
            Write-Verbose "Could not fetch features for ${repoName}: $($_.Exception.Message)"
        }
    }
    
    return $features
}

function Get-GHASAuditEvents {
    param(
        [string]$Organization,
        [array]$GHASRepositories
    )
    
    $allEvents = [System.Collections.ArrayList]::new()
    
    $ghesEventActions = @(
        "repo.advanced_security_enabled", "repo.advanced_security_disabled",
        "repository_code_security.enable", "repository_code_security.disable",
        "repository_security_configuration.applied", "repository_security_configuration.removed",
        "repository_secret_scanning.enable", "repository_secret_scanning.disable",
        "repository_secret_scanning_push_protection.enable", "repository_secret_scanning_push_protection.disable",
        "repository_secret_scanning_non_provider_patterns.enabled",
        "repository_secret_scanning_automatic_validity_checks.enabled",
        "repo.secret_scanning_enabled", "repo.secret_scanning_disabled",
        "repo.secret_scanning_push_protection_enabled", "repo.secret_scanning_push_protection_disabled",
        "repository.code_scanning_enabled", "repository.code_scanning_disabled",
        "repo.codeql_enabled", "repo.codeql_disabled",
        "repository.dependabot_alerts_enabled", "repository.dependabot_alerts_disabled",
        "repository.dependabot_security_updates_enabled", "repository.dependabot_security_updates_disabled",
        "repository_vulnerability_alerts.enable", "repository_vulnerability_alerts.disable",
        "repository_vulnerability_alerts_auto_dismissal.enable", "repository_vulnerability_alerts_auto_dismissal.disable",
        "repository_dependency_graph.enable", "repository_dependency_graph.disable"
    )
    
    $counter = 0
    foreach ($repo in $GHASRepositories) {
        $counter++
        
        Write-Host "  → [$counter/$($GHASRepositories.Count)] Fetching audit events for $($repo.Repository)..." -ForegroundColor Gray -NoNewline
        
        # Add progress indicator and rate limit check every 20 repos
        if ($counter % 20 -eq 0) {
            Write-Host "" # New line before rate limit message
            $rateLimitStatus = Get-RateLimitStatus
            Write-Host "     Rate limit: $($rateLimitStatus.Remaining)/$($rateLimitStatus.Limit)" -ForegroundColor DarkGray
            
            if ($rateLimitStatus.Remaining -lt 30) {
                Wait-ForRateLimit -MinimumRemaining 30
            }
        }
        
        try {
            $phrase = "repo:$Organization/$($repo.Repository)"
            $response = Invoke-GitHubAPI -Endpoint "/orgs/$Organization/audit-log?phrase=$phrase&per_page=100"
            
            if ($response) {
                # Response might already be parsed or might be a string
                $events = if ($response -is [string]) {
                    try {
                        $response | ConvertFrom-Json -ErrorAction Stop
                    } catch {
                        Write-Verbose "Failed to parse JSON for $($repo.Repository): $_"
                        $null
                    }
                } else {
                    $response
                }
                
                if ($events) {
                    $eventCount = 0
                    foreach ($evt in $events) {
                        if ($ghesEventActions -contains $evt.action) {
                            [void]$allEvents.Add($evt)
                            $eventCount++
                        }
                    }
                    if ($eventCount -gt 0) {
                        Write-Host " ✓ Found $eventCount events" -ForegroundColor Green
                    } else {
                        Write-Host " (no relevant events)" -ForegroundColor DarkGray
                    }
                } else {
                    Write-Host " (no events)" -ForegroundColor DarkGray
                }
            }
            
        } catch {
            Write-Host " ✗ Error" -ForegroundColor Red
            Write-Verbose "Error fetching audit log for $($repo.Repository): $_"
        }
    }
    
    return $allEvents
}

function Get-CommitterDetails {
    param(
        [string]$Organization,
        [string]$Repository,
        [string]$Author,
        [string]$GHASEnabledDate
    )
    
    $result = @{
        FirstPushDateAfterGHAS = ""
        FirstCommitSHA = ""
    }
    
    # Only query commits if we have a GHAS enabled date
    if (-not $GHASEnabledDate) {
        return $result
    }
    
    try {
        $ErrorActionPreference = "SilentlyContinue"
        $enableDateTime = [DateTime]::Parse($GHASEnabledDate)
        $sinceParam = $enableDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        $commitsAfterGHASJson = Invoke-GitHubAPI -Endpoint "/repos/$Organization/$Repository/commits?author=$Author&since=$sinceParam&per_page=100"
        
        if ($commitsAfterGHASJson) {
            $commitsAfterGHAS = $commitsAfterGHASJson | ConvertFrom-Json -ErrorAction SilentlyContinue
            
            if ($commitsAfterGHAS -and $commitsAfterGHAS.Count -gt 0) {
                # Sort to get the first commit after GHAS enablement
                $sortedCommits = $commitsAfterGHAS | Sort-Object { [DateTime]$_.commit.author.date }
                $firstCommit = $sortedCommits[0]
                
                $result.FirstPushDateAfterGHAS = ([DateTime]$firstCommit.commit.author.date).ToString("yyyy-MM-dd HH:mm:ss")
                $result.FirstCommitSHA = $firstCommit.sha
            }
        }
    } catch {}
    
    return $result
}

# ============================================================================
# BANNER & SETUP
# ============================================================================

Write-Host ""
Write-Host "GHAS Audit Report" -ForegroundColor Cyan
Write-Host "Organization: $Organization" -ForegroundColor White
Write-Host "Output Path: $OutputPath" -ForegroundColor White

# Show optional parameters status
Write-Host ""
Write-Host "Report Options:" -ForegroundColor White
Write-Host "  Base reports: Always included (licenses, committers summary)" -ForegroundColor Gray
if ($DetailedAudit) {
    Write-Host "  Audit Mode: DETAILED (includes repository details, features, and commit details)" -ForegroundColor Green
} else {
    Write-Host "  Audit Mode: BASIC (use -DetailedAudit for complete audit)" -ForegroundColor DarkGray
}
Write-Host ""

# ============================================================================
# PREREQUISITES CHECK
# ============================================================================

# Run prerequisites check before starting audit
if (-not (Test-Prerequisites -OrgName $Organization)) {
    exit 1
}

# ============================================================================
# AUDIT EXECUTION
# ============================================================================

# Check initial rate limit status
Write-Host "Checking GitHub API rate limit..." -ForegroundColor Gray
$initialRateLimit = Get-RateLimitStatus
Write-Host "  Rate limit: $($initialRateLimit.Remaining)/$($initialRateLimit.Limit) requests remaining" -ForegroundColor White
if ($initialRateLimit.Reset -gt 0) {
    $resetTime = [DateTimeOffset]::FromUnixTimeSeconds($initialRateLimit.Reset).LocalDateTime
    Write-Host "  Resets at: $($resetTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
}
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportDir = Join-Path $OutputPath "$Organization-$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

# ============================================================================
# STEP 1: Billing Information
# ============================================================================
Write-Host "[1/4] Retrieving Billing Data..." -ForegroundColor Yellow

$billingData = Get-GHASBillingInfo -Organization $Organization
if ($billingData) {
    Write-Host "  ✓ Code Security: $($billingData.code_security_committers) committers | Secret Protection: $($billingData.secret_protection_committers) committers" -ForegroundColor Green
} else {
    Write-Warning "  Error retrieving billing data"
}
Write-Host ""

# Build list of GHAS repositories from billing data
$ghasRepositories = @()
if ($billingData.repositories) {
    foreach ($repo in $billingData.repositories) {
        $ghasRepositories += [PSCustomObject]@{
            Repository = Get-NormalizedRepoName -Name $repo.name
        }
    }
}

# ============================================================================
# STEP 2: Audit Log
# ============================================================================
Write-Host "[2/5] Retrieving Audit Log..." -ForegroundColor Yellow

$auditLogData = @()

try {
    if ($ghasRepositories.Count -gt 0) {
        $auditLogData = Get-GHASAuditEvents -Organization $Organization -GHASRepositories $ghasRepositories
        Write-Host "  ✓ Audit log retrieval completed: $($auditLogData.Count) total events" -ForegroundColor Green
    } else {
        Write-Warning "  ⚠ No GHAS repositories found to query audit log"
    }
} catch {
    Write-Warning "  Audit log not available: $_"
}
Write-Host ""

# ============================================================================
# STEP 3: Optional - Repository Details
# ============================================================================
$repositoryDetails = @{}
if ($DetailedAudit) {
    Write-Host "[3/5] Retrieving Repository Details (detailed audit)..." -ForegroundColor Yellow
    
    $repoNames = $ghasRepositories | ForEach-Object { $_.Repository }
    if ($repoNames.Count -gt 0) {
        $repositoryDetails = Get-RepositoryDetails -Organization $Organization -RepositoryNames $repoNames
        Write-Host "  ✓ Repository details retrieved for $($repositoryDetails.Count) repositories" -ForegroundColor Green
    }
    Write-Host ""
} else {
    Write-Host "[3/5] Skipping Repository Details (use -DetailedAudit to enable)" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# STEP 4: Optional - Repository Features
# ============================================================================
$repositoryFeatures = @{}
if ($DetailedAudit) {
    Write-Host "[4/5] Retrieving Repository Features (detailed audit)..." -ForegroundColor Yellow
    
    $repoNames = $ghasRepositories | ForEach-Object { $_.Repository }
    if ($repoNames.Count -gt 0) {
        $repositoryFeatures = Get-RepositoryFeatures -Organization $Organization -RepositoryNames $repoNames
        Write-Host "  ✓ Repository features retrieved for $($repositoryFeatures.Count) repositories" -ForegroundColor Green
    }
    Write-Host ""
} else {
    Write-Host "[4/5] Skipping Repository Features (use -DetailedAudit to enable)" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# STEP 5: Generate Reports
# ============================================================================
Write-Host "[5/5] Generating Reports..." -ForegroundColor Yellow

# Process audit logs
$repoAuditEvents = @{}
$auditLogSummary = [System.Collections.ArrayList]::new()

foreach ($evt in $auditLogData) {
    $rawRepoName = if ($evt.repo) { $evt.repo } elseif ($evt.data.repo) { $evt.data.repo } else { $null }
    $repoName = Get-NormalizedRepoName -Name $rawRepoName
    
    $timestamp = if ($evt.created_at) { $evt.created_at } 
                 elseif ($evt.PSObject.Properties['@timestamp']) { $evt.PSObject.Properties['@timestamp'].Value } 
                 else { 0 }
    
    $simplifiedEvent = @{
        Repository = $repoName
        Action = $evt.action
        Actor = $evt.actor
        Timestamp = ConvertTo-FormattedTimestamp -Timestamp $timestamp
        SecurityConfigurationName = if ($evt.PSObject.Properties['security_configuration_name']) { 
            $evt.security_configuration_name 
        } else { "" }
        ConfigurationMethod = if ($evt.action -eq "repository_security_configuration.applied") { "Policy" } 
                              elseif ($evt.action -match "repository_code_security|repository_secret_scanning|repo.advanced_security_enabled") { "Manual" } 
                              else { "" }
        EventType = if ($evt.action -match "advanced_security") { "GHAS" }
                    elseif ($evt.action -match "secret_scanning") { "SECRET_SCANNING" }
                    elseif ($evt.action -match "code_scanning") { "CODE_SCANNING" }
                    elseif ($evt.action -match "dependabot") { "DEPENDABOT" }
                    elseif ($evt.action -match "vulnerability") { "VULNERABILITY" }
                    elseif ($evt.action -match "security") { "SECURITY" }
                    else { "OTHER" }
    }
    
    [void]$auditLogSummary.Add($simplifiedEvent)
    
    if ($repoName) {
        if (-not $repoAuditEvents.ContainsKey($repoName)) {
            $repoAuditEvents[$repoName] = [System.Collections.ArrayList]::new()
        }
        [void]$repoAuditEvents[$repoName].Add($simplifiedEvent)
    }
}

# Build generated files list dynamically
$generatedFiles = @{
    CSV = [System.Collections.ArrayList]::new()
    JSON = @("summary-report.json", "audit-log.json")
}
[void]$generatedFiles.CSV.Add("ghas-licensing.csv")
[void]$generatedFiles.CSV.Add("active-committers.csv")
if ($IncludeRepositoryDetails) {
    [void]$generatedFiles.CSV.Add("repositories-metadata.csv")
}
if ($IncludeFeatures) {
    [void]$generatedFiles.CSV.Add("repositories-features.csv")
}
if ($IncludeCommitDetails) {
    [void]$generatedFiles.CSV.Add("active-committers-detailed.csv")
}

# Complete Report JSON
$completeReport = @{
    Organization = $Organization
    ReportDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    Summary = [ordered]@{
        RepositoriesWithActiveCommitters = $billingData.total_count
        CodeSecurityCommitters = $billingData.code_security_committers
        CodeSecurityRepositories = $billingData.code_security_repositories
        SecretProtectionCommitters = $billingData.secret_protection_committers
        SecretProtectionRepositories = $billingData.secret_protection_repositories
        MeteredLicensesPurchased = $billingData.purchased_advanced_security_committers
        MaximumCommittersAllowed = $billingData.maximum_advanced_security_committers
        AuditEventsFound = $auditLogData.Count
    }
    GeneratedFiles = $generatedFiles
}

$jsonFile = Join-Path $reportDir "summary-report.json"
$completeReport | ConvertTo-Json -Depth 10 | Out-File $jsonFile -Encoding UTF8
Write-Host "  ✓ summary-report.json" -ForegroundColor Green

# Audit Log JSON
if ($auditLogSummary.Count -gt 0) {
    $auditReport = @{
        Organization = $Organization
        ReportDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        TotalEvents = $auditLogSummary.Count
        EventTypes = ($auditLogSummary | Group-Object EventType | ForEach-Object { 
            @{ Type = $_.Name; Count = $_.Count } 
        })
        Events = $auditLogSummary
    }
    
    $auditFile = Join-Path $reportDir "audit-log.json"
    $auditReport | ConvertTo-Json -Depth 10 | Out-File $auditFile -Encoding UTF8
    Write-Host "  ✓ audit-log.json ($($auditLogSummary.Count) events)" -ForegroundColor Green
}

# Build repository committers map and determine CodeSecurity/SecretProtection from billing data
$repoCommitters = @{}
$repoCodeSecurity = @{}
$repoSecretProtection = @{}

if ($billingData.repositories) {
    # Extract product info from billing data (already fetched)
    foreach ($repo in $billingData.repositories) {
        $normalizedName = Get-NormalizedRepoName -Name $repo.name
        
        # Determine which products this repo has based on the billing data
        if ($repo.PSObject.Properties['product_type']) {
            if ($repo.product_type -eq "code_security") {
                $repoCodeSecurity[$normalizedName] = $true
            } elseif ($repo.product_type -eq "secret_protection") {
                $repoSecretProtection[$normalizedName] = $true
            }
        }
        if ($repo.PSObject.Properties['product_type_additional']) {
            if ($repo.product_type_additional -eq "code_security") {
                $repoCodeSecurity[$normalizedName] = $true
            } elseif ($repo.product_type_additional -eq "secret_protection") {
                $repoSecretProtection[$normalizedName] = $true
            }
        }
        
        # Build committers map
        $committers = [System.Collections.ArrayList]::new()
        if ($repo.advanced_security_committers_breakdown) {
            foreach ($c in $repo.advanced_security_committers_breakdown) {
                [void]$committers.Add([PSCustomObject]@{
                    Username = $c.user_login
                    Email = $c.last_pushed_email
                    LastPushedDate = $c.last_pushed_date
                })
            }
        }
        $repoCommitters[$normalizedName] = $committers
    }
}

# ghas-licensing.csv (base report - always generated)
$repoGHASEnabledDates = @{}
$licensesData = [System.Collections.ArrayList]::new()

foreach ($repoName in $repoCommitters.Keys) {
    $committerCount = $repoCommitters[$repoName].Count
    
    $enabledBy = ""
    $enabledAt = ""
    $configMethod = ""
    $policyName = ""
    
    if ($repoAuditEvents[$repoName]) {
        $firstEvent = Get-FirstEnableEvent -Events $repoAuditEvents[$repoName]
        if ($firstEvent) {
            $enabledBy = $firstEvent.Actor
            $enabledAt = $firstEvent.Timestamp
            $configMethod = $firstEvent.ConfigurationMethod
            $policyName = $firstEvent.SecurityConfigurationName
            $repoGHASEnabledDates[$repoName] = $enabledAt
        }
    }
    
    $hasCodeSecurity = $repoCodeSecurity.ContainsKey($repoName)
    $hasSecretProtection = $repoSecretProtection.ContainsKey($repoName)
    
    [void]$licensesData.Add([PSCustomObject]@{
        Repository = $repoName
        CodeSecurity = if ($hasCodeSecurity) { "enabled" } else { "disabled" }
        SecretProtection = if ($hasSecretProtection) { "enabled" } else { "disabled" }
        GHASEnabledBy = $enabledBy
        GHASEnabledAt = $enabledAt
        GHASConfigurationMethod = $configMethod
        GHASPolicyName = $policyName
        ActiveCommittersCount = $committerCount
    })
}

$licensesCsv = Join-Path $reportDir "ghas-licensing.csv"
$licensesData | Sort-Object Repository | Export-Csv -Path $licensesCsv -NoTypeInformation -Encoding UTF8
Write-Host "  ✓ ghas-licensing.csv ($($licensesData.Count) repos)" -ForegroundColor Green

# repositories-metadata.csv (optional - requires -DetailedAudit)
if ($DetailedAudit -and $repositoryDetails.Count -gt 0) {
    $detailsData = [System.Collections.ArrayList]::new()
    
    foreach ($repoName in $repositoryDetails.Keys) {
        $details = $repositoryDetails[$repoName]
        [void]$detailsData.Add([PSCustomObject]@{
            Repository = $details.Repository
            IsPrivate = $details.IsPrivate
            CreatedAt = ConvertTo-ISO8601 -DateString $details.CreatedAt
            Size = $details.Size
            Language = $details.Language
            DefaultBranch = $details.DefaultBranch
        })
    }
    
    $detailsCsv = Join-Path $reportDir "repositories-metadata.csv"
    $detailsData | Sort-Object Repository | Export-Csv -Path $detailsCsv -NoTypeInformation -Encoding UTF8
    Write-Host "  ✓ repositories-metadata.csv ($($detailsData.Count) repos)" -ForegroundColor Green
}

# repositories-features.csv (optional - requires -DetailedAudit)
if ($DetailedAudit -and $repositoryFeatures.Count -gt 0) {
    $featuresData = [System.Collections.ArrayList]::new()
    
    foreach ($repoName in $repositoryFeatures.Keys) {
        $features = $repositoryFeatures[$repoName]
        [void]$featuresData.Add($features)
    }
    
    $featuresCsv = Join-Path $reportDir "repositories-features.csv"
    $featuresData | Sort-Object Repository | Export-Csv -Path $featuresCsv -NoTypeInformation -Encoding UTF8
    Write-Host "  ✓ repositories-features.csv ($($featuresData.Count) repos)" -ForegroundColor Green
}


# active-committers.csv (always generated - summary)
$uniqueCommitters = @{}
foreach ($repoName in $repoCommitters.Keys) {
    $committers = $repoCommitters[$repoName]
    foreach ($c in $committers) {
        if (-not $uniqueCommitters.ContainsKey($c.Username)) {
            $uniqueCommitters[$c.Username] = @{
                Email = $c.Email
                Repositories = [System.Collections.ArrayList]::new()
            }
        }
        [void]$uniqueCommitters[$c.Username].Repositories.Add($repoName)
    }
}

$committersData = [System.Collections.ArrayList]::new()
foreach ($username in $uniqueCommitters.Keys) {
    [void]$committersData.Add([PSCustomObject]@{
        Username = $username
        Email = $uniqueCommitters[$username].Email
        TotalRepositories = $uniqueCommitters[$username].Repositories.Count
        RepositoryList = ($uniqueCommitters[$username].Repositories -join "; ")
    })
}

$committersCsv = Join-Path $reportDir "active-committers.csv"
$committersData | Sort-Object Username | Export-Csv -Path $committersCsv -NoTypeInformation -Encoding UTF8
Write-Host "  ✓ active-committers.csv ($($committersData.Count) unique committers)" -ForegroundColor Green

# active-committers-detailed.csv (optional - requires -DetailedAudit)
if ($DetailedAudit) {
    $totalCommitters = ($repoCommitters.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    Write-Host "  Processing commit details for $totalCommitters committers (this may take a while)..." -ForegroundColor Gray
    
    $detailedCommittersData = [System.Collections.ArrayList]::new()
    $committerIndex = 0
    
    foreach ($repoName in $repoCommitters.Keys) {
        $committers = $repoCommitters[$repoName]
        if ($committers -and $committers.Count -gt 0) {
            $ghesEnabledDate = $repoGHASEnabledDates[$repoName]
            
            Write-Host "  → Processing $($committers.Count) committers for $repoName..." -ForegroundColor Gray
            
            foreach ($c in $committers) {
                $committerIndex++
                
                if ($committerIndex % 10 -eq 0) {
                    Write-Host "     Progress: $committerIndex/$totalCommitters committers" -ForegroundColor DarkGray
                }
                
                # Check rate limit every 50 committers
                if ($committerIndex % 50 -eq 0) {
                    $rateLimitStatus = Get-RateLimitStatus
                    if ($rateLimitStatus.Remaining -lt 30) {
                        Wait-ForRateLimit -MinimumRemaining 30
                    }
                }
                
                $details = Get-CommitterDetails -Organization $Organization -Repository $repoName `
                                               -Author $c.Username -GHASEnabledDate $ghesEnabledDate
                
                [void]$detailedCommittersData.Add([PSCustomObject]@{
                    Repository = $repoName
                    Username = $c.Username
                    Email = $c.Email
                    LastPushedDate = $c.LastPushedDate
                    GHASEnabledDate = if ($ghesEnabledDate) { 
                        try { ([DateTime]::Parse($ghesEnabledDate)).ToString("yyyy-MM-dd HH:mm:ss") } 
                        catch { $ghesEnabledDate } 
                    } else { "" }
                    FirstPushDateAfterGHAS = $details.FirstPushDateAfterGHAS
                    FirstCommitSHA = $details.FirstCommitSHA
                })
            }
        }
    }
    
    if ($detailedCommittersData.Count -gt 0) {
        $detailedCommittersCsv = Join-Path $reportDir "active-committers-detailed.csv"
        $detailedCommittersData | Sort-Object Username, Repository | Export-Csv -Path $detailedCommittersCsv -NoTypeInformation -Encoding UTF8
        Write-Host "  ✓ active-committers-detailed.csv ($($detailedCommittersData.Count) user-repository combinations)" -ForegroundColor Green
    }
}

Write-Host ""

# ============================================================================
# Final Summary
# ============================================================================
Write-Host "Report completed!" -ForegroundColor Green
Write-Host "  Organization: $Organization" -ForegroundColor White
Write-Host "  Repositories with Active Committers: $($completeReport.Summary.RepositoriesWithActiveCommitters)" -ForegroundColor White
Write-Host "    - Code Security: $($completeReport.Summary.CodeSecurityCommitters) committers in $($completeReport.Summary.CodeSecurityRepositories) repositories" -ForegroundColor Gray
Write-Host "    - Secret Protection: $($completeReport.Summary.SecretProtectionCommitters) committers in $($completeReport.Summary.SecretProtectionRepositories) repositories" -ForegroundColor Gray
Write-Host "  Output: $reportDir" -ForegroundColor Cyan

# Show optional reports status
if ($DetailedAudit) {
    Write-Host ""
    Write-Host "  Detailed Audit included:" -ForegroundColor White
    Write-Host "    ✓ Repository Details" -ForegroundColor Green
    Write-Host "    ✓ Repository Features" -ForegroundColor Green
    Write-Host "    ✓ Commit Details" -ForegroundColor Green
}

Write-Host ""

# Final rate limit status
$finalRateLimit = Get-RateLimitStatus
Write-Host "GitHub API Rate Limit Status:" -ForegroundColor Cyan
Write-Host "  API calls made by this script: $script:ApiCallCount" -ForegroundColor Yellow
Write-Host "  Requests used (total session): $($finalRateLimit.Used)" -ForegroundColor White
Write-Host "  Requests remaining: $($finalRateLimit.Remaining)/$($finalRateLimit.Limit)" -ForegroundColor White
if ($finalRateLimit.Reset -gt 0) {
    $resetTime = [DateTimeOffset]::FromUnixTimeSeconds($finalRateLimit.Reset).LocalDateTime
    Write-Host "  Next reset: $($resetTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
}
Write-Host ""
