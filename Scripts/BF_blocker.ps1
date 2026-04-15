
<#
.SYNOPSIS
Automatically detects and blocks IP addresses involved in brute force attacks on a Windows server.

.DESCRIPTION
This script analyzes Windows Security Event Logs (failed logon attempts) to identify suspicious activity.
Based on defined thresholds (number of attempts, time window, failure reasons), it can automatically block offending IP addresses using Windows Firewall.

An audit mode is available to monitor activity without applying any blocking rules.

The script also includes:
- Attempt history tracking and caching mechanism
- Country-based threshold adjustment (TrustedCountries)
- Trusted IP exclusion (TrustedIPs)
- Failure reason analysis to reduce false positives

.PARAMETER Mode
Enables or disables blocking (false = audit mode, true = active blocking)

.PARAMETER Threshold
Number of failed attempts before triggering a block

.PARAMETER Minutes
Time window used to evaluate failed attempts

.PARAMETER FilterReason
Filter based on failure reasons (e.g., "user does not exist")

.PARAMETER TrustedCountries
Countries allowed with higher thresholds

.PARAMETER TrustedIPs
List of IP addresses to exclude from analysis

.NOTES
Version : 1.0
Author : Mehdi Dakhama  
Project : LogonIT.fr / BruteForce Blocker  
Recommended usage via scheduled task  
#>

#region parameters

# Audit mode, rules will be create but not enabled by default, change to $true if you want to active rules.
$Mode = "false"
# Time to monitor all other tentative in history on hours
$HistoryAttempt= 24   
# Default path for loging
$Path = "C:\temp\BruteForceBlocker\"

# Detection thresholds

# Number of failed attempts required to trigger a block
$Minutes = 1
$threshold = 10

# Filter by failure reasons (leave empty to disable) Example: @("User does not exist")
$filterReason = @("User does not exist")
# Number of identical failure reasons required to trigger a block
# Only used if $filterReason is defined
$reasonThreshold = 7

# Filter by Country 
# List of trusted countries (will apply higher tolerance) Example: @("France")
$trustedCountries = @("France")
# Higher threshold for trusted countries (to reduce false positives)
$trustedThreshold = 15
# Lower threshold for foreign countries (more aggressive protection)
$thresetrange = 10

#  Trusted sources 
# List of IP publics addresses that will never be blocked
$trustedIPs = @(
    "127.0.0.1",
    "::1"
)

# Variables
# Cache used to store IP geolocation results (performance optimization)
$IPCache = @{}
$ms = [int](New-TimeSpan -Minutes $Minutes).TotalMilliseconds

#  Internal network detection 

# Regex used to detect private/local IP ranges (not processed)
# Covers: 127.x.x.x, 10.x.x.x, 192.168.x.x, 172.16-31.x.x, IPv6 local 
$isPrivateIP = '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1)'

#endregion parameters

#region Function 

$StatusMap = @{
    "0xc0000064" = "User does not exist"
    "0xc000006a" = "Wrong password"
    "0xc000006d" = "Bad username or password"
    "0xc0000072" = "Account disabled"
    "0xc0000234" = "Account locked out"
}

function Resolve-Status {
    param($Code)
    if ($StatusMap.ContainsKey($Code)) { $StatusMap[$Code] } else { $Code }
}

function Get-IPLocation {
    param($ip)

    # Skip local / empty
    if (-not $ip -or $ip -eq '-' -or $ip -eq '::1' -or $ip -match "^(127\.|192\.168\.|10\.)") {
        return [PSCustomObject]@{
            Country = "Local"
            City    = "Local"
        }
    }

    # Cache check
    if ($IPCache.ContainsKey($ip)) {
        return $IPCache[$ip]
    }

    try {
        $url = "http://ip-api.com/json/$ip"
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 3

        if ($response.status -eq "success") {

            $location = [PSCustomObject]@{
                Country = $response.country
                City    = $response.city
            }
        }
        else {
            $location = [PSCustomObject]@{
                Country = "Unknown"
                City    = "Unknown"
            }
        }
    }
    catch {
        $location = [PSCustomObject]@{
            Country = "Error"
            City    = "Error"
        }
    }

    # Store in cache
    $IPCache[$ip] = $location

    return $location
}

#endregion Function

#region event

 $xpath = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='3']]"

# Get events
    
    $events = Get-WinEvent -FilterXPath $xpath -LogName Security

   if (-not $events) {
    Write-Host "No events found, exiting..."
    return
    }

    $result = $events | ForEach-Object {

    $Event = ([xml]$_.ToXml()).Event

    $data = @{}
    $Event.EventData.Data | ForEach-Object {
        $data[$_.Name] = $_.'#text'
    }

    $obj = [PSCustomObject]$data

    # Filter trusted IPs + invalid
    if ($obj.IpAddress -and
        $obj.IpAddress -ne '-' -and
        $obj.IpAddress -notmatch $isPrivateIP -and
        $obj.IpAddress -notin $trustedIPs) {

        $loc = Get-IPLocation $obj.IpAddress

        [PSCustomObject]@{
            UserName  = $obj.TargetUserName
            IpAddress = $obj.IpAddress
            Country  = $loc.Country
            City      = $loc.City
            Date      = ([datetime]$Event.System.TimeCreated.SystemTime).ToString("yyyy-MM-dd HH:mm:ss") #[datetime]$Event.System.TimeCreated.SystemTime
            Reason    = Resolve-Status $obj.SubStatus
            #SubStatus = $obj.SubStatus
        }
    }
}

# Check if rule exists
    $ruleName = "Block-BruteForce-logonIT"
    $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $rule) {

    Write-Host "Creating firewall rule..."

    # Create rule with dummy IP (mandatory)
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Description "Rules block IP Brute Force by LogonIT.fr" `
        -Action Block `
        -RemoteAddress "1.2.3.4" `
        -Profile Any `
        -Enabled $Mode

    $currentIPs = @()
    }
    else {
    $currentIPs = ($rule | Get-NetFirewallAddressFilter).RemoteAddress
    }

#endregion event

#region filtres

$history = $combined = $null

if (Test-Path "$Path\BF_single_attempts.csv") {

$history = Import-Csv "$Path\BF_single_attempts.csv"

# Short history
$limit = (Get-Date).AddMinutes(-$Minutes)
# Old history
$historyLimit = (Get-Date).AddHours(-$HistoryAttempt)

$history = $history | Where-Object { [datetime]$_.Date -lt $limit -and [datetime]$_.Date -ge $historyLimit} 

}

$combined = @($result) + @($history)

# Group by IP
$groups = $combined | Group-Object IpAddress | Where-Object {$_.name -notin $currentIPs }

$ipNotBlocked = $null
$ipNotBlocked = @()

# Grouping
$ipToBlock = foreach ($g in $groups) {

    $ip = $g.Name
    $events = $g.Group
    $total = $events.Count

    $block = $false

    # 1. Base condition (always active)
    if ($total -ge $threshold) {
        $block = $true
    }

    # 2. Reason filter (only if defined)
    if ($filterReason) {
        $reasonGroups = $events | Group-Object Reason

        foreach ($r in $reasonGroups) {
            if ($r.Name -in $filterReason -and $r.Count -ge $reasonThreshold) {
                $block = $true
            }
        }
    }

    # 3. Geo filter (only if defined)
    if ($trustedCountries) {

    $country = $events[0].Country

    if ($country -and $country -notin @("Unknown","Error")) {

        $isForeign = $country.Trim() -notin $trustedCountries

        if ($isForeign -and $total -ge $thresetrange) {
            $block = $true
        } 

        $isTrusted = $country.Trim() -in $trustedCountries

        # If trusted country → allow higher threshold
        if ($isTrusted -and $total -lt $trustedThreshold) {
            $block = $false
        }
    }
    }

    if ($block) {
        $ip
        #$logLine += "Block prevent $ip - Reason: $($events[0].Reason) - $($events[0].Country)/$($events[0].City) - Count: $total - Date: $($events[0].Date)`r`n"
        Write-Host Block prevent $ip et $events[0].reason $events[0].Country $events[0].City et $total a $events[0].date -ForegroundColor Cyan 
    }

    if ($total -le $threshold) {
    $ipNotBlocked += $g.Group
    }

}

if ($ipNotBlocked) {
    $ipNotBlocked | Export-Csv "$Path\BF_single_attempts.csv" -NoTypeInformation -Encoding UTF8
}
else {
    Set-Content "$Path\BF_single_attempts.csv" -Value $null
}

#endregion filtres

#region blockip

# Ensure arrays
$currentIPs = @($currentIPs)
$newIPs = @($ipToBlock)

# Merge + deduplicate
$allIPs = ($currentIPs + $newIPs) | Where-Object { $_ } | Sort-Object -Unique

# Remove dummy IP if present
$allIPs = $allIPs | Where-Object { $_ -ne "1.2.3.4" }

# Update firewall rule
Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $allIPs

# Logging
if ($newIPs) {
$date = Get-Date
#$logLine | Out-File -Append "$Path\Log_RDP_block.txt"
"[$date] Blocked IPs: $($newIPs -join ', ')" | Out-File -Append "$Path\Logs_BF_Blocked.txt"
Write-Host "Updated firewall with: $($newIPs -join ', ')"
}

#endregion blockip