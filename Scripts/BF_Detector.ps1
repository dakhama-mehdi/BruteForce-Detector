<#
.SYNOPSIS
    Detect and analyze brute force attacks from Windows authentication logs.

.DESCRIPTION
    BruteForce-Detector is a forensic PowerShell tool designed to identify
    suspicious authentication activity such as brute force attempts, password spraying,
    and abnormal login patterns.

    The tool analyzes:
    - Failed logons (Event ID 4625)
    - Successful logons (Event ID 4624)

    It correlates IP addresses, usernames, countries, and failure reasons
    to detect malicious behavior and generate actionable insights.

    Output can be used for:
    - Security investigations (forensic analysis)
    - Real-time detection
    - HTML dashboard reporting

.PARAMETER FailedLogons
    Collection of failed authentication events (Event ID 4625).

.PARAMETER SuccessfulLogons
    Collection of successful authentication events (Event ID 4624). by default (remote connection type 10 or network 7)

.PARAMETER TimeWindow
    Time range of the analysis (e.g., Last 24h, 48h, custom range).

.EXAMPLE
    Invoke-Forensic -FailedLogons $failed -SuccessfulLogons $success

.NOTES
    Author      : Mehdi Dakhama
    Company     : LogonIT.fr
    Project     : BruteForce-Detector
    Version     : 1.4
    License     : MIT
    GitHub      : https://github.com/dakhama-mehdi/BruteForce-Detector

#>

#change new update 

Add-Type -AssemblyName PresentationFramework

# Parameters 
# Default limit for HTML table entries to prevent page overload and performance issues
$maxeventhtmltable = 4000

#region XAML 
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Brute-Force Detector"
        Height="500" Width="1100"
        WindowStartupLocation="CenterScreen"
        Background="#1E1E1E">

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>  <!-- Toolbar -->
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>


        <!-- MENU -->
        <Menu Grid.Row="0" Background="#2b2b2b" Foreground="White">
            <MenuItem Header="File">
                <MenuItem Header="Export CSV" Name="btnExportcsv" Foreground="Black"/>
                <Separator/>
                <MenuItem Header="Exit" Name="menuExit" Foreground="Black"/>
            </MenuItem>
            <MenuItem Header="About" Name="menuAbout" Foreground="White" />
        </Menu>

    <StackPanel Orientation="Horizontal" Grid.Row="1">

    <Button x:Name="btnScan" Content="Scan" Width="100" Margin="0,0,10,0"/>

    <Button x:Name="btnGenHTML" Content="Rapport HTML" Width="100" Margin="0,0,10,0"/>

    <TextBlock Text="Time Range:" VerticalAlignment="Center" Foreground="White" Margin="0,0,10,0"/>

    <ComboBox x:Name="cbHours" Width="80" SelectedIndex="3" Margin="5">
        <ComboBoxItem Content="1 hour"/>
        <ComboBoxItem Content="2 hours"/>
        <ComboBoxItem Content="4 hours"/>
        <ComboBoxItem Content="10 hours"/>
        <ComboBoxItem Content="24 hours"/>
        <ComboBoxItem Content="48 hours"/>
        <ComboBoxItem Content="4 days"/>
        <ComboBoxItem Content="7 days"/>
        <ComboBoxItem Content="15 days"/>
        <ComboBoxItem Content="30 days"/>
    </ComboBox>

    <!-- SEARCH -->
    <TextBox x:Name="txtSearch"
             Width="200"
             Height="25"
             VerticalAlignment="Center"
             ToolTip="Search..."/>

    <Button x:Name="btnForensic" Content="Forensic" Width="100" Margin="20,0,20,0"/>

    <TextBlock Text="Mode" VerticalAlignment="Center" Foreground="White" Margin="0,0,0,0"/>

    <ComboBox x:Name="cbMode" Width="120" SelectedIndex="0" Margin="5">
    <ComboBoxItem Content="Bruteforce (4625)" />
    <ComboBoxItem Content="Successful Logon (4624)" />
    </ComboBox>

    <TextBlock Text="Max Events" VerticalAlignment="Center" Foreground="White" Margin="10,0,0,0"/>

    <ComboBox Name="cbMaxEvents" Width="80" SelectedIndex="0" Margin="5">
    <ComboBoxItem Content="4000" />
    <ComboBoxItem Content="8000" />
    <ComboBoxItem Content="10000" />
    <ComboBoxItem Content="20000" />
    <ComboBoxItem Content="40000" />
    <ComboBoxItem Content="Unlimited" />
   </ComboBox>

</StackPanel>

<TabControl Grid.Row="2" Margin="0,10,0,0">
  
    <!-- TAB 1 EVENTS -->
    <TabItem>
    <TabItem.Header>
        <TextBlock Text="Event" Width="80" TextAlignment="Center"/>
    </TabItem.Header>
        <DataGrid x:Name="dgResults"
                  Margin="5"
                  AutoGenerateColumns="true"
                  ColumnWidth="*"
                  HorizontalScrollBarVisibility="Auto"
                  IsReadOnly="True">


        </DataGrid>
    </TabItem>

    <!-- TAB 2 STATS -->
<TabItem>
<TabItem.Header>
        <TextBlock Text="Statistic" Width="80" TextAlignment="Center"/>
    </TabItem.Header>
    <Grid Background="#1E1E1E" Margin="10">

        <Grid.RowDefinitions>
            <RowDefinition Height="0.9*"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- CARD 1 -->
        <Border Grid.Row="0" Grid.Column="0" Margin="5" Background="#007ACC" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Total Attempts" Foreground="White" FontSize="18"/>
                <TextBlock x:Name="lblTotal" Text="0" Foreground="White" FontSize="26" FontWeight="Bold"/>
            </StackPanel>
        </Border>

        <!-- CARD 2 -->
        <Border Grid.Row="0" Grid.Column="1" Margin="5" Background="#E74C3C" CornerRadius="8" Padding="6">
           <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">

        <TextBlock x:Name="lblUniqueIP" Text="Attacker IPs: 0" Foreground="White" FontSize="18"
                   FontWeight="Bold" HorizontalAlignment="Center"/>
        <TextBlock x:Name="lblBlockedIP" Text="Blocked: 0" Foreground="White" FontSize="18"
                   FontWeight="Bold" HorizontalAlignment="Center"/>
        </StackPanel>
        </Border>

         <!-- CARD 3 -->
        <Border Grid.Row="0" Grid.Column="2" Margin="5" Background="#1ABC9C" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top Reason"  FontWeight="Bold" Foreground="White" FontSize="18"/>
                <StackPanel x:Name="spTopReason" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>

        <!-- CARD 4 -->
        <Border Grid.Row="1" Grid.Column="0" Margin="5" Background="#8E44AD" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top Country" FontWeight="Bold" Foreground="White" FontSize="18"/>
                <StackPanel x:Name="spTopCountry" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>

        <!-- CARD 5 -->
        <Border Grid.Row="1" Grid.Column="1" Margin="5" Background="#34495E" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top IP" FontWeight="Bold" Foreground="White" FontSize="18"/>
                <StackPanel x:Name="spTopIP" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>

        <!-- CARD 6 -->
        <Border Grid.Row="1" Grid.Column="2" Margin="5" Background="#E67E22" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top User" FontWeight="Bold" Foreground="White" FontSize="18"/>
                <StackPanel x:Name="spTopUser" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>



    </Grid>
</TabItem>
</TabControl>

       <TextBlock x:Name="lblSummary"
           Grid.Row="3"
           Text="Ready"
           Foreground="White"
           HorizontalAlignment="Left"/>

       <TextBlock Grid.Row="3"
           Text=" v1.4 | Dakhama Mehdi | logonIT.fr"
           Foreground="White"
           FontSize="12"
           HorizontalAlignment="Right"
           Margin="0,0,10,0"/>

    </Grid>
</Window>
"@

# LOAD XAML
$reader = New-Object System.IO.StringReader($xaml)
$xmlReader = [System.Xml.XmlReader]::Create($reader)
$Window = [Windows.Markup.XamlReader]::Load($xmlReader)

# FIND CONTROLS 
$btnScan   = $Window.FindName("btnScan")
$btnGenHTML = $Window.FindName("btnGenHTML")
$btnExportCSV = $Window.FindName("btnExportcsv")
$btnmenuExit = $Window.FindName("menuExit")
$cbHours   = $Window.FindName("cbHours")
$cbMaxEvents   = $Window.FindName("cbMaxEvents")
$menuabout = $Window.FindName("menuAbout")
$cbMode   = $Window.FindName("cbMode")
$dgResults = $Window.FindName("dgResults")
$lblSummary= $Window.FindName("lblSummary")
$txtSearch = $Window.FindName("txtSearch")
$btnForensic = $Window.FindName("btnForensic")
$lblTotal      = $Window.FindName("lblTotal")
$spTopIP       = $Window.FindName("spTopIP")
$spTopUser     = $Window.FindName("spTopUser")
$spTopCountry  = $Window.FindName("spTopCountry")
$spTopReason   = $Window.FindName("spTopReason")
$lblUniqueIP  = $Window.FindName("lblUniqueIP")
$lblBlockedIP = $Window.FindName("lblBlockedIP")

#endregion XAML

#region function

# Error code mapping
$StatusMap = @{
    "0xc0000064" = "User does not exist"
    "0xc000006a" = "Wrong password"
    "0xc000006d" = "Bad username or password"
    "0xc000006e" = "Account restriction"
    "0xc000006f" = "Invalid logon hours"
    "0xc0000070" = "Invalid workstation"
    "0xc0000071" = "Password expired"
    "0xc0000072" = "Account disabled"
    "0xc0000193" = "Account expired"
    "0xc0000234" = "Account locked out"
}

$script:fullData = $null 

# Resolve function
function Resolve-Status {
    param($value)

    $uint = [System.BitConverter]::ToUInt32(
        [System.BitConverter]::GetBytes([int32]$value), 0
    )

    $code = "0x{0:X8}" -f $uint

    if ($StatusMap.ContainsKey($code)) {
        [PSCustomObject]@{
            Code    = $code
            Message = $StatusMap[$code]
        }
    }
    else {
        [PSCustomObject]@{
            Code    = $code
            Message = "Unknown"
        }
    }
}
function Get-IPLocation {
    param($ip)

    if (-not $script:IPCache) {
        $script:IPCache = @{}
    }

    # Skip local / empty
    if (-not $ip -or $ip -eq '-' -or $ip -eq '::1' -or $ip -match "^(127\.|192\.168\.|10\.)") {
        return [PSCustomObject]@{
            Country = "Local"
            City    = "Local"
        }
    }

    # Cache check
    if ($script:IPCache.ContainsKey($ip)) {
        return $script:IPCache[$ip]
    }

    try {
        $url = "http://ipwho.is/$ip" #"http://ip-api.com/json/$ip"
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 3

        if ($response.success -eq "True") {
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
         # Fallback API
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
        # Last fallback
        $location = [PSCustomObject]@{
            Country = "Error"
            City    = "Error"
        }
    }
    }

    $script:IPCache[$ip] = $location

    return $location
}
function Get-RDPFailedEvents {
    param(
        [int]$Hours = 1,
        [int]$MaxEvents = 4000
    )

    $ms = (New-TimeSpan -Hours $hours).TotalMilliseconds

    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
        "Security",
        [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='3'or Data[@Name='LogonType']='10']]"

    )

    $query.ReverseDirection = $true

    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

    $count = 0

    $result =  while ($event = $reader.ReadEvent()) {

    $count++

    if ($count -ge $MaxEvents) { break }

    $props = $event.Properties

    $ip = $props[19].Value
    if (-not $ip -or $ip -eq "-") { continue }
    
    $loc = Get-IPLocation $ip.Trim()

    $status = Resolve-Status $props[9].Value

    $protocole = $props[12].Value

    [PSCustomObject]@{
        UserName    = $props[5].Value
        IpAddress   = $ip
        Date        = [datetime]$event.TimeCreated
        Reason      = $status.Message
        SubStatus   = $status.Code
        Country     = $loc.Country
        City        = $loc.City
        ProcessName = $props[11].Value
        Protocol    = $protocole
        Source      = $props[6].Value
        #Status     = $obj.Status
    }   
}

    return $result
}
function Get-RDPSuccessEvents {
    param(
        [int]$Hours = 1,
        [int]$MaxEvents = 2000
    )

    $ms = (New-TimeSpan -Hours $Hours).TotalMilliseconds

    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
        "Security",
        [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[(Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='7')]]"
    )

    $query.ReverseDirection = $true

    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

    $count = 0

    $result = while ($event = $reader.ReadEvent()) {

        $count++
        if ($MaxEvents -gt 0 -and $count -ge $MaxEvents) { break }

        $props = $event.Properties
        if ($props.Count -lt 19) { continue }

        $ip = $props[18].Value
        if (-not $ip -or $ip -eq "-") { continue }

        $loc = Get-IPLocation $ip.Trim()  

        $protocol = $props[14].Value
        
        if (!$protocol -or ($protocol -eq "-")) {
        $protocol = $props[10].Value
         }      

        [PSCustomObject]@{
            UserName    = $props[5].Value
            IpAddress   = $ip
            Date        = [datetime]$event.TimeCreated
            Country     = $loc.Country
            City        = $loc.City
            Source      = $props[11].Value # Computer name call
            Type        = $props[8].Value
            Protocol    = $protocol # Protocol
            ProcessName = ($props[17].Value -split "\\")[-1]
            Domain      = $props[6].Value
        }
    }

    return $result
}
function Update-Stats {

    param(
        [Parameter(Mandatory)]
        $Data
    )

    # TOTAL
    $lblTotal.Text = @($Data).Count

    # UNIQUE IP
    $uniqueIPs = $Data.IpAddress | Where-Object { $_ } | Sort-Object -Unique
    $lblUniqueIP.Text = "Attacker IPs: $($uniqueIPs.Count)"

    # RESET UI
    $spTopIP.Children.Clear()
    $spTopUser.Children.Clear()
    $spTopCountry.Children.Clear()
    $spTopReason.Children.Clear()

    # TOP IP
    $Data |
        Group-Object IpAddress |
        Sort-Object Count -Descending |
        Select-Object -First 5 |
        ForEach-Object {
            $txt = New-Object System.Windows.Controls.TextBlock
            $txt.Text = "$($_.Name) ($($_.Count))"
            $txt.Foreground = "White"
            #$txt.HorizontalAlignment = "Center"
            $spTopIP.Children.Add($txt)
        }

    # TOP USER
    $Data |
        Group-Object Username |
        Sort-Object Count -Descending |
        Select-Object -First 5 |
        ForEach-Object {
            $txt = New-Object System.Windows.Controls.TextBlock
            $txt.Text = "$($_.Name) ($($_.Count))"
            $txt.Foreground = "White"
            #$txt.HorizontalAlignment = "Center"
            $spTopUser.Children.Add($txt)
        }

    # TOP COUNTRY
    $Data |
        Group-Object Country |
        Sort-Object Count -Descending |
        Select-Object -First 5 |
        ForEach-Object {
            $txt = New-Object System.Windows.Controls.TextBlock
            $txt.Text = "$($_.Name) ($($_.Count))"
            $txt.Foreground = "White"
            $txt.HorizontalAlignment = "Center"
            $spTopCountry.Children.Add($txt)
        }

    # TOP REASON
    $Data |
        Group-Object Reason |
        Sort-Object Count -Descending |
        Select-Object -First 3 |
        ForEach-Object {
            $txt = New-Object System.Windows.Controls.TextBlock
            $txt.Text = "$($_.Name) ($($_.Count))"
            $txt.Foreground = "white"
            $txt.HorizontalAlignment = "Center"
            $spTopReason.Children.Add($txt)
        }

    # FIREWALL CHECK
    $fwRules = Get-NetFirewallRule -DisplayName "Block-BruteForce-logonIT*" -ErrorAction SilentlyContinue | Get-NetFirewallAddressFilter

    if ($fwRules) {

    $blockedIPs = $fwRules.RemoteAddress | Where-Object { $_ -and $_ -ne "Any" } | Sort-Object -Unique

    $blockedDetectedIPs = $uniqueIPs | Where-Object { $_ -in $blockedIPs }

    $lblBlockedIP.Text = "Blocked: $($blockedDetectedIPs.Count)"
    } else { $lblBlockedIP.Text = "Blocked: 0)" }
}
function Resize-Gridview {

    foreach ($col in $dgResults.Columns) {
    if ($col.SortMemberPath -eq "Date") {
        $col.Width = 150
    } 
    if ($col.SortMemberPath -eq "Type") {
        $col.Width = 60
    } 
    if ($col.SortMemberPath -eq "Reason") {
        $col.Width = 120
    } 
    }
}
function comment {
    param ( [String]$Comment
    )

    $lblSummary.Text = $Comment    
    # Refresh
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke(
    [action]{}, 
    [System.Windows.Threading.DispatcherPriority]::Background
    )
}
function Get-InterestingListeningPorts {

    param(
        [string[]]$ExcludedProcesses = @("lsass","services","spoolsv","wininit"),
        [int]$MaxPort = 49152
    )

    # Mapping ports → service
    $portMap = @{
        139  = "NetBIOS"
        445  = "SMB"
        135  = "RPC"
        3389 = "RDP"
        5985 = "WinRM"
        53   = "DNS"
        443  = "HTTPS"
        8080 = "HTTP"
        5060 = "SIP"
        2179 = "Hyper-V"
    }

    $results = @()

    foreach ($conn in Get-NetTCPConnection -State Listen) {

        # Filtre IP
        if (
            $conn.LocalAddress -notmatch '^\d+\.\d+\.\d+\.\d+$' -or
            $conn.LocalAddress -match '^(127\.|192\.168\.|10\.|172\.16\.|169\.254\.)'
        ) { continue }

        # Filtre port
        if ($conn.LocalPort -ge $MaxPort) { continue }

        # Process
        try {
            $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction Stop).Name
        } catch {
            $procName = "Unknown"
        }

        # Filtre process
        if ($procName -in $ExcludedProcesses -or $procName -like "Microsoft*") { continue }

        # Mapping service
        $portNumber = [int]$conn.LocalPort
        $service = if ($portMap.ContainsKey($portNumber)) {
            $portMap[$portNumber]
        } else {
            "Unknown"
        }

        # Résultat final
        $results += [PSCustomObject]@{
            Address = $conn.LocalAddress
            Port    = $conn.LocalPort
            Process = $procName
            Service = $service
            PID     = $conn.OwningProcess
        }
    }

    return $results
}
function Invoke-Forensic {
     param(
        $failedevent,  # Events failed logon (4625)
        $successevent  # Events successful logon (4624)
    )


$failGrouped    = $failedevent | Group-Object IpAddress | Sort-Object Count -Descending
$successGrouped = $successevent | Group-Object IpAddress | Sort-Object Count -Descending

$successMap = @{}
$successGrouped | ForEach-Object {
    $successMap[$_.Name] = $_.Count
}

$successSet = @{}
$successGrouped.Name | ForEach-Object {
    $successSet[$_] = $true
}

# Check Failed IP success to logon
$forensic = $failGrouped | Where-Object { $successSet.ContainsKey($_.Name) }

$result = foreach ($f in $forensic) {

    $ip = $f.Name
    $failCount = $f.Count

    $reason = ($f.Group | Group-Object Reason | ForEach-Object {
    "$($_.Name) ($($_.Count))"}) -join "<br>"
    $protocol = ($f.Group | Group-Object protocol | ForEach-Object {
    "$($_.Name) ($($_.Count))"}) -join "<br>"
    $Username = ($f.Group | Group-Object Username | ForEach-Object {
    "$($_.Name) ($($_.Count))"}) -join "<br>"
    $Source = ($f.Group | Group-Object source | ForEach-Object {
    "$($_.Name) ($($_.Count))"}) -join "<br>"

    # Succes with Same IP
    $successCount = $successMap[$ip]

    $dates = $f.Group | Select-Object -ExpandProperty Date

    $measure = $dates | Measure-Object -Minimum -Maximum
    $first = $measure.Minimum
    $last  = $measure.Maximum

    $times = $f.Group | ForEach-Object { $_.Date.TimeOfDay }

    $measureTime = $times | Measure-Object -Minimum -Maximum
    $minTime = $measureTime.Minimum
    $maxTime = $measureTime.Maximum

    $range = "{0:hh\:mm} → {1:hh\:mm}" -f $minTime, $maxTime

    [PSCustomObject]@{
        IP       = $ip
        Username = $Username
        Success  = $successCount
        Failures = $failCount
        Reason   = $reason
        Protocol = $protocol
        Source   = $Source
        Range    = $range
        'First logon' = $first
        'Last logon' = $last
    }
}

$successusername = $successevent | Group-Object Username | Sort-Object Count -Descending

$userView = $successusername | ForEach-Object {

    $user = $_.Name
    $events = $_.Group

    $uniqueIPs     = $events.IpAddress | Select-Object -Unique
    $uniqueCountry = $events.Country   | Select-Object -Unique
    $uniqueCity    = $events.City      | Select-Object -Unique

    [PSCustomObject]@{
        User        = $user
        Connections = $events.Count
        IPCount     = $uniqueIPs.Count
        Country     = $uniqueCountry
        City        = $uniqueCity -join "<br>"
        IPs         = $uniqueIPs -join "<br>"
    }
}

$groupProcess  = $successevent | Group-Object ProcessName | Where-Object { $_.name -ne "-" }
$groupProtocol = $successevent | Group-Object Protocol

$protocolStats = $groupProtocol | Where-Object {
    $_.Name -notin @("NTLM V2","-","Negotiate")
} | Select-Object Count, Name

# Detection weak protocol
if ($protocolStats.Count -eq 0) {
    $protocolStatus = "<span style='color:lightgreen; font-weight:bold;'>✔ No weak protocol</span>"
    $protocolList = ($groupProtocol | ForEach-Object {
        "$($_.Name) ($($_.Count))"
    }) -join "<br>"
}
else {
    $protocolStatus = "<span style='color:orange; font-weight:bold;'> Weak protocol detected</span>"

    $protocolList = ($groupProtocol | ForEach-Object {
        "$($_.Name) ($($_.Count))"
    }) -join "<br>"
}

# Detected suspicious logon and defaut user account stat
$isAnonymous = $successusername.Name -contains "Anonymous"

$anonymousStatus = if ($isAnonymous) {
    "<span style='color:red; font-weight:bold;'>Detected</span>"
} 
else {
    "<span style='color:lightgreen; font-weight:bold;'>✔ Not detected</span>"
}

$users = Get-LocalUser

$isDefaultEnabled = foreach ($u in $users) {
    $rid = $u.SID.Value.Split("-")[-1]

    if ($rid -in "500","501","503","504" ) {
        [PSCustomObject]@{
            Name    = $u.Name
            Enabled = $u.Enabled
            Type    = switch ($rid) {
                "500" { "Administrator" }
                "501" { "Guest" }
                "503" { "DefaultAccount" }
                "504" { "WDAGUtility" }
            }
        }
    }
}

$enabledAccounts = $isDefaultEnabled | Where-Object { $_.Enabled }

$accountsStatus = if ($enabledAccounts.Count -gt 0) {

    # First line
    $status = "<br><br><span style='color:white;'>Default Account :</span> <span style='color:orange;'>Enabled<br></span>"

    # Sample line
    $lines = $enabledAccounts | ForEach-Object {

    if ($_.Type -eq "Guest") {
        "<span style='color:red; font-size:16px; font-weight:normal;'>$($_.Name)</span>"
    }
    else {
        "<span style='font-size:16px; font-weight:normal;'>$($_.Name)</span>"
    }
    }

    $names = $lines -join "<br>"

    $status + $names
}
else {
    "<br><br><span style='color:white;'>Default Account :</span> <span style='color:lightgreen;'>✔ Not Enabled</span>"
}

$finalStatus = $anonymousStatus + $accountsStatus

$processStats = $successevent |
    Group-Object ProcessName |
    Where-Object { $_.Name -notin @("svchost.exe","lsass.exe","winlogon.exe","-") }

if ($processStats.Count -eq 0) {
    $processStatus = "<span style='color:lightgreen; font-weight:bold;'>✔ Clean</span>"
    $processList   = ($groupProcess | ForEach-Object {
        "$($_.Name) ($($_.Count))"
    }) -join "<br>"
}
else {
    $processStatus = "<span style='color:orange; font-weight:bold;'>⚠ Suspicious</span>"

    $processList = ($processStats | ForEach-Object {
        "$($_.Name) ($($_.Count))"
    }) -join "<br>"
}

$interestingPorts = Get-InterestingListeningPorts

$portlist = ($interestingPorts | ForEach-Object {
    "{0}:{1} - {2} ({3} - PID {4})" -f $_.Address, $_.Port, $_.Process, $_.Service, $_.PID
}) -join "<br>"

$openPortsStatus = if ($portlist) {
    "<span style='color:red; font-weight:bold;'>Detected</span>"
} else {
    "<span style='color:lightgreen; font-weight:bold;'>✔ Not detected</span>"
}

# Check remote config
$rdpReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | select fDenyTSConnections
$tsPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

$rdpconf = (Get-ItemProperty -Path "$tsPath\WinStations\RDP-Tcp") | select Portnumber,UserAuthentication,SecurityLayer
$rdpPort = $rdpconf.PortNumber
$rdpEnabled = ($rdpReg.fDenyTSConnections -eq 0)
$nla = $rdpconf.UserAuthentication
$nlaEnabled = ($nla -eq 1)
$securityLayer = $rdpconf.SecurityLayer

$lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | select restrictanonymous,restrictanonymoussam,EveryoneIncludesAnonymous

$restrictAnonymous       = $lsa.restrictanonymous
$restrictAnonymousSAM    = $lsa.restrictanonymoussam
$everyoneIncludesAnon    = $lsa.EveryoneIncludesAnonymous

$fwProfiles = Get-NetFirewallProfile
$firewallEnabled = -not ($fwProfiles | Where-Object { $_.Enabled -eq $false })

$remoteInfo = [PSCustomObject]@{
    RDP          = if ($rdpEnabled) { "Enabled" } else { "Disabled" }
    NLA          = if ($nlaEnabled) { "Enabled" } else { "Disabled" }
    TLS_CredSSP  = if ($securityLayer -eq 2) { "Enabled" } else { "Disabled" }
    RDP_Port     = $rdpPort

    Firewall     = if ($firewallEnabled) { "Enabled" } else { "Disabled" }

    Anonymous    = switch ($restrictAnonymous) {
        0 { "Allowed" }
        1 { "Restricted" }
        2 { "Secured" }
        default { "Unknown" }
    }
    AnonymousSAM = if ($restrictAnonymousSAM -eq 1) { "Protected" } else { "Weak" }
    EveryoneAnon = if ($everyoneIncludesAnon -eq 1) { "Enabled" } else { "Disabled" }
}
$remoteInfoHtml = ($remoteInfo.PSObject.Properties | ForEach-Object {

    $name  = $_.Name
    $value = $_.Value

    if (
        ($value -eq "Enabled") -or
        ($value -eq "Protected") -or
        ($name -eq "EveryoneAnon" -and $value -eq "Disabled")
    ) {
        $value = "<span style='color:lightgreen;'>$value</span>"
    }
    elseif (($value -eq "Disabled") -or ($value -eq "3389") ) {
        $value = "<span style='color:red;'>$value</span>"
    }

    "$name : $value"

}) -join "<br>"

$ipRows = $result | ForEach-Object {
    "<tr>
        <td>$($_.IP)</td>
        <td>$($_.Username)</td>
        <td>$($_.Failures)</td>
        <td>$($_.Success)</td>
        <td>$($_.Reason)</td>
        <td>$($_.Protocol)</td>
        <td>$($_.Source)</td>
        <td>$($_.Range)</td>
        <td>$($_.'First Logon')</td>
        <td>$($_.'Last Logon')</td>
    </tr>"
}

$userRows = $userView | ForEach-Object {
    "<tr>
        <td>$($_.User)</td>
        <td>$($_.Connections)</td>
        <td>$($_.IPCount)</td>
        <td>$($_.Country)</td>
        <td>$($_.City)</td>
        <td>$($_.IPs)</td>
    </tr>"
}

# Caclulate stats
$totalFail    = @($failedevent).Count
$totalSuccess = @($successevent).Count
$total        = $totalFail + $totalSuccess

$successRate = if ($totalFail -gt 0) {
    [math]::Round(
        ($totalSuccess * 100.0) / $total,
        0,
        [System.MidpointRounding]::AwayFromZero
    )
}
elseif ($totalSuccess -gt 0) {
    100
}
else {
    0
}

    $risk = 100
    if ($successRate -le 10) { $risk -= 60 }
    elseif ($successRate -le 20) { $risk -= 40 }
    elseif ($successRate -le 30) { $risk -= 20 }

    if ($enabledAccounts.type -eq "Guest") {
    $risk -= 30
    }

    if ($protocolStatus -notmatch "No weak") {
    $risk -= 20
    }

    if ($processStatus -match "Suspicious") {
    $risk -= 15
    }

    # RDP check score 
    if ($rdpEnabled) {    
    if (-not $nlaEnabled) { $risk -= 15 }
    if ($securityLayer -ne 2) { $risk -= 10 }
    if ($rdpPort -eq "3389") { $risk -= 20 }
    if (-not $firewallEnabled) { $risk -= 15 }
}

    if ($risk -lt 0) { $risk = 0 }
    if ($risk -gt 100) { $risk = 100 }


    $level = if ($risk -ge 80) {
    "Low"
    }
    elseif ($risk -ge 50) {
    "Medium"
    }
    elseif ($risk -ge 30) {
    "High"
    }
    else {
    "Critical"
    }

 $date = (get-date)
 $server = ($env:COMPUTERNAME) 
 $selected = $cbHours.SelectedItem.Content.ToString()
 $range = "Range: $selected"



$html = @"
<html>
<head>
<style>
body { font-family: Arial; background:#1E1E1E; color:white; margin:20px; }

table { border-collapse: collapse; width:100%; margin-bottom:20px; }
th, td {border-bottom:1px solid #3a3a3a; border-right:1px solid #555; padding:8px; text-align:left;}
th { background:#1f4e79; position:sticky; top:0; }
tr:nth-child(even) { background:#2b2b2b; }

.header {
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:10px;
}

.header-right {
    font-size:12px;
    color:#ccc;
}
.cards {
    display:flex;
    gap:15px;
    margin-bottom:20px;
}

.card {
    background:#2b2b2b;
    padding:15px;
    border-radius:6px;
    flex:1;
    text-align:center;
    font-size:16px;
}

.findings {
    background:#2b2b2b;
    padding:15px;
    border-radius:6px;
    margin-bottom:20px;
}

.finding {
    margin-bottom:10px;
}

/* FINDINGS */

.findings-row {display: flex;gap: 15px; margin-bottom: 20px;
}

.finding-box {flex: 1;background: #2b2b2b;padding: 10px;
    border-radius: 6px;border: 1px solid #444;font-size: 13px;
}

.big-box {flex: 1;height: 100%;
}

h2 {border-bottom:2px solid #444;padding-bottom:5px;
}
</style>
</head>
<body>

<div class="header">
    <h1 style="margin:0;">BF-Detector : Forensic Report</h1>
    <div class="header-right">
        $($server) - $($date) - $range
    </div>
</div>

<!-- CARDS -->
<div class="cards">

<div class="card">
<b>Total Attempts</b><br>
$totalFail
</div>

<div class="card">
<b>Total Success</b><br>
$totalSuccess
</div>

<div class="card">
<b>Success Rate</b><br>
   $successRate %
</div>

<div class="card">
<b>Risk Level : $level</b><br>
Score : $risk %
</div>

</div>

<div class="findings-row">

<! PROTOCOL >
<div class="finding-box" style="font-size:16px;">

<b>Protocols : $protocolStatus</b>

<br><br>

$protocolList

</div>

<! Defaut Account >
<div class="finding-box" style="font-size:16px;">

<b>Suspicious Login : $finalStatus</b>

</div>

<! PROCESS >
<div class="finding-box" style="font-size:16px;">

<b>Processes Logon : $processStatus</b>

<br><br>
$processList
</div>

<! Open Ports >
<div class="finding-box" style="font-size:16px;">
<b>Open Ports : $openPortsStatus</b>
<br><br>
$portlist
</div>

<div class="finding-box" style="font-size:16px;">

$remoteInfoHtml

</div>

</div>

</div>

</div>

<!-- TABLE IP -->
<h2>IPs that Failed and Successfully Logged In</h2>
<table>
<tr>
<th>IP</th>
<th>User</th>
<th>Failures</th>
<th>Success</th>
<th>Reason</th>
<th>Protocol</th>
<th>Source</th>
<th>Time Range</th>
<th>First Logon</th>
<th>Last Logon</th>
</tr>
$($ipRows -join "`n")
</table>

<!-- TABLE USER -->
<h2>User Logon Analysis</h2>
<table>
<tr>
<th>User</th>
<th>Connections</th>
<th>IP Count</th>
<th>Country</th>
<th>City</th>
<th>IPs</th>
</tr>
$($userRows -join "`n")
</table>

</body>
</html>
"@
return $html

}

$txtSearch.Add_TextChanged({

    if (-not $script:fullData) { return }

    $search = $txtSearch.Text.ToLower()

    if (-not $search) {
        $dgResults.ItemsSource = @($script:fullData)
        Resize-Gridview
        return
    }

    $pattern = [regex]::Escape($search)

    $filtered = $script:fullData | Where-Object {
    "$($_.UserName) $($_.IpAddress) $($_.Country) $($_.City) $($_.Reason) $($_.ProcessName) $($_.Protocol)" -match $pattern
    }
    
    $dgResults.ItemsSource = @($filtered)

    Resize-Gridview         
})

#endregion function

#  EVENTS 
$btnScan.Add_Click({
    
    $startTime = Get-Date
    $dgResults.ItemsSource = $null

    comment -Comment "Scan in progress..."

    $selected = $cbHours.SelectedItem.Content.ToString()
    $value = [int]($selected -replace "[^0-9]")

    if ($selected -like "*day*") {
        $hours = $value * 24
    } 
    else {
        $hours = $value
    }

    $selectedEvent = $cbMaxEvents.SelectedItem.Content

    if ($selectedEvent -eq "Unlimited") {
    $MaxEvents = 100000
    }
    else {
    $MaxEvents = [int]$selectedEvent
    }

    $mode = $cbMode.SelectedItem.Content

    switch ($mode) {

    "Bruteforce (4625)" {
        $data = Get-RDPFailedEvents -Hours $Hours -MaxEvents $MaxEvents
    }

    "Successful Logon (4624)" {
        $data = Get-RDPSuccessEvents -Hours $Hours -MaxEvents $MaxEvents
    }
    }

    if ($data) {
    $script:fullData = $data
    $dgResults.ItemsSource = @($script:fullData)    
    Resize-Gridview       

    comment -Comment "Update stats..." 
    Update-Stats -Data $data

    } 
    else { 
    $script:fullData = $null }

    $elapsed = (Get-Date) - $startTime
    $elapsedText = "{0:mm\:ss}" -f $elapsed
    $lblSummary.Text = "Scan done - $($data.Count) events ($hours h) - Time: $elapsedText s"

})

$btnExportcsv.Add_Click({

if ($script:fullData) {
Add-Type -AssemblyName System.Windows.Forms

$dialog = New-Object System.Windows.Forms.SaveFileDialog
$dialog.Filter = "CSV files (*.csv)|*.csv"
$dialog.FileName = "Brutforcelogs_$(Get-Date -Format 'MMdd_HHmmss').csv"

if ($dialog.ShowDialog() -eq "OK") {
    $script:fullData | Export-Csv $dialog.FileName -NoTypeInformation -Encoding UTF8
    $lblSummary.Text = "Export done: $($dialog.FileName)"
}
} 
else {
    $lblSummary.Text = "Not enough data"
}

})

$btnGenHTML.Add_Click({
   
    if (-not $script:fullData) {
    $lblSummary.Text = "Not enough data"
    return
    }

    # Generate HTML
    
    #region Mapslocation
    # 1. Get IP to location Maps 
    $uniqueIPs = $script:fullData.IpAddress |
    Where-Object { $_ } |
    Sort-Object -Unique |
    Select-Object -First 1000

    # 2. Resolve GeoIP
    comment -Comment "Check IP for Maps..."   
    $geoPoints = foreach ($ip in $uniqueIPs) {

    try {
        $res = Invoke-RestMethod "http://ipwho.is/$ip" -Method Get -TimeoutSec 3 -ErrorAction Stop # "http://ip-api.com/json/$ip" -ErrorAction Stop

        if ($res.success -eq "True") {
            [PSCustomObject]@{
                IP   = $ip
                Lat  = $res.latitude
                Lon  = $res.longitude
                City = $res.city
                Country = $res.country
            }
        }
    }
    catch {
        try {
        $url = "http://ip-api.com/json/$ip"
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 3

        if ($response.status -eq "success") {
            $location = [PSCustomObject]@{
                IP   = $ip
                Lat  = $response.lat
                Lon  = $response.lon
                Country = $response.country
                City    = $response.city
            }
        }
        }
        catch {
        Write-Host "Error IP: $ip"
    }
    }
}

    # 3. Get JS points
    $markers = ""

    foreach ($g in $geoPoints) {

    $markers += @"
L.circle([$($g.Lat), $($g.Lon)], {color:'red', radius:50000}).addTo(map)
.bindPopup("$($g.City), $($g.Country)<br>$($g.IP)");
"@
}
#endregion Mapslocation
    
    $tableRows = ""
    comment -Comment "Build Data..."    

    # Limit Html table event to 4000 events for better fluidity
    $currentdata = $script:fulldata | select -First $maxeventhtmltable

    foreach ($row in $currentdata ) {
    $tableRows += "<tr>
        <td>$($row.Date)</td>
        <td>$($row.UserName)</td>
        <td>$($row.IpAddress)</td>
        <td>$($row.Country)</td>
        <td>$($row.City)</td>
        <td>$($row.Reason)</td>
        <td>$($row.Protocol)</td>
    </tr>"
    }

    # Build HTML
   comment -Comment "Build Stats..."

    # Data by days
    $daily = $script:fulldata |
    Group-Object { (Get-Date $_.Date).ToString("dd/MM") } |
    Sort-Object Name


    $total = $lblTotal.Text

    $topIP = ($spTopIP.Children | ForEach-Object { $_.Text } | select -First 4 )  -join "<br>"

    $topUser = ($spTopUser.Children | ForEach-Object { $_.Text } | select -First 4 )  -join "<br>"

    $topCountry = ($spTopCountry.Children | ForEach-Object { $_.Text } | select -First 4 )  -join "<br>"

    $topReason = ($spTopReason.Children | ForEach-Object { $_.Text } | select -First 4 )  -join "<br>"

    $server = $env:COMPUTERNAME
    $date = Get-Date -Format "dd/MM/yyyy HH:mm"
    $range = $cbHours.SelectedItem.Content.ToString()

    $titleDash = "Brut Force : Dashboard"
    $mode = $cbMode.SelectedItem.Content

    if ($Mode -like "*4624*") {
    $titleDash = "Successfull Network Login : Dashboard" } 


    $dailyRows = ""
    foreach ($d in $daily) {
    $dailyRows += "<tr>
        <td>$($d.Name)</td>
        <td>$($d.Count)</td>
    </tr>"
}

    comment -Comment "Done HTML"

# HTML 
$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>Brut-Force-Detected Dashboard</title>

<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<style>
body {font-family: Segoe UI; margin: 40px 20px 20px 20px; background: #1E1E1E; color: white;
}

/* HEADER */
.header {display:flex; justify-content:space-between; border-bottom:1px solid #444; padding-bottom:8px;
    margin-bottom:30px;
}

/* CARDS */
.cards { display:flex;gap:15px; margin-top:20px;  
    margin-bottom:20px;
}

.card { flex:1; background:#2b2b2b; padding:25px; border-radius:10px;
    text-align:center;
}

.cards .card:first-child { flex:0.6; font-weight:700;
}

.card b { font-size:14px; line-height:1.4;
}

.section { display:flex; gap:20px; height:450px;
}

.table-box { width:60%; height:100%; overflow:auto;
}

.table-header { position: sticky; top: 0; background: #1E1E1E; z-index: 20; padding-bottom: 10px;
    display: flex; justify-content: space-between; align-items: center;
}

.table-header input:focus {
    outline: none; box-shadow: none;
}

.right-box { width:40%; display:flex; flex-direction:column; gap:10px;
}

.daily-box { background:#2b2b2b; padding:10px; border-radius:10px;
    max-height:120px; overflow:auto;      
}

.map-box {
    flex:1;
}

#map { height:100%;  width:100%;
    border-radius:10px; border:2px solid #333;
}

/* TABLE STYLE */
table {  width:100%; border-collapse:collapse;
    font-size:12px;  background:#2b2b2b;
}

th, td { padding:6px; border:1px solid #444;
    text-align:left;
}

th { background:#333; }
tr:hover { background:#2a2a2a; }
</style>

</head>
<body>

<!-- HEADER -->
<div class="header">
    <div>
        <h2 style="margin:0;">$titleDash</h2>
    </div>
    <div style="font-size:12px;color:white;">
      $server : $date - Range : $range
            
    </div>
</div>

<!-- CARDS -->
<div class="cards">
<div class="card">Total Attemps<br><b>$total</b></div>
<div class="card">Top IP<br><b>$topIP</b></div>
<div class="card">Top Username<br><b>$topUser</b></div>
<div class="card">Top Country<br><b>$topCountry</b></div>
<div class="card">Top Reason<br><b>$topReason</b></div>
</div>

<!-- SECTION -->
<div class="section">

    <!-- TABLE LEFT -->
<div class="table-box">

    <div class="table-header">
    <h3 style="margin:0;">Events max $maxeventhtmltable entry</h3>   
     <input type="text" id="searchMain" onkeyup="filterTable('searchMain','tableMain')" placeholder="Search..."
     style="padding:6px 10px; border:1px solid #444; border-radius:6px; background:#1E1E1E; color:white;">
</div>

<table id="tableMain">
    <thead><tr><th>Date</th> <th>User</th><th>IP</th><th>Country</th><th>City</th><th>Reason</th> <th>Protocol</th></tr>
    </thead>
            <tbody>
                $tableRows
            </tbody>
        </table>
    </div>

    <!-- RIGHT PANEL -->
    <div class="right-box">
        <!-- DAILY STATS -->
        <div class="daily-box">
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Attempts</th>
                    </tr>
                </thead>
                <tbody>
                    $dailyRows
                </tbody>
            </table>
        </div>

        <!-- MAP -->
        <div class="map-box">
            <div id="map"></div>
        </div>

    </div>

</div>

<script>

// MAP
var map = L.map('map', {
    minZoom: 2,
    maxZoom: 6
}).setView([40, 60], 2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    noWrap: true
}).addTo(map);

$markers

function filterTable(inputId, tableId) {
    var input = document.getElementById(inputId);
    var filter = input.value.toUpperCase();
    var table = document.getElementById(tableId);
    var tr = table.getElementsByTagName("tr");

    for (var i = 1; i < tr.length; i++) {
        var row = tr[i];
        var text = row.textContent || row.innerText;
        row.style.display = text.toUpperCase().indexOf(filter) > -1 ? "" : "none";
    }
}

</script>

<hr style="margin-top:30px; border-top:1px solid #444;" />

<div style="font-size:12px; color:#888; text-align:center; padding-top:10px;">
    Developed by <strong>Dakhama Mehdi</strong> – logonIT.fr <br>
    Powered by community knowledge <a href="https://www.it-connect.fr" target="_blank" style="color:#4FC3F7;">IT-Connect</a><br>
    © 2026
</div>
</body>
</html>
"@

    # 5. Export + Open
    $path = "$env:TEMP\attack_map.html"
    $html | Out-File -Encoding utf8 $path
    Start-Process $path
})

$btnForensic.Add_Click({

    $startTime = Get-Date
    $dgResults.ItemsSource = $null
    comment -Comment "Scan in progress..."

    $selected = $cbHours.SelectedItem.Content.ToString()
    $value = [int]($selected -replace "[^0-9]")

    if ($selected -like "*day*") {
        $hours = $value * 24
    } 
    else {
        $hours = $value
    }

    $selectedEvent = $cbMaxEvents.SelectedItem.Content

    if ($selectedEvent -eq "Unlimited") {
    $MaxEvents = 100000
    }
    else {
    $MaxEvents = [int]$selectedEvent
    }
    
    comment -Comment "Get Data Failed..." 

    $failedevent = Get-RDPFailedEvents -Hours $Hours -MaxEvents $MaxEvents
    comment -Comment "Get Succes Data..." 

    $successevent = Get-RDPSuccessEvents -Hours $Hours -MaxEvents $MaxEvents

    if (-not $failedevent -and -not $successevent) {
    $lblSummary.Text = "Not enough data"
    return
    }

    comment -Comment "Build Html..."
    $html = Invoke-Forensic -failedevent @($failedevent) -successevent @($successevent)

    $elapsed = (Get-Date) - $startTime
    $elapsedText = "{0:mm\:ss}" -f $elapsed
    $lblSummary.Text = "Scan done - $($data.Count) events ($hours h) - Time: $elapsedText s"

    # 5. Export + open
    $path = "$env:TEMP\attack_map.html"
    $html | Out-File -Encoding utf8 $path
    Start-Process $path
})

$menuAbout.Add_Click({
    [System.Windows.MessageBox]::Show(
    "Brute Force Detector`nVersion 1.4`n`nDevelopped : Dakhama Mehdi`nCompany : logonIT.fr`nThanks : It-Connect.fr`n@ 2026",
    "About",
    [System.Windows.MessageBoxButton]::OK,
    [System.Windows.MessageBoxImage]::Information

)
   
})

$btnmenuExit.Add_Click({
$window.Close()
})

# SHOW WPF
$Window.ShowDialog() | Out-Null
# SIG # Begin signature block
# MIItjQYJKoZIhvcNAQcCoIItfjCCLXoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCT2kMMhaB7c7WH
# k4/5cquGaK7Rp0gaZHfvUoTMNZT8HqCCEtUwggXJMIIEsaADAgECAhAbtY8lKt8j
# AEkoya49fu0nMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYTAlBMMSIwIAYDVQQK
# ExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkxIjAgBgNVBAMTGUNlcnR1bSBUcnVzdGVkIE5l
# dHdvcmsgQ0EwHhcNMjEwNTMxMDY0MzA2WhcNMjkwOTE3MDY0MzA2WjCBgDELMAkG
# A1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAl
# BgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMb
# Q2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAvfl4+ObVgAxknYYblmRnPyI6HnUBfe/7XGeMycxca6mR5rlC
# 5SBLm9qbe7mZXdmbgEvXhEArJ9PoujC7Pgkap0mV7ytAJMKXx6fumyXvqAoAl4Va
# qp3cKcniNQfrcE1K1sGzVrihQTib0fsxf4/gX+GxPw+OFklg1waNGPmqJhCrKtPQ
# 0WeNG0a+RzDVLnLRxWPa52N5RH5LYySJhi40PylMUosqp8DikSiJucBb+R3Z5yet
# /5oCl8HGUJKbAiy9qbk0WQq/hEr/3/6zn+vZnuCYI+yma3cWKtvMrTscpIfcRnNe
# GWJoRVfkkIJCu0LW8GHgwaM9ZqNd9BjuiMmNF0UpmTJ1AjHuKSbIawLmtWJFfzcV
# WiNoidQ+3k4nsPBADLxNF8tNorMe0AZa3faTz1d1mfX6hhpneLO/lv403L3nUlbl
# s+V1e9dBkQXcXWnjlQ1DufyDljmVe2yAWk8TcsbXfSl6RLpSpCrVQUYJIP4ioLZb
# MI28iQzV13D4h1L92u+sUS4Hs07+0AnacO+Y+lbmbdu1V0vc5SwlFcieLnhO+Nqc
# noYsylfzGuXIkosagpZ6w7xQEmnYDlpGizrrJvojybawgb5CAKT41v4wLsfSRvbl
# jnX98sy50IdbzAYQYLuDNbdeZ95H7JlI8aShFf6tjGKOOVVPORa5sWOd/7cCAwEA
# AaOCAT4wggE6MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLahVDkCw6A/joq8
# +tT4HKbROg79MB8GA1UdIwQYMBaAFAh2zcsH/yT2xc3tu5C84oQ3RnX3MA4GA1Ud
# DwEB/wQEAwIBBjAvBgNVHR8EKDAmMCSgIqAghh5odHRwOi8vY3JsLmNlcnR1bS5w
# bC9jdG5jYS5jcmwwawYIKwYBBQUHAQEEXzBdMCgGCCsGAQUFBzABhhxodHRwOi8v
# c3ViY2Eub2NzcC1jZXJ0dW0uY29tMDEGCCsGAQUFBzAChiVodHRwOi8vcmVwb3Np
# dG9yeS5jZXJ0dW0ucGwvY3RuY2EuY2VyMDkGA1UdIAQyMDAwLgYEVR0gADAmMCQG
# CCsGAQUFBwIBFhhodHRwOi8vd3d3LmNlcnR1bS5wbC9DUFMwDQYJKoZIhvcNAQEM
# BQADggEBAFHCoVgWIhCL/IYx1MIy01z4S6Ivaj5N+KsIHu3V6PrnCA3st8YeDrJ1
# BXqxC/rXdGoABh+kzqrya33YEcARCNQOTWHFOqj6seHjmOriY/1B9ZN9DbxdkjuR
# mmW60F9MvkyNaAMQFtXx0ASKhTP5N+dbLiZpQjy6zbzUeulNndrnQ/tjUoCFBMQl
# lVXwfqefAcVbKPjgzoZwpic7Ofs4LphTZSJ1Ldf23SIikZbr3WjtP6MZl9M7JYjs
# NhI9qX7OAo0FmpKnJ25FspxihjcNpDOO16hO0EoXQ0zF8ads0h5YbBRRfopUofbv
# n3l6XYGaFpAP4bvxSgD5+d2+7arszgowggZHMIIEL6ADAgECAhA12OBytW+cTayv
# VHUpRhwLMA0GCSqGSIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhB
# c3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNp
# Z25pbmcgMjAyMSBDQTAeFw0yNTExMTYxMTAwMTlaFw0yNjExMTYxMTAwMThaMG0x
# CzAJBgNVBAYTAkZSMQ8wDQYDVQQHDAZUb3Vsb24xHjAcBgNVBAoMFU9wZW4gU291
# cmNlIERldmVsb3BlcjEtMCsGA1UEAwwkT3BlbiBTb3VyY2UgRGV2ZWxvcGVyLCBE
# QUtIQU1BIE1FSERJMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp6Ku
# m/VmkWCqAaF/3zHh9f1FuJYY2ozbXOu7mo1/Q8i1c0fE0TXpkZXLY2GZbfpj9BmH
# AAFM0IhOsPR2vdxq3jOUJUb9TICneFor6YaPpySsXR3WSE7X42kgpkkmPELovm1Y
# hwSzhJ4a+E+NWL/MU8h5JpmGVlqPJ02/ZTlMj5kcpIQtq8hoQMcUEDkGFt9IcamE
# 1yN4IHkBA5nm4jJPaos0IuS77t805992JSGWhxBxWARH+2vyltv8Rmq1pZV1lE6n
# JgrWT7Ichjw2X/A+OP68ooTzQwCIpzXb4UuUcwHEfrmP3HGMQJoj//SNC4QPMao+
# 3Z8zbevl73E3d6Kfvra1S+pWM2Ze5YCsIqAd98GUHgi5E6GiG8FQq/+d6msL7l8B
# UASCqXlcAKIjRNMHp8BrUaaW6HS9Kpc+3O3t/LUmK6X3FFiW8QsWoh4K+7YSpopa
# CQbNXmEI4xftctwBOJrEU2oqRnYiwchfjqBNlrGwVGPK1rmM0iTt5KiLTus7AgMB
# AAGjggF4MIIBdDAMBgNVHRMBAf8EAjAAMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6
# Ly9jY3NjYTIwMjEuY3JsLmNlcnR1bS5wbC9jY3NjYTIwMjEuY3JsMHMGCCsGAQUF
# BwEBBGcwZTAsBggrBgEFBQcwAYYgaHR0cDovL2Njc2NhMjAyMS5vY3NwLWNlcnR1
# bS5jb20wNQYIKwYBBQUHMAKGKWh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1bS5wbC9j
# Y3NjYTIwMjEuY2VyMB8GA1UdIwQYMBaAFN10XUwA23ufoHTKsW73PMAywHDNMB0G
# A1UdDgQWBBSXTmfHi9BD9GDRwk5/doNtKHBXYzBLBgNVHSAERDBCMAgGBmeBDAEE
# ATA2BgsqhGgBhvZ3AgUBBDAnMCUGCCsGAQUFBwIBFhlodHRwczovL3d3dy5jZXJ0
# dW0ucGwvQ1BTMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAN
# BgkqhkiG9w0BAQsFAAOCAgEAe+khGqwUUkFYuFRsrvenX2/a+PIt2Tu9d3VoW6Or
# MX3YLpe7S2CgFkXwEi2Siq5KiD1labP9jsh/3G1ZQwwlnPv8dB7ocl/nOrQ9OZex
# GVE1r7IO6VYVa5F7XuJ/KadKLEbQSs1BpBVhESo1ZYr6w9NCLuO9q2Sh3H5MktET
# D6sB+g1TFOYMdwYl8eAawgI2kGPe3dRQSoumP0mHkm3x5SIwRCW+08md5uyzCIui
# 85WmcNPtM1QCqjkSpfdFGYPsnf/BO9NATpZkqFxhXwa9+PqseX+mofCIL49guCXG
# kU4RpeRHcUie14oYkxvBw7VUO4MT6wYbS2C3j2nyoAV4XqqNMfrhZIBJG5haj2RB
# V46bMJ+DsW6hxlm3lIlCaJT2pLbbk79OP+Bk0HIdC9mAbKzcqaZpBpn4+ljrcx7/
# X7OHv4XTCCDWwlZbaogy4Wci6TiSjjfpfXK5N/eJTEEh2w4qoYTTrR61ptkVnTUT
# vGRfPnVtS/3aOm2v4UahtOc/ygcL0A/J85r1e6CEeOaTm9eJbHoNdwNIYaZ81VlX
# /V/MoJgFCtioYOKiTf2Rdq7XrEEHLU2YGwCqJyKYz9tz10yXBcMW6/+gX+PGqAYz
# eKg5jbKLdi9lVrKspQUXAPHdcl6VJMXy799J0lbsQeJNgBVy6HWxOWvdLBGX3hPE
# 3aYwgga5MIIEoaADAgECAhEAmaOACiZVO2Wr3G6EprPqOTANBgkqhkiG9w0BAQwF
# ADCBgDELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVz
# IFMuQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEk
# MCIGA1UEAxMbQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMB4XDTIxMDUxOTA1
# MzIxOFoXDTM2MDUxODA1MzIxOFowVjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFz
# c2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMbQ2VydHVtIENvZGUgU2ln
# bmluZyAyMDIxIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnSPP
# BDAjO8FGLOczcz5jXXp1ur5cTbq96y34vuTmflN4mSAfgLKTvggv24/rWiVGzGxT
# 9YEASVMw1Aj8ewTS4IndU8s7VS5+djSoMcbvIKck6+hI1shsylP4JyLvmxwLHtSw
# orV9wmjhNd627h27a8RdrT1PH9ud0IF+njvMk2xqbNTIPsnWtw3E7DmDoUmDQiYi
# /ucJ42fcHqBkbbxYDB7SYOouu9Tj1yHIohzuC8KNqfcYf7Z4/iZgkBJ+UFNDcc6z
# okZ2uJIxWgPWXMEmhu1gMXgv8aGUsRdaCtVD2bSlbfsq7BiqljjaCun+RJgTgFRC
# tsuAEw0pG9+FA+yQN9n/kZtMLK+Wo837Q4QOZgYqVWQ4x6cM7/G0yswg1ElLlJj6
# NYKLw9EcBXE7TF3HybZtYvj9lDV2nT8mFSkcSkAExzd4prHwYjUXTeZIlVXqj+ea
# YqoMTpMrfh5MCAOIG5knN4Q/JHuurfTI5XDYO962WZayx7ACFf5ydJpoEowSP07Y
# aBiQ8nXpDkNrUA9g7qf/rCkKbWpQ5boufUnq1UiYPIAHlezf4muJqxqIns/kqld6
# JVX8cixbd6PzkDpwZo4SlADaCi2JSplKShBSND36E/ENVv8urPS0yOnpG4tIoBGx
# VCARPCg1BnyMJ4rBJAcOSnAWd18Jx5n858JSqPECAwEAAaOCAVUwggFRMA8GA1Ud
# EwEB/wQFMAMBAf8wHQYDVR0OBBYEFN10XUwA23ufoHTKsW73PMAywHDNMB8GA1Ud
# IwQYMBaAFLahVDkCw6A/joq8+tT4HKbROg79MA4GA1UdDwEB/wQEAwIBBjATBgNV
# HSUEDDAKBggrBgEFBQcDAzAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vY3JsLmNl
# cnR1bS5wbC9jdG5jYTIuY3JsMGwGCCsGAQUFBwEBBGAwXjAoBggrBgEFBQcwAYYc
# aHR0cDovL3N1YmNhLm9jc3AtY2VydHVtLmNvbTAyBggrBgEFBQcwAoYmaHR0cDov
# L3JlcG9zaXRvcnkuY2VydHVtLnBsL2N0bmNhMi5jZXIwOQYDVR0gBDIwMDAuBgRV
# HSAAMCYwJAYIKwYBBQUHAgEWGGh0dHA6Ly93d3cuY2VydHVtLnBsL0NQUzANBgkq
# hkiG9w0BAQwFAAOCAgEAdYhYD+WPUCiaU58Q7EP89DttyZqGYn2XRDhJkL6P+/T0
# IPZyxfxiXumYlARMgwRzLRUStJl490L94C9LGF3vjzzH8Jq3iR74BRlkO18J3zId
# mCKQa5LyZ48IfICJTZVJeChDUyuQy6rGDxLUUAsO0eqeLNhLVsgw6/zOfImNlARK
# n1FP7o0fTbj8ipNGxHBIutiRsWrhWM2f8pXdd3x2mbJCKKtl2s42g9KUJHEIiLni
# 9ByoqIUul4GblLQigO0ugh7bWRLDm0CdY9rNLqyA3ahe8WlxVWkxyrQLjH8ItI17
# RdySaYayX3PhRSC4Am1/7mATwZWwSD+B7eMcZNhpn8zJ+6MTyE6YoEBSRVrs0zFF
# IHUR08Wk0ikSf+lIe5Iv6RY3/bFAEloMU+vUBfSouCReZwSLo8WdrDlPXtR0gicD
# nytO7eZ5827NS2x7gCBibESYkOh1/w1tVxTpV2Na3PR7nxYVlPu1JPoRZCbH86gc
# 96UTvuWiOruWmyOEMLOGGniR+x+zPF/2DaGgK2W1eEJfo2qyrBNPvF7wuAyQfiFX
# LwvWHamoYtPZo0LHuH8X3n9C+xN4YaNjt2ywzOr+tKyEVAotnyU9vyEVOaIYMk3I
# eBrmFnn0gbKeTTyYeEEUz/Qwt4HOUBCrW602NCmvO1nm+/80nLy5r0AZvCQxaQ4x
# ghoOMIIaCgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0
# YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAy
# MSBDQQIQNdjgcrVvnE2sr1R1KUYcCzANBglghkgBZQMEAgEFAKB8MBAGCisGAQQB
# gjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDuoQTPeLcAxkfrNlVj
# AXBS/U9NWcp9MTT81UL7UZs5/zANBgkqhkiG9w0BAQEFAASCAYCI8n9Xckc7Tgk3
# 5wNUr+Gp2A9wzg2quEfNO7QkqSEfW5/j7J0P0jwAgbS+jIYeel3ATnzbk2z/uZhs
# Tjtu1w9IjGK2LlNrkF2YrmzdifWJV/pbAPvOAImlsIgq639u4SoPpbuOwomkaZiz
# FWsqXZwEyJfOOr8uk2HTZRUsnnQkZSE4YIpmuL9egd4vWweY5JVHK/RUyKTOWzHW
# At3TZ08qz1Ip5TnKvFfV8UwBtipfn7423OoJOiPJa/KdiekBSjWTWd0mWDQDYmp2
# Gb9PlZP8LXs1e7djiIk4ILLMh7qkhU7y1EaiwKEA6HHT26UwVSOrhw8eYJhI5pPk
# gu3POo7Nt/tIREZcbk5Yt7LdGsrjQQhzaaYtGHJE8jHTDr54jFlL25JfdGXBfkDW
# oRImOJa63UIvtkROlUISwd5YE4BTwsTMpYwi+R5zzxEKs28mwl7LxNhm+gj33Ctr
# 9Dm9SEH/hIacX8118pMskGOFoqwjgycCwHwfEUVWLc+axAkoxY6hghd3MIIXcwYK
# KwYBBAGCNwMDATGCF2MwghdfBgkqhkiG9w0BBwKgghdQMIIXTAIBAzEPMA0GCWCG
# SAFlAwQCAQUAMHgGCyqGSIb3DQEJEAEEoGkEZzBlAgEBBglghkgBhv1sBwEwMTAN
# BglghkgBZQMEAgEFAAQgIEXIAXVtRFPNOqfdBWLkK5DVFXmcaUDPIFYjRnLzhBMC
# EQDo477AhcisUIytoCMb4IcPGA8yMDI2MDQyODEzMzcxMFqgghM6MIIG7TCCBNWg
# AwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEy
# NTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3
# zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8Tch
# TySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWj
# FDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2Uo
# yrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjP
# KHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KS
# uNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7w
# JNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vW
# doUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOg
# rY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K
# 096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCf
# gPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zy
# Me39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsG
# AQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# dDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZ
# D9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/
# ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu
# +WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4o
# bEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2h
# ECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasn
# M9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol
# /DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgY
# xQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3oc
# CVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcB
# ZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCBrQwggSc
# oAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1
# MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0
# IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2t
# jQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn
# 7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vt
# La4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0Xa
# F9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhx
# KTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXK
# FifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3
# ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F
# 20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9b
# H7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u
# 70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczs
# G7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW
# BBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/
# 57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYI
# KwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1Ud
# IAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEA
# F877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzS
# UGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ
# 3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvR
# R2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmT
# nM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqox
# W6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9
# M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSm
# E+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3
# rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnI
# n/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKd
# vlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggWNMIIEdaADAgECAhAO
# mxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# JDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEw
# MDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprN
# rnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVy
# r2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4
# IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13j
# rclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4Q
# kXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQn
# vKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu
# 5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/
# 8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQp
# JYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFf
# xCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGj
# ggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/
# 57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8B
# Af8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6
# oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Um9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEB
# AHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0a
# FPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNE
# m0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZq
# aVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCs
# WKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9Fc
# rBjDTZ9ztwGpn1eqXijiuZQxggN8MIIDeAIBATB9MGkxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3Rl
# ZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhL
# jfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqG
# SIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjA0MjgxMzM3MTBaMCsGCyqGSIb3
# DQEJEAIMMRwwGjAYMBYEFN1iMKyGCi0wa9o4sWh5UjAH+0F+MC8GCSqGSIb3DQEJ
# BDEiBCApQE2wiSouVeBCK6lsfXYRgOkCA/W21X1mArtLhwUk8zA3BgsqhkiG9w0B
# CRACLzEoMCYwJDAiBCBKoD+iLNdchMVck4+CjmdrnK7Ksz/jbSaaozTxRhEKMzAN
# BgkqhkiG9w0BAQEFAASCAgA1JV/UAEID7ZWFvvIY+CMD8oO6dzTzO5ddI+os4j+A
# 8pmps+Hx8X4P/Ys9LOqeRcTvrVQ7nXU/EF08bcS0PAJyA/XTZDf1nu6hiQsZiyr0
# BGenZ9D7vsTZC4s1Vzcz0ofkfFd9hI6bIYxndajrijWTO+ogULm7jULjKkoyjnP2
# NPY/v5WRyyuQ2dhddRCuHVT0uk1BdkZy22ntuwBLU8+rTNa8QMhcl9yZ+e6cgxpS
# gHGypmXVBSh/bQ6lDX+oBy42FuYSiU3X6TttR6UcV4f7+qeBbWM2evccq0C6STik
# RgAsHH5bF2P8Rj0TQFI/2e+vimEPITxJv2kyvbbpYJarOYswDCRWAcGHl9wqi8/P
# v5v66XgWerHe/rA68TAOdJexX4rclR0+NyrjYPUyVwlbe3pmdaxbHsCu489+UnPu
# mpWdgeaQc4LaI64G6pkxm6fpHS/TRB6OuoJvRQ22HTneOLrVB12hu0EgKBV79nJm
# sF0H2D9mQvOzDDnUdmROwnzbz1q9sGxmPB200L7Mv8b/jR4OxWxHM60AvHvmpEUb
# iF8NBQZJfkBM+uyhMvxGxephBt7cB0txQQVjaNyC0x1YO+1USkID5gypuVWCYcKk
# e0VHZfITIWxmvZvEbAMlNi4EtZWr3215tPHYnB/xGM5mNiTh1Ps3ErV7/ebW20Eq
# xw==
# SIG # End signature block
