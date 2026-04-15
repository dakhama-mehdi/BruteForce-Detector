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
    Version     : 1.1
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
           Text=" v1.1 | Dakhama Mehdi | logonIT.fr"
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
        Write-Host $_
        $location = [PSCustomObject]@{
            Country = "Error"
            City    = "Error"
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
        "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='3']]"
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
        "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[(Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10')]]"
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
        $failedevent, # Events failed logon (4625)
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

    # chercher les succès avec la même IP
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

# Detected suspicious logon
$isAnonymous = $successusername.Name -contains "ANONYMOUS"
$anonymousStatus = if ($isAnonymous) {
    "<span style='color:red; font-weight:bold;'>● Detected</span>"
} 
else {
    "<span style='color:lightgreen; font-weight:bold;'>✔ Not detected</span>"
}

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

$successRate = if ($total -gt 0) {
    [math]::Round(
        ($totalSuccess * 100.0) / $total,
        0,
        [System.MidpointRounding]::AwayFromZero
    )
} else {
    0
}

    $risk = 100
    if ($successRate -le 10) { $risk -= 60 }
    elseif ($successRate -le 20) { $risk -= 40 }

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
<b>Risk Level</b><br>
$level : $risk %
</div>

</div>

<div class="findings-row">

<!-- PROTOCOL -->
<div class="finding-box" style="font-size:16px;">

<b>Protocols : $protocolStatus</b>

<br><br>

$protocolList

</div>

<div class="finding-box" style="font-size:16px;">

<b>Suspicious Login : $anonymousStatus</b>

</div>

<!-- PROCESS -->
<div class="finding-box" style="font-size:16px;">

<b>Processes Logon : $processStatus</b>

<br><br>

$processList

</div>

<!-- Open Ports -->
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
        $res = Invoke-RestMethod "http://ipwho.is/$ip" -ErrorAction Stop # "http://ip-api.com/json/$ip" -ErrorAction Stop

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
        Write-Host "Error IP: $ip"
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
   comment -Comment  "Build Stats..."

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

    comment -Comment "Build HTML..."

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

    if (!$failedevent -or !$successevent) {
    $lblSummary.Text = "Not enough data"
    return
    }

    comment -Comment "Build Html..."
    $html = Invoke-Forensic -failedevent $failedevent -successevent $successevent

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
    "Brute Force Detector`nVersion 1.0`n`nDevelopped : Dakhama Mehdi`nCompany : logonIT.fr`n@ 2026",
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
# MIItjAYJKoZIhvcNAQcCoIItfTCCLXkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAQ1nDMb1BYLQ3Z
# CR8cYBrjJDJ16WPuu0VnI0paA8nO3qCCEtUwggXJMIIEsaADAgECAhAbtY8lKt8j
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
# ghoNMIIaCQIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0
# YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAy
# MSBDQQIQNdjgcrVvnE2sr1R1KUYcCzANBglghkgBZQMEAgEFAKB8MBAGCisGAQQB
# gjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCUlVwxG0lj6hTSlSuW
# AnPCZ67P3lUMZLi0kdAmixpnSDANBgkqhkiG9w0BAQEFAASCAYAlv9MxElJgIbSG
# Vveyzew8H91DFJfmmUcqHGbiN3K9cvXDNsrBQoP5n+VV2JVvIlt+GJDzyoVOohqk
# HR17pmHohspuVbXSALkov9T7AG/csOqTwhKwnU7hAUPZWMl2UnpFzhyggtjxGGCf
# gpL2D/k/3Hx0bA+tYMYoAKFuEuOpWaiM3TC1pc2Hsfdx7eKoq2X0Evewvg8B8Vfw
# WAOKDhebn728YIDYBvHIHzQNyN/TVpt9xC0lZuZvntb9PQu07aIzYQj7Hqesvo4P
# Z8qPDw82UePDYl7euxkOyyjYpEaeGkcOJrcrTH+7oKf3ySGhtrOjygw1YuYg8OkV
# mqigYRWe/6/g8xdGyOfQzwu5fKnrr60+/xzLUrua8fNIzsD1G4DwRLgHk6cZESr/
# 01HZqwsRKiIjqmzy7EATWshwH4jpRKM/t8jg9S7lxbb8AC6uKiMn5JnC2XvkOT4o
# MzcoPtXSx/v8W0BbF+wyVQywOfDG7veA2aQGLUf3ZojdSOlQJ52hghd2MIIXcgYK
# KwYBBAGCNwMDATGCF2IwghdeBgkqhkiG9w0BBwKgghdPMIIXSwIBAzEPMA0GCWCG
# SAFlAwQCAQUAMHcGCyqGSIb3DQEJEAEEoGgEZjBkAgEBBglghkgBhv1sBwEwMTAN
# BglghkgBZQMEAgEFAAQgdFXhU/JfJ/EwliaH2yPpHMtoeq1cOetIQqkQcGNyEUUC
# EF1e416YMNPbhPZejoFinGgYDzIwMjYwNDE1MTcyMDM5WqCCEzowggbtMIIE1aAD
# AgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEw
# HhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1
# NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfM
# GUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFP
# JIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMU
# Ng7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjK
# s3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8o
# dbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK4
# 0uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk
# 12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2
# hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6Ct
# juuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT
# 3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A
# 9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx
# 7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtO
# MA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYB
# BQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0
# MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP
# 2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8w
# v2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75
# ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihs
# QyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQ
# JmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz
# 0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8
# MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjF
# BtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJ
# VxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFl
# Txq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMIIGtDCCBJyg
# AwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUw
# NTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2N
# DZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qft
# JYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0t
# rj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX
# 0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEp
# NVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coW
# J+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdk
# DjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0Xb
# Qcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sf
# uZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7v
# QTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwb
# tmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/n
# upiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3Bggr
# BgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAX
# zvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQ
# a8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd
# 6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FH
# aoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOc
# zgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFb
# qrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z
# 4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT
# 70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43es
# aUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif
# /sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+
# VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6b
# GI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEk
# MCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAw
# MDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMY
# RGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2u
# exuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKv
# aJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/gh
# YZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOt
# yU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCR
# cKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8
# oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m
# 1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y
# 1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkl
# iWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/E
# IFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOC
# ATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/n
# upiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB
# /wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqg
# OKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEA
# cKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU
# 9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0Sb
# QyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1Rmpp
# VLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxY
# oA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0Vys
# GMNNn3O3AamfV6peKOK5lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN
# 8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZI
# hvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MDQxNTE3MjAzOVowKwYLKoZIhvcN
# AQkQAgwxHDAaMBgwFgQU3WIwrIYKLTBr2jixaHlSMAf7QX4wLwYJKoZIhvcNAQkE
# MSIEIGoNPwySfLIjJWTkMhfGsaFZ8KZ3JJsKEsTTKmSve6hVMDcGCyqGSIb3DQEJ
# EAIvMSgwJjAkMCIEIEqgP6Is11yExVyTj4KOZ2ucrsqzP+NtJpqjNPFGEQozMA0G
# CSqGSIb3DQEBAQUABIICAElixwwuKANQA4UP1hjv4puG7j1ZcspVdDPNCBZhQfpb
# 6xuMbolqoi+nHXFNckOmM4HjoH1YPlCIxNGM9tdDpMUCnLATa2t98a6eybkX5kLM
# jbPPjo0hImvw7Wvv8N/jmkhK6vYXImRcfL18uY7iWtaCF3B7OqLBDsNxkasMfdYo
# 7ycG2JxpE2pqJDmIUFcznVuDO7VQoO82GqjYeKK/Uk4gYN7chwlKnvzrL2BwatrA
# MddCZfodB8VIqtNEwr9iPXWeaB+ZZC8xOlegGIrGoAeBzlEs7hBdC/umT1c3I0gX
# xzN3xl5ixcCcbMtfFXpMgkSQRs4qxQM0AovIZ2Y9Jqf6wXTtaVPBZ6rH6Kf0mJyt
# QNc380qIt4swEu8jUa9SnNTU5bMLY8eL2RKWJBdjbi4tLrnFO/fhsNI3PDeqZuec
# 0jRDOu2hT0n1biojOGAmeCubUhjgEHzXoYFibcv6O3u8ph84APYKMd4e/p+dIGQK
# c37rNSf1sl6Mvgh+OuyasxMlbist0rr29q52JslJcWtK1e5YyD89cOxdV4/iqvV5
# MPzIn5SAhWUvDzEcBYoOY1Nu9oofNS6HiDQhF5phGo9uHzmOTsYewyGCaL10GQIx
# UoZXnsBo4BJMeAGmZ1rgqVj3qDc2ioS6H2Y89P7MzL5qtrXkAWI6e0KqS43Q83d+
# SIG # End signature block
