<#
.SYNOPSIS
   This script performs network traffic analysis, scans ports, and detects potentially suspicious activities.
    
.DESCRIPTION
    The script runs different scans and threat detection tasks on a network, such as port scanning,
    verification of HTTP/HTTPS connections, detection of Man-in-the-Middle (MitM) attacks on IPv4 and IPv6,
    consultations to threat intelligence services, DNS traffic analysis, and validation of SSL/TLS certificates.

.NOTES
    Author: Nooch98
    Creation Date: 05/24/2024
    Last Modification: 10/24/2024
    Version: 1.1

    - Requires a VirusTotal API key and another IP geolocation service.
    - Download a JSON file with IP ranges from Microsoft services.
#>

$log_file = "network_analysis_log.log"
$jsonFilePath = "ServiceTags_Public_20240520.json"

function CheckMicrosoftIPfile {
    $url = "https://raw.githubusercontent.com/Nooch98/MITM-Detector/refs/heads/main/ServiceTags_Public_20240520.json"
    
    if (Test-Path -Path $jsonFilePath) {
        Write-Host "[*] $jsonFilePath already exists." -ForegroundColor Green
    } else {
        Write-Host "[!] $jsonFilePath does not exist. Downloading from $url" -ForegroundColor Yellow

        try {
            Invoke-WebRequest -Uri $url -OutFile $jsonFilePath
            Write-Host "[*] File Downloaded successfully to '$jsonFilePath'." -ForegroundColor Green
        } catch {
            Write-Host "[!] Error Downloading the file from $url -> $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function PortScan {
    $ipublic = (Invoke-WebRequest http://ifconfig.me/ip).Content
    $hosts = @("localhost", "127.0.0.1", $ipublic)
    $portServices = @{
        80 = "HTTP"
        443 = "HTTPS"
        25 = "SMTP"
        587 = "SMTP"
        22 = "SSH"
        445 = "SMB"
        139 = "SMB"
        135 = "RPC"
        3389 = "WinRM"
        5985 = "WinRM"
        1433 = "SQL Server"
    }

    foreach ($hostname in $hosts) {
        foreach ($port in $portServices.Keys) {
            $result = Test-NetConnection -ComputerName $hostname -Port $port
            if ($result.TcpTestSucceeded) {
                $serviceName = $portServices[$port]
                Write-Host "[*] Port $port ($serviceName) in $hostname is Open." -ForegroundColor Red
            } else {
                $serviceName = $portServices[$port]
                Write-Host "[!] Port $port ($serviceName) in $hostname is Closed." -ForegroundColor Green
            }
        }
    }
}

function AnalyzeDNS {
    $dnsTraffic = Get-DnsClientCache

    if ($dnsTraffic) {
        Write-Host "[!] Suspicious DNS traffic detected:" -ForegroundColor Red
        foreach ($query in $dnsTraffic) {
            $domain = $query.Name
            $ipAddress = $query.Data

            if ($ipAddress -match '10\.(0|1|2|3)\.') {
                Write-Host "[!] Suspicious DNS query: $domain -> $ipAddress" -ForegroundColor Yellow
            } else {
                Write-Host "[*] DNS query: $domain -> $ipAddress" -ForegroundColor Magenta
            }
        }
    } else {
        Write-Host "[+] No DNS traffic detected." -ForegroundColor Green
    }
    Write-Host "[i] Writing results in a log file..." -ForegroundColor Cyan
    Add-Content -Path $log_file -Value "Suspect activiti detected over DNS -> $domain -> $ipAddress on $(Get-Date)"
}

function AnalyzeHTTPAndHTTPS {
    $httpTraffic = Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 80 -or $_.LocalPort -eq 443 }

    if ($httpTraffic) {
        Write-Host "[!] Suspicious HTTP/HTTPS traffic detected:" -ForegroundColor Red
        foreach ($connection in $httpTraffic) {
            $remoteIP = $connection.RemoteAddress
            $remotePort = $connection.RemotePort

            # Verificar si la IP es sospechosa
            if ($remoteIP -match '10\.(0|1|2|3)\.') {
                Write-Host "[!] Suspicious HTTP/HTTPS connection: $remoteIP : $remotePort" -ForegroundColor Red
            } elseif ($remotePort -eq 443) {
                Write-Host "[*] HTTPS connection: $remoteIP : $remotePort" -ForegroundColor Yellow
                # Verificar el certificado SSL/TLS
                GetThreatIntel $remoteIP
                GetIPOrganization $remoteIP
            } else {
                Write-Host "[*] HTTP connection: $remoteIP : $remotePort" -ForegroundColor Magenta
            }
        }
    } else {
        Write-Host "[i] No HTTP/HTTPS traffic detected." -ForegroundColor Green
    }

    Write-Host "[i] Writing results in a log file..." -ForegroundColor Cyan
    Add-Content -Path $log_file -Value "Suspect activiti detected over HTTP/HTTPS -> $remoteIP -> $remotePort on $(Get-Date)"
}

function GetIPOrganization {
    $tcpConnections = Get-NetTCPConnection -State Established

    foreach ($connection in $tcpConnections) {
        $remoteIP = $connection.RemoteAddress

        # Check if the IP is localhost (127.0.0.1) and skip if it is
        if ($remoteIP -eq '127.0.0.1') {
            Write-Host "Skipping localhost (127.0.0.1)" -ForegroundColor Magenta
            continue
        }

        try {
            # Obtain WHOIS information
            $response = (Invoke-WebRequest "https://who.is/whois-ip/ip-address/$remoteIP" -ErrorAction Stop).Content
            $orgRegex = "Organization:\s+(.*)"
            $orgMatch = [regex]::match($response, $orgRegex)

            if ($orgMatch.Success) {
                $organization = $orgMatch.Groups[1].Value.Trim()  # Get the organization name and trim spaces
                Write-Host "[i] IP $remoteIP belongs to the organization -> $organization" -ForegroundColor Cyan
            } else {
                Write-Host "[x] Could not find the organization for IP -> $remoteIP" -ForegroundColor Red
            }
        } catch {
            Write-Host "Error retrieving the organization for IP $remoteIP -> $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function DetectSuspiciousHosts {
    $tcpConnections = Get-NetTCPConnection -State Established

    foreach ($connection in $tcpConnections) {
        $remoteIP = $connection.RemoteAddress

        if ($remoteIP -match '192\.168\.0\.(10|20)') {
            Write-Host "[!] Suspicious connection detected: $remoteIP" -ForegroundColor Red
        }
    }
}

function CheckMicrosoftServiceIP($ip, $jsonFilePath) {
    try {
        if (Test-Path -Path $jsonFilePath) {
            $jsonContent = Get-Content -Path $jsonFilePath -Raw
            $ipRanges = ConvertFrom-Json $jsonContent

            $isMicrosoftIP = $ipRanges.values | Where-Object { $_.properties.addressPrefixes -contains $ip }

            if ($isMicrosoftIP) {
                Write-Host "[+] The IP $ip belongs to a Microsoft service." -ForegroundColor Green
            } else {
                Write-Host "[!] The IP $ip does not belong to a Microsoft service." -ForegroundColor Red
                GetIPGeolocation $ip
            }
        } else {
            Write-Host "[!] The JSON file does not exist at the specified path: $jsonFilePath" -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Error loading JSON file." -ForegroundColor Blue
    }

    Write-Host "[i] Writing results in a log file..." -ForegroundColor Cyan
    Add-Content -Path $log_file -Value "Suspect activiti detected over IP -> $ip el $(Get-Date)"
}

function CheckIPInternal($ip) {
    $ipconfig = Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -contains $ip -or $_.IPv6Address.IPAddress -contains $ip }

    if ($ipconfig) {
        Write-Host "[+] The IP $ip is internal to your network." -ForegroundColor Green
    } else {
        Write-Host "[!] The IP $ip is external to your network." -ForegroundColor Red
    }
    Write-Host "[i] Writing results in a log file..." -ForegroundColor Cyan
    Add-Content -Path $log_file -Value "Suspect activiti detected over IP -> $ip el $(Get-Date)"
}

function GetIPGeolocation($ip) {
    $apiKey = "<API-KEY>"
    $url = "https://api.ipgeolocation.io/ipgeo?apiKey=$apiKey&ip=$ip&fields=geo"

    try {
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop

        Write-Host "[!] The location of the IP $ip is:" -ForegroundColor Yellow
        $response | Format-Table -AutoSize
    } catch {
        Write-Host "Error getting geolocation from IP $ip $($_.Exception.Message)" -ForegroundColor Red
    }
}

function CheckMitMIPv4 {
    $gatewayIP = (Get-NetRoute -DestinationPrefix "0.0.0.0/0").NextHop

    $arptable = Get-NetNeighbor | Where-Object { $_.State -eq 'Reachable' }

    if ($arptable) {
        Write-Host "[!] A suspicious ARP table was found:" -ForegroundColor Red
        $arptable

        foreach ($entry in $arptable) {
            $ip = $entry.IPAddress

            if ($ip -eq $gatewayIP) {
                Write-Host "Skipping gateway IP: $ip" -ForegroundColor Magenta
                continue
            }

            CheckIPInternal $ip
            CheckMicrosoftServiceIP $ip $jsonFilePath
        }
    } else {
        Write-Host "[*] No suspicious activity found in the ARP table." -ForegroundColor Green
    }
}

function CheckMitMIPv6 {
    $ndtable = Get-NetNeighbor -AddressFamily IPv6 | Where-Object { $_.State -eq 'Reachable' }

    if ($ndtable) {
        Write-Host "[!] A suspicious ND table was found:" -ForegroundColor Red
        $ndtable

        $ndtable | ForEach-Object {
            $ip = $_.IPAddress
            CheckIPInternal $ip
            CheckMicrosoftServiceIP $ip $jsonFilePath
        }
    } else {
        Write-Host "[*] No suspicious activity was found in the ND table." -ForegroundColor Green
    }
}

function GetThreatIntel($ip) {
    $apiKey = "<API-KEY>"
    $url = "https://www.virustotal.com/api/v3/ip_addresses/$ip"

try {
        $headers = @{
            "x-apikey" = $apiKey
        }
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

        if ($response.error -eq $null) {
            $reputation = $response.data.attributes.reputation
            $owner = $response.data.attributes.as_owner
            Write-Host "IP address reputation ${ip}: $reputation" -ForegroundColor Green
            Write-Host "IP Owner: $owner" -ForegroundColor Green
        } else {
            Write-Host "IP address $ip was not found in the VirusTotal database." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "VirusTotal API error" -ForegroundColor Red
    }
}

function Get-InternalIPs {
    $internalIPs = Get-NetIPAddress | Where-Object { $_.IPAddress -match '^(10|192\.168|172\.16|172\.31)' }
    return $internalIPs
}

function Get-ADComputersIPs {
    Import-Module ActiveDirectory
    $computers = Get-ADComputer -Filter * -Property Name, IPv4Address

    $computerIPs = @()
    foreach ($computer in $computers) {
        if ($computer.IPv4Address) {
            $computerIPs += $computer.IPv4Address
        }
    }
    return $computerIPs
}

function Check-InternalIPs {
    $internalIPs = Get-InternalIPs
    $adIPs = Get-ADComputersIPs

    Write-Host "[*] Internal IPs from the network interfaces:" -ForegroundColor Cyan
    foreach ($ip in $internalIPs) {
        Write-Host $ip.IPAddress -ForegroundColor Green
    }

    Write-Host "[*] IPs from Active Directory computers:" -ForegroundColor Cyan
    foreach ($ip in $adIPs) {
        Write-Host $ip -ForegroundColor Green
    }

    $ipToCheck = $ip.IPAddress
    if ($internalIPs.IPAddress -contains $ipToCheck -or $adIPs -contains $ipToCheck) {
        Write-Host "[+] The IP $ipToCheck is internal." -ForegroundColor Green
    } else {
        Write-Host "[!] The IP $ipToCheck is external." -ForegroundColor Red
    }
}

Write-Host "[#] Check ServiceTags file..." -ForegroundColor Blue
CheckMicrosoftIPfile

$quest = Read-Host "[?] You are on Active directory or business enviroment(y/n)(Default n)"
if ($quest -eq "Y") {
    Check-InternalIPs
} else {
    Write-Host "[i] Omited internal IP search" -ForegroundColor Cyan
}

Write-host "[#] Scanning Ports..." -ForegroundColor Blue
PortScan

Write-Host "[#] Verifying Man-in-the-Middle activity in IPv4..." -ForegroundColor Blue
CheckMitMIPv4

Write-Host "[#]Verifying Man-in-the-Middle activity in IPv6..." -ForegroundColor Blue
CheckMitMIPv6

Write-Host "[#] Detecting suspicious hosts..." -ForegroundColor Blue
DetectSuspiciousHosts

Write-Host "[#] Verifying SSL/TLS certificates..." -ForegroundColor Blue
GetIPOrganization

Write-Host "[#] Verifying DNS..." -ForegroundColor Blue
AnalyzeDNS

Write-Host "[#] Verifying HTTP/HTTPS traffic..." -ForegroundColor Blue
AnalyzeHTTPAndHTTPS
