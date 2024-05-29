<#
.SYNOPSIS
    This script performs traffic analysis on a home network, scans ports, and detects potential suspicious activities.

.DESCRIPTION
    The script consists of several functions that perform different analysis and threat detection tasks on a home network.

.NOTES
    Author: Nooch98
    Creation Date: 29/05/2024
    Last Modified: 29/05/2024

#>

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
                Write-Host "[*] Puerto $port ($serviceName) en $hostname está abierto." -ForegroundColor Red
            } else {
                $serviceName = $portServices[$port]
                Write-Host "[!] Puerto $port ($serviceName) en $hostname está cerrado." -ForegroundColor Green
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
                Write-Host "[!] Suspicious DNS query detected." -ForegroundColor Yellow
            } else {
                Write-Host "[*] DNS query detected. -> {$ipAddress}" -ForegroundColor Magenta
            }
        }
    } else {
        Write-Host "[+] No DNS traffic detected." -ForegroundColor Green
    }
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
                VerifySSL $remoteIP
            } else {
                Write-Host "[*] HTTP connection: $remoteIP : $remotePort" -ForegroundColor Magenta
            }
        }
    } else {
        Write-Host "[+] No HTTP/HTTPS traffic detected." -ForegroundColor Green
    }
}

function VerifySSL {
    $tcpConnections = Get-NetTCPConnection -State Established

    foreach ($connection in $tcpConnections) {
        $remoteIP = $connection.RemoteAddress

        # Verificar si la IP es localhost (127.0.0.1) y omitirla si es así
        if ($remoteIP -eq '127.0.0.1') {
            Write-Host "Skipping localhost (127.0.0.1)" -ForegroundColor Magenta
            continue
        }

        $commonPorts = @(443)  # Puerto HTTPS (443)

        try {
            $check = (Invoke-WebRequest "https://ssl-checker.io/api/v1/check/$remoteIP").Content | ConvertFrom-JSON
            Write-Host "SSL Status for {$remoteIP}:" $check -ForegroundColor Yellow
        } catch {
            Write-Host "Error checking SSL status for $remoteIP" -ForegroundColor Red
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
}

function CheckIPInternal($ip) {
    $ipconfig = Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -contains $ip -or $_.IPv6Address.IPAddress -contains $ip }

    if ($ipconfig) {
        Write-Host "[+] The IP $ip is internal to your network." -ForegroundColor Green
    } else {
        Write-Host "[!] The IP $ip is external to your network." -ForegroundColor Red
    }
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
        Write-Host "[!] A suspicious ARP table was found." -ForegroundColor Red

        foreach ($entry in $arptable) {
            $ip = $entry.IPAddress
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

$jsonFilePath = "ServiceTags_Public_20240520.json"

Write-host "[#] Scanning Ports..." -ForegroundColor Blue
PortScan

Write-Host "[#] Verifying Man-in-the-Middle activity in IPv4..." -ForegroundColor Blue
CheckMitMIPv4

Write-Host "[#]Verifying Man-in-the-Middle activity in IPv6..." -ForegroundColor Blue
CheckMitMIPv6

Write-Host "[#] Detecting suspicious hosts..." -ForegroundColor Blue
DetectSuspiciousHosts

Write-Host "[#] Verifying SSL/TLS certificates..." -ForegroundColor Blue
VerifySSL

Write-Host "[#] Verifying DNS..." -ForegroundColor Blue
AnalyzeDNS

Write-Host "[#] Verifying HTTP/HTTPS traffic..." -ForegroundColor Blue
AnalyzeHTTPAndHTTPS

