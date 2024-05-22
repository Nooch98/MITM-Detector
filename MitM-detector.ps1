function AnalyzeDNS {
    $dnsTraffic = Get-DnsClientCache | Where-Object { $_.Type -eq "A" -or $_.Type -eq "AAAA" }

    if ($dnsTraffic) {
        Write-Host "[!] Se ha detectado tráfico DNS sospechoso:" -ForegroundColor Red
        foreach ($query in $dnsTraffic) {
            $domain = $query.Name
            $ipAddress = $query.Address

            if ($ipAddress -match '10\.(0|1|2|3)\.') {
                Write-Host "[!] Consulta DNS sospechosa: $domain -> $ipAddress" -ForegroundColor Yellow
            } else {
                Write-Host "[*] Consulta DNS: $domain -> $ipAddress"
            }
        }
    } else {
        Write-Host "[+] No se ha detectado tráfico DNS." -ForegroundColor Green
    }
}

function AnalyzeHTTP {
    $httpTraffic = Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 80 -or $_.LocalPort -eq 443 }

    if ($httpTraffic) {
        Write-Host "[!] Se ha detectado tráfico HTTP sospechoso:" -ForegroundColor Red
        foreach ($connection in $httpTraffic) {
            $remoteIP = $connection.RemoteAddress
            $remotePort = $connection.RemotePort

            # Realiza comprobaciones y análisis adicionales según tus necesidades
            # Puedes utilizar servicios de reputación de IPs, analizar los encabezados HTTP, etc.

            # Ejemplo: Verificar si la IP es sospechosa
            if ($remoteIP -match '10\.(0|1|2|3)\.') {
                Write-Host "[!] Conexión HTTP sospechosa: $remoteIP : $remotePort" -ForegroundColor Red
            } else {
                Write-Host "[*] Conexión HTTP: $remoteIP : $remotePort"
            }
        }
    } else {
        Write-Host "[+] No se ha detectado tráfico HTTP." -ForegroundColor Green
    }
}

function AnalyzeHTTPS {
    $httpsTraffic = Get-NetTCPConnection | Where-Object { $_.RemotePort -eq 443 }

    if ($httpsTraffic) {
        Write-Host "[!] Se ha detectado tráfico HTTPS:" -ForegroundColor Red
        foreach ($connection in $httpsTraffic) {
            $remoteIP = $connection.RemoteAddress
            $remotePort = $connection.RemotePort

            # Verificar si la IP es sospechosa
            if ($remoteIP -match '10\.(0|1|2|3)\.') {
                Write-Host "[!] Conexión HTTPS sospechosa: $remoteIP : $remotePort" -ForegroundColor Yellow
            } else {
                Write-Host "[*] Conexión HTTPS: $remoteIP : $remotePort"
            }

            # Verificar el certificado SSL/TLS
            VerifySSL $remoteIP
        }
    } else {
        Write-Host "[+] No se ha detectado tráfico HTTPS." -ForegroundColor Green
    }
}

function VerifySSL ($remoteIP) {
    $tcpConnections = Get-NetTCPConnection -State Established

    foreach ($connection in $tcpConnections) {
        $remoteIP = $connection.RemoteAddress

        # Verificar si la IP es sospechosa
        if ($remoteIP -match '192\.168\.0\.(10|20)') {
            Write-Host "[!] Conexión sospechosa detectada: $remoteIP" -ForegroundColor Red
        }

        $commonPorts = @(443)  # Puerto HTTPS (443)
        foreach ($port in $commonPorts) {
            try {
                if (![string]::IsNullOrEmpty($remoteIP)) {
                    $sslStream = (New-Object System.Net.Sockets.TcpClient).GetStream()
                    $sslStream.Connect($remoteIP, $port)
                    $sslStream.ReadTimeout = 500

                    $sslStream.Write([byte[]] @(0x16, 0x03, 0x01, 0x00, 0xfe))
                    $response = New-Object byte[] 256
                    $sslStream.Read($response, 0, 256)

                    $sslStream.Dispose()

                    # Analizar el certificado SSL/TLS
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $cert.Import($sslStream)

                    if ($cert -ne $null) {
                        Write-Host "[+] Conexión SSL/TLS exitosa en $remoteIP : $port" -ForegroundColor Green
                        Write-Host "    - Emisor: $($cert.Issuer)"
                        Write-Host "    - Sujeto: $($cert.Subject)"
                        Write-Host "    - Fecha de Vencimiento: $($cert.NotAfter)"
                        Write-Host "    - Algoritmo de Firma: $($cert.SignatureAlgorithm.FriendlyName)"
                        Write-Host "    - Tamaño de la Clave Pública: $($cert.PublicKey.Key.KeySize) bits"
                        Write-Host "    - Hash del Certificado: $($cert.GetCertHashString())"
                        Write-Host "    - Uso de Clave: $($cert.GetKeyUsageFlags())"
                        Write-Host "    - Propósitos Extendidos: $($cert.Extensions)"
                    } else {
                        Write-Host "[!] No se pudo analizar el certificado SSL/TLS en $remoteIP : $port" -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-Host "[!] Error al verificar el certificado SSL/TLS en $remoteIP : $port" -ForegroundColor Red
            }
        }
    }
}

function DetectSuspiciousHosts {
    $tcpConnections = Get-NetTCPConnection -State Established

    foreach ($connection in $tcpConnections) {
        $remoteIP = $connection.RemoteAddress

        # Verificar si la IP es sospechosa
        if ($remoteIP -match '192\.168\.0\.(10|20)') {
            Write-Host "[!] Conexión sospechosa detectada: $remoteIP" -ForegroundColor Red
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
                Write-Host "[+] La IP $ip pertenece a un servicio de Microsoft." -ForegroundColor Green
            } else {
                Write-Host "[!] La IP $ip no pertenece a un servicio de Microsoft." -ForegroundColor Red
                GetIPGeolocation $ip
            }
        } else {
            Write-Host "[!] El archivo JSON no existe en la ruta especificada: $jsonFilePath" -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Error al cargar el archivo JSON." -ForegroundColor Blue
    }
}

function CheckIPInternal($ip) {
    $ipconfig = Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -contains $ip -or $_.IPv6Address.IPAddress -contains $ip }

    if ($ipconfig) {
        Write-Host "[+] La IP $ip es interna a tu red." -ForegroundColor Green
    } else {
        Write-Host "[!] La IP $ip es externa a tu red." -ForegroundColor Red
    }
}

function GetIPGeolocation($ip) {
    $apiKey = "<API-KEY>"
    $url = "https://api.ipgeolocation.io/ipgeo?apiKey=$apiKey&ip=$ip&fields=geo"

    try {
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop

        Write-Host "[!] La ubicación de la IP $ip es:"
        $response | Format-Table -AutoSize
    } catch {
        Write-Host "Error al obtener la ubicación geográfica de la IP $ip $($_.Exception.Message)"
    }
}

function CheckMitMIPv4 {
    $arptable = Get-NetNeighbor | Where-Object { $_.State -eq 'Reachable' }

    if ($arptable) {
        Write-Host "[!] Se ha encontrado una tabla ARP sospechosa:" -ForegroundColor Red
        $arptable

        $arptable | ForEach-Object {
            $ip = $_.IPAddress
            CheckIPInternal $ip
            CheckMicrosoftServiceIP $ip $jsonFilePath
        }
    } else {
        Write-Host "[*] No se ha encontrado ninguna actividad sospechosa en la tabla ARP." -ForegroundColor Green
    }
}

function CheckMitMIPv6 {
    $ndtable = Get-NetNeighbor -AddressFamily IPv6 | Where-Object { $_.State -eq 'Reachable' }

    if ($ndtable) {
        Write-Host "[!] Se ha encontrado una tabla ND sospechosa:" -ForegroundColor Red
        $ndtable

        $ndtable | ForEach-Object {
            $ip = $_.IPAddress
            CheckIPInternal $ip
            CheckMicrosoftServiceIP $ip $jsonFilePath
        }
    } else {
        Write-Host "[*] No se ha encontrado ninguna actividad sospechosa en la tabla ND."
    }
}

$jsonFilePath = "ServiceTags_Public_20240520.json"

Write-Host "[#] Verificando actividad Man-in-the-Middle en IPv4..." -ForegroundColor Blue
CheckMitMIPv4

Write-Host "[#] Verificando actividad Man-in-the-Middle en IPv6..." -ForegroundColor Blue
CheckMitMIPv6

Write-Host "[#] Detectando hosts sospechosos..." -ForegroundColor Blue
DetectSuspiciousHosts

Write-Host "[#] Verificando certificados SSL/TLS..." -ForegroundColor Blue
VerifySSL

Write-Host "[#] Verificando DNS..." -ForegroundColor Blue
AnalyzeDNS

Write-Host "[#] Verificando tráfico HTTP..." -ForegroundColor Blue
AnalyzeHTTP

Write-Host "[#] Verificando trafico HTTPS..." -ForegroundColor Blue
AnalyzeHTTPS
