<#
.SYNOPSIS
    SentinelCore Enterprise Agent - Silent Deployment Script für Windows (GPO / MSI Wrapper)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$EnrollmentToken,
    
    [Parameter(Mandatory=$false)]
    [string]$HubUrl = "https://hub.sentinel-core.local:8443"
)

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\SentinelCore"
$BinaryPath = "$InstallDir\sentinel-agent.exe"
$ConfigPath = "$InstallDir\config.yaml"

Write-Host "[*] Starte SentinelCore Agenten-Deployment..."

# 1. Installationsverzeichnis erstellen
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 2. Agenten-Binary herunterladen (oder aus lokalem MSI-Pfad kopieren)
Write-Host "[*] Lade Sentinel-Agenten-Binary herunter..."
$DownloadUrl = "$HubUrl/downloads/windows/sentinel-agent.exe"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13
# Fallvoraussetzung: Zertifikatsprüfung für internes Deployment anpassen falls Self-Signed
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinaryPath
} catch {
    Write-Error "Fehler beim Herunterladen des Agenten: $_"
    exit 1
}

# 3. Hardware-Fingerprint & Konfiguration generieren
$Hostname = $env:COMPUTERNAME
$OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
$HardwareUUID = (Get-CimInstance Win32_ComputerSystemProduct).UUID

$Body = @{
    enrollment_token = $EnrollmentToken
    hostname         = $Hostname
    os_version       = $OSVersion
    hardware_uuid    = $HardwareUUID
} | ConvertTo-Json

Write-Host "[*] Registriere Agent am Sentinel Hub ($HubUrl)..."
try {
    $Response = Invoke-RestMethod -Uri "$HubUrl/enroll" -Method Post -Body $Body -ContentType "application/json"
    
    # Credentials lokal sicher speichern
    $ConfigContent = @"
node_id: "$($Response.agent_id)"
shared_secret: "$($Response.mTLS_shared_secret)"
hub_url: "$HubUrl"
"@
    Set-Content -Path $ConfigPath -Value $ConfigContent -Encoding utf8
} catch {
    Write-Error "Enrollment fehlgeschlagen: $_"
    exit 1
}

# 4. Als Windows Service registrieren und starten
$ServiceName = "SentinelAgent"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force
    sc.exe delete $ServiceName | Out-Null
}

Write-Host "[*] Installiere Windows-Dienst..."
New-Service -Name $ServiceName -BinaryPathName "`"$BinaryPath`" --config `"$ConfigPath`"" -DisplayName "SentinelCore Security Agent" -StartupType Automatic
Start-Service -Name $ServiceName

Write-Host "[+] SentinelCore Agent erfolgreich installiert und gestartet!"
