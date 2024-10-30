# PowerShell Script for Attack Surface Reduction with Optional NVD API Integration, Permission Checking, DLL/EXE Vulnerability Check, and Port Scanning

# Prompt user for directory or file location
$location = Read-Host "Enter the file or directory location to scan for attack surface reduction"

# Function to generate the report
function Generate-Report {
    param (
        [string]$reportName,
        [string]$scanResults
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $reportFullName = "$reportName_$timestamp.txt"
    
    # Create ASR_Loot folder if it doesn't exist
    $reportFolder = "ASR_Loot"
    if (-not (Test-Path -Path $reportFolder)) {
        New-Item -Path $reportFolder -ItemType Directory | Out-Null
    }
    
    $reportFullPath = Join-Path -Path $reportFolder -ChildPath $reportFullName

    "Attack Surface Reduction Report" | Out-File -FilePath $reportFullPath -Force
    "===============================" | Out-File -FilePath $reportFullPath -Append
    "`nDate: $timestamp" | Out-File -FilePath $reportFullPath -Append
    "`nScan Results:" | Out-File -FilePath $reportFullPath -Append
    $scanResults | Out-File -FilePath $reportFullPath -Append

    Write-Host "Report generated at: $reportFullPath"
}

# Function to query NVD API for vulnerabilities
function Query-NVD {
    param (
        [string]$apiKey,
        [string]$productName,
        [string]$version
    )

    $baseUrl = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    $queryUrl = "$baseUrl?keyword=$productName&version=$version&apiKey=$apiKey"

    try {
        $response = Invoke-RestMethod -Uri $queryUrl -Method Get -ErrorAction Stop
        return $response
    }
    catch {
        Write-Warning "Failed to query NVD for $productName. Error: $_"
        return $null
    }
}

# Function to check file version and query NVD API for vulnerabilities
function Check-File-With-NVD {
    param (
        [string]$filePath,
        [string]$nvdAPIKey
    )

    # Get file version information
    $file = Get-Item $filePath
    $fileVersionInfo = Get-ItemProperty $filePath
    $productName = $fileVersionInfo.ProductName
    $productVersion = $fileVersionInfo.ProductVersion

    if (-not $productName) {
        return "`n[INFO] No product information available for file: $filePath"
    }

    # Query NVD API with product name and version
    $nvdResponse = Query-NVD -apiKey $nvdAPIKey -productName $productName -version $productVersion

    if ($nvdResponse -and $nvdResponse.result.CVE_Items.Count -gt 0) {
        $vulnerabilities = $nvdResponse.result.CVE_Items | ForEach-Object {
            $_.cve.CVE_data_meta.ID + ": " + $_.cve.description.description_data[0].value
        }
        return "`n[WARNING] Vulnerabilities found for ${filePath}:`n" + ($vulnerabilities -join "`n")
    }
    else {
        return "`n[SAFE] No vulnerabilities found for ${filePath}."
    }
}

# Function to check directory and file permissions
function Check-Permissions {
    param (
        [string]$path
    )

    $permissionResults = "`n[+] Checking for weak file or directory permissions..."
    $files = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue

    foreach ($file in $files) {
        $acl = Get-Acl -Path $file.FullName
        $permissions = $acl.Access | Where-Object { $_.FileSystemRights -match "FullControl" -or $_.FileSystemRights -match "Modify" }
        if ($permissions) {
            $permissionResults += "`n[ALERT] Weak permissions detected on file or directory: $($file.FullName)"
        }
    }

    if (-not $permissions) {
        $permissionResults += "`nNo weak permissions found."
    }

    return $permissionResults
}

# Function to find and check DLL/EXE files with NVD API
function Check-DLL-EXE-Vulnerabilities {
    param (
        [string]$path,
        [string]$nvdAPIKey
    )

    $files = Get-ChildItem -Path $path -Recurse -Include *.dll, *.exe -ErrorAction SilentlyContinue
    $scanResults = ""

    foreach ($file in $files) {
        $filePath = $file.FullName
        $scanResults += Check-File-With-NVD -filePath $filePath -nvdAPIKey $nvdAPIKey
    }

    return $scanResults
}

# Function to perform a port scan using Netstat
function Perform-Port-Scan {
    param ()

    $portScanResults = "`n[+] Performing port scan to detect open ports..."

    # Use netstat to find listening ports (TCP and UDP)
    $netstatOutput = netstat -ano | Select-String "LISTENING"

    foreach ($line in $netstatOutput) {
        # Split the line by whitespace
        $parts = $line -split "\s+"
        if ($parts.Length -ge 5) {
            # Parse protocol, local address (IP and Port), state, and Process ID (PID)
            $protocol = "TCP"  # Assuming TCP since netstat shows LISTENING for TCP connections
            $localAddress = $parts[1]  # IP and Port (like 0.0.0.0:80)
            $state = $parts[3]  # State (LISTENING)
            $processId = $parts[4]  # Process ID (PID)

            # Try to get the associated process name by Process ID (PID)
            try {
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                $processName = if ($process) { $process.ProcessName } else { "Unknown" }
            }
            catch {
                $processName = "Unknown"
            }

            # Format and append the result to portScanResults
            $portScanResults += "`nPort: $protocol - Address: $localAddress - State: $state - Process ID: $processId - Process: $processName"
        }
    }

    if (-not $netstatOutput) {
        $portScanResults += "`nNo open ports found."
    }

    return $portScanResults
}

# Function to crawl directory for .config and .db files
function Crawl-Directory-For-Files {
    param (
        [string]$path
    )

    $crawlResults = "`n[+] Crawling directory for .config and .db files..."

    # Find all .config files
    $configFiles = Get-ChildItem -Path $path -Recurse -Include *.config -ErrorAction SilentlyContinue
    foreach ($file in $configFiles) {
        $crawlResults += "`nFound .config file: $($file.FullName)"
    }

    # Find all .db files
    $dbFiles = Get-ChildItem -Path $path -Recurse -Include *.db -ErrorAction SilentlyContinue
    foreach ($file in $dbFiles) {
        $crawlResults += "`nFound .db file: $($file.FullName)"
    }

    if (-not $configFiles -and -not $dbFiles) {
        $crawlResults += "`nNo .config or .db files found."
    }

    return $crawlResults
}

# Function to perform attack surface reduction
function Perform-AttackSurfaceReduction {
    param (
        [string]$path,
        [bool]$useNvdApi,
        [string]$nvdAPIKey = $null
    )

    # Placeholder for scan results
    $scanResults = ""

    # Check file and directory permissions
    $scanResults += Check-Permissions -path $path

    # If user has NVD API key, check DLL/EXE files for vulnerabilities using NVD API
    if ($useNvdApi -and $nvdAPIKey) {
        $scanResults += Check-DLL-EXE-Vulnerabilities -path $path -nvdAPIKey $nvdAPIKey
    } else {
        $scanResults += "`n[INFO] Skipping NVD API check as no API key was provided."
    }

    # Perform port scan
    $scanResults += Perform-Port-Scan

    # Crawl directory for .config and .db files
    $scanResults += Crawl-Directory-For-Files -path $path

    return $scanResults
}

# Main execution
# Prompt user if they have an NVD API key
$useNvdApi = Read-Host "Do you have an NVD API key? (Yes/No)"

# Determine whether to use NVD API
if ($useNvdApi -eq "Yes") {
    # Prompt for NVD API Key if the user says Yes
    $nvdAPIKey = Read-Host "Enter your NVD API Key"
    $useNvdApi = $true
} else {
    $nvdAPIKey = $null
    $useNvdApi = $false
}

# Perform attack surface reduction scan
$scanResults = Perform-AttackSurfaceReduction -path $location -useNvdApi $useNvdApi -nvdAPIKey $nvdAPIKey

# Prompt user to name the report
$reportName = Read-Host "Enter a name for the report"

# Generate the report
Generate-Report -reportName $reportName -scanResults $scanResults
