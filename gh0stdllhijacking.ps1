# Extensive Script to check for potential DLL hijacking vulnerabilities similar to PowerSploit's DLL Hijacking checks
# and store results in a custom-named report within a DLL_Loot folder

# Determine where the script is being executed from
if ($PSScriptRoot) {
    # Use the script's location
    $baseFolder = $PSScriptRoot
} else {
    # Use the current working directory as a fallback
    $baseFolder = Get-Location
}

# Prompt the user for the directory to check
$directory = Read-Host "Please enter the directory path to scan for DLL hijacking"

# Validate if the directory exists
if (-Not (Test-Path -Path $directory)) {
    Write-Host "The directory does not exist. Exiting..." -ForegroundColor Red
    exit
}

# Prompt the user to name the report
$reportName = Read-Host "Please enter a name for the report (without extension)"
$reportName = $reportName -replace '\s', '_'

# Create the DLL_Loot folder in the same directory where the PowerShell script is located, if it doesn't already exist
$lootFolder = Join-Path -Path $baseFolder -ChildPath "DLL_Loot"
if (-Not (Test-Path -Path $lootFolder)) {
    New-Item -Path $lootFolder -ItemType Directory | Out-Null
    Write-Host "Created folder: $lootFolder" -ForegroundColor Green
} else {
    Write-Host "DLL_Loot folder already exists at: $lootFolder" -ForegroundColor Yellow
}

# Array to store findings
$dllHijackingFindings = @()

# List of common vulnerable DLL names
$commonVulnerableDlls = @("user32.dll", "kernel32.dll", "ntdll.dll", "advapi32.dll", "gdi32.dll", "shell32.dll")

# Function to check for DLL hijacking opportunities
function Test-DLLHijack {
    param (
        [string]$filePath
    )

    $acl = Get-Acl $filePath
    $insecureDll = $false
    $insecureDir = $false

    # Look for entries in the ACL that indicate the file itself is writable by "Everyone" or "Authenticated Users"
    foreach ($access in $acl.Access) {
        if ($access.IdentityReference -match "Everyone|Authenticated Users" -and $access.FileSystemRights -match "Write") {
            $insecureDll = $true
        }
    }

    # If the DLL itself is insecure, add to findings
    if ($insecureDll) {
        $dllHijackingFindings += [PSCustomObject]@{
            FilePath = $filePath
            Reason   = "DLL file is writable by Everyone/Authenticated Users"
            PoC      = "Replace this DLL with a malicious version to exploit."
        }
    }

    # Now check if the directory where the DLL resides is insecure
    $dirPath = Split-Path -Parent $filePath
    $dirAcl = Get-Acl $dirPath

    foreach ($access in $dirAcl.Access) {
        if ($access.IdentityReference -match "Everyone|Authenticated Users" -and $access.FileSystemRights -match "Write") {
            $insecureDir = $true
        }
    }

    # If the directory is insecure, add to findings
    if ($insecureDir) {
        $dllHijackingFindings += [PSCustomObject]@{
            FilePath = $dirPath
            Reason   = "DLL directory is writable by Everyone/Authenticated Users"
            PoC      = "Place a malicious DLL in this directory to exploit hijacking vulnerabilities."
        }
    }
}

# Function to check for missing DLLs
function Check-MissingDll {
    param (
        [string]$dllName,
        [string]$path
    )
    
    $dllPath = Join-Path -Path $path -ChildPath $dllName

    # If DLL doesn't exist, it may be a hijacking opportunity
    if (-Not (Test-Path -Path $dllPath)) {
        $dllHijackingFindings += [PSCustomObject]@{
            FilePath = $path
            Reason   = "DLL '$dllName' missing in this directory."
            PoC      = "Place a malicious DLL named '$dllName' in this directory to exploit."
        }
    }
}

# Function to check for DLLs being loaded from untrusted paths (non-system paths)
function Check-UntrustedPath {
    param (
        [string]$dllPath
    )

    $systemPaths = @("C:\Windows\System32", "C:\Windows\SysWOW64")

    $dirPath = Split-Path -Parent $dllPath

    # Check if the DLL is being loaded from a non-system path
    if (-Not ($systemPaths -contains $dirPath)) {
        $dllHijackingFindings += [PSCustomObject]@{
            FilePath = $dllPath
            Reason   = "DLL loaded from untrusted path: $dirPath"
            PoC      = "Replace the DLL with a malicious version to exploit."
        }
    }
}

# Function to perform extensive checks similar to PowerSploit
function PowerSploitDLLHijackCheck {
    param (
        [string]$filePath
    )

    # Check if the DLL is missing, writable, or loaded from an untrusted path
    Test-DLLHijack -filePath $filePath
    Check-UntrustedPath -dllPath $filePath

    # Additional PowerSploit-style checks: simulate path hijacking checks
    $parentDir = Split-Path -Parent $filePath
    $dllName = Split-Path -Leaf $filePath

    # Search for the DLL in common directories, and if it's not found, flag it for hijacking
    if (-Not (Test-Path "$parentDir\$dllName")) {
        $dllHijackingFindings += [PSCustomObject]@{
            FilePath = $filePath
            Reason   = "DLL search path vulnerability (DLL not found)"
            PoC      = "Place a malicious DLL in this directory to exploit DLL search order."
        }
    }
}

# Recursively scan the specified directory for DLL files
Get-ChildItem -Path $directory -Recurse -Filter *.dll | ForEach-Object {
    # Perform PowerSploit-style DLL hijacking checks
    PowerSploitDLLHijackCheck -filePath $_.FullName
}

# Check for known vulnerable DLLs in the directory and check if they are missing
$pathsToCheck = @("C:\Program Files", "C:\Windows\System32", "C:\Windows\SysWOW64", "C:\ProgramData")
foreach ($path in $pathsToCheck) {
    foreach ($dll in $commonVulnerableDlls) {
        Check-MissingDll -dllName $dll -path $path
    }
}

# Check for weak folder permissions that could lead to DLL hijacking
Get-ChildItem -Path $directory -Recurse -Directory | ForEach-Object {
    $acl = Get-Acl $_.FullName
    foreach ($access in $acl.Access) {
        if ($access.IdentityReference -match "Everyone|Authenticated Users" -and $access.FileSystemRights -match "Write") {
            $dllHijackingFindings += [PSCustomObject]@{
                FilePath = $_.FullName
                Reason   = "Directory writable by Everyone/Authenticated Users"
                PoC      = "Place a malicious DLL in this directory to exploit potential hijacking."
            }
        }
    }
}

# Create the report path
$reportPath = Join-Path -Path $lootFolder -ChildPath "$reportName.txt"

# Report generation
$dllHijackingFindings | ForEach-Object {
    Add-Content -Path $reportPath -Value "Location: $($_.FilePath)"
    Add-Content -Path $reportPath -Value "Reason: $($_.Reason)"
    Add-Content -Path $reportPath -Value "Proof of Concept: $($_.PoC)"
    Add-Content -Path $reportPath -Value "-----------------------------"
}

# Check if findings exist
if ($dllHijackingFindings.Count -eq 0) {
    Write-Host "No potential DLL hijacking vulnerabilities found in the directory." -ForegroundColor Green
} else {
    Write-Host "DLL Hijacking Report generated at: $reportPath" -ForegroundColor Yellow
}
