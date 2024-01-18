param (
    [string]$directoryPath = $(Read-Host "Please enter the directory path to scan"),
    [string]$outputDirectory = $(Read-Host "Please enter the output directory path"),
    [string]$outputLogFileName = $(Read-Host "Please enter the name for the output report file"),
    [switch]$verbose
)

$outputLogFile = Join-Path $outputDirectory $outputLogFileName

# Define advanced regex patterns for sensitive data
$patterns = @{
    "Key or Secret" = "\b(?:key|secret)\s*[:=]\s*\S+"
    "Password" = "\bpassword\s*[:=]\s*\S+"
    "Hexadecimal String" = "\b[a-fA-F0-9]{16,}\b"  # At least 16 characters long to reduce false positives
    "Base64 String" = "\b[A-Za-z0-9+/=]{16,}\b"  # At least 16 characters long to reduce false positives
    "Hardcoded Token (Java)" = "\b(?:private|public|protected)?\s+(?:static\s+)?(?:final\s+)?String\s+\w+\s*=\s*`"[^`"]+`""
    "IP Address" = "\b\d{3}\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b"
    "Email Address" = "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    "Database Connection String" = "Server=(.*);Database=(.*);User Id=(.*);Password=(.*)"
    "AWS Secret Key" = "(?i)aws(.{0,20})['""=](?:[A-Za-z0-9/\+=]{40})"
    "Azure Token" = "\b[A-Za-z0-9+/=]{50,}\b"  # Azure tokens, typically long base64 strings
    "Admin User" = "\b(?:admin|administrator|root)\b"
    "Database User" = "\b(?:db|database|sql)_?user(?:name)?\s*[:=]\s*\S+"
    "Database Password" = "\b(?:db|database|sql)_?password\s*[:=]\s*\S+"
}

# Initialize counters
$foundItemCount = 0

# Verify if the provided directory path exists
if (-not (Test-Path $directoryPath)) {
    Write-Host "The provided directory path for scanning does not exist or is not accessible."
    return
}

# Verify if the output directory exists, if not, create it
if (-not (Test-Path $outputDirectory)) {
    Write-Host "Output directory does not exist. Creating directory."
    New-Item -Path $outputDirectory -ItemType Directory
}

# Get all files in the directory and its subdirectories
$files = Get-ChildItem -Path $directoryPath -Recurse -File
$totalFileCount = $files.Count

# Create/Clear the output log file
if (Test-Path $outputLogFile) { Clear-Content $outputLogFile } else { New-Item $outputLogFile -ItemType File }

# Function to search within a file and log findings
function Search-File {
    param (
        [string]$filePath
    )

    if ($verbose) {
        Write-Host "Scanning file: $filePath"
    }

    try {
        $reader = [System.IO.StreamReader]::new($filePath)
        while ($reader.Peek() -ge 0) {
            $line = $reader.ReadLine()

            foreach ($patternName in $patterns.Keys) {
                if ($line -match $patterns[$patternName]) {
                    $matchesFound = $Matches.Values
                    foreach ($match in $matchesFound) {
                        $message = "$patternName found in $filePath - Match: $match"
                        Add-Content $outputLogFile $message
                        $foundItemCount++
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Error reading file: $filePath"
    }
    finally {
        if ($reader -ne $null) {
            $reader.Close()
        }
    }
}

# Iterate over each file and search for sensitive data
$processedFileCount = 0
foreach ($file in $files) {
    Search-File -filePath $file.FullName

    $processedFileCount++
    if ($verbose) {
        $percentageComplete = [math]::Round(($processedFileCount / $totalFileCount) * 100, 2)
        Write-Host "$processedFileCount of $totalFileCount files processed ($percentageComplete% complete)"
    }
}

Write-Host "Scan completed. Total files scanned: $totalFileCount"
Write-Host "Total items found: $foundItemCount"
Write-Host "Results are logged in $outputLogFile"
