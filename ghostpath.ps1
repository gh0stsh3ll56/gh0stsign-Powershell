# Function to prompt user for file or directory input
function Get-PathInput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$inputType
    )

    if ($inputType -eq "file") {
        # Prompt for file path input
        $path = Read-Host "Please enter the full path to the file"
        if (Test-Path $path -PathType Leaf) {
            return $path
        } else {
            Write-Host "Invalid file path. Please try again."
            return Get-PathInput "file"
        }
    } elseif ($inputType -eq "directory") {
        # Prompt for directory path input
        $path = Read-Host "Please enter the full directory path"
        if (Test-Path $path -PathType Container) {
            return $path
        } else {
            Write-Host "Invalid directory path. Please try again."
            return Get-PathInput "directory"
        }
    }
}

# Function to check for unquoted paths
function Check-UnquotedPath {
    param($filePath)

    # Remove any quotes from the path
    $cleanPath = $filePath -replace '"', ''

    # Check if the path contains spaces and is not quoted
    if ($cleanPath -match ' ' -and !$filePath.StartsWith('"')) {
        return $true
    } else {
        return $false
    }
}

# Function to check Microsoft's secure DLL loading guidelines
function Check-DLLLoadingCompliance {
    param($filePath)

    # Define trusted directories according to Microsoft's guidelines
    $trustedDirs = @("C:\Windows\System32", "C:\Windows", "C:\Program Files", "C:\Program Files (x86)")

    # Clean the path (remove quotes)
    $cleanPath = $filePath -replace '"', ''

    # Extract the directory from the file path
    $fileDir = [System.IO.Path]::GetDirectoryName($cleanPath)

    # Check if the file directory is in the trusted list
    if ($trustedDirs -notcontains $fileDir) {
        return $false  # If it's not in the trusted directories, return false
    } else {
        return $true   # Safe if it's in the trusted directories
    }
}

# Function to crawl directory recursively and write results to a report
function Crawl-Directory {
    param($directoryPath, $reportFile)

    # Get all executable files (e.g., .exe, .dll) in the directory and subdirectories
    $files = Get-ChildItem -Path $directoryPath -Recurse -Include *.exe, *.dll

    foreach ($file in $files) {
        $filePath = $file.FullName
        $unquoted = Check-UnquotedPath $filePath
        $dllCompliant = Check-DLLLoadingCompliance $filePath

        if ($unquoted -or !$dllCompliant) {
            Add-Content -Path $reportFile -Value "Security concern found for file: $filePath"
            if ($unquoted) {
                Add-Content -Path $reportFile -Value "  - Unquoted path: $filePath"
            }
            if (!$dllCompliant) {
                Add-Content -Path $reportFile -Value "  - Executable not in a trusted directory: $filePath"
            }
        }
    }
}

# Main script starts here
# Create a folder called 'unquoted_loot' in the current directory
$lootFolder = Join-Path -Path (Get-Location) -ChildPath "unquoted_loot"
if (-not (Test-Path $lootFolder)) {
    New-Item -Path $lootFolder -ItemType Directory | Out-Null
}

# Prompt user for report name
$reportName = Read-Host "Please enter the name for the report (without file extension)"
$reportFile = Join-Path -Path $lootFolder -ChildPath "$reportName.txt"

Write-Host "Would you like to check a single file or a directory?"
$choice = Read-Host "Enter 'file' for single file or 'directory' for recursive directory search"

if ($choice -eq "file") {
    # Get the file path from the user
    $filePath = Get-PathInput "file"
    $unquoted = Check-UnquotedPath $filePath
    $dllCompliant = Check-DLLLoadingCompliance $filePath

    if ($unquoted -or !$dllCompliant) {
        Add-Content -Path $reportFile -Value "Security concern found for file: $filePath"
        if ($unquoted) {
            Add-Content -Path $reportFile -Value "  - Unquoted path: $filePath"
        }
        if (!$dllCompliant) {
            Add-Content -Path $reportFile -Value "  - Executable not in a trusted directory: $filePath"
        }
    } else {
        Add-Content -Path $reportFile -Value "File: $filePath is secure."
    }

} elseif ($choice -eq "directory") {
    # Get the directory path from the user
    $directoryPath = Get-PathInput "directory"
    Crawl-Directory $directoryPath $reportFile
} else {
    Write-Host "Invalid choice. Please restart and choose either 'file' or 'directory'."
}

Write-Host "Report has been saved to: $reportFile"
