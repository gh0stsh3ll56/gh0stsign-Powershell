[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [string]$ReportPath = "FileSecurityReport.txt"
)

function Display-Menu {
    Write-Host "PowerShell File Security Analysis Script"
    Write-Host "---------------------------------------"
    Write-Host "This script checks the security status of files in a specified directory."
    Write-Host "It reports on whether each file is signed and outputs the signature details."
    Write-Host "Additionally, it displays the security properties of each file."
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\YourScriptName.ps1 -Path <Path to directory or file> [-ReportPath <Path to save report>]"
    Write-Host ""
    Write-Host "Example:"
    Write-Host "  .\YourScriptName.ps1 -Path 'C:\MyFolder' -ReportPath 'C:\MyReport.txt'"
    Write-Host "---------------------------------------"
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Check-FileSecurity {
    param (
        [string]$FilePath
    )

    Write-Verbose "Checking file: $FilePath"
    $fileInfo = Get-Item $FilePath
    $fileSecurity = Get-Acl $FilePath
    $securityProperties = $fileSecurity | Select-Object -ExpandProperty Access | Out-String
    
    try {
        $signature = Get-AuthenticodeSignature $FilePath
        $signStatus = if ($signature.Status -ne 'NotSigned') { $signature.Status } else { "Not Signed" }
        $signSubject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "N/A" }
    } catch {
        Write-Warning "Unable to access file: $FilePath. It may be in use by another process."
        $signStatus = "Access Denied"
        $signSubject = "Access Denied"
    }

    $fileSecurityDetails = @{
        Path              = $fileInfo.FullName
        SignatureStatus   = $signStatus
        SignatureSubject  = $signSubject
        SecurityProperties = $securityProperties.Trim()
    }

    return $fileSecurityDetails
}

function Generate-Report {
    param (
        [array]$FileSecurities
    )

    Write-Verbose "Generating report..."
    $signedFiles = $FileSecurities | Where-Object { $_.SignatureStatus -ne 'Not Signed' }
    $unsignedFiles = $FileSecurities | Where-Object { $_.SignatureStatus -eq 'Not Signed' }
    $totalFiles = $FileSecurities.Count
    $filesWithIssues = $FileSecurities | Where-Object { $_.SignatureStatus -eq 'Access Denied' }

    $signedCount = $signedFiles.Count
    $unsignedCount = $unsignedFiles.Count
    $filesWithIssuesCount = $filesWithIssues.Count

    $extensionGroups = $FileSecurities | Group-Object { [System.IO.Path]::GetExtension($_.Path) }

    $report = "File Security Report`n"
    $report += "=" * 20 + "`n"
    $report += "Total Files Scanned: $totalFiles`n"
    $report += "Number of Unsigned Files: $unsignedCount`n"
    $report += "Number of Files with Issues: $filesWithIssuesCount`n"
    $report += "`nUnsigned Files:`n"
    $report += "=" * 20 + "`n"

    foreach ($file in $unsignedFiles) {
        $report += "File: $($file.Path)`n"
    }

    $report += "`nFiles with Issues:`n"
    $report += "=" * 20 + "`n"
    foreach ($file in $filesWithIssues) {
        $report += "File: $($file.Path)`n"
    }

    $report += "`nFile Extensions Summary:`n"
    $report += "=" * 20 + "`n"
    foreach ($group in $extensionGroups) {
        $report += "Extension $($group.Name): $($group.Count) Files`n"
    }

    Set-Content -Path $ReportPath -Value $report
    Write-Host "Report generated at $ReportPath"
}


Display-Menu

if (-not (Test-Path -Path $Path)) {
    Write-Error "The specified path does not exist."
    exit
}

if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    Write-Error "Report path is not specified."
    exit
}

if (Test-Path -Path $Path -PathType Container) {
    Write-Verbose "Path is a directory. Checking all files within $Path"
    $allFiles = Get-ChildItem -Path $Path -Recurse -File
} else {
    Write-Verbose "Path is a file. Checking file $Path"
    $allFiles = Get-Item -Path $Path
}

$fileSecurities = @()
$totalFiles = $allFiles.Count
$currentFileIndex = 0

foreach ($file in $allFiles) {
    $currentFileIndex++
    $percentComplete = ($currentFileIndex / $totalFiles) * 100
    Write-Progress -Activity "Analyzing Files" -Status "$currentFileIndex of $totalFiles" -PercentComplete $percentComplete
    $fileSecurities += Check-FileSecurity -FilePath $file.FullName
}

Generate-Report -FileSecurities $fileSecurities
