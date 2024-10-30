# Script to identify potential vulnerabilities in a specified directory.
# Includes configuration issues, database files, sensitive data, permission issues, services, and network checks.
# Results are saved into a report folder created in the specified directory.

# Prompt the user to enter the directory path to check
$directory = Read-Host "Enter the directory path to check for vulnerabilities"

# Validate if the directory exists
if (-Not (Test-Path $directory)) {
    Write-Host "Directory does not exist. Exiting script." -ForegroundColor Red
    exit
}

# Create a folder for the report in the specified directory
$reportFolder = Join-Path $directory "Vulnerability_Scan_Report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')"
New-Item -ItemType Directory -Path $reportFolder | Out-Null

# Prepare a log file for the findings inside the new folder
$reportFile = Join-Path $reportFolder "Vulnerability_Report.txt"
Add-Content -Path $reportFile -Value "Vulnerability Report for directory: $directory"
Add-Content -Path $reportFile -Value "Generated on: $(Get-Date)"
Add-Content -Path $reportFile -Value "-------------------------------------------"

# Define potential server and database files
$serverFiles = @("web.config", "applicationHost.config", "httpd.conf", "nginx.conf", "php.ini", "*.htaccess")
$databaseFiles = @("*.db", "*.sqlite", "*.sql", "*.mdb", "*.ldf", "*.mdf", "*.ora", "*.ibd", "*.frm", "*.myd", "*.myi")
$configFiles = @("*.config", "*.ini", "*.yml", "*.xml", "*.env", "*.properties")
$sensitiveFiles = @("*.bak", "*.key", "*.pem", "*.pfx", "*.csr", "*.crt", "*.backup", "*.old", "*.log")

# Function to check for the presence of server-related config files
function Check-ServerConfigs {
    Write-Host "Checking for server configuration files..." -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`n[Server Configuration Files]"

    foreach ($file in $serverFiles) {
        Get-ChildItem -Path $directory -Recurse -Filter $file | ForEach-Object {
            Write-Host "Server config file found: $($_.FullName)" -ForegroundColor Yellow
            Add-Content -Path $reportFile -Value "Server config file found: $($_.FullName)"
            # Analyze the file for sensitive data exposure
            Analyze-Config $_.FullName
        }
    }
}

# Function to check for the presence of database-related files
function Check-DatabaseFiles {
    Write-Host "Checking for database files..." -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`n[Database Files]"

    foreach ($file in $databaseFiles) {
        Get-ChildItem -Path $directory -Recurse -Filter $file | ForEach-Object {
            Write-Host "Database file found: $($_.FullName)" -ForegroundColor Yellow
            Add-Content -Path $reportFile -Value "Database file found: $($_.FullName)"
            # Analyze the file for potential misconfigurations
            Analyze-Database $_.FullName
        }
    }
}

# Function to check for sensitive configurations in application files
function Check-ConfigFiles {
    Write-Host "Checking for sensitive application config files..." -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`n[Application Config Files]"

    foreach ($file in $configFiles) {
        Get-ChildItem -Path $directory -Recurse -Filter $file | ForEach-Object {
            Write-Host "Config file found: $($_.FullName)" -ForegroundColor Yellow
            Add-Content -Path $reportFile -Value "Config file found: $($_.FullName)"
            # Analyze the config file for potential vulnerabilities
            Analyze-Config $_.FullName
        }
    }
}

# Function to analyze config files for sensitive information or misconfigurations
function Analyze-Config {
    param ($filePath)
    Write-Host "Analyzing config file: $filePath" -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "Analyzing config file: $filePath"
    $content = Get-Content $filePath

    # Check for common misconfigurations
    if ($content -match "allowOverride\s*none") {
        Write-Host "Found 'allowOverride none' - may prevent local overrides." -ForegroundColor Yellow
        Add-Content -Path $reportFile -Value "'allowOverride none' found."
    }

    if ($content -match "enableRemoteLogin\s*=\s*true") {
        Write-Host "Warning: Remote login is enabled in the config!" -ForegroundColor Red
        Add-Content -Path $reportFile -Value "Warning: Remote login is enabled in $filePath"
    }

    if ($content -match "debug\s*=\s*true") {
        Write-Host "Warning: Debug mode is enabled!" -ForegroundColor Red
        Add-Content -Path $reportFile -Value "Warning: Debug mode is enabled in $filePath"
    }

    # Look for credentials stored in plain text
    if ($content -match "password\s*=\s*.+") {
        Write-Host "Warning: Plain text password found in $filePath" -ForegroundColor Red
        Add-Content -Path $reportFile -Value "Warning: Plain text password found in $filePath"
    }

    # Check for the use of insecure protocols (HTTP instead of HTTPS)
    if ($content -match "http://") {
        Write-Host "Warning: Insecure HTTP protocol detected in $filePath" -ForegroundColor Red
        Add-Content -Path $reportFile -Value "Warning: Insecure HTTP protocol detected in $filePath"
    }

    # Check for weak password policy (if a configuration specifies one)
    if ($content -match "minPasswordLength\s*=\s*[1-7]") {
        Write-Host "Warning: Weak password policy detected (password length less than 8) in $filePath" -ForegroundColor Red
        Add-Content -Path $reportFile -Value "Warning: Weak password policy detected (password length less than 8) in $filePath"
    }
}

# Function to analyze database files for potential misconfigurations
function Analyze-Database {
    param ($filePath)
    Write-Host "Analyzing database file: $filePath" -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "Analyzing database file: $filePath"

    # Check for permissions
    $permissions = Get-Acl $filePath
    if ($permissions.Access | Where-Object { $_.FileSystemRights -eq "FullControl" -and $_.IdentityReference -ne "BUILTIN\Administrators" }) {
        Write-Host "Warning: Non-administrators have full control over $filePath" -ForegroundColor Red
        Add-Content -Path $reportFile -Value "Warning: Non-administrators have full control over $filePath"
    }

    # Check if sensitive database files are accessible by everyone
    if ($permissions.Access | Where-Object { $_.IdentityReference -eq "Everyone" }) {
        Write-Host "Warning: Database file accessible by 'Everyone' on $filePath" -ForegroundColor Red
        Add-Content -Path $reportFile -Value "Warning: Database file accessible by 'Everyone' on $filePath"
    }
}

# Function to check file permissions and ACLs
function Check-Permissions {
    Write-Host "Checking file and directory permissions..." -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`n[Permission Checks]"

    Get-ChildItem -Path $directory -Recurse | ForEach-Object {
        $acl = Get-Acl $_.FullName
        if ($acl.Access | Where-Object { $_.FileSystemRights -eq "FullControl" -and $_.IdentityReference -ne "BUILTIN\Administrators" }) {
            Write-Host "Warning: Full control for non-administrator on $($_.FullName)" -ForegroundColor Red
            Add-Content -Path $reportFile -Value "Warning: Full control for non-administrator on $($_.FullName)"
        }

        if ($acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" }) {
            Write-Host "Warning: File accessible by 'Everyone' on $($_.FullName)" -ForegroundColor Red
            Add-Content -Path $reportFile -Value "Warning: File accessible by 'Everyone' on $($_.FullName)"
        }
    }
}

# Function to check for running services related to web servers or databases
function Check-RunningServices {
    Write-Host "Checking for related running services..." -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`n[Running Services]"

    $services = Get-Service | Where-Object { $_.DisplayName -match "IIS|Apache|MySQL|MSSQL|MongoDB|Oracle|PostgreSQL" }

    if ($services.Count -eq 0) {
        Write-Host "No relevant services are running on the machine." -ForegroundColor Green
        Add-Content -Path $reportFile -Value "No relevant services are running on the machine."
    } else {
        Write-Host "Relevant services running:" -ForegroundColor Yellow
        Add-Content -Path $reportFile -Value "Relevant services running:"
        $services | ForEach-Object {
            Write-Host "$($_.DisplayName) - Status: $($_.Status)"
            Add-Content -Path $reportFile -Value "$($_.DisplayName) - Status: $($_.Status)"
        }
    }
}

# Function to check for open ports and firewall rules
function Check-NetworkSecurity {
    Write-Host "Checking firewall status and open ports..." -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`n[Network Security]"

    # Check Windows Firewall status
    $firewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
    Write-Host "Windows Firewall status:" -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "Windows Firewall status:"
    $firewallStatus | ForEach-Object {
        Write-Host "$($_.Name) - Enabled: $($_.Enabled)"
        Add-Content -Path $reportFile -Value "$($_.Name) - Enabled: $($_.Enabled)"
    }

    # List open ports
    Write-Host "Open ports:" -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`n[Open Ports]"
    Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | ForEach-Object {
        Write-Host "Port $($_.LocalPort) is open on $($_.LocalAddress)" -ForegroundColor Yellow
        Add-Content -Path $reportFile -Value "Port $($_.LocalPort) is open on $($_.LocalAddress)"
    }
}

# Function to search for sensitive file types (e.g., backup files, certificates)
function Check-SensitiveFiles {
    Write-Host "Checking for sensitive file types..." -ForegroundColor Cyan
    Add-Content -Path $reportFile -Value "`n[Sensitive Files]"

    foreach ($file in $sensitiveFiles) {
        Get-ChildItem -Path $directory -Recurse -Filter $file | ForEach-Object {
            Write-Host "Sensitive file found: $($_.FullName)" -ForegroundColor Yellow
            Add-Content -Path $reportFile -Value "Sensitive file found: $($_.FullName)"
        }
    }
}

# Execute the functions
Check-ServerConfigs
Check-DatabaseFiles
Check-ConfigFiles
Check-Permissions
Check-RunningServices
Check-NetworkSecurity
Check-SensitiveFiles

Write-Host "Vulnerability scan completed! Report saved to $reportFile" -ForegroundColor Green
Add-Content -Path $reportFile -Value "`nScan completed successfully."
