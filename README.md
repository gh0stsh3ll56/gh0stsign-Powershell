# gh0stsign-Powershell
Powershell Script to enumerate directories or files to view permissions and file signing property.

REQUIREMENTS FOR POWERSHELL SCRIPT

Operating System:
- Windows 10 or later

PowerShell Version:
- Windows PowerShell 5.1 or later
- PowerShell Core 6.0 or later (Optional, for cross-platform compatibility)

User Permissions:
- Script must be run with a user account that has read access to the target directory and files.
- Administrative privileges may be required for accessing certain system directories or files.

Additional Notes:
- No external modules or packages are required.
- Ensure Execution Policy in PowerShell allows script execution (use 'Set-ExecutionPolicy' cmdlet if needed).

Usage:
- Save the script as 'YourScriptName.ps1'.
- Run the script in PowerShell with required parameters:
  .\gh0stsign.ps1 -Path "C:\path\to\directory" -ReportPath "C:\path\to\report.txt"
