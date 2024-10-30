# gh0stedPowershell

Powershell scripts that will conduct checks to identify misconfigurations or potential internal vulnerabilites against file paths.

gh0stasr.ps1: Conducts checks that helps conduct Attack surface reducting. The script identifies open ports, API's, and endpoints that are used based on the files being hosted internally from the file path.

gh0stdllhijacking: Conducts searches on directory paths internally to identify potential dllhijacking.

gh0stpermissions: Conducts checks on the file permissions based on the directory provided to find misconfigurations.

gh0stsign: conducts checks on the directory or file provided to identify security risks of unsigned files

gh0ststrings: Scans directories and craws file directories to look for potential secrets.

ghostpath: scans internal direcotry paths looking for misconfigurations and vulnerabilities.

ghostsecurity: conducts common checks on the file paths presented looking for common security issues. If an endpoint is identifed, curl commands will be ran against it to check for potenial low hanging fruit vulnerabilites. 
