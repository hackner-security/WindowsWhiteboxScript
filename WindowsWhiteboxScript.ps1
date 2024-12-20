#Requires -version 2.0

<#
.SYNOPSIS
    Performing a whitebox check of the Windows operating system.
.DESCRIPTION
    The following Powershell script performs a whitebox check of the Windows
    operating system it is running on. The check includes general information
    about the operating system like the hostname, network configuration,
    information about open ports, file system permissions, installed programs,
    processes, services and service paths, patch level, RDP configuration,
    security configuration, the local group policy, WSUS settings, SMB settings,
    antivirus information, possibilities for privilege escalation, user account
    control, credential protection, spoofable protocols.
.NOTES
    File Name     : WindowsWhiteboxScript.ps1
    Author        : HACKNER Security Intelligence GmbH
    Prerequisite  : PowerShell V2 over Windows Server 2008 R2 and upper.
.PARAMETER outputdir
    The results are written to the directory specified here - this can also be
    a file share. Per default a folder is created named after the hostname.
.PARAMETER paths
    String or String array containing paths for which ACLs should be dumped.
    Per default the Program Files paths are scanned.
.PARAMETER force
    Forces script execution if the calling user is no administrator
.PARAMETER onlyJson
    Possibility to only create result JSON for automated analyses; nothing else!
.PARAMETER testing
    Shows error messages on the command line instead of piping them to a file
.PARAMETER dumpPermissions
    Dumps permissions of the paths set via the parameter paths (default Program
    Files)
.PARAMETER version
    Display the script version
.PARAMETER captureTraffic
    Capture the network traffic of the host for a certain amount of time. The time
    can be specified in seconds.
.PARAMETER generateCommandList
    Generate a list of commands that could be executed individually
#>
param(
    [string] $outputdir = (Get-Item -Path ".\").FullName,
    [switch] $testing = $false,
    [string[]] $paths = @(),
    [switch] $force = $false,
    [switch] $version = $false,
    [switch] $dumpPermissions = $false,
    [switch] $onlyJson = $false,
    [int] $captureTraffic,
    [switch] $generateCommandList
)

# Version
$versionString = "v3.7.2"

# Check permissions of the following paths
$paths += $env:ProgramFiles
$paths += ${env:ProgramFiles(x86)}
$outputdir = "$outputdir\$ENV:ComputerName"

# File and section names
$filenames = @{
    "secedit"              = "secedit_output.inf"
    "aclsdirname"          = "ACLs"
    "logfile"              = "console.log"
    "errorlog"             = "error.log"
    "autostart"            = "autostart"
    "antivirus"            = "antivirus"
    "openports"            = "open_ports"
    "rdp"                  = "rdp"
    "unquotedservices"     = "unquoted_services"
    "unattend"             = "unattend"
    "installedprograms"    = "installed_programs"
    "services"             = "services"
    "processes"            = "processes"
    "network"              = "network"
    "basicinfo"            = "basic_information"
    "host"                 = "host"
    "patchlevel"           = "patchlevel"
    "psremote"             = "powershell_remoting"
    "firewall"             = "firewall"
    "smb"                  = "smb"
    "groups"               = "groups"
    "gpresult"             = "gpresult.html"
    "autologon"            = "autologon"
    "responder"            = "responder_protocols"
    "privilegeEscalation"  = "privilege_escalation"
    "wsus"                 = "wsus"
    "credentialProtection" = "credential_protection"
    "uac"                  = "user_account_control"
    "bitlocker"            = "bitlocker"
    "tasks"                = "scheduled_tasks"
    "devicesec"            = "device_security"
    "cmdlist"              = "command_list"
    "mssql"                = "mssql_configuration"
    "nfs"                  = "nfs"
    "drivers"              = "drivers"
    "spooler"              = "print_spooler"
    "asrrules"             = "asr_rules"
}

$rememberFormatEnumerationLimit = $null
$psVersion = $null
$outputFileContents = @{}
$Script:InformationPreference = "Continue"
# Do not display progress bars in order to not break certain connections (e.g., SSH)
$Script:ProgressPreference = "SilentlyContinue"

function Invoke-Setup {

    # If version parameter is specified, only display version of script and exit
    if ($script:version) {
        Write-Output "Script Version: $versionString"
        Exit
    }

    # Check for administrator privileges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (!$script:force -and !$isAdmin) {
        Write-Warning "[-] This script needs to be run with admin privileges. To run it with lower privileges, the -Force option can be used."
        Exit
    }

    # Remove previously generated folders
    if ($script:testing) {
        Remove-Item -Recurse $outputdir
        Remove-Item $outputdir
        $script:DebugPreference = "Continue"
    }
    else {
        $script:ErrorActionPreference = "SilentlyContinue"
    }

    # Create output directory if they do not already exist
    if (!(Test-Path "$outputdir")) {
        New-Item -ItemType directory -Path $outputdir | Out-Null
    }

    $Script:startTime = Get-Date -UFormat '%Y/%m/%d %H:%M'
    Write-Data -Output "Started script execution." -File $filenames.logfile -useWriteOutput

    # Store the script version in log files
    Write-Data -Output "Script version: $versionString" -File $filenames.logfile -useWriteOutput

    # Print the powershell version
    $Script:psversion = $PSVersionTable.PSVersion
    Write-Data -Output "Powershell version: $($psversion.Major).$($psversion.Minor)" -File $filenames.logfile -useWriteOutput
    Write-Data -Output "Output directory: $outputdir" -File $filenames.logfile -useWriteOutput

    #Change the enumeration limit, so our outputs do not get truncated on 4 elements
    # (do to a PowerShell bug, we have to set it globally during the script execution and set at back at the end)
    $script:rememberFormatEnumerationLimit = $global:FormatEnumerationLimit
    $global:FormatEnumerationLimit = -1
    Write-Data -Output "Global FormatEnumerationLimit: $script:rememberFormatEnumerationLimit" -File $filenames.logfile

}

function Invoke-Teardown {

    # Set enumeration limit back to what it was before
    $global:FormatEnumerationLimit = $script:rememberFormatEnumerationLimit
    Write-Data -Output "Reset FormatEnumerationLimit to $global:FormatEnumerationLimit" -File $filenames.logfile

    If (-Not $onlyJson) {
        # Write encountered errors to log file
        Write-Data -Output $Error -File $filenames.errorlog

        # Write output to result folder
        foreach ($h in $outputFileContents.Keys) {
            Add-Content -Path "$outputdir\$h.txt" -Value $outputFileContents.Item($h)
        }

        # Compress files for easier copying
        Compress-Result
    }

    Write-Data -Output "All Done." -File $filenames.logfile -useWriteOutput
}

#Writes to console screen and output file
function Write-Data() {
    param (
        [parameter(Mandatory = $true)] $Output,
        [parameter(Mandatory = $true)][String] $File,
        [switch] $useWriteOutput,
        [switch] $useWriteInformation
    )

    if ($useWriteInformation) {
        $time = Get-Date -UFormat '%Y/%m/%d %H:%M'
        Write-Information -MessageData "[*] $time - $Output"
    }
    elseif ($useWriteOutput) {
        # Put $Output in the stream, so it is returned by the function. Use this parameter with care if you
        # are not handling the output accordingly
        $time = Get-Date -UFormat '%Y/%m/%d %H:%M'
        Write-Output "[*] $time - $Output"
    }
    else {
        Write-Debug "$Output"
    }

    if (-Not $outputFileContents.ContainsKey($File)) {
        $outputFileContents.$File = ($Output | Out-String -Width 4096)
    }
    else {
        $outputFileContents.$File += ($Output | Out-String -Width 4096)
    }

}

function Invoke-PowerShellCommandAndDocumentation {
    param(
        [Parameter(Mandatory = $true)][scriptblock] $scriptBlock,
        [Parameter(Mandatory = $true)][string] $headline,
        [Parameter(Mandatory = $true)][string] $outputFile
    )
    if ($script:generateCommandList) {
        Write-Data -Output "### [PowerShell] $headline" -File $filenames.cmdlist
        Write-Data -Output $scriptBlock -File $filenames.cmdlist
    }

    Write-Data -Output "### $headline ###" -File $outputFile
    Write-Data -Output "[Command][PS] $scriptBlock" -File $outputFile
    $commandResult = & $scriptBlock
    Write-Data -Output $commandResult -File $outputFile

}

function Invoke-CmdCommandAndDocumentation {
    param(
        [Parameter(Mandatory = $true)][string] $command,
        [string] $subPath = "",
        [string] $headline = "",
        [Parameter(Mandatory = $true)][string] $outputFile,
        [string] $manualCommandListOverride
    )
    if ($script:generateCommandList) {
        Write-Data -Output "### [CMD] $headline" -File $filenames.cmdlist
        if ($manualCommandListOverride) {
            Write-Data -Output $manualCommandListOverride -File $filenames.cmdlist
        }
        else {
            Write-Data -Output $command -File $filenames.cmdlist
        }
    }

    if ($headline) {
        Write-Data -Output "### $headline ###" -File $outputFile
    }
    $windirPath = "%windir%\System32\"
    Write-Data -Output "[Command][CMD] $command" -File $outputFile
    $commandResult = & "$env:windir\System32\cmd.exe" /c "$windirPath\$subpath\$command 2> nul"
    # For external executables, try-catch blocks cannot be used. We need to check $LASTEXITCODE instead
    if ($LASTEXITCODE -ne 0) {
        Write-Data -Output "[Error] Command execution failed." -File $outputFile
    }
    Write-Data -Output $commandResult -File $outputFile

}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string] $path,
        [Parameter(Mandatory = $true)][string] $key,
        [Parameter(Mandatory = $true)][string] $outputFile,
        [switch] $censor
    )
    if ($script:generateCommandList) {
        Write-Data -Output "### [Registry] $path\$key" -File $filenames.cmdlist
        Write-Data -Output "### [PowerShell command for registry]" -File $filenames.cmdlist
        Write-Data -Output "(Get-ItemProperty `"$path`").`"$key`"" -File $filenames.cmdlist
    }

    try {
        # Use ErrorAction Stop here in order to trigger the catch block if the registry item cannot be found
        $result = (Get-ItemProperty -Path $path -Name $key -ErrorAction Stop).$key
        $returnValue = $result
        if ($censor) {
            $resultString = "(censored)"
        }
        else {
            $resultString = $result
        }
    }
    catch {
        $returnValue = -1
        $resultString = "not found!"
    }

    Write-Data -Output "[Registry] $path\$key = $resultString" -File $outputFile
    $returnValue
}

function Compress-Result {

    $zipFilename = "results.zip"
    $zipFilepath = (Get-Item -Path ".\").FullName
    $zipFile = "$zipFilepath\$zipFilename"

    if ($Script:psVersion.Major -ge 5) {
        Compress-Archive -Path $outputdir -DestinationPath "$outputdir\$zipFilename"
    }
    else {

        # Compression method for Powershell < 5
        if (-not (Test-Path($zipFile))) {
            Set-Content $zipFile ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
            (Get-ChildItem $zipFile).IsReadOnly = $false
        }

        $shellApplication = New-Object -com shell.application
        $zipPackage = $shellApplication.NameSpace($zipFile)
        $files = Get-ChildItem -Path $outputdir -Recurse | Where-Object { ! $_.PSIsContainer }

        foreach ($file in $files) {
            $zipPackage.CopyHere($file.FullName)
            # using this method, sometimes files can be 'skipped'
            # this 'while' loop checks each file is added before moving to the next
            while ($null -eq $zipPackage.Items().Item($file.name)) {
                Start-Sleep -Milliseconds 250
            }
        }
        Move-Item -Path $zipFile -Destination "$outputdir"
    }
}

# Check if the given path is writable to low-privilged accounts
function Test-Writable {
    param(
        [string] $pathItem,
        [switch] $complexServicePath
    )
    # SIDs for well-known groups in order to handle different locales
    $sidUsers = "S-1-5-32-545"
    $sidAuthenticatedUser = "S-1-5-11"
    $sidGuest = "S-1-5-32-546"
    $sidEveryone = "S-1-1-0"

    # Convert this SIDs to the corresponding groups
    $tmp = New-Object System.Security.Principal.SecurityIdentifier($sidUsers)
    $usersLocale = $tmp.Translate([System.Security.Principal.NTAccount]).Value
    $tmp = New-Object System.Security.Principal.SecurityIdentifier($sidAuthenticatedUser)
    $authenticatedUsersLocale = $tmp.Translate([System.Security.Principal.NTAccount]).Value
    $tmp = New-Object System.Security.Principal.SecurityIdentifier($sidGuest)
    $guestsLocale = $tmp.Translate([System.Security.Principal.NTAccount]).Value
    $tmp = New-Object System.Security.Principal.SecurityIdentifier($sidEveryone)
    $everyoneLocale = $tmp.Translate([System.Security.Principal.NTAccount]).Value

    # Here for quoted paths, quotes are removed
    if ($pathItem.Contains('"')) {
        $pathItem = ($pathItem.split('"') | Select-Object -Index 0, 1) -join ''
        $pathItem = $pathItem.Trim()
        $pathItem = $pathItem.Trim()
    }
    elseif ($complexServicePath) {
        # TODO: this might not cover sth like "C:\folder.exe foldercontinued\test.exe
        $pathItem = $pathItem.Trim()
        $pos = $pathItem.IndexOf('.exe ')
        if ($pos -ne -1) {
            $pathItem = $pathItem.Substring(0, $pos + 4)
        }
    }

    $resultList = @()
    #We want to check the permissions of the executable itself and the containing folder
    if ($complexServicePath) {
        $pathsToCheck = @(($pathItem), ($pathItem | Split-Path))
    }
    else {
        $pathsToCheck = @($pathItem)
    }

    $writePermissionsFolder = ("FullControl", "CreateFiles", "ChangePermissions", "TakeOwnership", "Write", "Modify")
    $writePermissionsFile = ("FullControl", "WriteData", "AppendData", "ChangePermissions", "TakeOwnership", "Write", "Modify")

    # Well, this is a real pickle here. Windows file system rights are a combination of permissions, identities, inheritance and propagation
    foreach ($pathToCheck in $pathsToCheck) {
        $pathToCheck = $pathToCheck.Trim('"')
        # Convert the path to a real path (not containing things like %windir% or %systemroot%)
        $pathToCheck = [System.Environment]::ExpandEnvironmentVariables($pathToCheck)
        if (Test-Path -Path $pathToCheck) {
            $acls = Get-Acl -Path $pathToCheck | Select-Object -ExpandProperty Access
            $writableAcls = @()
            foreach ($acl in $acls) {
                if (($acl.IdentityReference -eq "$usersLocale") -or ($acl.IdentityReference -eq "$authenticatedUsersLocale") -or ($acl.IdentityReference -eq "$guestsLocale") -or ($acl.IdentityReference -eq "$everyoneLocale")) {
                    if (Test-Path -Path $pathToCheck -PathType Container) {
                        # If the path is a folder, we check if we can write something into the folder (this checks permissions, inheritance and propagation flags)
                        if (($acl.AccessControlType -eq 0) -and (($writePermissionsFolder | ForEach-Object { $acl.FileSystemRights.tostring().contains($_) }) -contains $true)) {
                            if (($acl.PropagationFlags.toString() -eq "None")) {
                                # If the propagation flag is not none, permissions are propagated to sub-folders which actually does not matter here
                                $writableAcls += @{
                                    FileSystemRights  = $acl.FileSystemRights.toString()
                                    IdentityReference = $acl.IdentityReference.Value
                                    InheritanceFlags  = $acl.InheritanceFlags.toString()
                                    PropagationFlags  = $acl.PropagationFlags.toString()
                                }
                            }
                        }
                    }
                    else {
                        # If the path is a file, we just check the permissions and do not need to care about propagation and inheritance flags
                        if (($acl.AccessControlType -eq 0) -and (($writePermissionsFile | ForEach-Object { $acl.FileSystemRights.tostring().contains($_) }) -contains $true)) {
                            $writableAcls += @{
                                FileSystemRights  = $acl.FileSystemRights.toString()
                                IdentityReference = $acl.IdentityReference.Value
                                InheritanceFlags  = "$($acl.InheritanceFlags.toString()) (not important for files)"
                                PropagationFlags  = "$($acl.PropagationFlags.toString()) (not important for files)"
                            }
                        }
                    }
                }
            }
            if ($writableAcls.Count -gt 0) {
                $resultList += @{
                    path = $pathToCheck
                    acls = $writableAcls
                }
            }
        }
    }
    $resultList
}

# Check ports using "netstat -ano" and print the corresponding process names for the process IDs
function Get-OpenPort {
    Write-Data -Output "Querying open network ports" -File $filenames.logfile -useWriteInformation
    $openPortsWithProcessesPowerShellCommand = { netstat.exe -ano | Select-String -Pattern "(TCP|UDP)" | ForEach-Object { $splitArray = $_ -split " "; $processId = $splitArray[-1]; $processName = Get-Process | Where-Object { $_.id -eq $processId } | Select-Object processname; $splitArray[-1] = $processId + "`t" + $processName.ProcessName; $splitArray -join " " } }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $openPortsWithProcessesPowerShellCommand -headline "Open Ports with Process Names" -outputFile $filenames.openports
    $openPortsElevatedCmdCommand = "netstat.exe -anob"
    Invoke-CmdCommandAndDocumentation -command $openPortsElevatedCmdCommand -outputFile $filenames.openports
}

# Check general information about OS users
# In case the system locale is set to German, the German commands are additionally added here
function Get-UserInformation {

    Write-Data -Output "Getting general OS user and group information" -File $filenames.logfile -useWriteInformation
    $whoamiCmdCommand = "whoami /all"
    Invoke-CmdCommandAndDocumentation -command $whoamiCmdCommand -outputFile $filenames.groups

    $localUsersPowerShellCommand = { Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | Format-Table -AutoSize PSComputername, Name, Status, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable, SID | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $localUsersPowerShellCommand -headline "List local users" -outputFile $filenames.groups
    $localGroupPowerShellCommand = { Get-WmiObject win32_group -Filter "LocalAccount='True'" | Format-Table -AutoSize | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $localGroupPowerShellCommand -headline "List local groups" -outputFile $filenames.groups

    Write-Data -Output "### List local group members ###" -File $filenames.groups
    $Groups = Get-WmiObject win32_group -Filter "LocalAccount='True'"
    $data = @()
    Foreach ($Group in $Groups) {

        $groupName = $Group.Name
        If (net localgroup $groupName) {

            # Invoke-CmdCommandAndDocumentation -command "net localgroup `"$groupName`"" -outputFile $filenames.groups
            # Adds all local groups to the command list :( .. but something like this could work here

            $members = net localgroup $groupName | Where-Object { $_ }
            if ($members.Count -gt 5) {
                $members = $members[4..$($members.Count - 2)]
                $groupobject = @{
                    Group   = $Group.Name
                    Members = $members
                }
                $data += $groupobject
            }
        }
    }
    Write-Data -Output ($data | ForEach-Object { [PSCustomObject]$_ } | Format-Table -AutoSize | Out-String -Width 4096) -File $filenames.groups

    $netAccountsCmdCommand = "net accounts"
    Invoke-CmdCommandAndDocumentation -command $netAccountsCmdCommand -outputFile $filenames.groups
    $netAccountsDomainCmdCommand = " net accounts /domain"
    Invoke-CmdCommandAndDocumentation -command $netAccountsDomainCmdCommand -outputFile $filenames.groups

}

function Get-WSUS {

    Write-Data -Output "Getting WSUS settings from registry" -File $filenames.logfile -useWriteInformation
    $wsusAURegistry = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $useWUServerKey = "UseWUServer"

    $wsusRegistry = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $wuServerKey = "WUServer"
    $wuStatusServerKey = "WUStatusServer"

    $useWUServer = Get-RegistryValue -path $wsusAURegistry -key $useWUServerKey -outputFile $filenames.wsus
    $wuServer = Get-RegistryValue -path $wsusRegistry -key $wuServerKey -outputFile $filenames.wsus
    $wuStatusServer = Get-RegistryValue -path $wsusRegistry -key $wuStatusServerKey -outputFile $filenames.wsus

    $wsus = @{
        $useWUServerKey    = $useWUServer
        $wuServerKey       = $wuServer
        $wuStatusServerKey = $wuStatusServer
    }
    $wsus
}

# Check RDP Configuration
function Get-RDPConfiguration {

    Write-Data -Output "Querying RDP settings" -File $filenames.logfile -useWriteInformation
    Write-Data -Output "NLA: 0: Disabled, 1: Enabled" -File $filenames.rdp
    Write-Data -Output "Encryption levels: 1: Low, 2: Client Compatible, 3: High, 4: FIPS (Federal Information Processing Standard 140-1)" -File $filenames.rdp
    Write-Data -Output "Security Layer: 0: Native RDP Encryption (not recommended), 1: Negotiate (Most secure version of client), 2: SSL/TLS (recommended)" -File $filenames.rdp

    $fDenyTSConnectionsRegistry = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\"
    $fDenyTSConnectionsKey = "fDenyTSConnections"
    $fDenyTSConnections = Get-RegistryValue -path $fDenyTSConnectionsRegistry -key $fDenyTSConnectionsKey -outputFile $filenames.rdp

    $rdpRegistry = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $nlaKey = "UserAuthentication"
    $nlaValue = Get-RegistryValue -path $rdpRegistry -key $nlaKey -outputFile $filenames.rdp
    $encryptionLevelKey = "MinEncryptionLevel"
    $encryptionLevel = Get-RegistryValue -path $rdpRegistry -key $encryptionLevelKey -outputFile $filenames.rdp
    $securityLayerKey = "SecurityLayer"
    $securityLayer = Get-RegistryValue -path $rdpRegistry -key $securityLayerKey -outputFile $filenames.rdp

    # First, lets find out the hash of the used RDP certificate, then get the certificate matching the hash
    $certificateHash = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices | Where-Object { $_.TerminalName -eq "RDP-Tcp" }).SSLCertificateSHA1Hash
    $certificate = Get-ChildItem -Path "Cert:\LocalMachine\" -Recurse | Where-Object { $_.Thumbprint -eq "$certificateHash" }

    # One liner for printing the certificate info to the text file
    $rdpCertificatePowerShellCommand = { Get-ChildItem -Path "Cert:\LocalMachine\" -Recurse | Where-Object { $_.Thumbprint -eq ((Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices | Where-Object { $_.TerminalName -eq "RDP-Tcp" }).SSLCertificateSHA1Hash) } | Format-List | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $rdpCertificatePowerShellCommand -headline "RDP Certificate Information" -outputFile $filenames.rdp

    $base64 = $([Convert]::ToBase64String($certificate.Export('Cert'), [System.Base64FormattingOptions]::InsertLineBreaks))
    $base64certificate = "-----BEGIN CERTIFICATE-----`n$base64`n-----END CERTIFICATE-----"
    Write-Data -Output $base64certificate -File $filenames.rdp
    $rdpjson += @{
        fDenyTSConnections = $fDenyTSConnections
        nla                = $nlaValue
        encryption         = $encryptionLevel
        securityLayer      = $securityLayer
        certificateIssuer  = $certificate.Issuer
        certificateSubject = $certificate.Subject
    }
    $rdpjson
}
function Get-UnquotedServicePath {

    Write-Data -Output "Checking for unquoted service paths" -File $filenames.logfile -useWriteInformation
    $services = get-wmiobject -query 'select * from win32_service'
    $servicesJson = New-Object System.Collections.ArrayList
    ForEach ($service in $services) {
        If ($service.pathname -match '^[^\\"].+\s.+\.exe') {

            $serviceName = $service.name
            $displayName = $service.displayname
            $servicePath = $service.pathname

            $subPaths = $servicePath.Split()
            $rememberPath = ""
            $permissions = New-Object System.Collections.ArrayList
            $len = $subPaths.Count
            $counter = 0

            foreach ($subPath in $subPaths) {
                # We do not need to check the last path (only the parts that are affected due to the unquoted service
                if ($counter -eq ($len - 1)) {
                    break
                }
                $rememberPath = "$rememberPath $subPath".Trim()
                if (!(Test-Path $rememberPath)) {
                    $checkPath = $rememberPath | Split-Path
                }
                else {
                    $checkPath = $rememberPath
                }
                $result = Test-Writable -pathItem $checkPath
                $permissions += $result
                $counter += 1

            }
            $serviceObject = @{
                serviceName = $serviceName
                displayName = $displayName
                user        = $service.StartName
                state       = $service.State
                startMode   = $service.StartMode
                path        = $servicePath
                permissions = $permissions
            }
            $servicesJson += $serviceObject
        }
    }
    $servicesJson
}

# Check SMB configuration: SMB signing, smb encryption, file share and NTFS permissions on a high level
function Get-SmbInformation {

    Write-Data -Output "Checking SMB configuration" -File $filenames.logfile -useWriteInformation
    $smbClientConfigurationPowerShellCommand = { Get-SmbClientConfiguration }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $smbClientConfigurationPowerShellCommand -headline "SMB Client Configuration" -outputFile $filenames.smb
    $smbServerConfigurationPowerShellCommand = { Get-SmbServerConfiguration }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $smbServerConfigurationPowerShellCommand -headline "SMB Server Configuration" -outputFile $filenames.smb
    $smbSharesPowerShellCommand = { Get-SmbShare | Format-Table -AutoSize Name, ScopeName, Path, Description, CurrentUsers, EncryptData, FolderEnumerationMode | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $smbSharesPowerShellCommand -headline "SMB Shares & SMB Encryption" -outputFile $filenames.smb
    $smbSharePermissionsPowerShellCommand = { Get-SmbShareAccess (Get-SmbShare).Name | Format-Table -AutoSize | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $smbSharePermissionsPowerShellCommand -headline "SMB Share Permissions" -outputFile $filenames.smb
    $smbShareNTFSPermissionsPowerShellCommand = { Get-SmbShare | ForEach-Object { "Share $($_.Name) on path $($_.Path)"; Get-Acl $_.Path | Select-Object -ExpandProperty Access | Format-Table -AutoSize | Out-String -Width 4096 } }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $smbShareNTFSPermissionsPowerShellCommand -headline "SMB Share NTFS Permissions" -outputFile $filenames.smb

    $netShareCmdCommand = "net share"
    Invoke-CmdCommandAndDocumentation -command $netShareCmdCommand -outputFile $filenames.smb
    $smbConnectionPowerShellCommand = { Get-SmbConnection | Format-List * }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $smbConnectionPowerShellCommand -headline "List active SMB connections" -outputFile $filenames.smb
    $netUseCmdCommand = "net use"
    Invoke-CmdCommandAndDocumentation -command $netUseCmdCommand -outputFile $filenames.smb

    # Find out about SMB1 support on older systems (<= Server 2008R2) because they do not have the Get-SmbServerConfiguration Cmdlet
    $smbRegistry = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $smb1Key = "SMB1"
    $smb1RegistryValue = Get-RegistryValue -path $smbRegistry -key $smb1Key -outputFile $filenames.smb
    $enableSMB1 = if ($smb1RegistryValue -eq 0) { $false } else { $true }

    $smbSigningEnabledKey = "enablesecuritysignature"
    $smbSigningRequiredKey = "requiresecuritysignature"

    $smbSigningEnabled = Get-RegistryValue -path $smbRegistry -key $smbSigningEnabledKey -outputFile $filenames.smb
    $smbSigningRequired = Get-RegistryValue -path $smbRegistry -key $smbSigningRequiredKey -outputFile $filenames.smb

    $smbSigningEnabledBool = if ($smbSigningEnabled -eq 1) { $true } else { $false }
    $smbSigningRequiredBool = if ($smbSigningRequired -eq 1) { $true } else { $false }

    $smbRegistryDumpPowerShellCommand = { Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | ForEach-Object { Get-ItemProperty $_.pspath } | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $smbRegistryDumpPowerShellCommand -headline "Dump SMB Registry Values" -outputFile $filenames.smb

    # Check for SMB Encryption Settings if the PowerShell version is greater or equal to PSv3
    if ($Script:psVersion.Major -ge 3) {
        $smbServerConfiguration = Get-SmbServerConfiguration
        $encryptData = $smbServerConfiguration.EncryptData
        $enableSMB1 = $smbServerConfiguration.EnableSMB1Protocol
        $rejectUnencryptedAccess = $smbServerConfiguration.RejectUnencryptedAccess
        $shares = Get-SmbShare | Select-Object Name, EncryptData
    }

    $smbSettings += @{
        EnableSMB1               = $enableSMB1
        EnableSecuritySignature  = $smbSigningEnabledBool
        RequireSecuritySignature = $smbSigningRequiredBool
        EncryptData              = $encryptData
        RejectUnencryptedAccess  = $rejectUnencryptedAccess
        Shares                   = $shares
    }

    $smbSettings
}

# Verify if there is an unattended install file somwehere on the system
function Get-UnattendedInstallFile {

    Write-Data "Checking for unattended install files" -File $filenames.unattend -File $filenames.logfile -useWriteInformation
    $targetFiles = @(
        "C:\unattended.xml",
        "C:\Windows\Panther\unattend.xml",
        "C:\Windows\Panther\Unattend\Unattend.xml",
        "C:\Windows\System32\sysprep.inf",
        "C:\Windows\System32\sysprep\sysprep.xml"
    )

    try {

        $targetFiles | Where-Object { $(Test-Path $_) -eq $true } | ForEach-Object {
            Write-Data -Output "    [!] Found : $_" -File $filenames.unattend
        }

    }
    catch {
        $errorMessage = $_.Exception.Message
        $failedItem = $_.Exception.ItemName
        "[-] Exception : " | Set-Content $exceptionsFilePath
        '[*] Error Message : `n', $errorMessage | Set-Content $exceptionsFilePath
        "[*] Failed Item   : `n", $failedItem   | Set-Content $exceptionsFilePath
    }
}

# Get installed programs (x86 and x64)
function Get-InstalledProgram {

    Write-Data -Output "Querying installed applications" -File $filenames.logfile -useWriteInformation
    $installedProgramsX64PowerShellCommand = { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Format-Table -AutoSize DisplayName, DisplayVersion, Publisher, InstallDate | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $installedProgramsX64PowerShellCommand -headline "x64" -outputFile $filenames.installedprograms
    $installedProgramsX86PowerShellCommand = { Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Format-Table -AutoSize DisplayName, DisplayVersion, Publisher, InstallDate | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $installedProgramsX86PowerShellCommand -headline "x86" -outputFile $filenames.installedprograms

}

function Get-FirewallConfiguration {

    Write-Data -Output "Reading firewall configuration and rules" -File $filenames.logfile -useWriteInformation

    $firewallProfilePowerShellCommand = { Get-NetFirewallProfile }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $firewallProfilePowerShellCommand -headline "Firewall Profiles" -outputFile $filenames.firewall
    $firewallRulePowerShellCommand = { Get-NetFirewallRule }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $firewallRulePowerShellCommand -headline "Firewall Rules" -outputFile $filenames.firewall

    $netshFirewallCmdCommand = "netsh advfirewall show allprofiles"
    Invoke-CmdCommandAndDocumentation -command $netshFirewallCmdCommand -outputFile  $filenames.firewall

    $alternativeFirewallRulesPowerShellCommand = { (New-Object -ComObject HNetCfg.FwPolicy2).rules | Where-Object { $_.Enabled -eq $true } | Format-List Name, Description, ApplicationName, serviceName, Protocol, LocalPorts, LocalAddresses, RemoteAddresses, Direction | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $alternativeFirewallRulesPowerShellCommand -headline "Firewall Rules" -outputFile $filenames.firewall

}

# This can be used to check file ACLs recursively, specified by the given parameter
function Get-FileAndPermission {
    param(
        [Parameter(Mandatory = $true)][string[]]$paths
    )

    Write-Data -Output "Querying ACLs for provided directories" -File $filenames.logfile -useWriteInformation

    ForEach ($path in $paths) {

        $filename = Split-Path $path -Leaf
        Write-Data -Output "Directory $path" -File "$($filenames.aclsdirname)_$filename.txt"
        Write-Data -Output "[Command][PS] Get-ChildItem `"$path`" -Recurse | Get-Acl | Format-List" -File "$($filenames.aclsdirname)_$filename.txt"
        Write-Data -Output (Get-ChildItem "$path" -Recurse | Get-Acl | Format-List) -File "$($filenames.aclsdirname)_$filename.txt"

    }

}

# This function tries to extract information about the antivirus software
function Get-AntiVirusProduct {

    Write-Data -Output "Getting antivirus information" -File $filenames.logfile -useWriteInformation
    $defenderSettings1PowerShellCommand = { Get-MpComputerStatus }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $defenderSettings1PowerShellCommand -headline "Defender Settings: MpComputerStatus" -outputFile $filenames.antivirus
    $defenderSettings2PowerShellCommand = { Get-MpPreference }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $defenderSettings2PowerShellCommand -headline "Defender Settings: MpPreference" -outputFile $filenames.antivirus
    $defenderExclusionPathPowerShellCommand = { Get-MpPreference | Select-Object -ExpandProperty ExclusionPath }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $defenderExclusionPathPowerShellCommand -headline "Defender Exclusion Path" -outputFile $filenames.antivirus
    $defenderExclusionIpAddressPowerShellCommand = { Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $defenderExclusionIpAddressPowerShellCommand -headline "Defender Exclusion IP Address" -outputFile $filenames.antivirus
    $defenderExclusionExtensionPowerShellCommand = { Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $defenderExclusionExtensionPowerShellCommand -headline "Defender Exclusion Extension" -outputFile $filenames.antivirus
    $defenderExclusionProcessPowerShellCommand = { Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $defenderExclusionProcessPowerShellCommand -headline "Defender Exclusion Process" -outputFile $filenames.antivirus
    $defenderExclusionRegistryPowerShellCommand = { Get-Item "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\*" }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $defenderExclusionRegistryPowerShellCommand -headline "Defender Exclusions from Registry" -outputFile $filenames.antivirus

    # Check antivirus software from WMI object
    $antiVirusWMIPowerShellCommand = { Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | Format-List * | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $antiVirusWMIPowerShellCommand -headline "Query Antivirus via WMI" -outputFile $filenames.antivirus
    $antiVirusCIMPowerShellCommand = { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Format-List * | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $antiVirusCIMPowerShellCommand -headline "Query Antivirus via CIM" -outputFile $filenames.antivirus

}

# Dump installed patches via WMIC and PowerShell
function Get-Patchlevel {

    Write-Data -Output "Querying OS updates and patch level" -File $filenames.logfile -useWriteInformation

    $installedUpdatesPowerShellCommand = { Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object "Caption", "CSName", "Description", "HotFixID", "InstalledBy", "InstalledOn", @{n = "InstallDate"; e = { ([datetime]$_.psbase.properties["InstalledOn"].Value).ToString("yyyy.MM.dd") } } -ExcludeProperty InstallDate | Format-Table -AutoSize | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $installedUpdatesPowerShellCommand -headline "Installed Updates (queried with PowerShell)" -outputFile $filenames.patchlevel

    $wmicQfeCmdCommand = "wmic qfe list full"
    $wmicQfeSubPath = "Wbem"
    Invoke-CmdCommandAndDocumentation -command $wmicQfeCmdCommand -subPath $wmicQfeSubPath -headline "Installed Patches via WMIC QFE" -outputFile $filenames.patchlevel

    $installedUpdates = Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object "Caption", "CSName", "Description", "HotFixID", "InstalledBy", "InstalledOn", @{n = "InstallDate"; e = { ([datetime]$_.psbase.properties["InstalledOn"].Value).ToString("yyyy.MM.dd") } } -ExcludeProperty InstallDate
    $installedUpdates
}

# Check if AutoLogin is enabled in the registry
function Get-AutoLogon {

    Write-Data -Output "Checking potential autologon configuration" -File $filenames.logfile -useWriteInformation
    $autologonRegistry = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $usernameKey = "DefaultUserName"
    $passwordKey = "DefaultPassword"

    $username = Get-RegistryValue -path $autologonRegistry -key $usernameKey -outputFile $filenames.autologon
    $password = Get-RegistryValue -path $autologonRegistry -key $passwordKey -outputFile $filenames.autologon -censor

    if ($password -eq -1) {
        $passwordSet = $false
    }
    else {
        $passwordSet = $true
    }

    $autologinJson = @{
        $usernameKey       = $username
        DefaultPasswordSet = $passwordSet
    }

    $autologinJson
}

# Check for protocols which are spoofable by responder (NBNS, LLMNR, mDNS)
function Get-ResponderProtocol {

    Write-Data -Output "Inspecting settings for potentially spoofable protocols" -File $filenames.logfile -useWriteInformation
    # NBNS Check
    $nbns = @()
    $nbns += Get-WmiObject win32_networkadapterconfiguration -filter 'IPEnabled=true' | Select-Object Description, TcpipNetbiosOptions
    # Print to output file
    $nbnsPowerShellCommand = { Get-WmiObject win32_networkadapterconfiguration -filter 'IPEnabled=true' | Format-Table -AutoSize Description, IPAddress, TcpipNetbiosOptions  | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $nbnsPowerShellCommand -headline "NBNS Settings" -outputFile $filenames.responder

    # LLMNR Check
    $llmnrRegistry = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $llmnrKey = "EnableMulticast"
    $llmnr = Get-RegistryValue -path $llmnrRegistry -key $llmnrKey -outputFile $filenames.responder

    # MDNS Check
    $mdnsRegistry = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    $mdnsKey = "EnableMDNS"
    $mdns = Get-RegistryValue -path $mdnsRegistry -key $mdnsKey -outputFile $filenames.responder

    $responderJson = @{
        nbns            = $nbns
        enableMulticast = $llmnr
        enableMDNS      = $mdns
    }
    $responderJson
}

# Privilege escalation checks: AlwaysInstallElevated in registry, writable tools in PATH variable,
# writable service executables, writable paths
function Get-PrivilegeEscalation {

    Write-Data -Output "Checking for privilege escalation possibilities" -File $filenames.logfile -useWriteInformation
    Write-Data -Output "[*] Check registry value for AlwaysInstallElevated (0 = Disabled, 1 = Enabled, -1 = Default (Disabled))" -File $filenames.privilegeEscalation
    Write-Data -Output "[*] Note that once the per-machine policy for AlwaysInstallElevated is enabled, any user can set their per-user setting." -File $filenames.privilegeEscalation

    # Check registry key for AlwaysInstallElevated
    $installElevatedHKCURegistry = "HKCU:\Software\Policies\Microsoft\Windows"
    $installElevatedHKLMRegistry = "HKLM:\Software\Policies\Microsoft\Windows"
    $installElevatedKey = "Installer"

    $installElevatedHKCU = Get-RegistryValue -Path $installElevatedHKCURegistry -key $installElevatedKey -outputFile $filenames.privilegeEscalation
    $installElevatedHKLM = Get-RegistryValue -path $installElevatedHKLMRegistry -key $installElevatedKey -outputFile $filenames.privilegeEscalation

    $installElevatedJson = @{
        HKCU = $installElevatedHKCU
        HKLM = $installElevatedHKLM
    }

    # Check writable paths
    $pathVariable = $env:PATH
    [array]$paths = foreach ($entry in $pathVariable.split(";")) { $entry }
    $writablePaths = @()

    foreach ($path in $paths) {

        $pathResult = Test-Writable -pathItem $path
        if ($pathResult) {
            $writablePaths += @{
                pathVariable = $pathVariable
                permissions  = $pathResult
            }
        }

    }

    $privEsc += @{
        writablePaths = $writablePaths
    }

    # Check for writable services executables for low-privileged accounts
    $services = Get-WmiObject win32_service
    $writableServicePaths = @()
    foreach ($service in $services) {
        $servicePath = $service.PathName
        $result = Test-Writable -pathItem $servicePath -complexServicePath
        if ($result) {
            $writableServicePaths += @{
                serviceName = $service.Name
                displayName = $service.displayname
                user        = $service.StartName
                state       = $service.State
                startMode   = $service.StartMode
                path        = $servicePath
                permissions = $result
            }
        }
    }

    # Check for permission issues in scheduled tasks (only works from Windows Server 2012)
    $scheduledTasks = Get-ScheduledTask
    $writableTasksJson = @()
    foreach ($task in $scheduledTasks) {
        $actions = $task.Actions
        $execute = $actions.Execute
        $writableTask = Test-Writable -pathItem $execute
        if ($writableTask) {
            $writableTasksJson += @{
                taskPath         = $task.TaskPath
                taskName         = $task.TaskName
                executePath      = $execute
                executeArguments = $actions.Arguments
                state            = "$($task.State)"
                userId           = $task.Principal.UserId
                permissions      = $writableTask
            }
        }
    }

    $privEsc += @{writableServicePaths = $writableServicePaths }
    $unquotedServicePaths = @(Get-UnquotedServicePath)
    $privEsc += @{unquotedServicePaths = $unquotedServicePaths }
    $privEsc += @{alwaysInstallElevated = $installElevatedJson }
    $privEsc += @{scheduledTasks = $writableTasksJson }

    Write-Data -Output "[*] Writable Service Paths" -File $filenames.privilegeEscalation
    Write-Data -Output ($writableServicePaths | ConvertTo-Json -Depth 20) -File $filenames.privilegeEscalation
    Write-Data -Output "[*] Unquoted Service Paths" -File $filenames.privilegeEscalation
    Write-Data -Output ($unquotedServicePaths | ConvertTo-Json -Depth 20) -File $filenames.privilegeEscalation
    Write-Data -Output "[*] Writable Paths (PATH variable)" -File $filenames.privilegeEscalation
    Write-Data -Output ($writablePaths | ConvertTo-Json -Depth 20) -File $filenames.privilegeEscalation
    Write-Data -Output "[*] AlwaysInstallElevated" -File $filenames.privilegeEscalation
    Write-Data -Output ($installElevatedJson | ConvertTo-Json -Depth 20) -File $filenames.privilegeEscalation
    Write-Data -Output "[*] Writable Scheduled Tasks" -File $filenames.privilegeEscalation
    Write-Data -Output ($writableTasksJson | ConvertTo-Json -Depth 20) -File $filenames.privilegeEscalation

    $privEsc
}

function Get-HostInformation {

    Write-Data -Output "Querying basic host information" -File $filenames.logfile -useWriteInformation
    $ipv4 = @()
    $ipv6 = @()
    # Due to older system support we cannot use Get-NetIPAddress here
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE
    foreach ($adapter in $adapters) {
        $ips = $adapter.IPAddress
        foreach ($ip in $ips) {
            if (($ip -like "*.*") -and ($ip -notlike "169.254.*")) {
                # IPv4 address found (which is not a link local address according to RFC 5735)
                $ipv4 += $ip
            }
            elseif ($ip -like "*:*") {
                # IPv6 address found
                $ipv6 += $ip
            }
        }
    }

    $hostJson = @{
        hostname        = "$ENV:ComputerName"
        domain          = "$(Get-WmiObject -namespace root\cimv2 -class win32_computersystem | Select-Object -exp domain)"
        operatingSystem = "$((Get-WmiObject Win32_OperatingSystem).Caption)"
        windowsVersion  = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
        build           = "$([System.Environment]::OSVersion.Version)"
        psVersion       = "$($Script:psversion.Major).$($Script:psversion.Minor)"
        scriptStartTime = "$Script:startTime"
        ipv4            = $ipv4
        ipv6            = $ipv6
        scriptVersion   = $script:versionString
    }

    Write-Data -Output $hostJson -File $filenames.host
    $hostJson
}

# Check potential credential protection settings: credential guad, LSASS as protected process light and LAPS
function Get-CredentialProtection {

    Write-Data -Output "Verifying settings for credential protection" -File $filenames.logfile -useWriteInformation
    $runaspplRegistry = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $runaspplKey = "RunAsPPL"
    $wdigestRegistry = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $wdigestKey = "UseLogonCredential"
    $lsaCfgFlagsRegistry = "HKLM:\System\CurrentControlSet\Control\LSA"
    $lsaCfgFlagsKey = "LsaCfgFlags"

    $runasppl = Get-RegistryValue -path $runaspplRegistry -key $runaspplKey -outputFile $filenames.credentialProtection
    $wdigest = Get-RegistryValue -path $wdigestRegistry -key $wdigestKey -outputFile $filenames.credentialProtection

    $securityServicesRunning = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
    if (!$?) {
        $securityServicesRunning = -1
    }

    $lsaCfgFlags = Get-RegistryValue -path $lsaCfgFlagsRegistry -key $lsaCfgFlagsKey -outputFile $filenames.credentialProtection

    $credentialProtection += @{
        LSASSRunAsPPL           = $runasppl
        WDigest                 = $wdigest
        SecurityServicesRunning = $securityServicesRunning
        LsaCfgFlags             = $lsaCfgFlags
    }

    $deviceGuardSettingsPowerShellCommand = { Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $deviceGuardSettingsPowerShellCommand -headline "Device Guard Settings" -outputFile $filenames.credentialProtection

    # Check for LAPS DLLs and registry settings
    $admpwddllPowerShellCommand = { Test-Path -Path "$env:ProgramFiles\LAPS\CSE\Admpwd.dll" -Type Leaf }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $admpwddllPowerShellCommand -headline "LAPS: Check for Admpwd.dll (x64)" -outputFile $filenames.credentialProtection
    $admpwddllx86PowerShellCommand = { Test-Path -Path "${env:ProgramFiles(x86)}\LAPS\CSE\Admpwd.dll" -Type Leaf }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $admpwddllx86PowerShellCommand -headline "LAPS: Check for Admpwd.dll (x86)" -outputFile $filenames.credentialProtection
    $lapsRegistryPowerShellCommand = { Get-Item "HKLM:\Software\Policies\Microsoft Services\AdmPwd" | ForEach-Object { Get-ItemProperty $_.pspath } | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $lapsRegistryPowerShellCommand -headline "LAPS: Registry Settings" -outputFile $filenames.credentialProtection

    $credentialProtection
}

# Check for User Account Control (UAC) settings in the registry
function Get-UAC {

    Write-Data -Output "Querying UAC settings from registry" -File $filenames.logfile -useWriteInformation
    $uacRegistry = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $adminPromptKey = "ConsentPromptBehaviorAdmin"
    $uacEnabledKey = "EnableLUA"
    $localAccountTokenFilterPolicyKey = "LocalAccountTokenFilterPolicy"
    $filterAdministratorTokenKey = "FilterAdministratorToken"

    $adminPrompt = Get-RegistryValue -path $uacRegistry -key $adminPromptKey -outputFile $filenames.uac
    $uacEnabled = Get-RegistryValue -path $uacRegistry -key $uacEnabledKey -outputFile $filenames.uac
    $localAccountTokenFilterPolicy = Get-RegistryValue -path $uacRegistry -key $localAccountTokenFilterPolicyKey -outputFile $filenames.uac
    $filterAdministratorToken = Get-RegistryValue -path $uacRegistry -key $filterAdministratorTokenKey -outputFile $filenames.uac

    $uacRegistryDumpPowerShellCommand = { Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | ForEach-Object { Get-ItemProperty $_.pspath } }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $uacRegistryDumpPowerShellCommand -headline "UAC Registry Dump" -outputFile $filenames.uac

    $uacJson += @{
        $adminPromptKey                   = $adminPrompt
        $uacEnabledKey                    = $uacEnabled
        $localAccountTokenFilterPolicyKey = $localAccountTokenFilterPolicy
        $filterAdministratorTokenKey      = $filterAdministratorToken
    }

    $uacJson
}

# Extract bitlocker settings via PowerShell Cmdlet and Windows executable
function Get-BitlockerStatus {

    Write-Data -Output "Querying hard drive encryption settings (Bitlocker)" -File $filenames.logfile -useWriteInformation
    $bitlockerCmdCommand = "manage-bde -status"
    Invoke-CmdCommandAndDocumentation -command $bitlockerCmdCommand -headline "Bitlocker Settings CMD" -outputFile $filenames.bitlocker

    $bitlockerPowerShellCommand = { Get-BitLockerVolume | Format-List * | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $bitlockerPowerShellCommand -headline "Bitlocker PowerShell" -outputFile $filenames.bitlocker

    $bitlockerWMIPowerShellCommand = { Get-WmiObject -namespace "Root\cimv2\security\MicrosoftVolumeEncryption" -ClassName "Win32_Encryptablevolume" | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $bitlockerWMIPowerShellCommand -headline "Bitlocker PowerShell WMI" -outputFile $filenames.bitlocker

}

# Check PowerShell remoting configuration
function Get-PSRemoting {

    Write-Data -Output "Getting PowerShell remoting configuration" -File $filenames.logfile -useWriteInformation
    $winRMService = Get-WmiObject win32_service | Where-Object { $_.Name -eq "WinRM" } | Select-Object Name, DisplayName, StartMode, State
    Write-Data -Output "[*] WinRM Service Status:" -File $filenames.psremote
    Write-Data -Output $winRMService -File $filenames.psremote

    if ($winRMService.State -eq "Running") {
        # Retrieve all importan PS remoting settings, collect them for the JSON file
        $listener = (Get-ChildItem -Recurse wsman:\localhost\listener | Select-Object PSPath, Name, Value)
        Write-Data -Output "[*] PSRemoting Listener Settings:" -File $filenames.psremote
        Write-Data -Output $listener -File $filenames.psremote
        $shell = (Get-ChildItem -Recurse wsman:\localhost\shell | Select-Object PSPath, Name, Value)
        Write-Data -Output "[*] PSRemoting Shell Settings:" -File $filenames.psremote
        Write-Data -Output $shell -File $filenames.psremote
        $service = (Get-ChildItem -Recurse wsman:\localhost\service | Select-Object PSPath, Name, Value)
        Write-Data -Output "[*] PSRemoting Service Settings:" -File $filenames.psremote
        Write-Data -Output $service -File $filenames.psremote
        $permissions = Get-PSSessionConfiguration
        Write-Data -Output "[*] PSRemoting Permissions:" -File $filenames.psremote
        Write-Data -Output $permissions -File $filenames.psremote

        # In case we missed something, use the winrm cmd command
        $winrmCmdCommand = "winrm get winrm/config"
        Invoke-CmdCommandAndDocumentation -command $winrmCmdCommand -outputFile $filenames.psremote
    }
    else {
        $listener = $null
        $shell = $null
        $service = $null
        $permissions = $null
    }

    # PS Remoting Firewall rules
    # Not supported on older systems: Get-NetFirewallRule
    # $firewall = (Get-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)'| Select -Property DisplayName, Profile, Enabled)
    $firewall = New-Object -ComObject HNetCfg.FwPolicy2
    $remotingrules = $firewall.Rules | Where-Object { $_.Name.Contains("Windows Remote Management") }
    if ($remotingrules) {
        Write-Data -Output "[*] Firewall Rules for PSRemoting:" -File $filenames.psremote
        Write-Data -Output $remotingrules -File $filenames.psremote
    }

    $psremotejson += @{
        winRMService = $winRMService
        listener     = $listener
        shell        = $shell
        service      = $service
        permissions  = $permissions
    }

    $psremotejson
}

# Run the secedit executable in order to get the local password policy, returning its content in order to include
# it in the JSON output file
function Invoke-Secedit {

    Write-Data -Output "Invoking secedit for password policy checks" -File $filenames.logfile -useWriteInformation
    $seceditCmdCommand = "secedit.exe /export /cfg `"$outputdir\$($filenames.secedit)`" /quiet"
    Invoke-CmdCommandAndDocumentation -command $seceditCmdCommand -headline "Secedit.exe Security Settings" -manualCommandListOverride "secedit.exe /export /cfg $($filenames.secedit) /quiet" -outputFile $filenames.logfile

    #Read file in order to store in JSON
    $output = Get-Content $outputdir\$($filenames.secedit) | Out-String

    if ($script:onlyJson) {
        Remove-Item "$outputdir\$($filenames.secedit)"
    }

    $output
}

# Verify whether PowerShell version 2 is installed on the system
function Get-InsecurePowerShellVersion {

    Write-Data -Output "Verifying installed PowerShell versions" -File $filenames.logfile -useWriteInformation

    $currentPSVersionPowerShellCommand = { $PSVersionTable.PSVersion }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $currentPSVersionPowerShellCommand -headline "Currently running PowerShell version" -outputFile $filenames.basicinfo

    $psVersion2CmdCommand = "powershell.exe -version 2 -command `"Write-Output `$PSVersionTable.PSVersion`""
    $psVersion2SubPath = "WindowsPowerShell\v1.0"
    Invoke-CmdCommandAndDocumentation -command $psVersion2CmdCommand -subPath $psVersion2SubPath -headline "Check for PowerShell version 2" -outputFile $filenames.basicinfo

    $psVersion2 = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -version 2 -command { $PSVersionTable.PSVersion }
    if ($?) {
        $psVersion2Installed = $true
    }
    else {
        $psVersion2Installed = $false
    }
    $ps2Json = @{
        psVersion2Installed = $psVersion2Installed
        psCommand           = $psCommand
        commandOutput       = ($psVersion2 | Out-String)
    }
    $ps2Json
}

# Extract all services and scheduled tasks of the system
function Get-SystemServiceAndScheduledTask {

    Write-Data -Output "Getting running services and scheduled tasks" -File $filenames.logfile -useWriteInformation

    # The following script block is used to pretty print all services in TXT files
    $servicesPowerShellCommand = { Get-WmiObject win32_service | Select-Object ProcessId, Name, State, StartName, StartMode, PathName | Sort-Object -Property State | Format-Table -AutoSize | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $servicesPowerShellCommand -headline "Services" -outputFile $filenames.services

    #Print scheduled tasks
    $schtasksCmdCommand = "schtasks.exe /query /fo LIST /v"
    Invoke-CmdCommandAndDocumentation -command $schtasksCmdCommand -headline "Query Scheduled Tasks" -outputFile $filenames.tasks

    # $services holds the information that is needed for the result JSON file
    $services = Get-WmiObject win32_service | Select-Object ProcessId, Name, State, StartName, StartMode, PathName
    $services
}

# Capture the network traffic of the local system for a certain amount of time. Since this method
# seems to not work all the time, this is done twice if the first traffic file is not big enough
function Invoke-NetworkTrafficCapture {
    param(
        [Parameter(Mandatory = $true)][int] $seconds,
        [Parameter(Mandatory = $true)][string] $outputPath
    )
    Write-Data -Output "Invoking network traffic capture for $seconds seconds" -File $filenames.logfile -useWriteInformation

    # In case the script is interrupted using Ctrl+C, there is a finally block that will always execute
    try {
        Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList "trace start capture=yes tracefile=$outputPath\traffic1.etl" -Wait -NoNewWindow
        Start-Sleep -Seconds $seconds
        Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList "trace stop" -Wait -NoNewWindow
        # If the output is exactly the size of 1MB, the capture most probably failed and we try it again
        $outputFileSizeKB = (Get-Item $outputPath\traffic1.etl).Length / 1KB
        if ($outputFileSizeKB -le 1024) {
            Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList "trace start capture=yes tracefile=$outputPath\traffic2.etl" -Wait -NoNewWindow
            Start-Sleep -Seconds $seconds
            Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList "trace stop" -Wait -NoNewWindow
        }
    }
    finally {
        Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList "trace stop" -Wait -NoNewWindow
        Write-Data -Output "You can use etl2pcapng to convert the created etl file (https://github.com/microsoft/etl2pcapng)" -File $filenames.logfile -useWriteOutput
        Write-Data -Output "Command: etl2pcapng.exe traffic1.etl" -File $filenames.logfile -useWriteOutput
    }
}

# Extract kernel DMA security from registry, extract installed drivers, sleep settings, power configuration and bios settings
function Get-DeviceSecurity {

    Write-Data -Output "Checking device security settings and drivers" -File $filenames.logfile -useWriteInformation
    $kernelDmaProtectionRegistry = "HKLM:\Software\Policies\Microsoft\Windows"
    $kernelDmaProtectionKey = "Kernel DMA Protection"
    Get-RegistryValue -path $kernelDmaProtectionRegistry -key $kernelDmaProtectionKey -outputFile $filenames.devicesec | Out-Null

    $driverListPowerShellCommand = { Get-WmiObject Win32_PnPSignedDriver | Format-Table -AutoSize DeviceName, FriendlyName, DriverVersion, DriverDate | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $driverListPowerShellCommand -headline "Installed Drivers" -outputFile $filenames.devicesec

    $sleepRegistryPowerShellCommand = { Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Power" | ForEach-Object { Get-ItemProperty $_.pspath } | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $sleepRegistryPowerShellCommand -headline "Registry Sleep Settings" -outputFile $filenames.devicesec

    $powerConfigCmdCommand = "powercfg.exe /availablesleepstates"
    Invoke-CmdCommandAndDocumentation -command $powerConfigCmdCommand -outputFile $filenames.devicesec

    $biosSettingsPowerShellCommand = { Get-WmiObject -Class Win32_BIOS | Format-List * }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $biosSettingsPowerShellCommand -headline "BIOS Information" -outputFile $filenames.devicesec

    # Include driver paths and file hashes in order to be able to compare them with loldrivers.io (directories according to loldrivers Github repository)
    $driversDirectories = @("C:\WINDOWS\inf", "C:\WINDOWS\System32\drivers", "C:\WINDOWS\System32\DriverStore\FileRepository")
    $driversResults = @()

    foreach ($directory in $driversDirectories) {
        $driverFiles = Get-ChildItem -Path $directory -Recurse -File
        foreach ($file in $driverfiles) {
            $driversResults += @{
                fileName = $file.Name
                path     = $file.FullName
                sha256   = (Get-FileHash -Algorithm SHA256 -Path $file.FullName).Hash
            }
        }
    }
    $driversResults
}

# Extract if the MSSQL database communication is encrypted, the TLS certificate parameters and the MSSQL version
function Get-MSSQLServerConfiguration {

    Write-Data -Output "Identifying MSSQL configuration" -File $filenames.logfile -useWriteInformation

    # Check if an MSSQL service is running on the machine
    $mssqlServices = Get-WmiObject win32_service | Where-Object { $_.Name -eq "MSSQLSERVER" -or $_.Name.StartsWith("MSSQL$") -and $_.State -eq "running" }
    if (-not $mssqlServices) {
        $mssqlResults = @{
            running = $false
        }
        $mssqlResults
        return
    }

    # First, we need to find the instance name of the database. We can use the instance name to find the correct path in the registry later
    $instanceNames = New-Object System.Collections.ArrayList
    foreach ($serviceName in $mssqlServices.Name) {
        if ($serviceName.Contains("$")) {
            $instanceName = $serviceName.Split("$")[1]
        }
        else {
            $instanceName = serviceName
        }
        $instanceNames += $instanceName
    }

    $mssqlRegistryRoot = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
    $instanceResults = New-Object System.Collections.ArrayList
    foreach ($instanceName in $instanceNames) {
        # Find the registry name of the instance (because, this is usually prepended by MSSQLxy)
        $instanceRegistryName = (Get-ItemProperty "$mssqlRegistryRoot\Instance Names\SQL")."$instanceName"
        $forceEncryption = (Get-ItemProperty "$mssqlRegistryRoot\$instanceRegistryName\MSSQLServer\SuperSocketNetLib")."ForceEncryption"
        $mssqlBaseVersionFull = (Get-ItemProperty "$mssqlRegistryRoot\$instanceRegistryName\MSSQLServer\CurrentVersion")."CurrentVersion"
        $mssqlBaseVersionMajor = $mssqlBaseVersionFull.split(".")[0]
        $mssqlPatchLevel = (Get-ItemProperty "$mssqlRegistryRoot\$($mssqlBaseVersionMajor)0\SQL*\CurrentVersion\")."Version"
        $certificateHash = (Get-ItemProperty "$mssqlRegistryRoot\$instanceRegistryName\MSSQLServer\SuperSocketNetLib")."Certificate"
        $certificate = $null
        if ($certificateHash) {
            $certificate = Get-ChildItem -Path "Cert:\LocalMachine\" -Recurse | Where-Object { $_.Thumbprint -eq "$certificateHash" }
            $mssqlCertificatePowerShellCommand = { Get-ChildItem -Path "Cert:\LocalMachine\" -Recurse | Where-Object { $_.Thumbprint -eq "$certificateHash" } | Format-List | Out-String -Width 4096 }
            Invoke-PowerShellCommandAndDocumentation -scriptBlock $mssqlCertificatePowerShellCommand -headline "MSSQL Certificate Information" -outputFile $filenames.mssql
            $base64 = $([Convert]::ToBase64String($certificate.Export('Cert'), [System.Base64FormattingOptions]::InsertLineBreaks))
            $base64certificate = "-----BEGIN CERTIFICATE-----`n$base64`n-----END CERTIFICATE-----"
            Write-Data -Output $base64certificate -File $filenames.mssql
        }
        $instanceResult = @{
            name               = $instanceName
            registryName       = $instanceRegistryName
            forceEncryption    = $forceEncryption
            certificateIssuer  = $certificate.Issuer
            certificateSubject = $certificate.Subject
            currentVersion     = $mssqlPatchLevel
        }
        $instanceResults += $instanceResult
    }

    # Print the relevant information to the output file, the important information is stored in the registry in "SuperSocketNetLib"
    $mssqlRegistryPowerShellCommand = { Get-ChildItem -Recurse "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" | Where-Object { $_ -match "SuperSocketNetLib" -or $_ -match "CurrentVersion" } }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $mssqlRegistryPowerShellCommand -headline "Full MSSQL registry settings" -outputFile $filenames.mssql

    $mssqlResults = @{
        running   = $true
        instances = $instanceResults
    }
    $mssqlResults
}

# Extract the NFS configuration if Windows uses NFS
function Get-NfsConfiguration {

    Write-Data -Output "Inspecting NFS configuration" -File $filenames.logfile -useWriteInformation
    $mountCmdCommand = "mount.exe"
    Invoke-CmdCommandAndDocumentation -command $mountCmdCommand -outputFile $filenames.nfs
    $nfsSharePowerShellCommand = { Get-NfsShare -ErrorAction SilentlyContinue | Format-List * }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $nfsSharePowerShellCommand -headline "List of NFS shares" -outputFile $filenames.nfs
    $nfsClientConfigurationPowerShellCommand = { Get-NfsClientconfiguration -ErrorAction SilentlyContinue }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $nfsClientConfigurationPowerShellCommand -headline "NFS Client Configuration" -outputFile $filenames.nfs
    $nfsServerConfigurationPowerShellCommand = { Get-NfsServerConfiguration -ErrorAction SilentlyContinue }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $nfsServerConfigurationPowerShellCommand -headline "NFS Server Configuration" -outputFile $filenames.nfs
    $nfsPermissionsPowerShellCommand = { Get-NfsShare -ErrorAction SilentlyContinue | ForEach-Object { "NFS share `"$($_.Name)`" on path `"$($_.Path)`""; Get-NfsSharePermission "$($_.Name)"; "" } }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $nfsPermissionsPowerShellCommand -headline "Check NFS Permissions" -outputFile $filenames.nfs
    $nfsNtfsPermissionsPowerShellCommand = { Get-NfsShare -ErrorAction SilentlyContinue | ForEach-Object { "NFS share `"$($_.Name)`" on path `"$($_.Path)`""; Get-Acl "$($_.Path)" | Select-Object -ExpandProperty Access | Format-Table -AutoSize | Out-String -Width 4096 } }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $nfsNtfsPermissionsPowerShellCommand -headline "Check NTFS Permissions of NFS Shares" -outputFile $filenames.nfs

}

# Check if the print spooler service is running and verify certain misconfigurations that could enable PrintNightmare
function Get-PrintSpoolerConfiguration {

    Write-Data -Output "Getting print spooler service settings" -File $filenames.logfile -useWriteInformation

    # Get print spooler service
    $spoolerService = Get-WmiObject win32_service | Where-Object { $_.name -eq "spooler" } | Select-Object Name, StartMode, State, Status

    $pointAndPrintRegistry = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $pointAndPrintKey1 = "NoWarningNoElevationOnInstall"
    $pointAndPrintKey2 = "UpdatePromptSettings"
    $restrictToAdminsKey = "RestrictDriverInstallationToAdministrators"

    $pointAndPrintNoWarningNoElevationOnInstall = Get-RegistryValue -path $pointAndPrintRegistry -key $pointAndPrintKey1 -outputFile $filenames.spooler
    $pointAndPrintUpdatePromptSettings = Get-RegistryValue -path $pointAndPrintRegistry -key $pointAndPrintKey2 -outputFile $filenames.spooler
    $pointAndPrintRestrictToAdmins = Get-RegistryValue -path $pointAndPrintRegistry -key $restrictToAdminsKey -outputFile $filenames.spooler

    $packagePointAndPrintRegistry = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint"
    $packagePointAndPrintOnlyKey = "PackagePointAndPrintOnly"
    $packagePointAndPrintServerListKey = "PackagePointAndPrintServerList"
    $packagePointAndPrintServerListFolder = "ListofServers"

    $packagePointAndPrintOnly = Get-RegistryValue -path $packagePointAndPrintRegistry -key $packagePointAndPrintOnlyKey -outputFile $filenames.spooler
    $packagePointAndPrintServerList = Get-RegistryValue -path $packagePointAndPrintRegistry -key $packagePointAndPrintServerListKey -outputFile $filenames.spooler
    $packagePointAndPrintServers = @()
    if ($packagePointAndPrintServerList -ne -1) {
        $packagePointAndPrintServers = Get-Item "$packagePointAndPrintRegistry\$packagePointAndPrintServerListFolder\" | Select-Object -ExpandProperty Property
    }

    $clientConnectRegistry = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $clientConnectKey = "RegisterSpoolerRemoteRpcEndPoint"
    $clientConnect = Get-RegistryValue -path $clientConnectRegistry -key $clientConnectKey -outputFile $filenames.spooler

    $pointAndPrintJson += @{
        service                               = $spoolerService
        $pointAndPrintKey1                    = $pointAndPrintNoWarningNoElevationOnInstall
        $pointAndPrintKey2                    = $pointAndPrintUpdatePromptSettings
        $restrictToAdminsKey                  = $pointAndPrintRestrictToAdmins
        $packagePointAndPrintOnlyKey          = $packagePointAndPrintOnly
        $packagePointAndPrintServerListKey    = $packagePointAndPrintServerList
        $packagePointAndPrintServerListFolder = $packagePointAndPrintServers
        $clientConnectKey                     = $clientConnect
    }
    $pointAndPrintJson
}

# Dump attack surface reduction rules that enabled on the system
function Get-AsrRulesConfiguration {

    Write-Data -Output "Verifying installed attack surface reduction rules" -File $filenames.logfile -useWriteInformation
    $mppref = Get-MpPreference
    $asrRulesAction = $mppref.AttackSurfaceReductionRules_Actions
    $asrRulesId = $mppref.AttackSurfaceReductionRules_ids

    $asrRulesJson = @{}

    Write-Data -Output "[*] ASR Rules" -File $filenames.asrrules
    Write-Data -Output "[*] Use the GUIDs from here to match to the rulenames https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix" -File $filenames.asrrules
    Write-Data -Output "[*] For the action the values mean: 0 = Not Enabled; 1 = Enabled; 2 = Audit; 6 = Warning; All others are not defined" -File $filenames.asrrules
    if ([string]::isnullorempty($asrRulesId)) {
        Write-Data -Output "[-] No ASR Rules configured" -File $filenames.asrrules
        $asrRulesJson += @{
            "asrRulesConfigured" = $false
        }
    }
    else {
        $asrRulesJson += @{
            "asrRulesConfigured" = $true
        }
        $count = 0
        $rules = @{}
        while ($count -lt $asrRulesId.Count) {
            $asrRulesIdLower = $asrRulesId[$count].toLower()
            $rules += @{
                $asrRulesIdLower = $asrRulesAction[$count]
            }
            $temp1 = $asrRulesId[$count]
            $temp2 = $asrRulesAction[$count]
            Write-Data -Output "$temp1`t:`t$temp2" -File $filenames.asrrules
            $count = $count + 1
        }
        $asrRulesJson += @{
            "rules" = $rules
        }
    }
    $asrRulesJson
}

# Extract basic information about the system: proxy settings, cmdlet Get-ComputerInfo and information in win32_operatingsystem
function Get-BasicSystemInformation {
    Write-Data -Output "Querying basic system information" -File $filenames.logfile -useWriteInformation
    $proxySettingsPowerShellCommand = { Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | ForEach-Object { Get-ItemProperty $_.pspath } | Out-String }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $proxySettingsPowerShellCommand -headline "Query Proxy and Internet Settings from Registry" -outputFile $filenames.basicinfo
    $computerInfoPowerShellCommand = { Get-ComputerInfo }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $computerInfoPowerShellCommand -headline "Computer Info PowerShell" -outputFile $filenames.basicinfo
    $computerInfoWMIPowerShellCommand = { Get-WmiObject win32_operatingsystem | Format-List * | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $computerInfoWMIPowerShellCommand -headline "Computer Info WMI" -outputFile $filenames.basicinfo
}

# Get basic network information: IP configuration, routing information and the ARP table
function Get-NetworkConfiguration {
    Write-Data -Output "Getting the system network information (IP addresses, interfaces, routes, ARP table)" -File $filenames.logfile -useWriteInformation
    $ipconfigCmdCommand = "ipconfig.exe /all"
    Invoke-CmdCommandAndDocumentation -command $ipconfigCmdCommand -headline "Query Network Configuration" -outputFile $filenames.network
    $routePrintCmdCommand = "route.exe PRINT"
    Invoke-CmdCommandAndDocumentation -command $routePrintCmdCommand -headline "Query Routing Information" -outputFile $filenames.network
    $arpCmdCommand = "arp.exe -a"
    Invoke-CmdCommandAndDocumentation -command $arpCmdCommand -headline "Query ARP Table" -outputFile $filenames.network
}

function Get-RunningProcess {
    Write-Data -Output "Querying running processes" -File $filenames.logfile -useWriteInformation
    $runningProcessesLegacyPowerShellCommand = { Get-WmiObject Win32_Process | Select-Object ProcessId, @{Name = "UserName"; Expression = { $_.GetOwner().Domain + "\" + $_.GetOwner().User } }, ProcessName, CommandLine, Path | Sort-Object ProcessId | Format-Table -AutoSize | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $runningProcessesLegacyPowerShellCommand -headline "Query Running Processes (legacy method)" -outputFile $filenames.processes
    # The following command should be used for PS > 3
    $runningProcessesPowerShellCommand = { Get-Process -IncludeUserName | Sort-Object -Property Id | Format-Table -AutoSize Id, UserName, ProcessName, Path | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $runningProcessesPowerShellCommand -headline "Query Running Processes (new method)" -outputFile $filenames.processes
}

function Invoke-GpResult {
    Write-Data -Output "Extracting local group policy via gpresult.exe" -File $filenames.logfile -useWriteInformation
    $gpresultCmdCommand = "gpresult.exe /H `"$outputdir\$($filenames.gpresult)`""
    Invoke-CmdCommandAndDocumentation -command $gpresultCmdCommand -headline "Dump Report of gpresult.exe" -manualCommandListOverride "gpresult.exe /H $($filenames.gpresult)" -outputFile $filenames.logfile
}

function Get-AutostartProgram {
    Write-Data -Output "Querying autostart programs via WMI object" -File $filenames.logfile -useWriteInformation
    $autostartPowerShellCommand = { Get-WmiObject win32_startupcommand | Format-List Command, Caption, Description, User, Location | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $autostartPowerShellCommand -headline "Check Autostart Programs via WMI" -outputFile $filenames.autostart
}

###############################
### Main Part of the Script ###
###############################

#Create basic file structure and adjust settings
Invoke-Setup

# Create the JSON result file with information gathered from various sources. This is done first because it is
# theoretically possible to only dump the JSON file and then the rest of the script will not be run
$result = @{
    $filenames.host                 = Get-HostInformation
    $filenames.autologon            = Get-AutoLogon
    $filenames.patchlevel           = Get-Patchlevel
    $filenames.privilegeEscalation  = Get-PrivilegeEscalation
    $filenames.responder            = Get-ResponderProtocol
    $filenames.rdp                  = Get-RDPConfiguration
    $filenames.wsus                 = Get-WSUS
    $filenames.credentialProtection = Get-CredentialProtection
    $filenames.smb                  = Get-SmbInformation
    $filenames.uac                  = Get-UAC
    $filenames.psremote             = Get-PSRemoting
    $filenames.secedit              = Invoke-Secedit
    $filenames.basicinfo            = Get-InsecurePowerShellVersion
    $filenames.services             = Get-SystemServiceAndScheduledTask
    $filenames.mssql                = Get-MSSQLServerConfiguration
    $filenames.drivers              = Get-DeviceSecurity
    $filenames.spooler              = Get-PrintSpoolerConfiguration
    $filenames.asrrules             = Get-AsrRulesConfiguration
}

# Only on PowerShell version 3 and above, JSON can be exported. In earlier versions, we export an XML file
if ($Script:psVersion.Major -ge 3) {
    Write-Data -Output "Exporting data to JSON" -File $filenames.logfile
    if ($script:testing) {
        ConvertTo-Json -InputObject $result -Depth 20 | Out-File -Encoding utf8 "$outputdir\$env:computername.json"
    }
    else {
        ConvertTo-Json -InputObject $result -Depth 20 -Compress | Out-File -Encoding utf8 "$outputdir\$env:computername.json"
    }
    Write-Data -Output "JSON export done" -File $filenames.logfile
}
else {
    Write-Data -Output "Exporting data to XML" -File $filenames.logfile
    Export-Clixml -InputObject $result -Depth 20 -Encoding UTF8 -Path "$outputdir\$env:computername.xml"
}

# If only the JSON file should be generated, we don't need to execute this part
If (-Not $onlyJson) {
    Get-NetworkConfiguration
    Get-BasicSystemInformation
    Get-UserInformation
    Get-OpenPort
    Get-AntiVirusProduct
    Get-RunningProcess
    Invoke-GpResult
    Get-FirewallConfiguration
    Get-InstalledProgram
    Get-AutostartProgram
    Get-UnattendedInstallFile
    Get-BitlockerStatus
    Get-NfsConfiguration

    # If dumpPermissions is set, dump all permissions of the program folders (or custom paths)
    if ($dumpPermissions) {
        Get-FileAndPermission -paths $paths
    }
    # Perform network trace if captureTraffic is set
    if ($PSBoundParameters.ContainsKey("captureTraffic")) {
        Invoke-NetworkTrafficCapture -seconds $captureTraffic -outputPath "$outputdir"
    }
}

# Clean up activities and error reporting
Invoke-Teardown

# SIG # Begin signature block
# MIInngYJKoZIhvcNAQcCoIInjzCCJ4sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCABGpnCli9I4H2i
# qH9qN+J9P4MmLxTJND3uhmyqLaN3o6CCILIwggYUMIID/KADAgECAhB6I67aU2mW
# D5HIPlz0x+M/MA0GCSqGSIb3DQEBDAUAMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5
# WjBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYD
# VQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFIzNjCCAaIwDQYJ
# KoZIhvcNAQEBBQADggGPADCCAYoCggGBAM2Y2ENBq26CK+z2M34mNOSJjNPvIhKA
# VD7vJq+MDoGD46IiM+b83+3ecLvBhStSVjeYXIjfa3ajoW3cS3ElcJzkyZlBnwDE
# JuHlzpbN4kMH2qRBVrjrGJgSlzzUqcGQBaCxpectRGhhnOSwcjPMI3G0hedv2eNm
# GiUbD12OeORN0ADzdpsQ4dDi6M4YhoGE9cbY11XxM2AVZn0GiOUC9+XE0wI7CQKf
# OUfigLDn7i/WeyxZ43XLj5GVo7LDBExSLnh+va8WxTlA+uBvq1KO8RSHUQLgzb1g
# bL9Ihgzxmkdp2ZWNuLc+XyEmJNbD2OIIq/fWlwBp6KNL19zpHsODLIsgZ+WZ1AzC
# s1HEK6VWrxmnKyJJg2Lv23DlEdZlQSGdF+z+Gyn9/CRezKe7WNyxRf4e4bwUtrYE
# 2F5Q+05yDD68clwnweckKtxRaF0VzN/w76kOLIaFVhf5sMM/caEZLtOYqYadtn03
# 4ykSFaZuIBU9uCSrKRKTPJhWvXk4CllgrwIDAQABo4IBXDCCAVgwHwYDVR0jBBgw
# FoAU9ndq3T/9ARP/FqFsggIv0Ao9FCUwHQYDVR0OBBYEFF9Y7UwxeqJhQo1SgLqz
# YZcZojKbMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBMBgNVHR8ERTBDMEGg
# P6A9hjtodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3Rh
# bXBpbmdSb290UjQ2LmNybDB8BggrBgEFBQcBAQRwMG4wRwYIKwYBBQUHMAKGO2h0
# dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ1Jv
# b3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAN
# BgkqhkiG9w0BAQwFAAOCAgEAEtd7IK0ONVgMnoEdJVj9TC1ndK/HYiYh9lVUacah
# RoZ2W2hfiEOyQExnHk1jkvpIJzAMxmEc6ZvIyHI5UkPCbXKspioYMdbOnBWQUn73
# 3qMooBfIghpR/klUqNxx6/fDXqY0hSU1OSkkSivt51UlmJElUICZYBodzD3M/SFj
# eCP59anwxs6hwj1mfvzG+b1coYGnqsSz2wSKr+nDO+Db8qNcTbJZRAiSazr7KyUJ
# Go1c+MScGfG5QHV+bps8BX5Oyv9Ct36Y4Il6ajTqV2ifikkVtB3RNBUgwu/mSiSU
# ice/Jp/q8BMk/gN8+0rNIE+QqU63JoVMCMPY2752LmESsRVVoypJVt8/N3qQ1c6F
# ibbcRabo3azZkcIdWGVSAdoLgAIxEKBeNh9AQO1gQrnh1TA8ldXuJzPSuALOz1Uj
# b0PCyNVkWk7hkhVHfcvBfI8NtgWQupiaAeNHe0pWSGH2opXZYKYG4Lbukg7HpNi/
# KqJhue2Keak6qH9A8CeEOB7Eob0Zf+fU+CCQaL0cJqlmnx9HCDxF+3BLbUufrV64
# EbTI40zqegPZdA+sXCmbcZy6okx/SjwsusWRItFA3DE8MORZeFb6BmzBtqKJ7l93
# 9bbKBy2jvxcJI98Va95Q5JnlKor3m0E7xpMeYRriWklUPsetMSf2NvUQa/E5vVye
# fQIwggZdMIIExaADAgECAhA6UmoshM5V5h1l/MwS2OmJMA0GCSqGSIb3DQEBDAUA
# MFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLDAqBgNV
# BAMTI1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgQ0EgUjM2MB4XDTI0MDEx
# NTAwMDAwMFoXDTM1MDQxNDIzNTk1OVowbjELMAkGA1UEBhMCR0IxEzARBgNVBAgT
# Ck1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEwMC4GA1UEAxMn
# U2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBTaWduZXIgUjM1MIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjdFn9MFIm739OEk6TWGBm8PY3EWlYQQ2
# jQae45iWgPXUGVuYoIa1xjTGIyuw3suUSBzKiyG0/c/Yn++d5mG6IyayljuGT9De
# XQU9k8GWWj2/BPoamg2fFctnPsdTYhMGxM06z1+Ft0Bav8ybww21ii/faiy+NhiU
# M195+cFqOtCpJXxZ/lm9tpjmVmEqpAlRpfGmLhNdkqiEuDFTuD1GsV3jvuPuPGKU
# JTam3P53U4LM0UCxeDI8Qz40Qw9TPar6S02XExlc8X1YsiE6ETcTz+g1ImQ1OqFw
# EaxsMj/WoJT18GG5KiNnS7n/X4iMwboAg3IjpcvEzw4AZCZowHyCzYhnFRM4PuNM
# VHYcTXGgvuq9I7j4ke281x4e7/90Z5Wbk92RrLcS35hO30TABcGx3Q8+YLRy6o0k
# 1w4jRefCMT7b5mTxtq5XPmKvtgfPuaWPkGZ/tbxInyNDA7YgOgccULjp4+D56g2i
# uzRCsLQ9ac6AN4yRbqCYsG2rcIQ5INTyI2JzA2w1vsAHPRbUTeqVLDuNOY2gYIoK
# BWQsPYVoyzaoBVU6O5TG+a1YyfWkgVVS9nXKs8hVti3VpOV3aeuaHnjgC6He2CCD
# L9aW6gteUe0AmC8XCtWwpePx6QW3ROZo8vSUe9AR7mMdu5+FzTmW8K13Bt8GX/YB
# FJO7LWzwKAUCAwEAAaOCAY4wggGKMB8GA1UdIwQYMBaAFF9Y7UwxeqJhQo1SgLqz
# YZcZojKbMB0GA1UdDgQWBBRo76QySWm2Ujgd6kM5LPQUap4MhTAOBgNVHQ8BAf8E
# BAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBKBgNV
# HSAEQzBBMDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3Nl
# Y3RpZ28uY29tL0NQUzAIBgZngQwBBAIwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDov
# L2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYu
# Y3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5zZWN0
# aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYuY3J0MCMGCCsG
# AQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOC
# AYEAsNwuyfpPNkyKL/bJT9XvGE8fnw7Gv/4SetmOkjK9hPPa7/Nsv5/MHuVus+aX
# wRFqM5Vu51qfrHTwnVExcP2EHKr7IR+m/Ub7PamaeWfle5x8D0x/MsysICs00xtS
# NVxFywCvXx55l6Wg3lXiPCui8N4s51mXS0Ht85fkXo3auZdo1O4lHzJLYX4RZovl
# VWD5EfwV6Ve1G9UMslnm6pI0hyR0Zr95QWG0MpNPP0u05SHjq/YkPlDee3yYOECN
# MqnZ+j8onoUtZ0oC8CkbOOk/AOoV4kp/6Ql2gEp3bNC7DOTlaCmH24DjpVgryn8F
# MklqEoK4Z3IoUgV8R9qQLg1dr6/BjghGnj2XNA8ujta2JyoxpqpvyETZCYIUjIs6
# 9YiDjzftt37rQVwIZsfCYv+DU5sh/StFL1x4rgNj2t8GccUfa/V3iFFW9lfIJWWs
# vtlC5XOOOQswr1UmVdNWQem4LwrlLgcdO/YAnHqY52QwnBLiAuUnuBeshWmfEb5o
# ieIYMIIGgjCCBGqgAwIBAgIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwF
# ADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcT
# C0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAs
# BgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcN
# MjEwMzIyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBU
# aW1lIFN0YW1waW5nIFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAiJ3YuUVnnR3d6LkmgZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizI
# CFNeINCSJS+lV1ipnW5ihkQyC0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ
# 2aHHsPHggGsCi7uE0awqKggE/LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2G
# AXsePHi+/JUNAax3kpqstbl3vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WA
# BKf+Gnoi4cmisS7oSimgHUI0Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/F
# DDrOJ3rWqauUP8hsokDoI7D/yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop0
# 6m7NUNHdlTDEMovXAIDGAvYynPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE
# 9vtiTMzz/o2dYfdP0KWZwZIXbYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj
# 3NgevsAsvxsAnI8Oa5s2oy25qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoq
# zEIbW3q0b2iPuWLA911cRxgY5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7
# jk27MAe145GWxK4O3m3gEFEIkv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYw
# ggESMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2
# d2rdP/0BE/8WoWyCAi/QCj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYD
# VR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVz
# dFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAl
# BggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0B
# AQwFAAOCAgEADr5lQe1oRLjlocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39rAARa
# AdAxUeiX1ktLJ3+lgxtoLQhn5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsD
# LRhsyeIiJsms9yAWnvdYOdEMq1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxV
# f7nkNtUjPfcxuFtrQdRMRi/fInV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJ
# yz9gvEOcF1VWXG8OMeM7Vy7Bs6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwDiGin
# CwKPyFO7ApcmVJOtlw9FVJxw/mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp
# 4pmAWjR+Pb/SIduPnmFzbSN/G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/U
# YOy8k60mKcmaAZsEVkhOFuoj4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SB
# IkiRzfPfS9T+JesylbHa1LtRV9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14su
# VFBmbzrt5V5cQPnwtd3UOTpS9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HH
# FHeRPRYrMBKjkb8/IN7Po0d0hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8wgga5MIIE
# oaADAgECAhEAmaOACiZVO2Wr3G6EprPqOTANBgkqhkiG9w0BAQwFADCBgDELMAkG
# A1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAl
# BgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMb
# Q2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMB4XDTIxMDUxOTA1MzIxOFoXDTM2
# MDUxODA1MzIxOFowVjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRh
# IFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMbQ2VydHVtIENvZGUgU2lnbmluZyAyMDIx
# IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnSPPBDAjO8FGLOcz
# cz5jXXp1ur5cTbq96y34vuTmflN4mSAfgLKTvggv24/rWiVGzGxT9YEASVMw1Aj8
# ewTS4IndU8s7VS5+djSoMcbvIKck6+hI1shsylP4JyLvmxwLHtSworV9wmjhNd62
# 7h27a8RdrT1PH9ud0IF+njvMk2xqbNTIPsnWtw3E7DmDoUmDQiYi/ucJ42fcHqBk
# bbxYDB7SYOouu9Tj1yHIohzuC8KNqfcYf7Z4/iZgkBJ+UFNDcc6zokZ2uJIxWgPW
# XMEmhu1gMXgv8aGUsRdaCtVD2bSlbfsq7BiqljjaCun+RJgTgFRCtsuAEw0pG9+F
# A+yQN9n/kZtMLK+Wo837Q4QOZgYqVWQ4x6cM7/G0yswg1ElLlJj6NYKLw9EcBXE7
# TF3HybZtYvj9lDV2nT8mFSkcSkAExzd4prHwYjUXTeZIlVXqj+eaYqoMTpMrfh5M
# CAOIG5knN4Q/JHuurfTI5XDYO962WZayx7ACFf5ydJpoEowSP07YaBiQ8nXpDkNr
# UA9g7qf/rCkKbWpQ5boufUnq1UiYPIAHlezf4muJqxqIns/kqld6JVX8cixbd6Pz
# kDpwZo4SlADaCi2JSplKShBSND36E/ENVv8urPS0yOnpG4tIoBGxVCARPCg1BnyM
# J4rBJAcOSnAWd18Jx5n858JSqPECAwEAAaOCAVUwggFRMA8GA1UdEwEB/wQFMAMB
# Af8wHQYDVR0OBBYEFN10XUwA23ufoHTKsW73PMAywHDNMB8GA1UdIwQYMBaAFLah
# VDkCw6A/joq8+tT4HKbROg79MA4GA1UdDwEB/wQEAwIBBjATBgNVHSUEDDAKBggr
# BgEFBQcDAzAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vY3JsLmNlcnR1bS5wbC9j
# dG5jYTIuY3JsMGwGCCsGAQUFBwEBBGAwXjAoBggrBgEFBQcwAYYcaHR0cDovL3N1
# YmNhLm9jc3AtY2VydHVtLmNvbTAyBggrBgEFBQcwAoYmaHR0cDovL3JlcG9zaXRv
# cnkuY2VydHVtLnBsL2N0bmNhMi5jZXIwOQYDVR0gBDIwMDAuBgRVHSAAMCYwJAYI
# KwYBBQUHAgEWGGh0dHA6Ly93d3cuY2VydHVtLnBsL0NQUzANBgkqhkiG9w0BAQwF
# AAOCAgEAdYhYD+WPUCiaU58Q7EP89DttyZqGYn2XRDhJkL6P+/T0IPZyxfxiXumY
# lARMgwRzLRUStJl490L94C9LGF3vjzzH8Jq3iR74BRlkO18J3zIdmCKQa5LyZ48I
# fICJTZVJeChDUyuQy6rGDxLUUAsO0eqeLNhLVsgw6/zOfImNlARKn1FP7o0fTbj8
# ipNGxHBIutiRsWrhWM2f8pXdd3x2mbJCKKtl2s42g9KUJHEIiLni9ByoqIUul4Gb
# lLQigO0ugh7bWRLDm0CdY9rNLqyA3ahe8WlxVWkxyrQLjH8ItI17RdySaYayX3Ph
# RSC4Am1/7mATwZWwSD+B7eMcZNhpn8zJ+6MTyE6YoEBSRVrs0zFFIHUR08Wk0ikS
# f+lIe5Iv6RY3/bFAEloMU+vUBfSouCReZwSLo8WdrDlPXtR0gicDnytO7eZ5827N
# S2x7gCBibESYkOh1/w1tVxTpV2Na3PR7nxYVlPu1JPoRZCbH86gc96UTvuWiOruW
# myOEMLOGGniR+x+zPF/2DaGgK2W1eEJfo2qyrBNPvF7wuAyQfiFXLwvWHamoYtPZ
# o0LHuH8X3n9C+xN4YaNjt2ywzOr+tKyEVAotnyU9vyEVOaIYMk3IeBrmFnn0gbKe
# TTyYeEEUz/Qwt4HOUBCrW602NCmvO1nm+/80nLy5r0AZvCQxaQ4wggbyMIIE2qAD
# AgECAhBGCHmXqbFFYJfPVYvlUPb0MA0GCSqGSIb3DQEBCwUAMFYxCzAJBgNVBAYT
# AlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMT
# G0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBDQTAeFw0yNDA4MDUwNjA0NDZaFw0y
# NzA4MDUwNjA0NDVaMIGXMQswCQYDVQQGEwJBVDEWMBQGA1UECAwNTG93ZXIgQXVz
# dHJpYTEWMBQGA1UEBwwNS3J1bW1udXNzYmF1bTErMCkGA1UECgwiSEFDS05FUiBT
# ZWN1cml0eSBJbnRlbGxpZ2VuY2UgR21iSDErMCkGA1UEAwwiSEFDS05FUiBTZWN1
# cml0eSBJbnRlbGxpZ2VuY2UgR21iSDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBALrftbHPa7oY3ggptYi7VjFtAqeu4X5KIJuIBVBoR1slCHbcTrOyQQg3
# EmUTGkfA8rzlmy09Ko9GauLQeLfDG4D1sCA3ycXZxeP00g108095v4sd5vUdX9I9
# EarIERHUG3pSaNMwLywTtX7w5rL8YX8YN27yaM8qnlDmC5UkSMxYmc9Q406FX12x
# DzOw0C0tQIFnkaEOCjnUbRN3jOZU06VVfWJiXsUqbUEfA9SDMlqttTWc6TOGH2oU
# qOHF7OkXOMGCkCGTTmGUFiqKC/qCgGuZOI7RDY7MHYsDIQ++fwNL4ENEOeXkob43
# /6gML70CfmOyzVuJrRy+bZnYNGGEdAM3pZ/hodAWy0EackatVaHwmkSYqX1rC2Dn
# pCMh/pzWT6npBNDBLfdITj0nsvm/EAnCnCAcKVckQVgCLRxZ77vThHRlmQsPz6N2
# RkndXAPGrqcC+V5QWsMUn5drnEOVXT4z7zkL8OCiPTymN/ikZbVUzsw4IXNEBjYp
# ColDCUwkWX6fcbKGN4xAkj3To4IqdoXwG1JEV/S1OLT0KfFcvAsKXajkGZsrgevo
# vDZrCS1n3N16xKZAH96f6QYG9If5f5O2X4ltc2zg68ypxi4I51F391aVAe8BOFnH
# Zdct93QGFShR/QqjPJ+ONu5bVXQIUdcWWa0ncJ9ZWRoH5rUFibGnAgMBAAGjggF4
# MIIBdDAMBgNVHRMBAf8EAjAAMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jY3Nj
# YTIwMjEuY3JsLmNlcnR1bS5wbC9jY3NjYTIwMjEuY3JsMHMGCCsGAQUFBwEBBGcw
# ZTAsBggrBgEFBQcwAYYgaHR0cDovL2Njc2NhMjAyMS5vY3NwLWNlcnR1bS5jb20w
# NQYIKwYBBQUHMAKGKWh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1bS5wbC9jY3NjYTIw
# MjEuY2VyMB8GA1UdIwQYMBaAFN10XUwA23ufoHTKsW73PMAywHDNMB0GA1UdDgQW
# BBRnfXfm28gZLAqPt7AOEpHq+FwsezBLBgNVHSAERDBCMAgGBmeBDAEEATA2Bgsq
# hGgBhvZ3AgUBBDAnMCUGCCsGAQUFBwIBFhlodHRwczovL3d3dy5jZXJ0dW0ucGwv
# Q1BTMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG
# 9w0BAQsFAAOCAgEAY63GA2hHIV5YhAEMWHGelxmhzKtoCEXDyUPG7nez/dILiFHs
# 2Dq/hQUa1sC/R+Qs8LiE5X61hO8T6BHDxYH2BTVes9ZkkmJZlCrCvJyM8iFgogRD
# RhyGsjLuxNgmcj/IHmSa/fX04pyTYUmEuclL2z67kU516jMY8xMq4BckXkaZmeCD
# llHjqGk2n4/IlaVJ06l/+3Uk5HPGP2f6iBwmJihkJVtFO/ymYPPN2Wa1JtEsmuls
# hrw9M6vjEDNddqzKItdibNo4sqLNlUkUm06GleOIGiyO9SVp9SjKsqiyA11hKt2J
# VIZ9BwzFGrNQCUl10v8KoT7cuOpvFXbKyx9CG9641W1oBAKVNDZ1F6XWOMaQ0Yb2
# dAa7h84eu9igmaXbIoUCX5RDhgUdQIcHGZPNa6GgDYk54UMUxpa4xUxI8DB3268u
# Eg4LFqzCy6GK1WjeA+uE9VnlCpeGKlOJL76QPE2srCik/s8yQzgNGNlFF2U2XqAx
# 6Q9igZl28LoruxTI9ZFcH+9QgMMgD359lti10efJJRrrExw7D/aOjVDKULQaUBd0
# 1xkVWprHXbQivYjQJRgIQzwEKyuq+u8hqW5169P9f6D7qA1nXERm2AOaWPGUy+7e
# 3aJSpnhz2pwjo1joxE5jd8DElzDrYQ1YMs9QS+OxYJBiibO4Pla50wfdY04xggZC
# MIIGPgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QQIQRgh5l6mxRWCXz1WL5VD29DANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDzkIEmbohO
# dOHzvUhYXul7b/rPPiM8TTBM9CpQ7mBMQzANBgkqhkiG9w0BAQEFAASCAgCN/yFL
# HdwviWPlx0IuCeuw+/Zl8njwl5icU4PKIqov7y14VoaVMlyj1MBaSGqHh+q0zr8a
# AxyqKTOsPgrb8D/B8uAWEoCCPMVZ93j9oPia2nCduVkI6YzH/8o/HIZ8y3SDJbQv
# Zx73CcPyAoq4ZzIPyK8PNC6GmvxKuU/fu3XWhoEZTzwT2bvjP7FWVR3KDbzcYdpk
# KMw3I6j94u9tbhJ5iIf7nSirBLIZp4346YLWkm0rbhwRLCP7RJ2mqkpjchCtoZNR
# mvi0rUFngtkFatYQAr8ZRIz+88M4Ln3dX85paREJNp0u64GxTGbJOtqdw/t/6n80
# vfeQD1FZoTE95/iG8u3dTQuNheTmE/FsL+BTKLwfszg7yr2CBIKX6RpYyH2GIJln
# QB6MQV7xIVXtuk9EmGkU0Xwl+qGDZV7UuuH/pS5mHcjQADTfYxIIkBTGveNxffoP
# iUyNTe7Fq58Jh6i07vV1fPtQ4R1FjqMcmtVN9LOHRBEqICz5XfDphGwVXINI6FaO
# J2uq7cGx+A5WJUPs+7LxHt8sxtL47aLrAM61Sezs51IIPND4Ltpy3PIRDKauC+Vr
# h0G89yHg6ZMCbmNxn5IdiN+6Rc30d8I2AJvW9wak+XeaZFFZYE/Bymkwep/KVloP
# +rVJQHG4ciZL973H6V+5E5yQS7YQq8LoTdoxOKGCAyIwggMeBgkqhkiG9w0BCQYx
# ggMPMIIDCwIBATBpMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExp
# bWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgQ0Eg
# UjM2AhA6UmoshM5V5h1l/MwS2OmJMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjQxMjIwMTAzMjUzWjA/
# BgkqhkiG9w0BCQQxMgQwhMBqAWNLtMYbSJcKD4DR3xFr4tOaYTJ1v5ZBOfe0dsnQ
# Mw1a3LrtwSQrgIvMCZcRMA0GCSqGSIb3DQEBAQUABIICADlA06guu3gkxvKhKcw2
# OZn3rrFSInvCfgLJaC8I8dsuUxWnpXawvoWYSeb/8zlRCRd5yTQCU5NjRrLf1NBl
# kQFkFh6DqJE4FtobFrBbJ2ZQ2oj+U2Gcy+YAHXZDQSMCyY2hnWp8hllJKRd8Omip
# kRpnkU/bXMYHOGPQ5hOoN1V9xvLonuxwyu0wmIHjEM+ryI8t/Tjj4NYdHs6Xb9Ix
# 3tppYeLsvuCXCzEFvm4cZCa/FSl+ZRtoam7hLeOr86GIvjVytatxhc91GeeMFUUW
# Qy5Xta8LqTDPe8EMIbI9z8vWUHlosROzCy2fL4hvCL+SKuGKCJyuLGIdq9SverLI
# b4pK0zuuTM4s66aDNKxdFrB+u9k2d46l3AIxv4taj83n1HmFMegapNXXN/SlRnl7
# mDGatDfyR+IeFNHyrrLM5rdhn6NSsTN/YfuTz5wW81qdMYKitVlspZ3N9ETr5IdU
# DcnUmRO9yvnKEW5TIHsl0kKDvM1dtAcFr5iM7JeNfZTmlwRkYr10oEWV5VR6n21R
# oEzZs/sgTFlFeoUK4bUngMGG/J9+BDXqegUFcMUm8GHnyrI5HWoH/WNgkCRTYgC9
# RRUrn4DR/qG7MVBRNUt9RU1nnERXZREdQU24DxFtxlLxPxaZu6Ty1dCJLmXti70T
# P+yBgFr2+VwG6GVygIIDPIjY
# SIG # End signature block
