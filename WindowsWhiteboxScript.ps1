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
.PARAMETER shareCheckTimeout
    Timeout for share executable check in seconds (default 60 seconds)
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
    [switch] $generateCommandList,
    [int] $shareCheckTimeout = 60
)

# Version
$versionString = "v3.8"

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
    "smbexecutables"       = "smb_executables"
}

$rememberFormatEnumerationLimit = $null
$psVersion = $null
$outputFileContents = @{}
$Script:InformationPreference = "Continue"
# Do not display progress bars in order to not break certain connections (e.g., SSH)
$Script:ProgressPreference = "SilentlyContinue"

$permissiveUserGroups = @(
    [PSCustomObject]@{
        "Description"      = "Users"
        "Sid"              = "S-1-5-32-545"
        "LocalTranslation" = $null
    }
    [PSCustomObject]@{
        "Description"      = "AuthenticatedUser"
        "Sid"              = "S-1-5-11"
        "LocalTranslation" = $null
    }
    [PSCustomObject]@{
        "Description"      = "Guests"
        "Sid"              = "S-1-5-32-546"
        "LocalTranslation" = $null
    }
    [PSCustomObject]@{
        "Description"      = "Everyone"
        "Sid"              = "S-1-1-0"
        "LocalTranslation" = $null
    }
) | ForEach-Object {
    $securityIdentifyer = New-Object System.Security.Principal.SecurityIdentifier($_.Sid)
    $_.LocalTranslation = $securityIdentifyer.Translate([System.Security.Principal.NTAccount]).Value
    $_
}

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
                if ($script:permissiveUserGroups.LocalTranslation -contains $acl.IdentityReference) {
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
    $certificateHash = (Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices | Where-Object { $_.TerminalName -eq "RDP-Tcp" }).SSLCertificateSHA1Hash
    $certificate = Get-ChildItem -Path "Cert:\LocalMachine\" -Recurse | Where-Object { $_.Thumbprint -eq "$certificateHash" }

    # One liner for printing the certificate info to the text file
    $rdpCertificatePowerShellCommand = { Get-ChildItem -Path "Cert:\LocalMachine\" -Recurse | Where-Object { $_.Thumbprint -eq ((Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices | Where-Object { $_.TerminalName -eq "RDP-Tcp" }).SSLCertificateSHA1Hash) } | Format-List | Out-String -Width 4096 }
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
    $services = Get-WmiObject -Query 'select * from win32_service'
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
    $nbns += Get-WmiObject win32_networkadapterconfiguration -Filter 'IPEnabled=true' | Select-Object Description, TcpipNetbiosOptions
    # Print to output file
    $nbnsPowerShellCommand = { Get-WmiObject win32_networkadapterconfiguration -Filter 'IPEnabled=true' | Format-Table -AutoSize Description, IPAddress, TcpipNetbiosOptions  | Out-String -Width 4096 }
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
        domain          = "$(Get-WmiObject -Namespace root\cimv2 -Class win32_computersystem | Select-Object -exp domain)"
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

    $bitlockerWMIPowerShellCommand = { Get-WmiObject -Namespace "Root\cimv2\security\MicrosoftVolumeEncryption" -ClassName "Win32_Encryptablevolume" | Out-String -Width 4096 }
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

function Get-DeduplicatedPath {
    param (
        [string[]]$Paths
    )

    $deduplicatedPaths = @()
    foreach ($path in $Paths) {
        $included = $false
        for ($i = 0; $i -lt $deduplicatedPaths.Length; $i++) {
            if (!$path) {
                $included = $true
            }
            elseif ($paths[$i].StartsWith($path)) {
                $deduplicatedPaths[$i] = $path
                $included = $true
            }
            elseif ($path.StartsWith($deduplicatedPaths[$i])) {
                $included = $true
            }
        }
        if (!$included) {
            $deduplicatedPaths += $path
        }
    }
    $deduplicatedPaths
}

function Test-SmbShareWritable {
    param (
        [CimInstance] $SmbShare
    )

    $results = @{}
    $accessPermissions = Get-SmbShareAccess -Name $SmbShare.Name

    foreach ($permission in $accessPermissions) {
        $sid = $null
        $account = New-Object System.Security.Principal.NTAccount($permission.AccountName)
        try {
            $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
            if ($script:permissiveUserGroups.Sid -contains $sid) {
                $affectsWritePermission = $permission.AccessRight -eq "Full" -or $permission.AccessRight -eq "Write" -or $permission.AccessRight -eq "Custom"
                if ($affectsWritePermission) {
                    $updateEntry = !$results.ContainsKey($sid) -or $permission.AccessControlType -eq "Deny" -or ($results[$sid] -ne "Deny") -and $permission.AccessControlType -eq "Allow"
                    if ($updateEntry) {
                        $results[$sid] = $permission.AccessControlType
                    }
                }
            }
        }
        catch {
            Write-Debug "Could not resolve account $($permission.AccountName) to an SID."
        }
    }

    $results.Values -contains "Allow"
}

function Get-SmbExecutable {
    param (
        [int] $TimeoutSeconds = 60
    )
    Write-Data -Output "Looking for executable files on local file shares" -File $filenames.smbexecutables -useWriteInformation

    $executableExtensions = @("exe", "ps1", "bat", "dll", "cmd", "jar", "vbs") | ForEach-Object { "." + $_ }

    $allSharePaths = Get-SmbShare | Where-Object { Test-SmbShareWritable -SmbShare $_ } | ForEach-Object { $_.Path }
    $paths = Get-DeduplicatedPath -Paths $allSharePaths

    $dirsNextRound = @()
    $writableExecutableFiles = @()

    $stopwatch = [system.diagnostics.stopwatch]::StartNew()
    do {
        foreach ($path in $paths) {
            $files = Get-ChildItem -Path $path -File -ErrorAction 'SilentlyContinue'
            foreach ($file in $files) {
                if ($stopwatch.Elapsed.TotalSeconds -le $TimeoutSeconds -and $executableExtensions -contains $file.Extension) {
                    $testWritableResult = Test-Writable -pathItem $file.FullName
                    if ($testWritableResult) {
                        $writableExecutableFiles += $testWritableResult
                    }
                }
            }

            if ($stopwatch.Elapsed.TotalSeconds -le $TimeoutSeconds) {
                foreach ($dir in Get-ChildItem -Path $path -Directory -ErrorAction 'SilentlyContinue') {
                    $dirsNextRound += $dir.FullName
                }
            }
        }
        $paths = $dirsNextRound
        $dirsNextRound = @()
    } while ($paths.Length -gt 0 -and $stopwatch.Elapsed.TotalSeconds -le $TimeoutSeconds)

    Write-Data -Output ($writableExecutableFiles | ConvertTo-Json -Depth 20) -File $filenames.smbexecutables
    $writableExecutableFiles
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
    $filenames.smbexecutables       = Get-SmbExecutable -TimeoutSeconds $script:shareCheckTimeout
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
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZ3GX9QyHn/BHr
# Gd0n3o+4bipLS85pkK8HNR1tCt+fBaCCILcwggYUMIID/KADAgECAhB6I67aU2mW
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
# fQIwggZiMIIEyqADAgECAhEApCk7bh7d16c0CIetek63JDANBgkqhkiG9w0BAQwF
# ADBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYD
# VQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFIzNjAeFw0yNTAz
# MjcwMDAwMDBaFw0zNjAzMjEyMzU5NTlaMHIxCzAJBgNVBAYTAkdCMRcwFQYDVQQI
# Ew5XZXN0IFlvcmtzaGlyZTEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTAwLgYD
# VQQDEydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFNpZ25lciBSMzYwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDThJX0bqRTePI9EEt4Egc83JSB
# U2dhrJ+wY7JgReuff5KQNhMuzVytzD+iXazATVPMHZpH/kkiMo1/vlAGFrYN2P7g
# 0Q8oPEcR3h0SftFNYxxMh+bj3ZNbbYjwt8f4DsSHPT+xp9zoFuw0HOMdO3sWeA1+
# F8mhg6uS6BJpPwXQjNSHpVTCgd1gOmKWf12HSfSbnjl3kDm0kP3aIUAhsodBYZsJ
# A1imWqkAVqwcGfvs6pbfs/0GE4BJ2aOnciKNiIV1wDRZAh7rS/O+uTQcb6JVzBVm
# PP63k5xcZNzGo4DOTV+sM1nVrDycWEYS8bSS0lCSeclkTcPjQah9Xs7xbOBoCdma
# hSfg8Km8ffq8PhdoAXYKOI+wlaJj+PbEuwm6rHcm24jhqQfQyYbOUFTKWFe901Vd
# yMC4gRwRAq04FH2VTjBdCkhKts5Py7H73obMGrxN1uGgVyZho4FkqXA8/uk6nkzP
# H9QyHIED3c9CGIJ098hU4Ig2xRjhTbengoncXUeo/cfpKXDeUcAKcuKUYRNdGDlf
# 8WnwbyqUblj4zj1kQZSnZud5EtmjIdPLKce8UhKl5+EEJXQp1Fkc9y5Ivk4AZacG
# MCVG0e+wwGsjcAADRO7Wga89r/jJ56IDK773LdIsL3yANVvJKdeeS6OOEiH6hpq2
# yT+jJ/lHa9zEdqFqMwIDAQABo4IBjjCCAYowHwYDVR0jBBgwFoAUX1jtTDF6omFC
# jVKAurNhlxmiMpswHQYDVR0OBBYEFIhhjKEqN2SBKGChmzHQjP0sAs5PMA4GA1Ud
# DwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBz
# Oi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEAjBKBgNVHR8EQzBBMD+gPaA7hjlo
# dHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdD
# QVIzNi5jcmwwegYIKwYBBQUHAQEEbjBsMEUGCCsGAQUFBzAChjlodHRwOi8vY3J0
# LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdDQVIzNi5jcnQw
# IwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEB
# DAUAA4IBgQACgT6khnJRIfllqS49Uorh5ZvMSxNEk4SNsi7qvu+bNdcuknHgXIaZ
# yqcVmhrV3PHcmtQKt0blv/8t8DE4bL0+H0m2tgKElpUeu6wOH02BjCIYM6HLInbN
# HLf6R2qHC1SUsJ02MWNqRNIT6GQL0Xm3LW7E6hDZmR8jlYzhZcDdkdw0cHhXjbOL
# smTeS0SeRJ1WJXEzqt25dbSOaaK7vVmkEVkOHsp16ez49Bc+Ayq/Oh2BAkSTFog4
# 3ldEKgHEDBbCIyba2E8O5lPNan+BQXOLuLMKYS3ikTcp/Qw63dxyDCfgqXYUhxBp
# XnmeSO/WA4NwdwP35lWNhmjIpNVZvhWoxDL+PxDdpph3+M5DroWGTc1ZuDa1iXmO
# FAK4iwTnlWDg3QNRsRa9cnG3FBBpVHnHOEQj4GMkrOHdNDTbonEeGvZ+4nSZXrwC
# W4Wv2qyGDBLlKk3kUW1pIScDCpm/chL6aUbnSsrtbepdtbCLiGanKVR/KC1gsR0t
# C6Q0RfWOI4owggaCMIIEaqADAgECAhA2wrC9fBs656Oz3TbLyXVoMA0GCSqGSIb3
# DQEBDAUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEUMBIG
# A1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0d29y
# azEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
# eTAeFw0yMTAzMjIwMDAwMDBaFw0zODAxMTgyMzU5NTlaMFcxCzAJBgNVBAYTAkdC
# MRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVi
# bGljIFRpbWUgU3RhbXBpbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCIndi5RWedHd3ouSaBmlRUwHxJBZvMWhUP2ZQQRLRBQIF3FJmp
# 1OR2LMgIU14g0JIlL6VXWKmdbmKGRDILRxEtZdQnOh2qmcxGzjqemIk8et8sE6J+
# N+Gl1cnZocew8eCAawKLu4TRrCoqCAT8uRjDeypoGJrruH/drCio28aqIVEn45NZ
# iZQI7YYBex48eL78lQ0BrHeSmqy1uXe9xN04aG0pKG9ki+PC6VEfzutu6Q3IcZZf
# m00r9YAEp/4aeiLhyaKxLuhKKaAdQjRaf/h6U13jQEV1JnUTCm511n5avv4N+jSV
# wd+Wb8UMOs4netapq5Q/yGyiQOgjsP/JRUj0MAT9YrcmXcLgsrAimfWY3MzKm1HC
# xcquinTqbs1Q0d2VMMQyi9cAgMYC9jKc+3mW62/yVl4jnDcw6ULJsBkOkrcPLUwq
# j7poS0T2+2JMzPP+jZ1h90/QpZnBkhdtixMiWDVgh60KmLmzXiqJc6lGwqoUqpq/
# 1HVHm+Pc2B6+wCy/GwCcjw5rmzajLbmqGygEgaj/OLoanEWP6Y52Hflef3XLvYnh
# EY4kSirMQhtberRvaI+5YsD3XVxHGBjlIli5u+NrLedIxsE88WzKXqZjj9Zi5ybJ
# L2WjeXuOTbswB7XjkZbErg7ebeAQUQiS/uRGZ58NHs57ZPUfECcgJC+v2wIDAQAB
# o4IBFjCCARIwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0O
# BBYEFPZ3at0//QET/xahbIICL9AKPRQlMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0g
# ADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNF
# UlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwNQYIKwYBBQUHAQEE
# KTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqG
# SIb3DQEBDAUAA4ICAQAOvmVB7WhEuOWhxdQRh+S3OyWM637ayBeR7djxQ8SihTnL
# f2sABFoB0DFR6JfWS0snf6WDG2gtCGflwVvcYXZJJlFfym1Doi+4PfDP8s0cqlDm
# dfyGOwMtGGzJ4iImyaz3IBae91g50QyrVbrUoT0mUGQHbRcF57olpfHhQEStz5i6
# hJvVLFV/ueQ21SM99zG4W2tB1ExGL98idX8ChsTwbD/zIExAopoe3l6JrzJtPxj8
# V9rocAnLP2C8Q5wXVVZcbw4x4ztXLsGzqZIiRh5i111TW7HV1AtsQa6vXy633vCA
# bAOIaKcLAo/IU7sClyZUk62XD0VUnHD+YvVNvIGezjM6CRpcWed/ODiptK+evDKP
# U2K6synimYBaNH49v9Ih24+eYXNtI38byt5kIvh+8aW88WThRpv8lUJKaPn37+YH
# Yafob9Rg7LyTrSYpyZoBmwRWSE4W6iPjB7wJjJpH29308ZkpKKdpkiS9WNsf/eeU
# tvRrtIEiSJHN899L1P4l6zKVsdrUu1FX1T/ubSrsxrYJD+3f3aKg6yxdbugot06Y
# wGXXiy5UUGZvOu3lXlxA+fC13dQ5OlL2gIb5lmF6Ii8+CQOYDwXM+yd9dbmocQsH
# jcRPsccUd5E9FiswEqORvz8g3s+jR3SFCgXhN4wz7NgAnOgpCdUo4uDyllU9PzCC
# BrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEBDAUAMIGA
# MQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dpZXMgUy5B
# LjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSQwIgYD
# VQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5MDUzMjE4
# WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMYQXNzZWNv
# IERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBTaWduaW5n
# IDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCdI88EMCM7
# wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbMbFP1gQBJ
# UzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse1LCitX3C
# aOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNCJiL+5wnj
# Z9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0NxzrOiRna4
# kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOAVEK2y4AT
# DSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuUmPo1govD
# 0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP55piqgxO
# kyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/TthoGJDy
# dekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+SqV3olVfxy
# LFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0igEbFUIBE8
# KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYDVR0TAQH/
# BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYDVR0jBBgw
# FoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQM
# MAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwuY2VydHVt
# LnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzABhhxodHRw
# Oi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRwOi8vcmVw
# b3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4GBFUdIAAw
# JjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0GCSqGSIb3
# DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/79PQg9nLF
# /GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7XwnfMh2YIpBr
# kvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2UBEqfUU/u
# jR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiIueL0HKio
# hS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0jXtF3JJp
# hrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzTMUUgdRHT
# xaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSCJwOfK07t
# 5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfzqBz3pRO+
# 5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+IVcvC9Yd
# qahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgyTch4GuYW
# efSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFpDjCCBvIw
# ggTaoAMCAQICEEYIeZepsUVgl89Vi+VQ9vQwDQYJKoZIhvcNAQELBQAwVjELMAkG
# A1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIG
# A1UEAxMbQ2VydHVtIENvZGUgU2lnbmluZyAyMDIxIENBMB4XDTI0MDgwNTA2MDQ0
# NloXDTI3MDgwNTA2MDQ0NVowgZcxCzAJBgNVBAYTAkFUMRYwFAYDVQQIDA1Mb3dl
# ciBBdXN0cmlhMRYwFAYDVQQHDA1LcnVtbW51c3NiYXVtMSswKQYDVQQKDCJIQUNL
# TkVSIFNlY3VyaXR5IEludGVsbGlnZW5jZSBHbWJIMSswKQYDVQQDDCJIQUNLTkVS
# IFNlY3VyaXR5IEludGVsbGlnZW5jZSBHbWJIMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAut+1sc9ruhjeCCm1iLtWMW0Cp67hfkogm4gFUGhHWyUIdtxO
# s7JBCDcSZRMaR8DyvOWbLT0qj0Zq4tB4t8MbgPWwIDfJxdnF4/TSDXTzT3m/ix3m
# 9R1f0j0RqsgREdQbelJo0zAvLBO1fvDmsvxhfxg3bvJozyqeUOYLlSRIzFiZz1Dj
# ToVfXbEPM7DQLS1AgWeRoQ4KOdRtE3eM5lTTpVV9YmJexSptQR8D1IMyWq21NZzp
# M4YfahSo4cXs6Rc4wYKQIZNOYZQWKooL+oKAa5k4jtENjswdiwMhD75/A0vgQ0Q5
# 5eShvjf/qAwvvQJ+Y7LNW4mtHL5tmdg0YYR0Azeln+Gh0BbLQRpyRq1VofCaRJip
# fWsLYOekIyH+nNZPqekE0MEt90hOPSey+b8QCcKcIBwpVyRBWAItHFnvu9OEdGWZ
# Cw/Po3ZGSd1cA8aupwL5XlBawxSfl2ucQ5VdPjPvOQvw4KI9PKY3+KRltVTOzDgh
# c0QGNikKiUMJTCRZfp9xsoY3jECSPdOjgip2hfAbUkRX9LU4tPQp8Vy8CwpdqOQZ
# myuB6+i8NmsJLWfc3XrEpkAf3p/pBgb0h/l/k7ZfiW1zbODrzKnGLgjnUXf3VpUB
# 7wE4Wcdl1y33dAYVKFH9CqM8n4427ltVdAhR1xZZrSdwn1lZGgfmtQWJsacCAwEA
# AaOCAXgwggF0MAwGA1UdEwEB/wQCMAAwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDov
# L2Njc2NhMjAyMS5jcmwuY2VydHVtLnBsL2Njc2NhMjAyMS5jcmwwcwYIKwYBBQUH
# AQEEZzBlMCwGCCsGAQUFBzABhiBodHRwOi8vY2NzY2EyMDIxLm9jc3AtY2VydHVt
# LmNvbTA1BggrBgEFBQcwAoYpaHR0cDovL3JlcG9zaXRvcnkuY2VydHVtLnBsL2Nj
# c2NhMjAyMS5jZXIwHwYDVR0jBBgwFoAU3XRdTADbe5+gdMqxbvc8wDLAcM0wHQYD
# VR0OBBYEFGd9d+bbyBksCo+3sA4Sker4XCx7MEsGA1UdIAREMEIwCAYGZ4EMAQQB
# MDYGCyqEaAGG9ncCBQEEMCcwJQYIKwYBBQUHAgEWGWh0dHBzOi8vd3d3LmNlcnR1
# bS5wbC9DUFMwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMA0G
# CSqGSIb3DQEBCwUAA4ICAQBjrcYDaEchXliEAQxYcZ6XGaHMq2gIRcPJQ8bud7P9
# 0guIUezYOr+FBRrWwL9H5CzwuITlfrWE7xPoEcPFgfYFNV6z1mSSYlmUKsK8nIzy
# IWCiBENGHIayMu7E2CZyP8geZJr99fTinJNhSYS5yUvbPruRTnXqMxjzEyrgFyRe
# RpmZ4IOWUeOoaTafj8iVpUnTqX/7dSTkc8Y/Z/qIHCYmKGQlW0U7/KZg883ZZrUm
# 0Sya6WyGvD0zq+MQM112rMoi12Js2jiyos2VSRSbToaV44gaLI71JWn1KMqyqLID
# XWEq3YlUhn0HDMUas1AJSXXS/wqhPty46m8VdsrLH0Ib3rjVbWgEApU0NnUXpdY4
# xpDRhvZ0BruHzh672KCZpdsihQJflEOGBR1AhwcZk81roaANiTnhQxTGlrjFTEjw
# MHfbry4SDgsWrMLLoYrVaN4D64T1WeUKl4YqU4kvvpA8TaysKKT+zzJDOA0Y2UUX
# ZTZeoDHpD2KBmXbwuiu7FMj1kVwf71CAwyAPfn2W2LXR58klGusTHDsP9o6NUMpQ
# tBpQF3TXGRVamsddtCK9iNAlGAhDPAQrK6r67yGpbnXr0/1/oPuoDWdcRGbYA5pY
# 8ZTL7t7dolKmeHPanCOjWOjETmN3wMSXMOthDVgyz1BL47FgkGKJs7g+VrnTB91j
# TjGCBkMwggY/AgEBMGowVjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBE
# YXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMbQ2VydHVtIENvZGUgU2lnbmluZyAy
# MDIxIENBAhBGCHmXqbFFYJfPVYvlUPb0MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisG
# AQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPJZ
# MP+VyoyzI7ibrKRoF4M6iQA3grnCj+0I9NgSFNaIMA0GCSqGSIb3DQEBAQUABIIC
# AK7c2Ap/eNP1LTTIaBpyGwogm7QVUMSUrO4jamms3D5prLS+cHWOMdMAY5G79Uth
# gpRLAlbmz/31joESl02KUfBsqg3mRGo2JFSz2H+f/+d2UiUoaOtgJknDHLYQoY5+
# ONCJ5v4Bvzb+YBMebmULtwO1QId+Pd8Ej0KehtTini15QyPe9sMCtBuV3zknGboV
# nPJHJvAmpG8h3FNcZf+HTvNE5a5+gpHDO06wT4kvYgLeXVcjQun3vdhB3hyJNx0e
# VKttm1O5epVJGoGmquKUiVImd+lvqsmZh82Sh1xU4fIGo3F/KsBRmwtUEe+XlD/w
# saiNnvP9h+g5bqAUQd6/+Rfwu/LshK3VBlQBPsb5i8CECxWUmqzUrlLusHKTKYEz
# ga0kWRN27V73g/crYgNGB+Q8IqAAWZh7iOM5xnIm8QbU0i/OFmNeoUBVSjDt1kCv
# 5BBmis+Au5lrR/yFpilg//TjzIEnKOEOU4g9A+Os1WaHLBl4KS+B7I74bKRBztQZ
# 16Dv/sRirqbD2E9gF6/CGvQM5JBLURB3MuSmAjzJJT8+dsYUzqeQ7UeOPmvwjKD0
# BOH39BVob5e8DGGPAqewrOeusZafImzpaNlCAmk2za8e1j6FP5B+JEJv/djzEqSX
# hwrw9HCrUjR9RXyzTr6yevyfCeol0QDAifdbSuwaXMedoYIDIzCCAx8GCSqGSIb3
# DQEJBjGCAxAwggMMAgEBMGowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGlu
# ZyBDQSBSMzYCEQCkKTtuHt3XpzQIh616TrckMA0GCWCGSAFlAwQCAgUAoHkwGAYJ
# KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUwNzEwMDgy
# MjUyWjA/BgkqhkiG9w0BCQQxMgQw23Lb9FSdq8v7YUlxAF4NIYfaK55OyVUhO8jM
# NxrAPG1tcsb0sPskZtWmc1YqQzyMMA0GCSqGSIb3DQEBAQUABIICACqMnGRszlNv
# UhDKgHJZBSl8zYooK3SJX07vycvv77T64BlcoK0ANTBe1CKQwCYKgB8m+2dt0luo
# 5H1VP/uD18pA548uVPIqBl7UFxM63vLBltzT3kdToUsjOLcTQTn2NhlQRsaq+NnN
# 2IUVJq5z0dWhEemu9QFECSbMPTP0nwO1u1l5lNhHlq4Y1TWi7oBAz/B34v7/yifm
# LwWoWKwT8PkOxxG9TBo/9B0ZEeLD7+wz5LzqvCaoUc0HlnWf9Wdn5+bVgPXe4tmC
# R82S3jW3peew4rGxBLbBdmGH5peO7WNNc4Ex44SiE/0O+cZ1ZPnikr+E2fal2I1+
# NRwLFz57rZNtWZAYtyAfxQ8CUIOxdrCTiH5Qbw++3rKh0I8IB7TmC3G7e4uhjWDr
# gDAt3hTPG/+tR0E9kbNYux9xiH0vAyK5O7OgVznHSnqgFVZyXfuXpJnVgi9xGfSX
# eCE864M2JMKy9D09KPaCaHxcflp9A6LHFA1W+n7eZXS69R3J1giMBT/TzRyu3WSj
# 1XedOOkvOW0Lo07OgFDeWcQUG5yMCoZS8byaJL1WigWQlIlcyOySYKJ4kMeRiyzh
# Bs3A9sH68JtXzSNtlzB/XHJbT7dJPvI4uYfX8RQyDh8MlU5h0om0z6cWzhQUddkj
# 4nxeJI5z6fjXX3/dfvVnDDx130DEFSwn
# SIG # End signature block
