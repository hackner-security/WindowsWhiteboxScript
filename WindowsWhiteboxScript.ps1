#REQUIRES -version 2.0

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
    [string[]] $paths = @(),
    [switch] $force = $false,
    [switch] $testing = $false,
    [switch] $version = $false,
    [switch] $dumpPermissions = $false,
    [switch] $onlyJson = $false,
    [int] $captureTraffic,
    [string] $outputdir = (Get-Item -Path ".\").FullName + "\" + $ENV:ComputerName,
    [switch] $generateCommandList
)

# Version
$versionString = "v3.6"

# Check permissions of the following paths
$paths += $env:ProgramFiles
$paths += ${env:ProgramFiles(x86)}

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

function Invoke-Setup {

    #If version parameter is specified, only display version of script and exit
    if ($script:version) {
        Write-Output "Script Version: $versionString"
        Exit
    }

    #Check for administrator privileges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (!$script:force -and !$isAdmin) {
        Write-Warning "[-] This script needs to be run with admin privileges. To run it with lower privileges, the -Force option can be used."
        Exit
    }

    #Remove previously generated folders
    if ($script:testing) {
        Remove-Item -Recurse $outputdir
        Remove-Item $outputdir
        $script:DebugPreference = "Continue"
    }
    else {
        $script:ErrorActionPreference = "SilentlyContinue"
    }

    #Create output directory if they do not already exist
    if (!(Test-Path "$outputdir")) {
        New-Item -ItemType directory -Path $outputdir | Out-Null
    }

    $Script:startTime = Get-Date -UFormat '%Y/%m/%d %H:%M'
    Write-Data -Output "${script:startTime}: Started script execution." -File $filenames.logfile -useWriteOutput

    # Store the script version in log files
    Write-Data -Output "Script version: $versionString" -File $filenames.logfile -useWriteOutput

    # Print the powershell version
    $Script:psversion = $PSVersionTable.PSVersion
    Write-Data -Output "Powershell version: $($psversion.Major).$($psversion.Minor)" -File $filenames.logfile -useWriteOutput

    #Change the enumeration limit, so our outputs do not get truncated on 4 elements
    # (do to a PowerShell bug, we have to set it globally during the script execution and set at back at the end)
    $script:rememberFormatEnumerationLimit = $global:FormatEnumerationLimit
    $global:FormatEnumerationLimit = -1
    Write-Data -Output "Global FormatEnumerationLimit: $script:rememberFormatEnumerationLimit" -File $filenames.logfile

}

function Invoke-Teardown {

    #Set enumeration limit back to what it was before
    $global:FormatEnumerationLimit = $script:rememberFormatEnumerationLimit
    Write-Data -Output "Reset FormatEnumerationLimit to $global:FormatEnumerationLimit" -File $filenames.logfile

    If (-Not $onlyJson) {
        #Write encountered errors to log file
        Write-Data -Output $Error -File $filenames.errorlog

        #Write output to result folder
        foreach ($h in $outputFileContents.Keys) {
            Add-Content -Path "$outputdir\$h.txt" -Value $outputFileContents.Item($h)
        }

        #Compress files for easier copying
        Compress-Result
    }

    $endTime = Get-Date -UFormat '%Y/%m/%d %H:%M'
    Write-Data -Output "${endTime}: All Done." -File $filenames.logfile -useWriteOutput
}

#Writes to console screen and output file
function Write-Data() {
    param (
        [parameter(Mandatory = $true)] $Output,
        [parameter(Mandatory = $true)][String] $File,
        [switch] $useWriteOutput
    )

    if ($useWriteOutput) {
        # Put $Output in the stream, so it is returned by the function. Use this parameter with care if you
        # are not handling the output accordingly
        $Output
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

        #Compression method for Powershell < 5
        if (-not (Test-Path($zipFile))) {
            Set-Content $zipFile ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
            (Get-ChildItem $zipFile).IsReadOnly = $false
        }

        $shellApplication = New-Object -com shell.application
        $zipPackage = $shellApplication.NameSpace($zipFile)
        $files = Get-ChildItem -Path $outputdir -Recurse | Where-Object { ! $_.PSIsContainer }

        foreach ($file in $files) {
            $zipPackage.CopyHere($file.FullName)
            #using this method, sometimes files can be 'skipped'
            #this 'while' loop checks each file is added before moving to the next
            while ($null -eq $zipPackage.Items().Item($file.name)) {
                Start-Sleep -Milliseconds 250
            }
        }
        Move-Item -Path $zipFile -Destination "$outputdir"
    }
}

#Check ports using "netstat -ano" and print the corresponding process names for the process IDs
function Get-OpenPort {

    $openPortsWithProcessesPowerShellCommand = { netstat.exe -ano | Select-String -Pattern "(TCP|UDP)" | ForEach-Object { $splitArray = $_ -split " "; $processId = $splitArray[-1]; $processName = Get-Process | Where-Object { $_.id -eq $processId } | Select-Object processname; $splitArray[-1] = $processId + "`t" + $processName.ProcessName; $splitArray -join " " } }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $openPortsWithProcessesPowerShellCommand -headline "Open Ports with Process Names" -outputFile $filenames.openports

    $openPortsElevatedCmdCommand = "netstat.exe -anob"
    Invoke-CmdCommandAndDocumentation -command $openPortsElevatedCmdCommand -outputFile $filenames.openports
}

# Check general information about OS users
# In case the system locale is set to German, the German commands are additionally added here
function Get-UserInformation {

    Write-Data "### Query General OS User Information ###" -File $filenames.groups
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

#Check RDP Configuration
function Get-RDPConfiguration {

    Write-Data -Output "### RDP Configuration ###" -File $filenames.rdp
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

# Get information about SMB settings
# These commands might fail on earlier Powershell versions
function Get-SmbInformation {

    # Here we collect some general SMB information and put it in text files
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

    # Find out about SMB1 support (this can also be done with Get-SmbServerConfiguration, but not on Server 2008)
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

function Get-UnattendedInstallFile {

    $targetFiles = @(
        "C:\unattended.xml",
        "C:\Windows\Panther\unattend.xml",
        "C:\Windows\Panther\Unattend\Unattend.xml",
        "C:\Windows\System32\sysprep.inf",
        "C:\Windows\System32\sysprep\sysprep.xml"
    )

    Write-Data "[*] Checking for unattended install files" -File $filenames.unattend

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

    $installedProgramsX64PowerShellCommand = { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Format-Table -AutoSize DisplayName, DisplayVersion, Publisher, InstallDate | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $installedProgramsX64PowerShellCommand -headline "x64" -outputFile $filenames.installedprograms

    $installedProgramsX86PowerShellCommand = { Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Format-Table -AutoSize DisplayName, DisplayVersion, Publisher, InstallDate | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $installedProgramsX86PowerShellCommand -headline "x86" -outputFile $filenames.installedprograms

}

function Get-FirewallConfiguration {

    # Check firewall information using PS cmdlet
    $firewallProfilePowerShellCommand = { Get-NetFirewallProfile }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $firewallProfilePowerShellCommand -headline "Firewall Profiles" -outputFile $filenames.firewall
    $firewallRulePowerShellCommand = { Get-NetFirewallRule }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $firewallRulePowerShellCommand -headline "Firewall Rules" -outputFile $filenames.firewall

    $netshFirewallCmdCommand = "netsh advfirewall show allprofiles"
    Invoke-CmdCommandAndDocumentation -command $netshFirewallCmdCommand -outputFile  $filenames.firewall

    $alternativeFirewallRulesPowerShellCommand = { (New-Object -ComObject HNetCfg.FwPolicy2).rules | Where-Object { $_.Enabled -eq $true } | Format-List Name, Description, ApplicationName, serviceName, Protocol, LocalPorts, LocalAddresses, RemoteAddresses, Direction | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $alternativeFirewallRulesPowerShellCommand -headline "Firewall Rules" -outputFile $filenames.firewall

}

#Get files and ACLs
function Get-FileAndPermission {
    param(
        [Parameter(Mandatory = $true)][string[]]$paths
    )

    ForEach ($path in $paths) {

        $filename = Split-Path $path -Leaf
        Write-Data -Output "Directory $path" -File "$($filenames.aclsdirname)_$filename.txt"
        Write-Data -Output "[Command][PS] Get-ChildItem `"$path`" -Recurse | Get-Acl | Format-List" -File "$($filenames.aclsdirname)_$filename.txt"
        Write-Data -Output (Get-ChildItem "$path" -Recurse | Get-Acl | Format-List) -File "$($filenames.aclsdirname)_$filename.txt"

    }

}

#Checks installed Antivirus products
function Get-AntiVirusProduct {

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

#Dump installed patches via WMIC and PowerShell
function Get-Patchlevel {

    $installedUpdatesPowerShellCommand = { Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object "Caption", "CSName", "Description", "HotFixID", "InstalledBy", "InstalledOn", @{n = "InstallDate"; e = { ([datetime]$_.psbase.properties["InstalledOn"].Value).ToString("yyyy.MM.dd") } } -ExcludeProperty InstallDate | Format-Table -AutoSize | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $installedUpdatesPowerShellCommand -headline "Installed Updates (queried with PowerShell)" -outputFile $filenames.patchlevel

    $wmicQfeCmdCommand = "wmic qfe list full"
    $wmicQfeSubPath = "Wbem"
    Invoke-CmdCommandAndDocumentation -command $wmicQfeCmdCommand -subPath $wmicQfeSubPath -headline "Installed Patches via WMIC QFE" -outputFile $filenames.patchlevel

    $installedUpdates = Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object "Caption", "CSName", "Description", "HotFixID", "InstalledBy", "InstalledOn", @{n = "InstallDate"; e = { ([datetime]$_.psbase.properties["InstalledOn"].Value).ToString("yyyy.MM.dd") } } -ExcludeProperty InstallDate
    $installedUpdates
}

#Check if AutoLogin is enabled in the registry
function Get-AutoLogon {

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

# Check for protocols which are spoofable by responder (NBNS, LLMNR)
function Get-ResponderProtocol {

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

function Get-PrivilegeEscalation {

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

    # Check writable services
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

    $hostname = "$ENV:ComputerName"
    $domain = "$(Get-WmiObject -namespace root\cimv2 -class win32_computersystem | Select-Object -exp domain)"
    $operatingSystem = "$((Get-WmiObject Win32_OperatingSystem).Caption)"
    $windowsVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    $psVersion = "$($Script:psversion.Major).$($Script:psversion.Minor)"
    $startTime = "$Script:startTime"
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
        hostname        = $hostname
        domain          = $domain
        operatingSystem = $operatingSystem
        windowsVersion  = $windowsVersion
        psVersion       = $psVersion
        scriptStartTime = $startTime
        ipv4            = $ipv4
        ipv6            = $ipv6
        scriptVersion   = $script:versionString
    }

    $hostJson
}

function Get-CredentialProtection {

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

function Get-UAC {

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

function Get-BitlockerStatus {

    $bitlockerCmdCommand = "manage-bde -status"
    Invoke-CmdCommandAndDocumentation -command $bitlockerCmdCommand -headline "Bitlocker Settings CMD" -outputFile $filenames.bitlocker

    $bitlockerPowerShellCommand = { Get-BitLockerVolume | Format-List * | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $bitlockerPowerShellCommand -headline "Bitlocker PowerShell" -outputFile $filenames.bitlocker

    $bitlockerWMIPowerShellCommand = { Get-WmiObject -namespace "Root\cimv2\security\MicrosoftVolumeEncryption" -ClassName "Win32_Encryptablevolume" | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $bitlockerWMIPowerShellCommand -headline "Bitlocker PowerShell WMI" -outputFile $filenames.bitlocker

}

function Get-PSRemoting {

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

function Invoke-Secedit {

    $seceditCmdCommand = "secedit.exe /export /cfg `"$outputdir\$($filenames.secedit)`" /quiet"
    Invoke-CmdCommandAndDocumentation -command $seceditCmdCommand -headline "Secedit.exe Security Settings" -manualCommandListOverride "secedit.exe /export /cfg $($filenames.secedit) /quiet" -outputFile $filenames.logfile

    #Read file in order to store in JSON
    $output = Get-Content $outputdir\$($filenames.secedit) | Out-String

    if ($script:onlyJson) {
        Remove-Item "$outputdir\$($filenames.secedit)"
    }

    $output
}

function Get-InsecurePowerShellVersion {

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

function Get-SystemService {

    # The following script block is used to pretty print all services in TXT files
    $servicesPowerShellCommand = { Get-WmiObject win32_service | Select-Object ProcessId, Name, State, StartName, StartMode, PathName | Sort-Object -Property State | Format-Table -AutoSize | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $servicesPowerShellCommand -headline "Services" -outputFile $filenames.services

    # $services holds the information that is needed for the result JSON file
    $services = Get-WmiObject win32_service | Select-Object ProcessId, Name, State, StartName, StartMode, PathName
    $services
}

function Invoke-NetworkTrafficCapture {
    param(
        [Parameter(Mandatory = $true)][int] $seconds,
        [Parameter(Mandatory = $true)][string] $outputPath
    )
    # In case the script is interrupted using Ctrl+C, there is a finally block that will always execute
    try {
        Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList "trace start capture=yes tracefile=$outputPath" -Wait -NoNewWindow
        Start-Sleep -Seconds $seconds
    }
    finally {
        Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList "trace stop" -Wait -NoNewWindow
        Write-Data -Output "You can use etl2pcapng to convert the created etl file (https://github.com/microsoft/etl2pcapng)" -File $filenames.logfile -useWriteOutput
        Write-Data -Output "Command: etl2pcapng.exe traffic.etl out.pcapng" -File $filenames.logfile -useWriteOutput
    }
}

function Get-DeviceSecurity {

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

function Get-MSSQLServerConfiguration {

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
        $currentVersion = (Get-ItemProperty "$mssqlRegistryRoot\$instanceRegistryName\MSSQLServer\CurrentVersion")."CurrentVersion"
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
            currentVersion     = $currentVersion
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

function Get-NfsConfiguration {

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

function Get-PrintSpoolerConfiguration {

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

function Get-AsrRulesConfiguration {
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

###############################
### Main Part of the Script ###
###############################

#Create basic file structure and adjust settings
Invoke-Setup

#Get information about host
$hostinfo = Get-HostInformation

# Create the JSON result file with information gathered from various sources
$result = @{
    $filenames.autologon            = Get-AutoLogon
    $filenames.host                 = $hostinfo
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
    $filenames.services             = Get-SystemService
    $filenames.mssql                = Get-MSSQLServerConfiguration
    $filenames.drivers              = Get-DeviceSecurity
    $filenames.spooler              = Get-PrintSpoolerConfiguration
    $filenames.asrrules             = Get-AsrRulesConfiguration
}

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
    #Get Hostname, Domain and OS version
    Write-Data -Output "[*] Query Basic Host Information" -File $filenames.host
    Write-Data -Output $hostinfo -File $filenames.host

    #Proxy and Internet Settings
    $proxySettingsPowerShellCommand = { Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | ForEach-Object { Get-ItemProperty $_.pspath } | Out-String }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $proxySettingsPowerShellCommand -headline "Query Proxy and Internet Settings from Registry" -outputFile $filenames.basicinfo
    #Get Basic Computer Information including VBS & Device Guard
    $computerInfoPowerShellCommand = { Get-ComputerInfo }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $computerInfoPowerShellCommand -headline "Computer Info PowerShell" -outputFile $filenames.basicinfo
    #In case Get-ComputerInfo fails the following commands should provide basic OS information
    $computerInfoWMIPowerShellCommand = { Get-WmiObject win32_operatingsystem | Format-List * | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $computerInfoWMIPowerShellCommand -headline "Computer Info WMI" -outputFile $filenames.basicinfo

    #Get the system's network information (IP addresses, interfaces, routes, ARP table)
    $ipconfigCmdCommand = "ipconfig.exe /all"
    Invoke-CmdCommandAndDocumentation -command $ipconfigCmdCommand -headline "Query Network Configuration" -outputFile $filenames.network
    $routePrintCmdCommand = "route.exe PRINT"
    Invoke-CmdCommandAndDocumentation -command $routePrintCmdCommand -headline "Query Routing Information" -outputFile $filenames.network
    $arpCmdCommand = "arp.exe -a"
    Invoke-CmdCommandAndDocumentation -command $arpCmdCommand -headline "Query ARP Table" -outputFile $filenames.network

    Get-UserInformation
    Get-OpenPort
    Get-AntiVirusProduct

    #Get running processes and their owners
    $runningProcessesPowerShellCommand = { Get-WmiObject Win32_Process | Select-Object ProcessId, ProcessName, @{Name = "UserName"; Expression = { $_.GetOwner().Domain + "\" + $_.GetOwner().User } }, Path | Sort-Object ProcessId | Format-Table -AutoSize | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $runningProcessesPowerShellCommand -headline "Query Running Processes" -outputFile $filenames.processes
    # The following command can be used for PS > 3
    # Write-Data -Output (Get-Process -IncludeUserName | Sort-Object -Property Id | Format-Table -AutoSize Id, UserName, ProcessName | Out-String -Width 4096) -File $filenames.processes

    #Print scheduled tasks
    $schtasksCmdCommand = "schtasks.exe /query /fo LIST /v"
    Invoke-CmdCommandAndDocumentation -command $schtasksCmdCommand -headline "Query Scheduled Tasks" -outputFile $filenames.tasks

    #Run gpresults.exe and save report
    $gpresultCmdCommand = "gpresult.exe /H `"$outputdir\$($filenames.gpresult)`""
    Invoke-CmdCommandAndDocumentation -command $gpresultCmdCommand -headline "Dump Report of gpresult.exe" -manualCommandListOverride "gpresult.exe /H $($filenames.gpresult)" -outputFile $filenames.logfile

    Get-FirewallConfiguration
    Get-InstalledProgram

    #Get Auto-Start Programs
    $autostartPowerShellCommand = { Get-WmiObject win32_startupcommand | Format-List Command, Caption, Description, User, Location | Out-String -Width 4096 }
    Invoke-PowerShellCommandAndDocumentation -scriptBlock $autostartPowerShellCommand -headline "Check Autostart Programs via WMI" -outputFile $filenames.autostart

    #If dumpPermissions is set, dump all permissions of the program folders (or custom paths)
    if ($dumpPermissions) {
        Get-FileAndPermission -paths $paths
    }

    #Check for unattended install files
    Get-UnattendedInstallFile

    #Check Bitlocker Information
    Get-BitlockerStatus

    # NFS Configuration (server and client configuration)
    Get-NfsConfiguration

    #Perform network trace
    if ($PSBoundParameters.ContainsKey("captureTraffic")) {
        Invoke-NetworkTrafficCapture -seconds $captureTraffic -outputPath "$outputdir\traffic.etl"
    }

}

#Do some error reporting
Invoke-Teardown

$result
