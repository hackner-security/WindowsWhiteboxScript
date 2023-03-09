# WindowsWhiteboxScript

*WindowsWhiteboxScript.ps1* is a PowerShell script and aims to collect as much information of the Windows operating system it runs on (e.g., general information about the OS like the hostname or network configuration, open ports, file system permissions, installed programs, processes, services and service paths, patch level, RDP configuration, etc.). It is mainly developed for Windows server systems and supports Windows Server 2008 R2 and upper.

The script stores all results in multiple text files in an output folder on the system. The text files can then be manually or automatically examined.

## How to Run

The script is designed to be run with administrative privileges to gain as much information about the system as possible. Use the parameter ``-Force`` if you are no admin.

```powershell
PS C:\whitebox> .\WindowsWhiteboxScript.ps1
2023/03/08 14:53: Started script execution.
Script version: v3.0
Powershell version: 5.1
2023/03/08 15:01: All Done.

Name                           Value
----                           -----
privilege_escalation           {writablePaths, writableServicePaths, scheduledTasks, unquotedServicePaths, alwaysIns...
responder_protocols            {enableMulticast, nbns, enableMDNS}
wsus                           {WSUSServerUsed, WUStatusServer, WUServer}
services                       {@{ProcessId=5012; Name=AdobeARMservice; State=Running; StartName=LocalSystem; StartM...
basic_information              {commandOutput, psCommand, psVersion2Installed}
secedit_output.inf             [Unicode]...
powershell_remoting            {psremotingenabled}
smb                            {Shares, EncryptData, EnableSMB1, RequireSecuritySignature, RejectUnencryptedAccess, ...
patchlevel                     {@{Caption=http://support.microsoft.com/?kbid=5022502; CSName=DESKTOP-II2BMID; Descri...
host                           {domain, ipv4, scriptVersion, windowsVersion, hostname, scriptStartTime, psVersion, o...
rdp                            {nla, fDenyTSConnections, encryption, certificateSubject, certificateIssuer, security...
autologon                      {DefaultUserName, DefaultPasswordSet}
user_account_control           {ConsentPromptBehaviorAdmin, EnableLUA, FilterAdministratorToken, LocalAccountTokenFi...
credential_protection          {LsaCfgFlags, WDigest, SecurityServicesRunning, LSASSRunAsPPL}
```

When you run the PowerShell script, you can see that the output is split into categories. The generated text files in the main output folder are for manual investigation and contain lots of information. The additionally generated JSON file (or XML if you are on an old machine) contains analyzable information you can potentially verify automatically.

## Examples

If the script is run without parameters, it performs basic information gathering of the system (reading interesting files, registry items and extraction information from PowerShell via Cmdlets). The following examples show additional functionalities:

### Change default output folder

```powershell
PS C:\whitebox> .\WindowsWhiteboxScript.ps1 -outputdir "C:\xyz"
```

### Only output the result JSON file

```powershell
PS C:\whitebox> .\WindowsWhiteboxScript.ps1 -onlyJson
```

### Additionally capture network traffic for 30 seconds

```powershell
PS C:\whitebox> .\WindowsWhiteboxScript.ps1 -captureTraffic 30
```

### Generate a file with commands executed by the script (stored as `command_list.txt`)

```powershell
PS C:\whitebox> .\WindowsWhiteboxScript.ps1 -generateCommandList
```

## List of functionalities

- Gather general information (hostname, IP addresses, routing, ARP table, system version, PowerShell version, etc.)
- Open ports
- Host firewall (status (enabled/disabled), rules)
- User onformation (whoami /all, local users, groups, group members, password policy)
- RDP configuration (NLA, encryption Level, security Layer, certificate)
- Privilege escalation (autologon, writeable service paths, writeable paths, unquoted service paths, AlwaysInstallElevated)
- User account control (UAC)
- Responder protocols (NBNS, LLMNR, mDNS)
- Autostart programs
- Windows patches
- Installed programs
- WSUS updates encrypted/unencrypted
- Credential protection (LSASS as Protected Process Light, WDigest Authentication, Credential Guard)
- SMB settings (SMB Signing, SMB Encryption, SMBv1)
- Unattended install files (but only its location and no content, since it could contain sensitive information)
- Files and permissions of folders (default: "Program Files")
- Defender status
- PowerShell remoting
- Device security (hard disk encryption, drivers)
- Capturing network traffic (parameter `-captureTraffic`)
- Local group policy
- Scheduled tasks
- etc.
