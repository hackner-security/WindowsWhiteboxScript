# WindowsWhiteboxScript

*WindowsWhiteboxScript.ps1* is a PowerShell script and aims to collect as much information of the Windows operating system it runs on (e.g., general information about the OS like the hostname or network configuration, open ports, file system permissions, installed programs, processes, services and service paths, patch level, RDP configuration, etc.). It is mainly developed for Windows server systems and supports Windows Server 2008 R2 and upper.

The script stores all results in multiple text files in an output folder on the system. The text files can then be manually or automatically examined.

## How to Run

The script is designed to be run with administrative privileges to gain as much information about the system as possible. Use the parameter ``-Force`` if you are no admin.

```powershell
PS C:\whitebox> .\WindowsWhiteboxScript.ps1
[*] 2024/10/29 10:05 - Started script execution.
[*] 2024/10/29 10:05 - Script version: v3.7.1
[*] 2024/10/29 10:05 - Powershell version: 5.1
[*] 2024/10/29 10:05 - Output directory: C:\whitebox\WIN-0E273E6
[*] 2024/10/29 10:05 - Querying basic host information
[*] 2024/10/29 10:05 - Checking potential autologon configuration
[*] 2024/10/29 10:05 - Querying OS updates and patch level
[*] 2024/10/29 10:05 - Checking for privilege escalation possibilities
[*] 2024/10/29 10:06 - Checking for unquoted service paths
[*] 2024/10/29 10:06 - Inspecting settings for potentially spoofable protocols
[*] 2024/10/29 10:06 - Querying RDP settings
[*] 2024/10/29 10:06 - Getting WSUS settings from registry
[*] 2024/10/29 10:06 - Verifying settings for credential protection
[*] 2024/10/29 10:06 - Checking SMB configuration
[*] 2024/10/29 10:06 - Querying UAC settings from registry
[*] 2024/10/29 10:06 - Getting PowerShell remoting configuration
[*] 2024/10/29 10:06 - Invoking secedit for password policy checks
[*] 2024/10/29 10:06 - Verifying installed PowerShell versions
[*] 2024/10/29 10:06 - Getting running services and scheduled tasks
[*] 2024/10/29 10:06 - Identifying MSSQL configuration
[*] 2024/10/29 10:06 - Checking device security settings and drivers
[*] 2024/10/29 10:06 - Getting print spooler service settings
[*] 2024/10/29 10:06 - Verifying installed attack surface reduction rules
[*] 2024/10/29 10:06 - Getting the system network information (IP addresses, interfaces, routes, ARP table)
[*] 2024/10/29 10:06 - Querying basic system information
[*] 2024/10/29 10:06 - Getting general OS user and group information
[*] 2024/10/29 10:06 - Querying open network ports
[*] 2024/10/29 10:06 - Getting antivirus information
[*] 2024/10/29 10:06 - Querying running processes
[*] 2024/10/29 10:06 - Extracting local group policy via gpresult.exe
[*] 2024/10/29 10:06 - Reading firewall configuration and rules
[*] 2024/10/29 10:06 - Querying installed applications
[*] 2024/10/29 10:06 - Querying autostart programs via WMI object
[*] 2024/10/29 10:06 - Querying hard drive encryption settings (Bitlocker)
[*] 2024/10/29 10:06 - Inspecting NFS configuration
[*] 2024/10/29 10:07 - All Done.
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
