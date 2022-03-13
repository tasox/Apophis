function TripleDESEncryption
{
	[CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $File,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $Password,
    
        [Parameter(Position = 2, Mandatory = $True)]
        [String]
        $Salt,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $String,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $EncryptedBinaryFile



    )

    $AsciiEncoder = New-Object System.Text.ASCIIEncoding
 
    if ($File){

        [Byte[]] $scriptBytes = Get-Content -AsByteStream -ReadCount 0 -Path $File
    }
    elseif ($String){

        [String] $plaintextContents = $String;
	    $b64 = [Convert]::ToBase64String($AsciiEncoder.GetBytes($plaintextContents));
        [Byte[]] $scriptBytes = [System.Convert]::FromBase64String($b64)
    }
    else {
        
        break;
    }    
    
    Write-Host "`n"
    Write-Host "[+] Password: "$Password
    Write-Host "[+] Salt: "$Salt
    #$InitializationVector = ((1..16 | % {[Char](Get-Random -Min 0x41 -Max 0x5B)}) -join '')
    #Use static InitializationVectory instead of dynamic
    $InitializationVector = "SBFTWSDXBYVOEMTD"
    Write-Host "[+] IV: " $InitializationVector
    $ivBytes = $AsciiEncoder.GetBytes($InitializationVector)
    $DerivedPass = New-Object System.Security.Cryptography.PasswordDeriveBytes($Password, $AsciiEncoder.GetBytes($Salt), "SHA1", 2)
    $Key = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
    $Key.Mode = [System.Security.Cryptography.CipherMode]::CBC
    [Byte[]] $KeyBytes = $DerivedPass.GetBytes(16)
    $Encryptor = $Key.CreateEncryptor($KeyBytes, $ivBytes)
    $MemStream = New-Object System.IO.MemoryStream
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemStream, $Encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $CryptoStream.Write($scriptBytes, 0, $scriptBytes.Length)
    $CryptoStream.FlushFinalBlock()
    $CipherTextBytes = $MemStream.ToArray()
    $MemStream.Close()
    $CryptoStream.Close()
    $Key.Clear()
    $Cipher_B64 = [Convert]::ToBase64String($CipherTextBytes)
    $export = "/home/kali/OSEP/labs/EncryptedB64.txt"
    $Cipher_B64 | Out-File -FilePath $export
    Write-Host "[+] Base64 Output File: "$export
    if($EncryptedBinaryFile){
        Set-Content $EncryptedBinaryFile -Value $CipherTextBytes -AsByteStream
        Write-Host "[+] Encrypted Binary File: "$EncryptedBinaryFile
    }
    Write-Host "[+] Encrypted Data: "$Cipher_B64
    
    #return $Cipher;
}
