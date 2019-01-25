using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    class Program
    {
        public static TcpListener listener;
        public static ECDiffieHellmanCng serverDH;

        public static void GenerationDHKey()
        {
            serverDH = new ECDiffieHellmanCng();
            serverDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            serverDH.HashAlgorithm = CngAlgorithm.Sha256;
            byte[] serverPublicKey = serverDH.PublicKey.ToByteArray();
            File.WriteAllBytes(@"D:\OSU\ЗПиД\ЗПиД7\Публичный ключ сервера.txt", serverPublicKey);
        }

        public static void GetMessages()
        {
            TcpClient client = listener.AcceptTcpClient();
            byte[] encryptedMessage = new byte[1024];
            NetworkStream nstream = client.GetStream();
            int count = nstream.Read(encryptedMessage, 0, encryptedMessage.Length);
            byte[] message = new byte[count];
            Array.Copy(encryptedMessage, message, count);
            byte[] decryptedMessage = Decrypt(message);
            string result = Encoding.UTF8.GetString(decryptedMessage);
            Console.WriteLine("<<" + result);
        }

        public static byte[] Decrypt(byte[] requestBytes)
        {
            byte[] publicKeyClient =
               File.ReadAllBytes(@"D:\OSU\ЗПиД\ЗПиД7\Публичный ключ клиента.txt");
            byte[] commonKeyForServer =
               serverDH.DeriveKeyMaterial(CngKey.Import(publicKeyClient, CngKeyBlobFormat.EccPublicBlob));
            Aes aesServer = new AesCryptoServiceProvider();
            aesServer.Key = commonKeyForServer;
            aesServer.IV = new byte[16];
            aesServer.Padding = PaddingMode.None;
            byte[] DecryptToServer;
            int rc = 0;
            using (MemoryStream ms = new MemoryStream(requestBytes))
            {
                using (CryptoStream cs = new CryptoStream(ms, aesServer.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    DecryptToServer = new byte[ms.Length];
                    rc = cs.Read(DecryptToServer, 0, DecryptToServer.Length);
                    cs.Close();
                }
                ms.Close();
            }
            return DecryptToServer;
        }

        private static void Main(string[] args)
        {
            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
            listener = new TcpListener(ipAddress, 7777);
            listener.Start();
            while (true)
            {
                GenerationDHKey();
                GetMessages();
            }
            listener.Stop();
        }
    }
}
