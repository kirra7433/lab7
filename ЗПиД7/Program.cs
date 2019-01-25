using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ЗПиД7
{
    internal class Program
    {
        public static TcpClient client;
        public static ECDiffieHellmanCng clientDH;

        public static void GenerationDHKey()
        {
            clientDH = new ECDiffieHellmanCng();
            clientDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            clientDH.HashAlgorithm = CngAlgorithm.Sha256;
            byte[] clientPublicKey = clientDH.PublicKey.ToByteArray();
            File.WriteAllBytes(@"D:\OSU\ЗПиД\ЗПиД7\Публичный ключ клиента.txt", clientPublicKey);
        }
        public static void WriteAndSendMessage(string message)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] enctyptedMessage = Encrypt(messageBytes);
            NetworkStream nstream = client.GetStream();
            nstream.Write(enctyptedMessage, 0, enctyptedMessage.Length);
            nstream.Close();
            client.Close();
        }

        public static byte[] Encrypt(byte[] messageBytes)
        {
            byte[] publicKeyServer =
                     File.ReadAllBytes(@"D:\OSU\ЗПиД\ЗПиД7\Публичный ключ сервера.txt");
            byte[] commonKeyForClient =
                clientDH.DeriveKeyMaterial(CngKey.Import(publicKeyServer, CngKeyBlobFormat.EccPublicBlob));
            Aes aesClient = new AesCryptoServiceProvider();
            aesClient.Key = commonKeyForClient;
            aesClient.IV = new byte[16];
            aesClient.Padding = PaddingMode.Zeros;
            byte[] EncryptFromClient;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aesClient.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(messageBytes, 0, messageBytes.Length);
                    cs.Close();
                }
                ms.Close();
                EncryptFromClient = ms.ToArray();
            }
            return EncryptFromClient;
        }
        private static void Main(string[] args)
        {
            while (true)
            {
                GenerationDHKey();
                client = new TcpClient("127.0.0.1", 7777);
                Console.Write(">>");
                string message = Console.ReadLine();
                WriteAndSendMessage(message);

            }
        }
    }
}


