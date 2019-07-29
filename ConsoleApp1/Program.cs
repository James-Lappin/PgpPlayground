using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                //BouncyCastleCopy.GenerateKeyPair();
                //
                //byte[] dataBytes = File.ReadAllBytes("input.txt");
                Stream pub = File.OpenRead("publicKey.asc");
                Stream priv = File.OpenRead("secretKey.asc");

                //Stream outStream = File.Create("data.enc");
                //var dave = new CopyFromStackoverflow();
                //
                //byte[] encrypted = dave.EncryptFile(dataBytes, string.Empty, dave.ReadPublicKey(pub));
                //outStream.Write(encrypted, 0, encrypted.Length);
                //outStream.Close();

                var dave1 = new AnotherCopy();
                var encryptedData = File.OpenRead("message_not_signed.txt.asc");
                //if (dave1.VerifyFile(encryptedData, pub))
                //{
                //    Console.WriteLine("Yay!");
                //}
                var decryptedStream = dave1.DecryptAndVerify(encryptedData, pub, priv, "7pU3^E%AEj9gRqTxzk7G*r".ToCharArray());
                var fileStream = File.OpenWrite($"{DateTime.UtcNow:yyyyMMddHHmm}.txt");
                decryptedStream.CopyTo(fileStream);
                fileStream.Close();
                decryptedStream.Close();
                encryptedData.Close();
                pub.Close();
                priv.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.ReadLine();
        }
    }


    public class CopyFromStackoverflow
    {
        public PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            //
            // iterate through the key rings.
            //

            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                    {
                        return k;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        public byte[] EncryptFile(byte[] clearData, string fileName, PgpPublicKey encKey)
        {
            MemoryStream bOut = new MemoryStream();

            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(
                CompressionAlgorithmTag.Zip);

            Stream cos = comData.Open(bOut); // open it with the final destination
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();

            // we want to Generate compressed data. This might be a user option later,
            // in which case we would pass in bOut.
            Stream pOut = lData.Open(
                cos, // the compressed output stream
                PgpLiteralData.Binary,
                fileName, // "filename" to store
                clearData.Length, // length of clear data
                DateTime.UtcNow // current time
            );

            pOut.Write(clearData, 0, clearData.Length);

            lData.Close();
            comData.Close();

            PgpEncryptedDataGenerator cPk =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, new SecureRandom());

            cPk.AddMethod(encKey);

            byte[] bytes = bOut.ToArray();

            MemoryStream encOut = new MemoryStream();
            Stream os = encOut;

            Stream cOut = cPk.Open(os, bytes.Length);
            cOut.Write(bytes, 0, bytes.Length); // obtain the actual bytes from the compressed stream
            cOut.Close();

            encOut.Close();

            return encOut.ToArray();
        }
    }
}