using System;
using System.IO;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace ConsoleApp1
{
    public class PgpCryptography
    {
       public byte[] Encrypt(byte[] data, Stream cert)
        {
            var pub = ReadPublicKey(cert);

            return EncryptFile(data, $"{DateTime.Now:yyyyMMddHHmm}.txt.enc", pub);
        }
        
        private PgpPublicKey ReadPublicKey(Stream inputStream)
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

        private byte[] EncryptFile(byte[] clearData, string fileName, PgpPublicKey encKey)
        {
            using (MemoryStream bOut = new MemoryStream())
            {
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(
                    CompressionAlgorithmTag.Zip);
                
                Stream compressedStream = compressedDataGenerator.Open(bOut); // open it with the final destination
                PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();

                // we want to Generate compressed data. This might be a user option later,
                // in which case we would pass in bOut.
                Stream pOut = lData.Open(
                    compressedStream, // the compressed output stream
                    PgpLiteralData.Binary,
                    fileName, // "filename" to store
                    clearData.Length, // length of clear data
                    DateTime.UtcNow // current time
                );

                pOut.Write(clearData, 0, clearData.Length);

                lData.Close();
                compressedDataGenerator.Close();

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
}