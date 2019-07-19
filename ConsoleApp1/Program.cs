using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                byte[] dataBytes = File.ReadAllBytes("input.txt");
                Stream asc = File.OpenRead("cert.asc");

                Stream outStream = File.Create("data.enc");
                var dave = new CopyFromStackoverflow();
                
                byte[] encrypted = dave.EncryptFile(dataBytes, $"{DateTime.Now:yyyyMMddHHmm}.txt.enc", dave.ReadPublicKey(asc), false);
                outStream.Write(encrypted, 0, encrypted.Length);
                outStream.Close();

                var dave1 = new AnotherCopy();
                var encryptedData = File.OpenRead("data.enc");
                dave1.DecryptFile(encryptedData, asc, "yourmum".ToCharArray(), "default.txt");

                encryptedData.Close();
                asc.Close();
                
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.ReadLine();
        }
    }

    public class AnotherCopy
    {
        public void DecryptFile(
            Stream inputStream,
            Stream keyIn,
            char[] passwd,
            string defaultFileName)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            try
            {
                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;

                PgpObject o = pgpF.NextPgpObject();
                //
                // the first object might be a PGP marker packet.
                //
                if (o is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList) o;
                }
                else
                {
                    enc = (PgpEncryptedDataList) pgpF.NextPgpObject();
                }

                //
                // find the secret key
                //
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                    PgpUtilities.GetDecoderStream(keyIn));

                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindSecretKey(pgpSec, pked.KeyId, passwd);

                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }

                if (sKey == null)
                {
                    throw new ArgumentException("secret key for message not found.");
                }

                Stream clear = pbe.GetDataStream(sKey);

                PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                PgpObject message = plainFact.NextPgpObject();

                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData) message;
                    PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());

                    message = pgpFact.NextPgpObject();
                }

                if (message is PgpLiteralData)
                {
                    PgpLiteralData ld = (PgpLiteralData) message;

                    string outFileName = ld.FileName;
                    if (outFileName.Length == 0)
                    {
                        outFileName = defaultFileName;
                    }

                    Stream fOut = File.Create(outFileName);
                    Stream unc = ld.GetInputStream();
                    Streams.PipeAll(unc, fOut);
                    fOut.Close();
                }
                else if (message is PgpOnePassSignatureList)
                {
                    throw new PgpException("encrypted message contains a signed message - not literal data.");
                }
                else
                {
                    throw new PgpException("message is not a simple encrypted file - type unknown.");
                }

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        Console.Error.WriteLine("message failed integrity check");
                    }
                    else
                    {
                        Console.Error.WriteLine("message integrity check passed");
                    }
                }
                else
                {
                    Console.Error.WriteLine("no message integrity check");
                }
            }
            catch (PgpException e)
            {
                Console.Error.WriteLine(e);

                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {
                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);
                }
            }
        }

        private PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyID, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
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

        public byte[] EncryptFile(byte[] clearData, string fileName, PgpPublicKey encKey, bool withIntegrityCheck)
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