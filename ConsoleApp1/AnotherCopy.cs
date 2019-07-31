using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;

namespace ConsoleApp1
{
    public class AnotherCopy
    {
        public Stream DecryptAndVerify(
            Stream inputStream,
            Stream publicKeyIn,
            Stream privateKeyIn,
            char[] password)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            var pgpF = new PgpObjectFactory(inputStream);
            var enc = (PgpEncryptedDataList) pgpF.NextPgpObject();

            PgpPrivateKey sKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                PgpUtilities.GetDecoderStream(privateKeyIn));

            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                sKey = FindSecretKey(pgpSec, pked.KeyId, password);

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

            PgpOnePassSignatureList onePassSignatureList = null;
            PgpSignatureList signatureList = null;
            PgpCompressedData compressedData = null;
            PgpLiteralData literalData = null;
            
            var message = plainFact.NextPgpObject();
            var actualOutput = new MemoryStream();

            while (message != null)
            {
                if (message is PgpCompressedData)
                {
                    compressedData = (PgpCompressedData) message;
                    plainFact = new PgpObjectFactory(compressedData.GetDataStream());
                    message = plainFact.NextPgpObject();
                }

                if (message is PgpLiteralData)
                {
                    Streams.PipeAll(((PgpLiteralData) message).GetInputStream(), actualOutput);
                }
                else if (message is PgpOnePassSignatureList)
                {
                    onePassSignatureList = (PgpOnePassSignatureList) message;
                }
                else if (message is PgpSignatureList)
                {
                    signatureList = (PgpSignatureList) message;
                }
                else
                {
                    throw new PgpException("message unknown message type.");
                }

                message = plainFact.NextPgpObject();
            }

            if (onePassSignatureList == null || signatureList == null)
            {
                Console.Out.WriteLine("message was not signed.");
                actualOutput.Seek(0, SeekOrigin.Begin);
                return actualOutput;
            }
            
            var publicKey = ReadPublicKey(publicKeyIn);
            for (int i = 0; i < onePassSignatureList.Count; i++)
            {
                var ops = onePassSignatureList[0];
                Console.WriteLine("verifier : " + ops.KeyId);

                if (publicKey != null)
                {
                    ops.InitVerify(publicKey);
                    ops.Update(actualOutput.ToArray());

                    PgpSignature firstSig = signatureList[0];
                    if (ops.Verify(firstSig))
                    {
                        Console.Out.WriteLine("signature verified.");
                    }
                    else
                    {
                        Console.Out.WriteLine("signature verification failed.");
                    }
                }
            }

            actualOutput.Seek(0, SeekOrigin.Begin);
            return actualOutput;
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
}