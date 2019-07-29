using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;

namespace ConsoleApp1
{
    public class AnotherCopy
    {
        /*public bool VerifyFile(
            Stream	inputStream,
            Stream	keyIn)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpObjectFactory			pgpFact = new PgpObjectFactory(inputStream);
            PgpCompressedData			c1 = (PgpCompressedData) pgpFact.NextPgpObject();
            pgpFact = new PgpObjectFactory(c1.GetDataStream());

            PgpOnePassSignatureList		p1 = (PgpOnePassSignatureList) pgpFact.NextPgpObject();
            PgpOnePassSignature			ops = p1[0];

            PgpLiteralData				p2 = (PgpLiteralData) pgpFact.NextPgpObject();
            Stream						dIn = p2.GetInputStream();
            PgpPublicKeyRingBundle		pgpRing = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
            PgpPublicKey				key = pgpRing.GetPublicKey(ops.KeyId);
            Stream						fos = File.Create(p2.FileName);

			ops.InitVerify(key);

			int ch;
			while ((ch = dIn.ReadByte()) >= 0)
            {
                ops.Update((byte)ch);
                fos.WriteByte((byte) ch);
            }
            fos.Close();

            PgpSignatureList	p3 = (PgpSignatureList)pgpFact.NextPgpObject();
			PgpSignature		firstSig = p3[0];
            if (ops.Verify(firstSig))
            {
                Console.Out.WriteLine("signature verified.");
                return true;
            }
            else
            {
                Console.Out.WriteLine("signature verification failed.");
                return false;
            }
        }*/

        /**
        * Generate an encapsulated signed file.
        *
        * @param fileName
        * @param keyIn
        * @param outputStream
        * @param pass
        * @param armor
        */
        private void SignFile(
            string fileName,
            Stream keyIn,
            Stream outputStream,
            char[] pass,
            bool armor,
            bool compress)
        {
            /*
            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            PgpSecretKey pgpSec = FindSecretKey(keyIn);
            PgpPrivateKey pgpPrivKey = pgpSec.ExtractPrivateKey(pass);
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(pgpSec.PublicKey.Algorithm, HashAlgorithmTag.Sha1);

            sGen.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);
            foreach (string userId in pgpSec.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();
                spGen.SetSignerUserId(false, userId);
                sGen.SetHashedSubpackets(spGen.Generate());
                // Just the first one!
                break;
            }

            Stream cOut = outputStream;
			PgpCompressedDataGenerator cGen = null;
			if (compress)
			{
				cGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.ZLib);

				cOut = cGen.Open(cOut);
			}

			BcpgOutputStream bOut = new BcpgOutputStream(cOut);

            sGen.GenerateOnePassVersion(false).Encode(bOut);

            FileInfo					file = new FileInfo(fileName);
            PgpLiteralDataGenerator     lGen = new PgpLiteralDataGenerator();
            Stream						lOut = lGen.Open(bOut, PgpLiteralData.Binary, file);
            FileStream					fIn = file.OpenRead();
            int                         ch = 0;

			while ((ch = fIn.ReadByte()) >= 0)
            {
                lOut.WriteByte((byte) ch);
                sGen.Update((byte)ch);
            }

			fIn.Close();
			lGen.Close();

			sGen.Generate().Encode(bOut);

			if (cGen != null)
			{
				cGen.Close();
			}

			if (armor)
			{
				outputStream.Close();
			}*/
        }

        /*private bool VerifyFile(
            byte[] encodedSig,
            HashAlgorithmTag hashAlgorithm,
            PgpPublicKey pubKey,
            byte[] original)
        {
            PgpObjectFactory        pgpFact = new PgpObjectFactory(encodedSig);
            PgpOnePassSignatureList p1 = (PgpOnePassSignatureList)pgpFact.NextPgpObject();
            PgpOnePassSignature     ops = p1[0];
            PgpLiteralData          p2 = (PgpLiteralData)pgpFact.NextPgpObject();
            Stream                  dIn = p2.GetInputStream();

            ops.InitVerify(pubKey);

            int ch;
            while ((ch = dIn.ReadByte()) >= 0)
            {
                ops.Update((byte)ch);
            }

            PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
            PgpSignature sig = p3[0];

            DateTime creationTime = sig.CreationTime;

            // Check creationTime is recent
            if (creationTime.CompareTo(DateTime.UtcNow) > 0
                || creationTime.CompareTo(DateTime.UtcNow.AddMinutes(-10)) < 0)
            {
                Fail("bad creation time in signature: " + creationTime);
            }

            if (sig.KeyId != pubKey.KeyId)
            {
                Fail("key id mismatch in signature");
            }

            if (!ops.Verify(sig))
            {
                Fail("Failed generated signature check - " + hashAlgorithm);
            }

            sig.InitVerify(pubKey);

            for (int i = 0; i != original.Length; i++)
            {
                sig.Update(original[i]);
            }

            sig.Update(original);

            if (!sig.Verify())
            {
                Fail("Failed generated signature check against original data");
            }
        }*/

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

            Object message = null;

            PgpOnePassSignatureList onePassSignatureList = null;
            PgpSignatureList signatureList = null;
            PgpCompressedData compressedData = null;
            PgpLiteralData literalData = null;
            
            message = plainFact.NextPgpObject();
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
                Console.Out.WriteLine("signature verification failed.");
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

        public Stream DecryptFileBackup(
            Stream inputStream,
            Stream publicKeyIn,
            Stream privateKeyIn,
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
                    PgpUtilities.GetDecoderStream(privateKeyIn));

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

                PgpObjectFactory pgpFact= null;
                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData) message;
                    pgpFact = new PgpObjectFactory(cData.GetDataStream());

                    message = pgpFact.NextPgpObject();
                }
                
                
               
                if (message is PgpLiteralData)
                {
                    return ((PgpLiteralData) message).GetInputStream();
                    
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
                    var onePassSignatureList = (PgpOnePassSignatureList) message; 
                    for (int i = 0; i < onePassSignatureList.Count; i++) 
                    {
                        var ops = onePassSignatureList[0];
                        Console.WriteLine("verifier : " + ops.KeyId);

                        var publicKey = ReadPublicKey(publicKeyIn);
                        // literal data
                        var hello = pgpFact.NextPgpObject();
                        
                        
                        /*new PgpPublicKeyRingCollection()
                        PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(
                            PGPUtil.getDecoderStream(publicKeyIn));
                        publicKey = pgpRing.getPublicKey(ops.getKeyID());*/
                        if (publicKey != null) {
                            //Stream						fos = File.Create(p2.FileName);
                            // TODO Public key is probably wrong
                            ops.InitVerify(publicKey);

                            //int ch;
                            //while ((ch = dIn.ReadByte()) >= 0)
                            //{
                            //    ops.Update((byte)ch);
                            //    fos.WriteByte((byte) ch);
                            //}
                            //fos.Close();

                            var david = pgpFact.NextPgpObject();
                            while (david != null)
                            {
                                david = pgpFact.NextPgpObject();
                            }

                            PgpSignatureList	p3 = (PgpSignatureList)pgpFact.NextPgpObject();
                            PgpSignature		firstSig = p3[0];
                            if (ops.Verify(firstSig))
                            {
                                Console.Out.WriteLine("signature verified.");
                            }
                            else
                            {
                                Console.Out.WriteLine("signature verification failed.");
                            }
                            
                            /*ops.
                            
                            ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                            ops.update(output);
                            PGPSignature signature = signatureList.get(i);
                            if (ops.verify(signature)) {
                                //Iterator<?> 
                                var userIds = publicKey.getUserIDs();
                                while (userIds.hasNext()) {
                                    String userId = (String) userIds.next();
                                    Console.WriteLine(String.Format($"Signed by {userId}"));
                                }
                                Console.WriteLine("Signature verified");
                            } else {
                                throw new SignatureException("Signature verification failed");
                            }*/
                        }
                    }
                    
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
            throw new Exception("Didnt go well");
        }

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