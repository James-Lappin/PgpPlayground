using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace ConsoleApp1
{
    public class BouncyCastleCopy
    {
        //  public sealed class RsaKeyRingGenerator
        //{
        private BouncyCastleCopy()
        {
        }

        private static void ExportKeyPair(
            Stream secretOut,
            Stream publicOut,
            AsymmetricKeyParameter publicKey,
            AsymmetricKeyParameter privateKey,
            string identity,
            char[] passPhrase,
            bool armor)
        {
            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }

            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                PublicKeyAlgorithmTag.RsaGeneral,
                publicKey,
                privateKey,
                DateTime.UtcNow,
                identity,
                SymmetricKeyAlgorithmTag.Cast5,
                passPhrase,
                null,
                null,
                new SecureRandom()
            );

            secretKey.Encode(secretOut);

            if (armor)
            {
                secretOut.Close();
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);

            if (armor)
            {
                publicOut.Close();
            }
        }

        public void GenerateKeyPair()
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator("RSA");

            generator.Init(new RsaKeyGenerationParameters(
                BigInteger.ValueOf(0x10001), new SecureRandom(), 3072, 25));

            var keyPair = generator.GenerateKeyPair();

            using (Stream out1 = File.Create("secret.asc"))
            using (Stream out2 = File.Create("pub.asc"))
            {
                ExportKeyPair(out1, out2, keyPair.Public, keyPair.Private, "james.lappin@checkout.com",
                    "knownpassword".ToCharArray(), true);
            }
        }
    }
}