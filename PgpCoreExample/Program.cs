using System;
using PgpCore;

namespace PgpCoreExample
{
    class Program
    {
        static void Main(string[] args)
        {
            var p = new Program();
            p.Do();
        }

        private void Do()
        {
            using (PGP pgp = new PGP())
            {
                // Encrypt file
                var inputPath = @"Messages\message.txt";
                var encryptedMessage = "Messages\\message_by_package.txt.asc";
                var publicKey = "Keys\\publicKey3072.asc";
                var myPrivateKey = "Keys\\secretKey3072.asc";
                var myPassword = "7pU3^E%AEj9gRqTxzk7G*r";

                pgp.EncryptFileAndSign(inputPath, encryptedMessage, publicKey, myPrivateKey, myPassword, true,
                    true);
                pgp.DecryptFileAndVerify(encryptedMessage, $"{DateTime.UtcNow:yyyyMMddHHmm}.txt", publicKey,
                    myPrivateKey, myPassword);
            }
        }
    }
}