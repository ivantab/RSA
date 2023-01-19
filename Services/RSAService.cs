using System.Security.Cryptography;
using System.Text;

namespace RSA.Api.Services
{
    public class RSAService
    {

        public string Encrypt(string plaintext, RSAParameters PrivateKey)      
        {
            using (RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048))
            {
                csp.ImportParameters(PrivateKey);
                var data = Encoding.Unicode.GetBytes(plaintext);
                var cipher = csp.Encrypt(data, true);
                return Convert.ToBase64String(cipher);
            }
        }

        public string Dencrypt(string cypherText, RSAParameters PublicKey)
        {
            using (RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048))
            {
                var dataBytes = Convert.FromBase64String(cypherText);
                csp.ImportParameters(PublicKey);
                var plainText = csp.Decrypt(dataBytes, true);
                return Encoding.Unicode.GetString(plainText);
            }
        }

        public string SignData(string message, RSAParameters privateKey)
        {
            //// The array to store the signed message in bytes
            byte[] signedBytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                //// Write the message to a byte array using UTF8 as the encoding.
                var encoder = new UTF8Encoding();
                byte[] originalData = encoder.GetBytes(message);

                try
                {
                    //// Import the private key used for signing the message
                    rsa.ImportParameters(privateKey);

                    //// Sign the data, using SHA512 as the hashing algorithm 
                    signedBytes = rsa.SignData(originalData, CryptoConfig.MapNameToOID("SHA512"));
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine(e.Message);
                    return null;
                }
                finally
                {
                    //// Set the keycontainer to be cleared when rsa is garbage collected.
                    rsa.PersistKeyInCsp = false;
                }
            }
            //// Convert the a base64 string before returning
            return Convert.ToBase64String(signedBytes);
        }


        public bool VerifyData(string originalMessage, string signedMessage, RSAParameters publicKey)
        {
            bool success = false;
            using (var rsa = new RSACryptoServiceProvider())
            {
                byte[] bytesToVerify = Convert.FromBase64String(originalMessage);
                byte[] signedBytes = Convert.FromBase64String(signedMessage);
                try
                {
                    rsa.ImportParameters(publicKey);

                    SHA512Managed Hash = new SHA512Managed();

                    byte[] hashedData = Hash.ComputeHash(signedBytes);

                    success = rsa.VerifyData(bytesToVerify, CryptoConfig.MapNameToOID("SHA512"), signedBytes);
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine(e.Message);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
            return success;
        }


        public string MakePem(byte[] ber, string header)
        {
            StringBuilder builder = new StringBuilder("-----BEGIN ");
            builder.Append(header);
            builder.AppendLine("-----");

            string base64 = Convert.ToBase64String(ber);
            int offset = 0;
            const int LineLength = 64;

            while (offset < base64.Length)
            {
                int lineEnd = Math.Min(offset + LineLength, base64.Length);
                builder.AppendLine(base64.Substring(offset, lineEnd - offset));
                offset = lineEnd;
            }

            builder.Append("-----END ");
            builder.Append(header);
            builder.AppendLine("-----");
            return builder.ToString();
        }
    }
}
