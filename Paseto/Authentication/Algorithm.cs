using System.Security.Cryptography;
using Sodium;

namespace Paseto.Authentication
{
    internal static class Algorithm
    {
        public static byte[] Encrypt(byte[] payload, byte[] macBytes, byte[] symmetricKey, byte[] additionalData) =>
            SecretAead.Encrypt(payload, macBytes, symmetricKey, additionalData, useXChaCha: true);

        public static byte[] Decrypt(byte[] payload, byte[] nonceBytes, byte[] symmetricKey, byte[] additionalData) =>
            SecretAead.Decrypt(payload, nonceBytes, symmetricKey, additionalData, useXChaCha: true);

        public static byte[] Sign(byte[] payload, byte[] privateKey) =>
            PublicKeyAuth.SignDetached(payload, privateKey);

        public static bool Verify(byte[] signature, byte[] payload, byte[] publicKey) =>
            PublicKeyAuth.VerifyDetached(signature, payload, publicKey);

        public static byte[] Hash(byte[] payload, byte[] nonce)
        {
            if (nonce == null)
            {
                nonce = new byte[24];
                using (var random = new RNGCryptoServiceProvider())
                    random.GetBytes(nonce);
            }

            var hashAlgorithm = new GenericHash.GenericHashAlgorithm(nonce, 24);
            return hashAlgorithm.ComputeHash(payload);
        }
    }
}
