using System;
using System.Linq;
using System.Security.Cryptography;
using Paseto.Internal.Chaos.NaCl;

namespace Paseto.Authentication
{
    internal static class Algorithm
    {
        public static byte[] Sign(byte[] payload, byte[] privateKey) =>
            Ed25519.Sign(payload, privateKey);

        public static bool Verify(byte[] signature, byte[] payload, byte[] publicKey) =>
            Ed25519.Verify(signature, payload, publicKey);

        public static byte[] Encrypt(byte[] payload, byte[] macBytes, byte[] symmetricKey, byte[] additionalData) =>
            throw new NotSupportedException("Paseto.Public does not yet support local encryption");

        public static byte[] Decrypt(byte[] payload, byte[] nonceBytes, byte[] symmetricKey, byte[] additionalData) =>
            throw new NotSupportedException("Paseto.Public does not yet support local encryption");

        public static byte[] Hash(byte[] payload, byte[] nonce) =>
            throw new NotSupportedException("Paseto.Public does not yet support local encryption");
    }
}
