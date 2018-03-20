using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using Paseto.Authentication;

namespace Paseto.Tests
{
    // Tests from here https://github.com/paragonie/paseto/blob/master/tests/Version2VectorTest.php
    public class PasetoTests
    {
        private readonly byte[] _publicKey;
        private readonly byte[] _privateKey;
        private readonly byte[] _symmetricKey;

        public PasetoTests()
        {
            _publicKey = HexToBytes("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");
            _privateKey = HexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774");
            _symmetricKey = HexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        }

        [Fact]
        public void PAE()
        {
            Assert.Equal("\x00\x00\x00\x00\x00\x00\x00\x00", Encoding.UTF8.GetString(PasetoUtility.PreAuthEncode(new List<byte[]>())));
            Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", Encoding.UTF8.GetString(PasetoUtility.PreAuthEncode(new[] { Encoding.UTF8.GetBytes("") })));
            Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test", Encoding.UTF8.GetString(PasetoUtility.PreAuthEncode(new[] { Encoding.UTF8.GetBytes("test") })));
        }

        [Fact]
        public void RoundTrip()
        {
            const string payload = "Frank Denis rocks";
            string signature = PasetoUtility.SignBytes(_publicKey, _privateKey, Encoding.UTF8.GetBytes(payload));
            Assert.Equal(payload, Encoding.UTF8.GetString(PasetoUtility.ParseBytes(_publicKey, signature).Payload));
        }

        [Theory]
        [InlineData("v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA", "")]
        [InlineData("v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz", "", "Cuon Alpinus")]
        [InlineData("v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM", "Frank Denis rocks")]
        public void Parse(string message, string payload, string footer = "")
        {
            var parsed = PasetoUtility.ParseBytes(_publicKey, message);
            Assert.Equal(payload, Encoding.UTF8.GetString(parsed.Payload));
            Assert.Equal(footer, Encoding.UTF8.GetString(parsed.Footer));

            Assert.Null(PasetoUtility.Parse(new byte[32], message));
        }

        [Fact]
        public void JsonDataRoundTrip()
        {
            var date = DateTime.UtcNow;

            var claims = new PasteoInstance
            {
                Issuer = "http://auth.example.com",
                Subject = "2986689",
                Audience = "audience",
                Expiration = new DateTime(date.Year, date.Month, date.Day, date.Hour, date.Minute, date.Second, date.Kind).AddMinutes(10),
                NotBefore = new DateTime(date.Year, date.Month, date.Day, date.Hour, date.Minute, date.Second, date.Kind).AddMinutes(-10),
                IssuedAt = new DateTime(date.Year, date.Month, date.Day, date.Hour, date.Minute, date.Second, date.Kind),
                AdditionalClaims = new Dictionary<string, object>
                {
                    ["roles"] = new[] { "Admin", "User" }
                },
                Footer = new Dictionary<string, object>
                {
                    ["kid"] = "dpm0"
                },
            };

            string token = PasetoUtility.Sign(_publicKey, _privateKey, claims);
            var parsedToken = PasetoUtility.Parse(_publicKey, token);

            Assert.Equal(claims.Issuer, parsedToken.Issuer);
            Assert.Equal(claims.Subject, parsedToken.Subject);
            Assert.Equal(claims.Audience, parsedToken.Audience);
            Assert.Equal(claims.Expiration, parsedToken.Expiration);
            Assert.Equal(claims.NotBefore, parsedToken.NotBefore);
            Assert.Equal(claims.IssuedAt, parsedToken.IssuedAt);
            Assert.Equal(claims.AdditionalClaims, parsedToken.AdditionalClaims);
            Assert.Equal(claims.Footer, parsedToken.Footer);
        }

        [Fact]
        public void ExpiredTokenDoesNotParse()
        {
            var testClaims = new PasteoInstance
            {
                Expiration = DateTime.UtcNow.AddSeconds(-1),
                Subject = "2986689",
            };

            Assert.Null(PasetoUtility.Parse(_publicKey, PasetoUtility.Sign(_publicKey, _privateKey, claims: testClaims)));
            testClaims.Expiration = DateTime.UtcNow.AddSeconds(1);
            Assert.NotNull(PasetoUtility.Parse(_publicKey, PasetoUtility.Sign(_publicKey, _privateKey, claims: testClaims)));
        }

        [Fact]
        public void FutureTokenDoesNotParse()
        {
            var testClaims = new PasteoInstance
            {
                NotBefore = DateTime.UtcNow.AddSeconds(1),
                Subject = "2986689",
            };

            Assert.Null(PasetoUtility.Parse(_publicKey, PasetoUtility.Sign(_publicKey, _privateKey, claims: testClaims)));
            testClaims.NotBefore = DateTime.UtcNow.AddSeconds(-1);
            Assert.NotNull(PasetoUtility.Parse(_publicKey, PasetoUtility.Sign(_publicKey, _privateKey, claims: testClaims)));
        }

        [Fact]
        public void EmptyTokenParses()
        {
            string token = PasetoUtility.SignBytes(_publicKey, _privateKey, Encoding.UTF8.GetBytes("{}"));
            PasetoUtility.Parse(_publicKey, token);
        }

        [Theory]
        [InlineData("{")]
        [InlineData("{ \"exp\": \"a\" }")]
        [InlineData("{ \"sub\": 2986689 }")]
        public void InvalidJsonThrows(string str)
        {
            string token = PasetoUtility.SignBytes(_publicKey, _privateKey, Encoding.UTF8.GetBytes(str));
            Assert.Throws<PasetoFormatException>(() => PasetoUtility.Parse(_publicKey, token));
        }

        [Fact]
        public void HexString()
        {
            Assert.Equal("Hello world", Encoding.UTF8.GetString(HexToBytes("48656C6C6F20776F726C64")));
        }

        private static byte[] HexToBytes(string hexString)
        {
            var bytes = new byte[hexString.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return bytes;
        }
        private const string Iso8601Format = "yyyy'-'MM'-'dd'T'HH':'mm':'sszzz";
    }
}
