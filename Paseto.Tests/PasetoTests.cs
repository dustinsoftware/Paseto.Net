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
			string signature = PasetoUtility.Sign(_publicKey, _privateKey, payload);
			Assert.Equal(payload, PasetoUtility.Parse(_publicKey, signature).Payload);
		}

		[Theory]
		[InlineData("v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA", "")]
		[InlineData("v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz", "", "Cuon Alpinus")]
		[InlineData("v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM", "Frank Denis rocks")]
		public void Parse(string message, string payload, string footer = "")
		{
			var parsed = PasetoUtility.Parse(_publicKey, message);
			Assert.Equal(payload, parsed.Payload);
			Assert.Equal(footer, parsed.Footer);

			Assert.Null(PasetoUtility.Parse(new byte[32], message));
		}

		[Fact]
		public void JsonDataRoundTrip()
		{
			var testClaims = new Dictionary<string, object>{
				["iss"] = "http://auth.example.com",
				["exp"] = DateTime.UtcNow.AddMinutes(10).ToString("o"),
				["sub"] = (long) 2986689,
				["roles"] = new[] {"Admin", "User"}
			};

			string token = PasetoUtility.Sign(_publicKey, _privateKey, claims: testClaims);
			var parsedToken = PasetoUtility.ParseJson(_publicKey, token);

			Assert.Equal(testClaims["iss"], parsedToken["iss"]);
			Assert.Equal(testClaims["exp"], parsedToken["exp"]);
			Assert.Equal(testClaims["sub"], parsedToken["sub"]);
			Assert.Equal(testClaims["roles"], parsedToken["roles"]);
		}

		[Fact]
		public void HexString()
		{
			Assert.Equal("Hello world", Encoding.UTF8.GetString(HexToBytes("48656C6C6F20776F726C64")));
		}

		public static byte[] HexToBytes(string hexString)
		{
			var bytes = new byte[hexString.Length / 2];
			for (int i = 0; i < bytes.Length; i++)
			{
				bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
			}

			return bytes;
		}
	}
}
