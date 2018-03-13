using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Paseto.Tests
{
	// Tests from here https://github.com/paragonie/paseto/blob/master/tests/Version2VectorTest.php
	public class PasetoTests
	{
		private Paseto _paseto;

		public PasetoTests()
		{
			_paseto = new Paseto(new Options
			{
				PublicKey = HexToBytes("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
				PrivateKey = HexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
			});
		}

		[Fact]
		public void PAE()
		{
			Assert.Equal("\x00\x00\x00\x00\x00\x00\x00\x00", Encoding.UTF8.GetString(Paseto.PreAuthEncode(new List<byte[]>())));
			Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", Encoding.UTF8.GetString(Paseto.PreAuthEncode(new[] { Encoding.UTF8.GetBytes("") })));
			Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test", Encoding.UTF8.GetString(Paseto.PreAuthEncode(new[] { Encoding.UTF8.GetBytes("test") })));
		}

		[Fact]
		public void RoundTrip()
		{
			const string payload = "Frank Denis rocks";
			string signature = _paseto.Sign(payload);
			Assert.Equal(payload, _paseto.Parse(signature).Payload);
		}

		[Theory]
		[InlineData("v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA", "")]
		[InlineData("v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz", "", "Cuon Alpinus")]
		[InlineData("v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM", "Frank Denis rocks")]
		public void Parse(string message, string payload, string footer = "")
		{
			var parsed = _paseto.Parse(message);
			Assert.Equal(payload, parsed.Payload);
			Assert.Equal(footer, parsed.Footer);

			var nullPublicKeyInstance = new Paseto(new Options { PublicKey = new byte[32] });
			Assert.Null(nullPublicKeyInstance.Parse(message));
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
