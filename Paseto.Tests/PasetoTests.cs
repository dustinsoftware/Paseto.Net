using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NSec.Cryptography;
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
				PrivateKey = HexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774"),
				SymmetricKey = HexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			});
		}

		[Fact]
		public void PAE()
		{
			Assert.Equal("\x00\x00\x00\x00\x00\x00\x00\x00", Encoding.UTF8.GetString(Paseto.PAE(new List<byte[]>())));
			Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", Encoding.UTF8.GetString(Paseto.PAE(new[] { Encoding.UTF8.GetBytes("") })));
			Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test", Encoding.UTF8.GetString(Paseto.PAE(new[] { Encoding.UTF8.GetBytes("test") })));
		}

		[Fact]
		public void RoundTripPublic()
		{
			const string payload = "Frank Denis rocks";
			string signature = _paseto.Sign(payload);
			Assert.Equal(payload, _paseto.Parse(signature).Payload);
		}

		[Fact]
		public void RoundTripPrivate()
		{
			const string payload = "Love is stronger than hate or fear";
			string encrypted = _paseto.Encrypt(payload, nonce: new byte[24]);
			Assert.Equal(payload, _paseto.Decrypt(encrypted));
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
		}

		[Theory]
		[InlineData("", "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ")]
		public void EncryptWithNullKey(string payload, string message)
		{
			var paseto = new Paseto(new Options { SymmetricKey = new byte[32] });
			var nonce = new byte[24];
			Assert.Equal(message, paseto.Encrypt(payload, nonce: nonce));
		}

		[Theory]
		[InlineData("", "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA")]
		[InlineData("Love is stronger than hate or fear", "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U")]
		public void Encrypt(string payload, string message)
		{
			var nonce = new byte[24];
			Assert.Equal(message, _paseto.Encrypt(payload, nonce: nonce));
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
