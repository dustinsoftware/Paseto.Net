using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using Paseto.Authentication;

namespace Paseto.Tests
{
	public sealed class LocalTests
	{
		private readonly byte[] _publicKey;
		private readonly byte[] _privateKey;
		private readonly byte[] _symmetricKey;

		public LocalTests()
		{
			_publicKey = HexToBytes("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");
			_privateKey = HexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774");
			_symmetricKey = HexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
		}

		[Fact]
		public void RoundTripPrivate()
		{
			const string payload = "Love is stronger than hate or fear";
			string encrypted = PasetoUtility.Encrypt(_symmetricKey, payload, nonce: new byte[24]);
			Assert.Equal(payload, PasetoUtility.Decrypt(_symmetricKey, encrypted));
		}

		[Theory]
		[InlineData("", "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ")]
		public void EncryptWithNullKey(string payload, string message)
		{
			Assert.Equal(message, PasetoUtility.Encrypt(new byte[32], payload, nonce: new byte[24]));
		}

		[Theory]
		[InlineData("", "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA")]
		[InlineData("", "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz", "Cuon Alpinus")]
		[InlineData("Love is stronger than hate or fear", "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U")]
		public void Encrypt(string payload, string message, string footer = "")
		{
			var nonce = new byte[24];
			Assert.Equal(message, PasetoUtility.Encrypt(_symmetricKey, payload, footer, nonce));
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
