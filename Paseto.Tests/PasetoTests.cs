using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using Xunit;

namespace Paseto.Tests
{
	public class PasetoTests
	{
		private Paseto _paseto;

		public PasetoTests()
		{
			_paseto = new Paseto(new Options
			{
				PublicKey = HexToBytes("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
				PrivateKey = HexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774"),
			});
		}

		[Fact]
		public void JsonConverterIsConfiguredProperly()
		{
			Assert.Equal(@"{
  ""data"": ""this is a signed message"",
  ""expires"": ""2019-01-01T00:00:00+00:00""
}",
				JsonConvert.SerializeObject(new { data = "this is a signed message", expires = "2019-01-01T00:00:00+00:00"}, Formatting.Indented));
		}

		[Fact]
		public void PAE()
		{
			Assert.Equal("\x00\x00\x00\x00\x00\x00\x00\x00", Paseto.PAE(new List<string>()));
			Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", Paseto.PAE(new[] { "" }));
			Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test", Paseto.PAE(new[] { "test" }));
		}

		[Fact]
		public void Sign()
		{
			const string payload = "Frank Denis rocks";
			string signature = _paseto.Sign(payload);
			Assert.Equal(payload, _paseto.Parse(signature).Payload);
		}

		[Fact]
		public void Parse()
		{
			var parsed = _paseto.Parse("v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM");
			Assert.Equal("Frank Denis rocks", parsed.Payload);
		}

		[Theory]
		[InlineData("RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM")]
		public void EncodingTest(string source)
		{
			Convert.FromBase64String(Paseto.PadBase64String(source));
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
