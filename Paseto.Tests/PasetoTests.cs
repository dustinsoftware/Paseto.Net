using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Xunit;

namespace Paseto.Tests
{
	public class UnitTest1
	{
		[Fact]
		public void JsonConverterIsConfiguredProperly()
		{
			Assert.Equal(@"{""data"":""this is a signed message"",""exp"":""2039-01-01T00:00:00+00:00""}",
				JsonConvert.SerializeObject(new { data = "this is a signed message", exp = "2039-01-01T00:00:00+00:00"}));
		}

		[Fact]
		public void PAE()
		{
			Assert.Equal("\x00\x00\x00\x00\x00\x00\x00\x00", Paseto.PAE(new List<string>()));
			Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", Paseto.PAE(new[] { "" }));
			Assert.Equal("\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test", Paseto.PAE(new[] { "test" }));
		}
	}
}
