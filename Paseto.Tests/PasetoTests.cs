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
		public void Test1()
		{
			var paseto = new Paseto(new Options { Key = Convert.FromBase64String("loVRUvzZuA/xi5qU8DA32saLpUJ0bJl9eqmgyVsIxuM=")} );
			
			var signature = Convert.ToBase64String(paseto.Sign("Frank Denis rocks"));
	
			Assert.Equal("tQAu6EGhRKILQnGHu0lUrq+VLDXm3CtAeXAbxuOlh2Ms1fF+RW+8gAnyOlPLZtmbPhPlO+ipsu7UIkTXSvjCCQ==", signature);
		}
	}
}
