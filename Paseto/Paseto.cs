using System;
using System.Text;
using Newtonsoft.Json.Linq;
using NSec.Cryptography;

namespace Paseto
{
	public sealed class Paseto
	{
		public Paseto(Options options)
		{
			_options = options;
		}

		public byte[] Sign(string payload)
		{
			var encrypter = new Ed25519();
			
			using (var key = Key.Import(encrypter, _options.Key, KeyBlobFormat.RawPrivateKey))
			{
				var data = Encoding.UTF8.GetBytes(payload);
				return encrypter.Sign(key, data);
			}
		}

		private Options _options;
	}

	public sealed class Options
	{
		public byte[] Key { get; set; }
	}

	public sealed class DecryptedPaseto
	{
		public string Version { get; set; }
		public string Purpose { get; set; }
		public string Payload { get; set; }
		public string Signature { get; set; }
	}
}
