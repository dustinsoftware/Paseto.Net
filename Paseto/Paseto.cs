using System;
using System.Collections.Generic;
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

		// https://github.com/paragonie/paseto/blob/63e2ddbdd2ac457a5e19ae3d815d892001c74de7/docs/01-Protocol-Versions/Version2.md#sign
		// public string Sign(string payload)
		// {
		// 	string header = "v2.public.";
		// 	string footer = "";

		// 	string m2 = PAE(new[] { header, payload, footer });

		// 	var encrypter = new Ed25519();			
		// 	using (var key = Key.Import(encrypter, _options.Key, KeyBlobFormat.RawPrivateKey))
		// 	{
		// 		var data = Encoding.UTF8.GetBytes(m2);
		// 		var signature = encrypter.Sign(key, data);

		// 		return $"{header}{Base64EncodeUnpadded(payload + sig)}";
		// 	}
		// }

		// https://github.com/paragonie/paseto/blob/785723a02bc27e0e90821b0852d9e86573bbe63d/docs/01-Protocol-Versions/Common.md#authentication-padding
		public static string PAE(IReadOnlyList<string> pieces)
		{
			string output = LE64(pieces.Count);
			foreach (string piece in pieces)
			{
				output += LE64(piece.Length);
				output += piece;
			}
			return output;
		}

		private static string LE64(int source) 
		{
			string str = "";
			for (int i = 0; i < 8; i++)
			{
				str += Encoding.ASCII.GetString(new[] { (byte) (source & 255) });
				source = source >> 8;
			}
			return str;
		}

		public static string Base64EncodeUnpadded(string source) => Convert.ToBase64String(Encoding.UTF8.GetBytes(source)).Replace("=","");

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
