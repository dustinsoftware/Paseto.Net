using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
		public string Sign(string payload, string footer = "")
		{
			if (payload == null) throw new ArgumentNullException(nameof(payload));
			if (footer == null) throw new ArgumentNullException(nameof(footer));

			string header = "v2.public.";

			string m2 = PAE(new[] { header, payload, footer });

			var encryptAlgorithm = new Ed25519();
			using (var key = Key.Import(encryptAlgorithm, _options.PrivateKey, KeyBlobFormat.RawPrivateKey))
			{
				var data = Encoding.UTF8.GetBytes(m2);

				string footerToAppend = footer == "" ? "" : $".{ToBase64Url(Encoding.UTF8.GetBytes(footer))}";
				return $"{header}{ToBase64Url(Encoding.UTF8.GetBytes(payload).Concat(encryptAlgorithm.Sign(key, data)))}{footerToAppend}";
			}
		}

		// https://github.com/paragonie/paseto/blob/63e2ddbdd2ac457a5e19ae3d815d892001c74de7/docs/01-Protocol-Versions/Version2.md#verify
		public ParsedPaseto Parse(string signedMessage)
		{
			if (signedMessage == null) throw new ArgumentNullException(signedMessage);

			const string header = "v2.public.";
			Assert(signedMessage.StartsWith(header), "Token did not start with v2.public.");
			var tokenParts = signedMessage.Split('.');
			string footer = Encoding.UTF8.GetString(FromBase64Url(tokenParts.Length > 3 ? tokenParts[3] : ""));

			var bytes = FromBase64Url(tokenParts[2]);
			Assert(bytes.Length >= 64, "Token was less than 64 bytes long");
			byte[] signature = bytes.Skip(bytes.Length - 64).ToArray();
			byte[] payload = bytes.Take(bytes.Length - 64).ToArray();

			string m2 = PAE(new[] { header, Encoding.UTF8.GetString(payload), footer });

			var encryptAlgorithm = new Ed25519();

			var publicKey = PublicKey.Import(encryptAlgorithm, _options.PublicKey, KeyBlobFormat.RawPublicKey);
			encryptAlgorithm.Verify(publicKey, Encoding.UTF8.GetBytes(m2), signature);

			return new ParsedPaseto
			{
				Payload = Encoding.UTF8.GetString(payload),
				Footer = footer,
			};
		}

		public void Assert(bool condition, string reason)
		{
			if (!condition)
			{
				throw new FormatException("The format of the message or signature was invalid. " + reason);
			}
		}

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

		public static string LE64(int source)
		{
			string str = "";
			for (int i = 0; i < 8; i++)
			{
				str += Encoding.ASCII.GetString(new[] { (byte) (source & 255) });
				source = source >> 8;
			}
			return str;
		}

		public static string ToBase64Url(IEnumerable<byte> source) => Convert.ToBase64String(source.ToArray())
			.Replace("=","")
			.Replace('+', '-')
			.Replace('/', '_');

		// Replace some characters in the base 64 string and add padding so .NET can parse it
		public static byte[] FromBase64Url(string source) => Convert.FromBase64String(source.PadRight((source.Length % 4) == 0 ? 0 : (source.Length + 4 - (source.Length % 4)), '=')
			.Replace('-', '+')
			.Replace('_', '/'));

		private Options _options;
	}

	public sealed class Options
	{
		public byte[] PublicKey { get; set; }
		public byte[] PrivateKey { get; set; }
	}

	public sealed class ParsedPaseto
	{
		public string Payload { get; set; }
		public string Footer { get; set; }
	}
}
