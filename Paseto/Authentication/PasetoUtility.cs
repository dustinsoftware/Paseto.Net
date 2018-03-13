using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NSec.Cryptography;

namespace Paseto.Authentication
{
	public static class PasetoUtility
	{
		// https://github.com/paragonie/paseto/blob/63e2ddbdd2ac457a5e19ae3d815d892001c74de7/docs/01-Protocol-Versions/Version2.md#sign
		public static string Sign(byte[] privateKey, string payload, string footer = "")
		{
			if (payload == null) throw new ArgumentNullException(nameof(payload));
			if (footer == null) throw new ArgumentNullException(nameof(footer));

			string header = "v2.public.";

			byte[] m2 = PreAuthEncode(new[] { header, payload, footer }.Select(Encoding.UTF8.GetBytes).ToArray());

			var encryptAlgorithm = new Ed25519();
			using (var key = Key.Import(encryptAlgorithm, privateKey, KeyBlobFormat.RawPrivateKey))
			{
				string footerToAppend = footer == "" ? "" : $".{ToBase64Url(Encoding.UTF8.GetBytes(footer))}";
				return $"{header}{ToBase64Url(Encoding.UTF8.GetBytes(payload).Concat(encryptAlgorithm.Sign(key, m2)))}{footerToAppend}";
			}
		}

		// https://github.com/paragonie/paseto/blob/63e2ddbdd2ac457a5e19ae3d815d892001c74de7/docs/01-Protocol-Versions/Version2.md#verify
		public static ParsedPaseto Parse(byte[] publicKey, string signedMessage)
		{
			if (signedMessage == null) throw new ArgumentNullException(signedMessage);

			const string header = "v2.public.";
			Assert(signedMessage.StartsWith(header), "Token did not start with v2.public.");
			var tokenParts = signedMessage.Split('.');
			byte[] footer = FromBase64Url(tokenParts.Length > 3 ? tokenParts[3] : "");

			var bytes = FromBase64Url(tokenParts[2]);
			Assert(bytes.Length >= 64, "Token was less than 64 bytes long");
			byte[] signature = bytes.Skip(bytes.Length - 64).ToArray();
			byte[] payload = bytes.Take(bytes.Length - 64).ToArray();

			byte[] m2 = PreAuthEncode(new[] { Encoding.UTF8.GetBytes(header), payload, footer });

			var encryptAlgorithm = new Ed25519();

			var publicKeyInstance = PublicKey.Import(encryptAlgorithm, publicKey, KeyBlobFormat.RawPublicKey);
			encryptAlgorithm.Verify(publicKeyInstance, m2, signature);

			return new ParsedPaseto
			{
				Payload = Encoding.UTF8.GetString(payload),
				Footer = Encoding.UTF8.GetString(footer),
			};
		}

		public static void Assert(bool condition, string reason)
		{
			if (!condition) throw new FormatException("The format of the message or signature was invalid. " + reason);
		}

		// https://github.com/paragonie/paseto/blob/785723a02bc27e0e90821b0852d9e86573bbe63d/docs/01-Protocol-Versions/Common.md#authentication-padding
		public static byte[] PreAuthEncode(IReadOnlyList<byte[]> pieces) =>
			BitConverter.GetBytes((ulong) pieces.Count)
			.Concat(pieces.SelectMany(piece => BitConverter.GetBytes((ulong) piece.Length).Concat(piece)))
			.ToArray();

		public static string ToBase64Url(IEnumerable<byte> source) =>
			Convert.ToBase64String(source.ToArray())
			.Replace("=", "")
			.Replace('+', '-')
			.Replace('/', '_');

		// Replace some characters in the base 64 string and add padding so .NET can parse it
		public static byte[] FromBase64Url(string source) =>
			Convert.FromBase64String(source.PadRight((source.Length % 4) == 0 ? 0 : (source.Length + 4 - (source.Length % 4)), '=')
			.Replace('-', '+')
			.Replace('_', '/'));
	}
}
