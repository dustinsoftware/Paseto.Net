using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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

		// https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#encrypt
		public string Encrypt(string payload, string footer = "", byte[] nonce = null)
		{
			if (payload == null) throw new ArgumentNullException(nameof(payload));

			string header = "v2.local.";

			if (nonce == null)
			{
				nonce = new byte[24];
				using (var random = new RNGCryptoServiceProvider())
					random.GetBytes(nonce);
			}

			byte[] macBytes;
			var macAlgorithm = new Blake2bMac();
			using (var key = Key.Import(macAlgorithm, nonce, KeyBlobFormat.RawSymmetricKey))
			{
				macBytes = macAlgorithm.Mac(key, Encoding.UTF8.GetBytes(payload), 24);
			}

			byte[] preAuth = PAE(new[] { Encoding.UTF8.GetBytes(header), macBytes, Encoding.UTF8.GetBytes(footer) });
			var encryptAlgorithm = new XChaCha20Poly1305();
			byte[] encryptedPayload;
			using (var key = Key.Import(encryptAlgorithm, _options.SymmetricKey, KeyBlobFormat.RawSymmetricKey))
			{
				encryptedPayload = encryptAlgorithm.Encrypt(key, new Nonce(macBytes, 0), preAuth, Encoding.UTF8.GetBytes(payload));
			}

			string footerToAppend = footer == "" ? "" : $".{ToBase64Url(Encoding.UTF8.GetBytes(footer))}";
			return $"{header}{ToBase64Url(macBytes.Concat(encryptedPayload))}{footerToAppend}";
		}

		public string Decrypt(string signedMessage)
		{
			if (signedMessage == null) throw new ArgumentNullException(signedMessage);

			const string header = "v2.local.";
			Assert(signedMessage.StartsWith(header), "Token did not start with v2.local.");

			var tokenParts = signedMessage.Split('.');
			string footer = Encoding.UTF8.GetString(FromBase64Url(tokenParts.Length > 3 ? tokenParts[3] : ""));

			var bytes = FromBase64Url(tokenParts[2]);
			Assert(bytes.Length >= 24, "Token was less than 24 bytes long");
			byte[] nonceBytes = bytes.Take(24).ToArray();
			byte[] payload = bytes.Skip(24).ToArray();

			byte[] preAuth = PAE(new[] { Encoding.UTF8.GetBytes(header), nonceBytes, Encoding.UTF8.GetBytes(footer) });

			var encryptAlgorithm = new XChaCha20Poly1305();

			using (var key = Key.Import(encryptAlgorithm, _options.SymmetricKey, KeyBlobFormat.RawSymmetricKey))
			{
				return Encoding.UTF8.GetString(encryptAlgorithm.Decrypt(key, new Nonce(nonceBytes, 0), preAuth, payload));
			}
		}

		public string XChaCha20RoundTrip(byte[] nonceBytes, byte[] symmetricKey, byte[] associatedData, string payload)
		{
			var encryptAlgorithm = new XChaCha20Poly1305();
			byte[] encryptedPayload;
			using (var key = Key.Import(encryptAlgorithm, symmetricKey, KeyBlobFormat.RawSymmetricKey))
			{
				encryptedPayload = encryptAlgorithm.Encrypt(key, new Nonce(nonceBytes, 0), associatedData, Encoding.UTF8.GetBytes(payload));
				return Encoding.UTF8.GetString(encryptAlgorithm.Decrypt(key, new Nonce(nonceBytes, 0), associatedData, encryptedPayload));
			}
		}

		// https://github.com/paragonie/paseto/blob/63e2ddbdd2ac457a5e19ae3d815d892001c74de7/docs/01-Protocol-Versions/Version2.md#sign
		public string Sign(string payload, string footer = "")
		{
			if (payload == null) throw new ArgumentNullException(nameof(payload));
			if (footer == null) throw new ArgumentNullException(nameof(footer));

			string header = "v2.public.";

			byte[] m2 = PAE(new[] { header, payload, footer }.Select(Encoding.UTF8.GetBytes).ToArray());

			var encryptAlgorithm = new Ed25519();
			using (var key = Key.Import(encryptAlgorithm, _options.PrivateKey, KeyBlobFormat.RawPrivateKey))
			{
				string footerToAppend = footer == "" ? "" : $".{ToBase64Url(Encoding.UTF8.GetBytes(footer))}";
				return $"{header}{ToBase64Url(Encoding.UTF8.GetBytes(payload).Concat(encryptAlgorithm.Sign(key, m2)))}{footerToAppend}";
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

			byte[] m2 = PAE(new[] { Encoding.UTF8.GetBytes(header), payload, Encoding.UTF8.GetBytes(footer) });

			var encryptAlgorithm = new Ed25519();

			var publicKey = PublicKey.Import(encryptAlgorithm, _options.PublicKey, KeyBlobFormat.RawPublicKey);
			encryptAlgorithm.Verify(publicKey, m2, signature);

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
		public static byte[] PAE(IReadOnlyList<byte[]> pieces)
		{
			byte[] output = LE64(pieces.Count);
			foreach (byte[] piece in pieces)
			{
				output = output.Concat(LE64(piece.Length)).ToArray();
				output = output.Concat(piece).ToArray();
			}
			return output;
		}

		public static byte[] LE64(int source)
		{
			byte[] str = new byte[0];
			for (int i = 0; i < 8; i++)
			{
				str = str.Concat(new[] { (byte) (source & 255) }).ToArray();
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
		public byte[] SymmetricKey { get; set; }
	}

	public sealed class ParsedPaseto
	{
		public string Payload { get; set; }
		public string Footer { get; set; }
	}
}
