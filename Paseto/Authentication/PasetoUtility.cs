﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using Paseto.Internal.SimpleJson;

namespace Paseto.Authentication
{
	public static class PasetoUtility
	{
		public static string ParseFooter(string signedMessage)
		{
			var tokenParts = signedMessage.Split('.');
			return Encoding.UTF8.GetString(FromBase64Url(tokenParts.Length > 3 ? tokenParts[3] : ""));
		}

		public static IDictionary<string, object> ParseFooterJson(string signedMessage) =>
			SimpleJson.DeserializeObject(ParseFooter(signedMessage)) as IDictionary<string, object>;

		// https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#encrypt
		public static string EncryptBytes(byte[] symmetricKey, byte[] payload, string footer = "", byte[] nonce = null)
		{
			if (payload == null) throw new ArgumentNullException(nameof(payload));

			string header = "v2.local.";

			byte[] macBytes = Algorithm.Hash(payload, nonce);

			byte[] preAuth = PreAuthEncode(new[] { Encoding.UTF8.GetBytes(header), macBytes, Encoding.UTF8.GetBytes(footer) });

			byte[] encryptedPayload = Algorithm.Encrypt(payload, macBytes, symmetricKey, preAuth);

			string footerToAppend = footer == "" ? "" : $".{ToBase64Url(Encoding.UTF8.GetBytes(footer))}";
			return $"{header}{ToBase64Url(macBytes.Concat(encryptedPayload))}{footerToAppend}";
		}

		public static string Encrypt(byte[] symmetricKey, PasetoInstance payload, byte[] nonce = null) =>
			EncryptBytes(symmetricKey, Encoding.UTF8.GetBytes(SimpleJson.SerializeObject(payload.ToDictionary())), SimpleJson.SerializeObject(payload.Footer), nonce);


		public static ParsedPasetoBytes DecryptBytes(byte[] symmetricKey, string signedMessage)
		{
			if (signedMessage == null) throw new ArgumentNullException(signedMessage);

			const string header = "v2.local.";
			Assert(signedMessage.StartsWith(header), "Token did not start with v2.local.");

			var tokenParts = signedMessage.Split('.');
			byte[] footer = FromBase64Url(tokenParts.Length > 3 ? tokenParts[3] : "");

			var bytes = FromBase64Url(tokenParts[2]);
			Assert(bytes.Length >= 24, "Token was less than 24 bytes long");
			byte[] nonceBytes = bytes.Take(24).ToArray();
			byte[] payload = bytes.Skip(24).ToArray();

			byte[] preAuth = PreAuthEncode(new[] { Encoding.UTF8.GetBytes(header), nonceBytes, footer });

			return new ParsedPasetoBytes
			{
				Payload = Algorithm.Decrypt(payload, nonceBytes, symmetricKey, preAuth),
				Footer = footer,
			};
		}

		public static PasetoInstance Decrypt(byte[] symmetricKey, string signedMessage, bool validateTimes = true)
		{
			var result = DecryptBytes(symmetricKey, signedMessage);
			if (result == null)
				return null;

			return ParsePayload(Encoding.UTF8.GetString(result.Payload), Encoding.UTF8.GetString(result.Footer), validateTimes);
		}

		public static string SignBytes(byte[] publicKey, byte[] privateKey, byte[] payload, string footer = "")
		{
			if (publicKey?.Length != 32)
				throw new ArgumentException(nameof(publicKey), "must be 32 bytes long");
			if (privateKey?.Length != 32)
				throw new ArgumentException(nameof(privateKey), "must be 32 bytes long");
			if (payload == null)
				throw new ArgumentNullException(nameof(payload));
			if (footer == null)
				throw new ArgumentNullException(nameof(footer));

			string header = "v2.public.";

			byte[] m2 = PreAuthEncode(new[] { Encoding.UTF8.GetBytes(header), payload, Encoding.UTF8.GetBytes(footer) }.ToArray());

			string footerToAppend = footer == "" ? "" : $".{ToBase64Url(Encoding.UTF8.GetBytes(footer))}";

			byte[] signature = Algorithm.Sign(m2, privateKey.Concat(publicKey).ToArray());

			string createdPaseto = $"{header}{ToBase64Url(payload.Concat(signature))}{footerToAppend}";

			Assert(ParseBytes(publicKey, createdPaseto) != null, "Created paseto could not be parsed");
			return createdPaseto;
		}

		public static string Sign(byte[] publicKey, byte[] privateKey, PasetoInstance claims)
		{
			return SignBytes(publicKey, privateKey, Encoding.UTF8.GetBytes(SimpleJson.SerializeObject(claims.ToDictionary())), SimpleJson.SerializeObject(claims.Footer));
		}

		// https://github.com/paragonie/paseto/blob/63e2ddbdd2ac457a5e19ae3d815d892001c74de7/docs/01-Protocol-Versions/Version2.md#verify
		public static ParsedPasetoBytes ParseBytes(byte[] publicKey, string signedMessage)
		{
			if (signedMessage == null)
				throw new ArgumentNullException(signedMessage);
			if (publicKey?.Length != 32)
				throw new ArgumentException(nameof(publicKey), "must be 32 bytes long");

			const string header = "v2.public.";
			Assert(signedMessage.StartsWith(header), "Token did not start with v2.public.");
			var tokenParts = signedMessage.Split('.');
			byte[] footer = FromBase64Url(tokenParts.Length > 3 ? tokenParts[3] : "");

			var bytes = FromBase64Url(tokenParts[2]);
			Assert(bytes.Length >= 64, "Token was less than 64 bytes long");
			byte[] signature = bytes.Skip(bytes.Length - 64).ToArray();
			byte[] payload = bytes.Take(bytes.Length - 64).ToArray();

			byte[] m2 = PreAuthEncode(new[] { Encoding.UTF8.GetBytes(header), payload, footer });

			if (!Algorithm.Verify(signature, m2, publicKey))
				return null;

			return new ParsedPasetoBytes
			{
				Payload = payload,
				Footer = footer,
			};
		}

		public static PasetoInstance Parse(byte[] publicKey, string signedMessage, bool validateTimes = true)
		{
			var result = ParseBytes(publicKey, signedMessage);
			if (result == null)
				return null;

			return ParsePayload(Encoding.UTF8.GetString(result.Payload), Encoding.UTF8.GetString(result.Footer), validateTimes);
		}

		internal static PasetoInstance ParsePayload(string payload, string footer, bool validateTimes = true)
		{
			IDictionary<string, object> payloadJson;
			try
			{
				payloadJson = SimpleJson.DeserializeObject(payload) as IDictionary<string, object>;
				if (payloadJson == null)
					return null;
			}
			catch (SerializationException e)
			{
				throw new PasetoFormatException("Serialization error. " + e);
			}

			var footerJson = footer == "" ? null : SimpleJson.DeserializeObject(footer) as IDictionary<string, object>;

			var pasetoInstance = new PasetoInstance(payloadJson) { Footer = footerJson };

			if (validateTimes)
			{
				if (pasetoInstance.Expiration != null && pasetoInstance.Expiration.Value < DateTime.UtcNow)
					return null;

				if (pasetoInstance.NotBefore != null && pasetoInstance.NotBefore.Value > DateTime.UtcNow)
					return null;
			}

			return pasetoInstance;
		}

		internal static void Assert(bool condition, string reason)
		{
			if (!condition)
				throw new PasetoFormatException("The format of the message or signature was invalid. " + reason);
		}

		// https://github.com/paragonie/paseto/blob/785723a02bc27e0e90821b0852d9e86573bbe63d/docs/01-Protocol-Versions/Common.md#authentication-padding
		internal static byte[] PreAuthEncode(IReadOnlyList<byte[]> pieces) =>
			BitConverter.GetBytes((ulong) pieces.Count)
			.Concat(pieces.SelectMany(piece => BitConverter.GetBytes((ulong) piece.Length).Concat(piece)))
			.ToArray();

		internal static string ToBase64Url(IEnumerable<byte> source) =>
			Convert.ToBase64String(source.ToArray())
			.Replace("=", "")
			.Replace('+', '-')
			.Replace('/', '_');

		// Replace some characters in the base 64 string and add padding so .NET can parse it
		internal static byte[] FromBase64Url(string source)
		{
			try
			{
				return Convert.FromBase64String(source.PadRight((source.Length % 4) == 0 ? 0 : (source.Length + 4 - (source.Length % 4)), '=')
					.Replace('-', '+')
					.Replace('_', '/'));
			}
			catch (FormatException e)
			{
				throw new PasetoFormatException("The base64 encoding was invalid. " + e);
			}
		}
	}
}
