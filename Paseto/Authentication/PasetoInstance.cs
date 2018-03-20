using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Paseto.Internal.SimpleJson;

namespace Paseto.Authentication
{
	public sealed class PasteoInstance
	{
		public PasteoInstance()
		{
		}

		public PasteoInstance(IDictionary<string, object> claims)
		{
			if (claims == null)
				throw new ArgumentNullException(nameof(claims));

			try
			{
				Issuer = TryGet(claims, "iss");
				Subject = TryGet(claims, "sub");
				Audience = TryGet(claims, "aud");
				Expiration = ToDateTime(TryGet(claims, "exp"));
				NotBefore = ToDateTime(TryGet(claims, "nbf"));
				IssuedAt = ToDateTime(TryGet(claims, "iat"));
				TokenIdentifier = TryGet(claims, "jti");
				AdditionalClaims = claims.Where(x => !_reservedKeys.Contains(x.Key)).ToDictionary(x => x.Key, x => x.Value);
			}
			catch (Exception exception) when (exception is FormatException || exception is InvalidCastException)
			{
				throw new PasetoFormatException("Claims were not in a valid format. " + SimpleJson.SerializeObject(claims));
			}
		}

		private string TryGet(IDictionary<string, object> dict, string key) =>
			((string) (dict.ContainsKey(key) ? dict[key] : null));

		public IDictionary<string, object> ToDictionary()
		{
			return (AdditionalClaims ?? new Dictionary<string, object>()).Concat(
				new Dictionary<string, object>
				{
					["iss"] = Issuer,
					["sub"] = Subject,
					["aud"] = Audience,
					["exp"] = Expiration?.ToString(_iso8601Format, CultureInfo.InvariantCulture),
					["nbf"] = NotBefore?.ToString(_iso8601Format, CultureInfo.InvariantCulture),
					["iat"] = IssuedAt?.ToString(_iso8601Format, CultureInfo.InvariantCulture),
					["jti"] = TokenIdentifier,
				}
			).Where(x => x.Value != null).ToDictionary(x => x.Key, x => x.Value);
		}

		public string Issuer { get; set; }
		public string Subject { get; set; }
		public string Audience { get; set; }

		public DateTime? Expiration { get; set; }
		public DateTime? NotBefore { get; set; }
		public DateTime? IssuedAt { get; set; }
		public string TokenIdentifier { get; set; }
		public IDictionary<string, object> AdditionalClaims { get; set; }
		public IDictionary<string, object> Footer { get; set; }

		private static DateTime? ToDateTime(string date) => date == null ? default(DateTime?) :
			DateTime.ParseExact(date, _iso8601Format, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

		private const string _iso8601Format = "yyyy'-'MM'-'dd'T'HH':'mm':'sszzz";
		private static HashSet<string> _reservedKeys = new HashSet<string>(new[] { "iss", "sub", "aud", "exp", "nbf", "iat", "jti" });
}
}
