using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Paseto.Authentication
{
    public sealed class PasteoInstance
    {
        public PasteoInstance()
        {
        }

        public PasteoInstance(IDictionary<string, object> claims)
        {
            Issuer = (string) claims["iss"];
            Subject = (string) claims["sub"];
            Audience = (string) claims["aud"];
            Expiration = ToDateTime((string) claims["exp"]);
            NotBefore = ToDateTime((string) claims["nbf"]);
            IssuedAt = ToDateTime((string) claims["iat"]);
            TokenIdentifier = (string) claims["jti"];
            AdditionalClaims = claims.Where(x => !_reservedKeys.Contains(x.Key)).ToDictionary(x => x.Key, x => x.Value);
        }

        public IDictionary<string, object> ToDictionary()
        {
            return AdditionalClaims.Concat(
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
            ).ToDictionary(x => x.Key, x => x.Value);
        }

        public string Issuer { get; set; }
        public string Subject { get; set; }
        public string Audience { get; set; }

        public DateTime? Expiration { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? IssuedAt { get; set; }
        public string TokenIdentifier { get; set; }
        public IDictionary<string, object> AdditionalClaims { get; set; } = new Dictionary<string, object>();
        public IDictionary<string, object> Footer { get; set; } = new Dictionary<string, object>();

        private static DateTime? ToDateTime(string date) => date == null ? default(DateTime?) :
            DateTime.ParseExact(date, _iso8601Format, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

        private const string _iso8601Format = "yyyy'-'MM'-'dd'T'HH':'mm':'sszzz";
        private static HashSet<string> _reservedKeys = new HashSet<string>(new[] { "iss", "sub", "aud", "exp", "nbf", "iat", "jti" });
}
}
