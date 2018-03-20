using System.Collections.Generic;

namespace Paseto.Authentication
{
	public sealed class PasetoDto
	{
		public IDictionary<string, object> Payload { get; set; }
		public IDictionary<string, object> Footer { get; set; }
	}
}
