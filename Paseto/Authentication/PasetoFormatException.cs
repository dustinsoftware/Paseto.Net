using System;

namespace Paseto.Authentication
{
	public sealed class PasetoFormatException : Exception
	{
		public PasetoFormatException(string message)
			: base(message)
		{
		}
	}
}
