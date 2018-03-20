namespace Paseto.Authentication
{
    public sealed class ParsedPasetoBytes
    {
        public byte[] Payload { get; set; }
        public byte[] Footer { get; set; }
    }
}
