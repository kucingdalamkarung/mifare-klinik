namespace MifareAppTest.Mifare
{
    public class GeneralAuthenticate
    {
        public byte Version { get; set; } = 0x01;
        public byte Msb { get; set; }
        public byte Lsb { get; set; }
        public KeyType KeyType { get; set; }
        public byte KeyNumber { get; set; }

        public byte[] ToArray() => new[] {Version, Msb, Lsb, (byte) KeyType, KeyNumber};
    }
}