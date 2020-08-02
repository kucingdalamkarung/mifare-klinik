using System;
using System.Diagnostics;
using PCSC;
using PCSC.Iso7816;

namespace MifareAppTest.Mifare
{
    class MifareCard
    {
        private const byte Cla = 0xFF;
        private readonly IIsoReader m_isoReader;

        public MifareCard(IIsoReader isoReader)
        {
            m_isoReader = isoReader;
        }

        public bool LoadKey(KeyStructure keyStructure, byte keyNumber, byte[] key)
        {
            var loadKeyCmd = new CommandApdu(IsoCase.Case3Short, SCardProtocol.Any)
            {
                CLA = Cla,
                Instruction = InstructionCode.ExternalAuthenticate,
                P1 = (byte)keyStructure,
                P2 = keyNumber,
                Data = key
            };

            Debug.WriteLine($"Load Authentication Keys: {BitConverter.ToString(loadKeyCmd.ToArray())}");
            var response = m_isoReader.Transmit(loadKeyCmd);
            Debug.WriteLine($"SW1 SW2 = {response.SW1:X2} {response.SW2:X2}");

            return IsSuccess(response);
        }

        public bool Authenticate(byte msb, byte lsb, KeyType keyType, byte keyNumber)
        {
            var authBlock = new GeneralAuthenticate
            {
                KeyNumber = keyNumber,
                KeyType = keyType,
                Lsb = lsb,
                Msb = msb
            };

            var authCmd = new CommandApdu(IsoCase.Case3Short, SCardProtocol.Any)
            {
                CLA = Cla,
                Instruction = InstructionCode.InternalAuthenticate,
                P1 = 0x00,
                P2 = 0x00,
                Data = authBlock.ToArray()
            };

            Debug.WriteLine($"GENERAL AUTHENTICATE: {BitConverter.ToString(authCmd.ToArray())}");
            var response = m_isoReader.Transmit(authCmd);
            Debug.WriteLine($"SW1 SW2 = {response.SW1:X2} {response.SW2:X2}");

            return IsSuccess(response);
        }

        public byte[] ReadBinary(byte msb, byte lsb, int size)
        {
            var readBinaryCmd = new CommandApdu(IsoCase.Case2Short, SCardProtocol.Any)
            {
                CLA = Cla,
                Instruction = InstructionCode.ReadBinary,
                P1 = msb,
                P2 = lsb,
                Le = size
            };

            Debug.WriteLine($"READ BINARY: {BitConverter.ToString(readBinaryCmd.ToArray())}");
            var response = m_isoReader.Transmit(readBinaryCmd);
            Debug.WriteLine($"SW1 SW2 = {response.SW1:X2} {response.SW2:X2}\nData = {BitConverter.ToString(response.GetData())}");

            return IsSuccess(response)
                ? response.GetData() ?? new byte[0]
                : null;
        }

        public bool UpdateBinary(byte msb, byte lsb, byte[] data)
        {
            var updateBinaryCmd = new CommandApdu(IsoCase.Case3Short, SCardProtocol.Any)
            {
                CLA = Cla,
                Instruction = InstructionCode.UpdateBinary,
                P1 = msb,
                P2 = lsb,
                Data = data
            };

            Debug.WriteLine($"UPDATE BINARY: {BitConverter.ToString(updateBinaryCmd.ToArray())}");
            var response = m_isoReader.Transmit(updateBinaryCmd);
            Debug.WriteLine($"SW1 SW2 = {response.SW1:X2} {response.SW2:X2}");

            return IsSuccess(response);
        }

        private bool IsSuccess(Response response) => (response.SW1 == (byte) SW1Code.Normal) && (response.SW2 == 0x00);
    }
}
