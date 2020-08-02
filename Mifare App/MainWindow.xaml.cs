using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Windows;
using MifareAppTest.Mifare;
using PCSC;
using PCSC.Iso7816;

namespace Mifare_App
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private const byte Msb = 0x00;
        private static byte[] key = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        private byte BlockidPasien = 12;
        private byte BlocknoRekamMedis = 13;
        private byte BlocknamaFrom = 14;
        private byte BlocknamaTo = 17;
        private byte BlockalamatFrom = 18;
        private byte BlockalamatTo = 22;
        private byte BlocknoTelp = 24;
        private byte BlocktglLahir = 25;
        private byte BlockjenisKelamin = 26;

        private static MifareCard _card;
        private static IsoReader isoReader;

        public MainWindow()
        {
            InitializeComponent();

            var contextFactory = ContextFactory.Instance;
            var context = contextFactory.Establish(SCardScope.System);
            var readerNames = context.GetReaders();
            if (NoReaderAvailable(readerNames))
            {
                MessageBox.Show("Tidak ada reader terdeteksi, periksa kembali koneksi reader anda...", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                Environment.Exit(0);
            }
            else
            {
                var reader = readerNames[0];
                if (reader == null) MessageBox.Show("Tidak ada reader terdeteksi, periksa kembali koneksi reader anda...", "Error",
                     MessageBoxButton.OK, MessageBoxImage.Error);

                try
                {
                    isoReader = new IsoReader(
                    context: context,
                    readerName: reader,
                    mode: SCardShareMode.Shared,
                    protocol: SCardProtocol.Any,
                    releaseContextOnDispose: false);
                    _card = new MifareCard(isoReader);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
        }

        private static bool WriteBlock(byte msb, byte lsb, byte[] data)
        {
            if (_card.LoadKey(KeyStructure.VolatileMemory, 0x00, key))
            {
                if (_card.Authenticate(msb, lsb, KeyType.KeyA, 0x00))
                {
                    if (_card.UpdateBinary(msb, lsb, data)) return true;
                    return false;
                }
            }

            return false;
        }

        private static byte[] ReadBlock(byte msb, byte lsb)
        {
            var readBinary = new byte[] { };

            if (_card.LoadKey(KeyStructure.VolatileMemory, 0x00, key))
            {
                if (_card.Authenticate(msb, lsb, KeyType.KeyA, 0x00))
                {
                    readBinary = _card.ReadBinary(msb, lsb, 16);
                }
            }

            return readBinary;
        }

        private static bool WriteBlockRange(byte msb, byte blockFrom, byte blockTo, byte[] data)
        {
            byte i;
            int count = 0;
            byte[] blockData = new byte[16];

            for (i = blockFrom; i <= blockTo; i++)
            {
                if ((i + 1) % 4 == 0) continue;
                Array.Copy(data, count * 16, blockData, 0, 16);
                if (WriteBlock(msb, i, blockData)) count++;
                else return false;
            }

            return true;
        }

        private static byte[] ReadBlockRange(byte msb, byte blockFrom, byte blockTo)
        {
            byte i;
            int nBlock = 0;
            int count = 0;

            for (i = blockFrom; i <= blockTo; i++)
            {
                if ((i + 1) % 4 == 0) continue;
                nBlock++;
            }

            var dataOut = new byte[nBlock * 16];
            for (i = blockFrom; i <= blockTo; i++)
            {
                if (((i + 1) % 4) == 0) continue;
                Array.Copy(ReadBlock(msb, i), 0, dataOut, count * 16, 16);
                count++;
            }

            return dataOut;
        }

        public void ClearAllBLock()
        {
            var res = MessageBox.Show("Apakah anda yakin ingin menghapus data kartu? ", "Warning", MessageBoxButton.YesNo);

            if (res == MessageBoxResult.Yes)
            {
                byte[] data = new byte[16];
                if (_card.LoadKey(KeyStructure.VolatileMemory, 0x00, key))
                {
                    for (byte i = 1; i <= 63; i++)
                    {
                        if ((i + 1) % 4 == 0) continue;
                        else
                        {
                            if (_card.Authenticate(Msb, i, KeyType.KeyA, 0x00))
                            {
                                Array.Clear(data, 0, 16);
                                if (WriteBlock(Msb, i, data)) { }
                                else
                                {
                                    MessageBox.Show("Data gagal dihapus");
                                    break;
                                }
                            }
                        }
                    }

                    MessageBox.Show("Data berhasil dihapus");
                }
            }
        }

        private bool NoReaderAvailable(ICollection<string> readerNames) => readerNames == null || readerNames.Count < 1;

        private void BtnAdd_Onclick(object sender, RoutedEventArgs e)
        {
            CultureInfo ci = CultureInfo.CreateSpecificCulture(CultureInfo.CurrentCulture.Name);
            ci.DateTimeFormat.ShortDatePattern = "yyyy-MM-dd";
            Thread.CurrentThread.CurrentCulture = ci;

            if (dtTanggalLahir.SelectedDate != null)
            {
                string noRm = TxtNoRm.Text;
                string noId = TxtNoIdentitas.Text;
                string nama = TxtNamaPasien.Text;
                string alamat = TextAlamat.Text;
                string telp = TxtNoTelp.Text;

                string tglLahir = dtTanggalLahir.SelectedDate.Value.Date.ToShortDateString();
                string jenisKelamin = cbJenisKelamin.Text;

                if (noId.Length > 0 && noId != "")
                {
                    if (WriteBlock(Msb, BlockidPasien, Util.ToArrayByte16(noId)))
                    {
                    }
                    //MessageBox.Show("ID pasien berhasil ditulis");
                    else
                        MessageBox.Show("ID pasien gagal ditulis");
                }

                if (noRm.Length > 0 && noRm != "")
                {
                    if (WriteBlock(Msb, BlocknoRekamMedis, Util.ToArrayByte16(noRm)))
                    {
                    }
                    //MessageBox.Show("No RM berhasil di tulis");
                    else
                        MessageBox.Show("No RM gagal di tulis");
                }

                if (nama.Length > 48)
                    nama = nama.Substring(0, 48);
                byte[] bin32 = Util.ToArrayByte48(nama);
                
                if (nama.Length > 0 && nama != "")
                {
                    if (WriteBlockRange(Msb, BlocknamaFrom, BlocknamaTo, bin32))
                    {
                    }

                    //MessageBox.Show("Nama pasien berhasil ditulis");
                    else
                        MessageBox.Show("Nama pasien gagal di tulis");
                }
                
                if (alamat.Length > 64)
                    alamat = alamat.Substring(0, 64);
                byte[] bin64 = Util.ToArrayByte64(alamat);
                
                if (alamat.Length > 0 && alamat != "")
                {
                    if (WriteBlockRange(Msb, BlockalamatFrom, BlockalamatTo, bin64))
                    {
                    }

                    //MessageBox.Show("Alamat berhasil ditulis");
                    else
                        MessageBox.Show("Alamat gagal ditulis");
                }

                if (telp.Length > 0 && telp != "")
                {
                    if (WriteBlock(Msb, BlocknoTelp, Util.ToArrayByte16(telp)))
                    {
                        //MessageBox.Show("Telpeon berhasil di tulis");
                    }
                    else
                    {
                        MessageBox.Show("Telepon gagal ditulis");
                    }
                }

                if (tglLahir.Length > 0 && tglLahir != "")
                {
                    if (WriteBlock(Msb, BlocktglLahir, Util.ToArrayByte16(tglLahir)))
                    {
                        //MessageBox.Show("Tgl lahir berhsail ditulis");
                    }
                    else
                    {
                        MessageBox.Show("Tgl lahir gagal ditulis");
                    }
                }

                if (jenisKelamin.Length > 0 && jenisKelamin != "")
                {
                    if (WriteBlock(Msb, BlockjenisKelamin, Util.ToArrayByte16(jenisKelamin)))
                    {
                        //MessageBox.Show("Jenis kelaim berhasil ditulis");
                    }
                    else
                    {
                        //MessageBox.Show("Jenis kelaim gagal di tulis");
                    }
                }

                MessageBox.Show("Data pasien berhasil di tulis");
            }
        }

        private void BtnRead_OnClick(object sender, RoutedEventArgs e)
        {
            string msg = "";
            var rm = ReadBlock(Msb, BlocknoRekamMedis);
            if(rm != null)
                msg += "Nomor Rekam Medis: \n" + Util.ToASCII(rm, 0, 16, false);

            var nId = ReadBlock(Msb, BlockidPasien);
            if(rm!= null)
                msg += "\n\nNomor ID Pasien: \n" + Util.ToASCII(nId, 0, 16, false);

            var namaP = ReadBlockRange(Msb, BlocknamaFrom, BlocknamaTo);
            if (namaP != null)
                msg += "\n\nNama Pasien: \n" + Util.ToASCII(namaP, 0, 48, false);

            var nTelp = ReadBlock(Msb, BlocknoTelp);
            if (nTelp != null)
                msg += "\n\nNomor Telepon Pasien: \n" + Util.ToASCII(nTelp, 0, 16, false);

            var alamatP = ReadBlockRange(Msb, BlockalamatFrom, BlockalamatTo);
            if (alamatP != null)
                msg += "\n\nAlamat Pasien: \n" + Util.ToASCII(alamatP, 0, 64, false);

            var tglHarie = ReadBlock(Msb, BlocktglLahir);
            if (tglHarie != null)
                msg += "\n\nTanggal Lahir: \n" + Util.ToASCII(tglHarie, 0, 16, false);

            var jk = ReadBlock(Msb, BlockjenisKelamin);
            if (jk != null)
                msg += "\n\nJenis Kelamin: \n" + Util.ToASCII(jk, 0, 16, false);

            MessageBox.Show(msg.ToString(), "Info Isi Kartu");
        }

        private void BtnErase_OnClick(object sender, RoutedEventArgs e)
        {
            ClearAllBLock();
        }

        private void BtnCheck_OnClick(object sender, RoutedEventArgs e)
        {
            var rm = ReadBlock(Msb, BlocknoRekamMedis);
            if (rm != null)
                TxtNoRm.Text = Util.ToASCII(rm, 0, 16, false);

            var nId = ReadBlock(Msb, BlockidPasien);
            if (nId != null)
                TxtNoIdentitas.Text = Util.ToASCII(nId, 0, 16, false);

            var namaP = ReadBlockRange(Msb, BlocknamaFrom, BlocknamaTo);
            if (namaP != null)
                TxtNamaPasien.Text = Util.ToASCII(namaP, 0, 48, false);

            var nTelp = ReadBlock(Msb, BlocknoTelp);
            if (nTelp != null)
                TxtNoTelp.Text = Util.ToASCII(nTelp, 0, 16, false);

            var alamatP = ReadBlockRange(Msb, BlockalamatFrom, BlockalamatTo);
            if (alamatP != null)
                TextAlamat.Text = Util.ToASCII(alamatP, 0, 64, false);

            var tglHarie = ReadBlock(Msb, BlocktglLahir);
            if (tglHarie != null)
                dtTanggalLahir.Text = Util.ToASCII(tglHarie, 0, 16, false);

            var jk = ReadBlock(Msb, BlockjenisKelamin);
            if (jk != null)
                if (Util.ToASCII(jk, 0, 16, false) == "Pria") cbJenisKelamin.SelectedIndex = 0;
        }
    } //class
} //namespace
