using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
namespace cryvis
{
    namespace Encryption
    {
        /// <summary>
        /// Used to Endcode to respective Bytes
        /// </summary>
        public class Encoder
        {	
            /// Change this values according to your convinience
            static readonly string PasswordHash = "R@s$W!%*";
            static readonly string SaltKey = "I@$pPSLR"; 
	    //This should be 16bit long.
            static readonly string VIKey = "BT@$%LK&^PP!RTY@";
            /// <summar y>
            /// Encodes Data to MD5Hash
            /// </summary>
            /// <param name="value"></param>
            /// <returns></returns>
            public static string EncodeToMD5(Data value)
            {
                StringBuilder builder = new StringBuilder();
		var input = ASCIIEncoding.ASCII.GetBytes((string)value);
                MD5 md = MD5.Create();
                var Hash = md.ComputeHash(input);
                foreach (byte b in Hash)
                {
                    builder.Append(b.ToString("X2").ToLower());
                }
                return builder.ToString();
            }
			//Encryption Using RiJndael Method
            public static string Encrypt(string Password)
            {
                byte[] PasswordBytes = Encoding.UTF8.GetBytes(Password);
                byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
                var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
                var encryptor = symmetricKey.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));
                byte[] cipherTextBytes;
                using (var memoryStream = new System.IO.MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(PasswordBytes, 0, PasswordBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        cipherTextBytes = memoryStream.ToArray();
                        cryptoStream.Close();
                    }
                    memoryStream.Close();
                }
                return System.Convert.ToBase64String(cipherTextBytes);
            }
            public static string Decrypt(string encryptedText)
            {
                byte[] cipherTextBytes = System.Convert.FromBase64String(encryptedText);
                byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
                var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };
                var decryptor = symmetricKey.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));
                var memoryStream = new System.IO.MemoryStream(cipherTextBytes);
                var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                byte[] plainTextBytes = new byte[cipherTextBytes.Length];
                int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                memoryStream.Close();
                cryptoStream.Close();
                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd("\0".ToCharArray());
            }
        }
    }
    namespace DataSaving
    {
        public class Saver
        {
            public static void SaveData(string FileName, string Password, Data data)
            {
                BinaryFormatter formater = new BinaryFormatter();
		FileStream stream = File.Create(FileName);
                data = Encryption.Encoder.EncodeToMD5(Password) + Encryption.Encoder.Encrypt((string)data);
                formater.Serialize(stream, data);
                stream.Close();
            }
            public static void LoadData(string FileName, string Password, out Data data)
            {
                data = null;
		if (File.Exists(FileName))
                    {
                        BinaryFormatter formater = new BinaryFormatter();
			FileStream stream = File.Open(FileName, FileMode.Open);
                        var output = (Data)formater.Deserialize(stream);
                        string Data = (string)output;
                        if (Data.Contains(Encryption.Encoder.EncodeToMD5(Password)))
                        {
                            var RequiredData = Data.Remove(0, Encryption.Encoder.EncodeToMD5(Password).Length);
                            data = Encryption.Encoder.Decrypt(RequiredData);
                        }
                        else
                        {
                        data = null;
                        throw new System.Exception("Wrong Password");
                        }
                        stream.Close();
                }else
                {
                    throw new System.Exception("File Not Found");
                }
            }
        }
        [System.Serializable]
        public struct Data
        {
            public int IntData;
            public float FloatData;
            public string StringData;
	    public long LongData;
	    public decimal DecimalData;
	    public double DoubleData;
            #region Constructors
            public Data(int Data)
            {
                IntData = Data;
                FloatData = (float)Data;
                StringData = Data.ToString();
				LongData = (long)Data;
				DecimalData = (decimal)Data;
				DoubleData = (double)Data;
            }
            public Data(float Data)
            {
                FloatData = Data;
                IntData = (int)Data;
                StringData = Data.ToString();
				LongData = (long)Data;
				DecimalData = (decimal)Data;
				DoubleData = (double)Data;
            }
            public Data(string Data)
            {
                StringData = Data;
                int.TryParse(Data, out IntData);
                float.TryParse(Data, out FloatData);
				long.TryParse (Data, out LongData);
				decimal.TryParse (Data, out DecimalData);
				double.TryParse (Data, out DoubleData);
            }
			public Data(long Data)
			{
				StringData = Data.ToString();
				IntData = (int)Data;
				FloatData = (float)Data;
				LongData = (long)Data;
				DecimalData = (decimal)Data;
				DoubleData = (double)Data;
			}
			public Data(decimal Data)
			{
				StringData = Data.ToString();
				IntData = (int)Data;
				FloatData = (float)Data;
				LongData = (long)Data;
				DecimalData = (decimal)Data;
				DoubleData = (double)Data;
			}
			public Data(double Data)
			{
				StringData = Data.ToString();
				IntData = (int)Data;
				FloatData = (float)Data;
				LongData = (long)Data;
				DecimalData = (decimal)Data;
				DoubleData = (double)Data;
			}
            #endregion
            #region Conversions
            public static implicit operator Data(int Data)
            {
                return new Data(Data);
            }
            public static implicit operator Data(float Data)
            {
                return new Data(Data);
            }
            public static implicit operator Data(string Data)
            {
                return new Data(Data);
            }
			public static implicit operator Data(long Data)
			{
				return new Data(Data);
			}
			public static implicit operator Data(double Data)
			{
				return new Data(Data);
			}
			public static implicit operator Data(decimal Data)
			{
				return new Data(Data);
			}
            /// <summary>
            /// returns IntegerDataStored
            /// </summary>
            /// <param name="D"></param>
            public static explicit operator int(Data D)
            {
                return D.IntData;
            }
            /// <summary>
            /// returns FloatDataStored
            /// </summary>
            /// <param name="D"></param>
            public static explicit operator float(Data D)
            {
                return D.FloatData;
            }
            /// <summary>
            /// returns StringDataStored
            /// </summary>
            /// <param name="D"></param>
            public static explicit operator string(Data D)
            {
                return D.StringData;
            }
			public static explicit operator long(Data D)
			{
				return D.LongData;
			}
			public static explicit operator decimal(Data D)
			{
				return D.DecimalData;
			}
			public static explicit operator double(Data D)
			{
				return D.DoubleData;
			}
            #endregion
        }
    }
	[System.Serializable]
	public struct Data
	{
		public int IntData;
		public float FloatData;
		public string StringData;
		public long LongData;
		public decimal DecimalData;
		public double DoubleData;
		#region Constructors
		public Data(int Data)
		{
			IntData = Data;
			FloatData = (float)Data;
			StringData = Data.ToString();
			LongData = (long)Data;
			DecimalData = (decimal)Data;
			DoubleData = (double)Data;
		}
		public Data(float Data)
		{
			FloatData = Data;
			IntData = (int)Data;
			StringData = Data.ToString();
			LongData = (long)Data;
			DecimalData = (decimal)Data;
			DoubleData = (double)Data;
		}
		public Data(string Data)
		{
			StringData = Data;
			int.TryParse(Data, out IntData);
			float.TryParse(Data, out FloatData);
			long.TryParse (Data, out LongData);
			decimal.TryParse (Data, out DecimalData);
			double.TryParse (Data, out DoubleData);
		}
		public Data(long Data)
		{
			StringData = Data.ToString();
			IntData = (int)Data;
			FloatData = (float)Data;
			LongData = (long)Data;
			DecimalData = (decimal)Data;
			DoubleData = (double)Data;
		}
		public Data(decimal Data)
		{
			StringData = Data.ToString();
			IntData = (int)Data;
			FloatData = (float)Data;
			LongData = (long)Data;
			DecimalData = (decimal)Data;
			DoubleData = (double)Data;
		}
		public Data(double Data)
		{
			StringData = Data.ToString();
			IntData = (int)Data;
			FloatData = (float)Data;
			LongData = (long)Data;
			DecimalData = (decimal)Data;
			DoubleData = (double)Data;
		}
		#endregion
		#region Conversions
		public static implicit operator Data(int Data)
		{
			return new Data(Data);
		}
		public static implicit operator Data(float Data)
		{
			return new Data(Data);
		}
		public static implicit operator Data(string Data)
		{
			return new Data(Data);
		}
		public static implicit operator Data(long Data)
		{
			return new Data(Data);
		}
		public static implicit operator Data(double Data)
		{
			return new Data(Data);
		}
		public static implicit operator Data(decimal Data)
		{
			return new Data(Data);
		}
		/// <summary>
		/// returns IntegerDataStored
		/// </summary>
		/// <param name="D"></param>
		public static explicit operator int(Data D)
		{
			return D.IntData;
		}
		/// <summary>
		/// returns FloatDataStored
		/// </summary>
		/// <param name="D"></param>
		public static explicit operator float(Data D)
		{
			return D.FloatData;
		}
		/// <summary>
		/// returns StringDataStored
		/// </summary>
		/// <param name="D"></param>
		public static explicit operator string(Data D)
		{
			return D.StringData;
		}
		public static explicit operator long(Data D)
		{
			return D.LongData;
		}
		public static explicit operator decimal(Data D)
		{
			return D.DecimalData;
		}
		public static explicit operator double(Data D)
		{
			return D.DoubleData;
		}
		#endregion
	}
}
