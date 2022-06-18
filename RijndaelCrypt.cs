using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Aurora.Crypt
{
    public class RijndaelCrypt
    {
        #region Consts
        /// <summary>
        /// Change this Inputkey GUID with a new GUID when you use this code in your own program !!!
        /// Keep this inputkey very safe and prevent someone from decoding it some way !!!
        /// </summary>
        //internal const string m_AppIndentifier = "B2C1323D-038B-4E8A-A142-BE8C20009A0D";
        #endregion
        #region Private Members
        internal static RijndaelManaged AesAlgorithm;
        #endregion
        #region Encryption
        /// <summary>
        /// Encrypt the given text and give the byte array back as a BASE64 string
        /// </summary>
        /// <param name="text">The text to encrypt</param>
        /// <param name="appIdentifier">Application unique identifier</param>
        /// <returns>The encrypted text</returns>
        public static string Encrypt(string text, string appIdentifier)
        {
            if (string.IsNullOrEmpty(text))
                throw new ArgumentNullException("text");
            byte[] salt = InitSalt();
            InitRijndael(appIdentifier, salt);
            var encryptor = AesAlgorithm.CreateEncryptor(AesAlgorithm.Key, AesAlgorithm.IV);
            var msEncrypt = new MemoryStream();

            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt))
                swEncrypt.Write(text+ Convert.ToBase64String(salt));
            byte[] helperArray = msEncrypt.ToArray().Concat(salt).ToArray();
            //List<byte> helper = new List<byte>();
            //helper.AddRange(msEncrypt.ToArray());
            //helper.AddRange(Salt);
            return Convert.ToBase64String(helperArray);
        }
        #endregion
        #region Decrypt
        /// <summary>
        /// Checks if a string is base64 encoded
        /// </summary>
        /// <param name="base64String">The base64 encoded string</param>
        /// <returns></returns>
        private static bool IsBase64String(string base64String)
        {
            base64String = base64String.Trim();

            return (base64String.Length % 4 == 0) &&
                    Regex.IsMatch(base64String, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        /// <summary>
        /// Decrypts the given text
        /// </summary>
        /// <param name="cipherText">The encrypted BASE64 text</param>
        /// <param name="appIdentifier">Application unique identifier</param>
        /// <returns>Decrypted text</returns>
        public static string Decrypt(string cipherText, string appIdentifier)
        {
            string decrypted = string.Empty;
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("cipherText invalid");

            if (!IsBase64String(cipherText))
                //return (String.Empty);
                throw new Exception("The cipherText input parameter is not base64 encoded");

            byte[] cipherPlusSalt = Convert.FromBase64String(cipherText);
            byte[] cipher = cipherPlusSalt.Take(cipherPlusSalt.Length - 16).ToArray();
            byte[] salt = cipherPlusSalt.Skip(cipherPlusSalt.Length - 16).ToArray();
            InitRijndael(appIdentifier, salt);
            var decryptor = AesAlgorithm.CreateDecryptor(AesAlgorithm.Key, AesAlgorithm.IV);
            

            using (var msDecrypt = new MemoryStream(cipher))
            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (var srDecrypt = new StreamReader(csDecrypt))
                decrypted = srDecrypt.ReadToEnd();
            
            return (decrypted.Remove(decrypted.Length - 24));
        }
        #endregion
        /// <summary>
        /// Create a new RijndaelManaged class and initialize it
        /// </summary>
        /// <param name="appIdentifier">Application unique identifier</param>
        /// <param name="salt">salt string to be used for key generation</param>
        private static void InitRijndael(string appIdentifier, byte[] salt)
        {
            var key = new Rfc2898DeriveBytes(appIdentifier, salt);
            AesAlgorithm = new RijndaelManaged();
            AesAlgorithm.Key = key.GetBytes(AesAlgorithm.KeySize / 8);
            AesAlgorithm.IV = key.GetBytes(AesAlgorithm.BlockSize / 8);
        }
        /// <summary>
        /// create a salt array
        /// </summary>
        /// <returns></returns>
        private static byte[] InitSalt()
        {
            byte[] salt = new byte[16];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(salt);
            return (salt);
        }
    }
}
