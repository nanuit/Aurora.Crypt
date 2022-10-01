using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Aurora.Crypt
{
    /// <summary>
    /// class to de-/encode string using the Aes Algorithm
    /// </summary>
    public class Encryption
    {
        #region Private Members
        private static Aes m_AesAlgorithm;
        #endregion
        #region Encryption
        /// <summary>
        /// Encrypt the given text and give the byte array back as a BASE64 string
        /// </summary>
        /// <param name="text">The text to encrypt</param>
        /// <param name="key">encryption key</param>
        /// <returns>The encrypted text</returns>
        public static string Encrypt(string text, string key)
        {
            string encodedString;
            if (string.IsNullOrEmpty(text))
                throw new ArgumentNullException("text");
            byte[] salt = InitSalt();
            InitAes(key, salt);
            ICryptoTransform encryptor = m_AesAlgorithm.CreateEncryptor(m_AesAlgorithm.Key, m_AesAlgorithm.IV);
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                        swEncrypt.Write(text + Convert.ToBase64String(salt));
                    encodedString = Convert.ToBase64String(msEncrypt.ToArray().Concat(salt).ToArray());
                }
            }
            return encodedString;
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
            string decrypted;
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("cipherText invalid");

            if (!IsBase64String(cipherText))
                throw new Exception("The cipherText input parameter is not base64 encoded");

            byte[] cipherPlusSalt = Convert.FromBase64String(cipherText);
            byte[] cipher = cipherPlusSalt.Take(cipherPlusSalt.Length - 16).ToArray();
            byte[] salt = cipherPlusSalt.Skip(cipherPlusSalt.Length - 16).ToArray();
            InitAes(appIdentifier, salt);
            var decryptor = m_AesAlgorithm.CreateDecryptor(m_AesAlgorithm.Key, m_AesAlgorithm.IV);


            using (var msDecrypt = new MemoryStream(cipher))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new StreamReader(csDecrypt))
                        decrypted = srDecrypt.ReadToEnd();
                }
            }
            return (decrypted.Remove(decrypted.Length - 24));
        }
        #endregion
        /// <summary>
        /// Create a new Aesalgortihm initialize it
        /// </summary>
        /// <param name="key">Application unique identifier</param>
        /// <param name="salt">salt string to be used for key generation</param>
        private static void InitAes(string key, byte[] salt)
        {
            var rfcKey = new Rfc2898DeriveBytes(key, salt);
            m_AesAlgorithm = Aes.Create();
            m_AesAlgorithm.Key = rfcKey.GetBytes(m_AesAlgorithm.KeySize / 8);
            m_AesAlgorithm.IV = rfcKey.GetBytes(m_AesAlgorithm.BlockSize / 8);
        }
        /// <summary>
        /// create a salt array
        /// </summary>
        /// <returns></returns>
        private static byte[] InitSalt()
        {
            byte[] salt = new byte[16];
            RandomNumberGenerator.Create().GetBytes(salt);
            return (salt);
        }
    }
}
