using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KingJulianDecryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== King Julian Password Decryptor ===\n");

            if (args.Length != 2)
            {
                Console.WriteLine("Usage: KingJulianDecryptor.exe <EncryptionKey> <EncryptedPassword>");
                Console.WriteLine("\nExample:");
                Console.WriteLine("  KingJulianDecryptor.exe \"your-base64-key\" \"your-encrypted-password\"");
                return;
            }

            string encryptionKey = args[0];
            string encryptedPassword = args[1];

            try
            {
                string decryptedPassword = DecryptPassword(encryptedPassword, encryptionKey);
                Console.WriteLine("\n✓ Decryption successful!");
                Console.WriteLine($"\nDecrypted Password: {decryptedPassword}");
            }
            catch (FormatException)
            {
                Console.WriteLine("\n✗ Error: Invalid Base64 format. Please check your encryption key and encrypted password.");
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine($"\n✗ Decryption failed: {ex.Message}");
                Console.WriteLine("Please verify that the encryption key is correct.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n✗ Unexpected error: {ex.Message}");
            }
        }

        /// <summary>
        /// Decrypts a password using AES-256.
        /// </summary>
        private static string DecryptPassword(string encryptedPassword, string key)
        {
            var keyBytes = Convert.FromBase64String(key);
            var encryptedBytes = Convert.FromBase64String(encryptedPassword);

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // Extract IV from the beginning of encrypted data
                var iv = new byte[aes.BlockSize / 8];
                Array.Copy(encryptedBytes, 0, iv, 0, iv.Length);
                aes.IV = iv;

                // Extract encrypted data (skip IV)
                var cipherText = new byte[encryptedBytes.Length - iv.Length];
                Array.Copy(encryptedBytes, iv.Length, cipherText, 0, cipherText.Length);

                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream(cipherText))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var reader = new StreamReader(cs))
                {
                    return reader.ReadToEnd();
                }
            }
        }
    }
}
