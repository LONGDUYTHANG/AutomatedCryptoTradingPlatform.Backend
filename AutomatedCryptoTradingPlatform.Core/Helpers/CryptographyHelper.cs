using System.Security.Cryptography;
using System.Text;

namespace AutomatedCryptoTradingPlatform.Core.Helpers;

public static class CryptographyHelper
{
    // AES-256 encryption key (32 bytes). 
    // IMPORTANT: In production, store this in environment variables or Azure Key Vault
    private static readonly byte[] _encryptionKey = Encoding.UTF8.GetBytes("MySecretKey12345MySecretKey12345"); // 32 characters for AES-256
    
    /// <summary>
    /// Encrypts a plaintext string using AES-256 encryption
    /// </summary>
    /// <param name="plainText">Text to encrypt</param>
    /// <returns>Base64 encoded encrypted text</returns>
    public static string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        using var aes = Aes.Create();
        aes.Key = _encryptionKey;
        aes.GenerateIV();

        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using var msEncrypt = new MemoryStream();
        
        // Prepend IV to the encrypted data
        msEncrypt.Write(aes.IV, 0, aes.IV.Length);
        
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        return Convert.ToBase64String(msEncrypt.ToArray());
    }

    /// <summary>
    /// Encrypts a plaintext string using AES-256 encryption with custom key
    /// </summary>
    /// <param name="plainText">Text to encrypt</param>
    /// <param name="key">Encryption key (must be 32 characters)</param>
    /// <returns>Base64 encoded encrypted text</returns>
    public static string Encrypt(string plainText, string key)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        var keyBytes = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));

        using var aes = Aes.Create();
        aes.Key = keyBytes;
        aes.GenerateIV();

        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using var msEncrypt = new MemoryStream();
        
        msEncrypt.Write(aes.IV, 0, aes.IV.Length);
        
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        return Convert.ToBase64String(msEncrypt.ToArray());
    }

    /// <summary>
    /// Decrypts a Base64 encoded encrypted string
    /// </summary>
    /// <param name="cipherText">Base64 encoded encrypted text</param>
    /// <returns>Decrypted plaintext</returns>
    public static string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        var fullCipher = Convert.FromBase64String(cipherText);

        using var aes = Aes.Create();
        aes.Key = _encryptionKey;

        // Extract IV from the beginning of the encrypted data
        var iv = new byte[aes.IV.Length];
        var cipher = new byte[fullCipher.Length - iv.Length];

        Array.Copy(fullCipher, iv, iv.Length);
        Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);

        aes.IV = iv;

        var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

        using var msDecrypt = new MemoryStream(cipher);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);

        return srDecrypt.ReadToEnd();
    }

    /// <summary>
    /// Decrypts a Base64 encoded encrypted string with custom key
    /// </summary>
    /// <param name="cipherText">Base64 encoded encrypted text</param>
    /// <param name="key">Decryption key (must be 32 characters)</param>
    /// <returns>Decrypted plaintext</returns>
    public static string Decrypt(string cipherText, string key)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        var keyBytes = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32));
        var fullCipher = Convert.FromBase64String(cipherText);

        using var aes = Aes.Create();
        aes.Key = keyBytes;

        var iv = new byte[aes.IV.Length];
        var cipher = new byte[fullCipher.Length - iv.Length];

        Array.Copy(fullCipher, iv, iv.Length);
        Array.Copy(fullCipher, iv.Length, cipher, 0, cipher.Length);

        aes.IV = iv;

        var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

        using var msDecrypt = new MemoryStream(cipher);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);

        return srDecrypt.ReadToEnd();
    }

    /// <summary>
    /// Hashes a password using BCrypt
    /// </summary>
    /// <param name="password">Plain text password</param>
    /// <returns>BCrypt hashed password</returns>
    public static string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
    }

    /// <summary>
    /// Verifies a password against a BCrypt hash
    /// </summary>
    /// <param name="password">Plain text password</param>
    /// <param name="hashedPassword">BCrypt hashed password</param>
    /// <returns>True if password matches</returns>
    public static bool VerifyPassword(string password, string hashedPassword)
    {
        return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
    }
}
