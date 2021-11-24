package example;

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;

class Main {

    val digestName = "md5"

    @Throws (NoSuchAlgorithmException::class)
    fun generateKey(n :Int) :SecretKey {
        val keyGenerator :KeyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(n)
        return keyGenerator.generateKey()
    }

    @Throws (Exception::class)
    fun generateSalt(n: Int): String {
       val key = generateKey(n);
       return java.util.Base64.getEncoder().encodeToString(key.getEncoded());
    }

    @Throws(Exception::class)
    fun setupSecretKey(digestPassword: String): SecretKey  {
        val md = MessageDigest.getInstance(digestName);
        val digestOfPassword = md.digest(digestPassword.toByteArray());
        val keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for ( j in 0..7 ) {
            keyBytes[j+16] = keyBytes[j];
        }

        return SecretKeySpec(keyBytes, "DESede");
    }

    @Throws(Exception::class)
    fun setupCipher(optMode: Int, digestPassword: String): Cipher {
      val key = setupSecretKey(digestPassword);
      val iv = IvParameterSpec(ByteArray(8));
      val cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
      cipher.init(optMode, key, iv);
      return cipher;
    }

    @Throws(Exception::class)
    fun encrypt(message: String, digestPassword: String): ByteArray {
        val cipher = setupCipher(Cipher.ENCRYPT_MODE, digestPassword);

        val plainTextBytes = message.toByteArray()
        val cipherText = cipher.doFinal(plainTextBytes);

        return cipherText;
    }

    @Throws(Exception::class)
    fun decrypt(message: ByteArray, digestPassword: String): String {
        val decipher = setupCipher(Cipher.DECRYPT_MODE, digestPassword);

        val plainText = decipher.doFinal(message);

        return String(plainText);
    }
}

@Throws(Exception::class)
fun main(args: Array<String>) {

    val text = "password";
    val m = Main()

    val digestPassword = m.generateSalt(256);
    val codedtext = m.encrypt(text, digestPassword);
    val decodedtext = m.decrypt(codedtext, digestPassword);

    println("Orignal: " + text);
    println("Encrypted: " + codedtext); // this is a byte array, you'll just see a reference to an array
    println("Decrypted: " + decodedtext); // This correctly shows "kyle boon"
}
