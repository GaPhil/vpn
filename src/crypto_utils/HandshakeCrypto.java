package crypto_utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

/**
 * Created by GaPhil on 2018-12-04.
 * <p>
 * Handles cryptographic operations during handshake
 */
public class HandshakeCrypto {

    /**
     * RSA encrypts plain text and returns cipher text.
     *
     * @param plainText plain text as byte array
     * @param key       RSA key (private or public)
     * @return cipher text as byte array
     */
    public static byte[] encrypt(byte[] plainText, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(ENCRYPT_MODE, key);
        return cipher.doFinal(plainText);
    }

    /**
     * RSA decrypts cipher text and returns plain text.
     *
     * @param cipherText cipher text as byte array
     * @param key        RSA key (private or public)
     * @return plain text as byte array
     */
    public static byte[] decrypt(byte[] cipherText, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    /**
     * Returns RSA public key from X.509 certificate
     *
     * @param certFile X.509 certificate in PEM file
     * @return RSA public key
     */
    public static PublicKey getPublicKeyFromCertFile(String certFile) throws Exception {
        return VerifyCertificate.readCertificate(certFile).getPublicKey();
    }

    /**
     * Returns RSA private key from private key file in DER format.
     *
     * @param keyFile private RSA key file in PEM format
     * @return RSA private key
     */
    public static PrivateKey getPrivateKeyFromKeyFile(String keyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File file = new File(keyFile);
        FileInputStream fileStream = new FileInputStream(file);
        DataInputStream dataStream = new DataInputStream(fileStream);
        byte[] keyBytes = new byte[(int) file.length()];
        dataStream.readFully(keyBytes);
        dataStream.close();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
}
