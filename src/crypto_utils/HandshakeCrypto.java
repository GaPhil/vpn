package crypto_utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
     * Returns RSA private key from private key file in PEM format.
     * First converts key file to der format and then reads in PKCS8.
     *
     * @param keyFile private RSA key file in PEM format
     * @return RSA private key
     */
    public static PrivateKey getPrivateKeyFromKeyFile(String keyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String file = keyFile.substring(0, keyFile.lastIndexOf("."));
        String outFile = file + ".der";
        try {
            ProcessBuilder processBuilder = new ProcessBuilder("openssl", "pkcs8", "-nocrypt", "-topk8", "-inform", "PEM", "-in", keyFile, "-outform", "DER", "-out", outFile);
            processBuilder.start();
        } catch (Exception exception) {
            System.out.println("Key conversion failed!");
        }
        Path path = Paths.get(outFile);
        byte[] privateKeyFileName = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyFileName);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
