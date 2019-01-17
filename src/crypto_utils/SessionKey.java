package crypto_utils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Created by GaPhil on 2018-11-20.
 * <p>
 * Creates symmetric (AES) encryption keys. Handles encoding and decoding into Base64
 */
public class SessionKey {

    private SecretKey secretKey;

    /**
     * Creates random crypto_utils.SessionKey object of specified length.
     *
     * @param keyLength key length in bits
     */
    public SessionKey(Integer keyLength) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keyLength);
        this.secretKey = keyGenerator.generateKey();
    }

    /**
     * Creates crypto_utils.SessionKey object from a string containing an existing key in Base64 encoding.
     *
     * @param encodedKey Base64 encoded key
     */
    public SessionKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        this.secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public SessionKey(byte[] key) {
        try {
            this.secretKey = new SecretKeySpec(key, 0, key.length, "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Returns SecretKey from crypto_utils.SessionKey object
     *
     * @return secret key
     */
    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    /**
     * Returns Base64 encoded string containing the AES key as a sequence of bytes, encoded using Base64.
     *
     * @return encoded key
     */
    public String encodeKey() {
        return Base64.getEncoder().encodeToString(this.secretKey.getEncoded());
    }

    /**
     * Returns Base64 decoded byte array containing the AES key.
     *
     * @param encodeKey Base64 encoded key as string
     * @return key as decoded byte array
     */
    public byte[] decodeKey(String encodeKey) throws IOException {
        return Base64.getDecoder().decode(encodeKey);
    }
}
