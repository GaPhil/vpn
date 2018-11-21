import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.sun.deploy.util.Base64Wrapper.encodeToString;

/**
 * Created by GaPhil on 2018-11-20.
 */
public class SessionKey {

    private SecretKey secretKey;

    /**
     * Creates random SessionKey object of specified length.
     *
     * @param keyLength key length in bits
     */
    public SessionKey(Integer keyLength) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keyLength);
        this.secretKey = keyGenerator.generateKey();
    }

    /**
     * Creates SessionKey object from a string containing an existing key in Base64 encoding.
     *
     * @param encodedKey Base64 encoded key
     */
    public SessionKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        this.secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    /**
     * Returns SecretKey from SessionKey object
     *
     * @return secret key
     */
    SecretKey getSecretKey() {
        return this.secretKey;
    }

    /**
     * Returns Base64 encoded string containing the AES key as a sequence of bytes, encoded using Base64.
     *
     * @return encoded key
     */
    String encodeKey() {
        return encodeToString(this.secretKey.getEncoded());
    }

    /**
     * Returns Base64 decoded byte array containing the AES key.
     *
     * @param encodeKey Base63 encoded key as string
     * @return key as decoded byte array
     */
    public byte[] decodeKey(String encodeKey) {
        return Base64.getDecoder().decode(encodeKey);
    }
}
