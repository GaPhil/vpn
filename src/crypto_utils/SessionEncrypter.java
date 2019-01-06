package crypto_utils;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Created by GaPhil on 2018-11-28.
 * <p>
 * Performs encryption of a stream of data using AES in CTR mode.
 */
public class SessionEncrypter {

    private SessionKey sessionKey;
    private IvParameterSpec ivParameterSpec;

    /**
     * Creates parameters needed for AES in CTR mode; namely key and counter
     * referred to as initialisation vector (IV) and initialises cipher used
     * for encryption.
     *
     * @param keyLength key length in bits
     */
    public SessionEncrypter(Integer keyLength) throws NoSuchAlgorithmException {
        this.sessionKey = new SessionKey(keyLength);
        SecureRandom randomByteGenerator = new SecureRandom();
        this.ivParameterSpec = new IvParameterSpec(randomByteGenerator.generateSeed(16));
    }

    public SessionEncrypter(SessionKey sessionKey, IvParameterSpec ivParameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.sessionKey = sessionKey;
        this.ivParameterSpec = ivParameterSpec;
    }

    /**
     * The plain text data to be encrypted is sent to the crypto_utils.SessionEncrypter via
     * a CipherOutputStream associated with the crypto_utils.SessionEncrypter. The output
     * from the crypto_utils.SessionEncrypter goes to another OutputStream.
     *
     * @param outputStream plain text output stream
     * @return encrypted output stream
     */
    public CipherOutputStream openCipherOutputStream(OutputStream outputStream) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, this.sessionKey.getSecretKey(), this.ivParameterSpec);
        return new CipherOutputStream(outputStream, cipher);
    }

    /**
     * Returns crypto_utils.SessionEncrypter's key
     *
     * @return Base64 encoded key
     */
    public String encodeStringKey() {
        return sessionKey.encodeKey();
    }

    /**
     * Returns crypto_utils.SessionEncrypter's key
     *
     * @return Base64 encoded key
     */
    public String encodeKey() {
        return this.sessionKey.encodeKey();
    }

    /**
     * Returns crypto_utils.SessionEncrypter's initialisation vector (IV)
     * [counter used for AES in CTR more].
     *
     * @return Base64 encoded initialisation vector (IV)
     */
    public String encodeStringIv() {
        return Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
    }

    /**
     * Returns crypto_utils.SessionEncrypter's initialisation vector (IV)
     * [counter used for AES in CTR more].
     *
     * @return Base64 encoded initialisation vector (IV)
     */
    public String encodeIV() {
        return Base64.getEncoder().encodeToString(this.ivParameterSpec.getIV());
    }
}
