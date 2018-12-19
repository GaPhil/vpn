package crypto_utils;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Created by GaPhil on 2018-11-28.
 * <p>
 * Performs decryption of a stream of data using AES in CTR mode.
 */
public class SessionDecrypter {

    private Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    private SessionKey sessionKey;
    private IvParameterSpec ivParameterSpec;

    /**
     * Takes parameters needed for AES in CTR mode; namely key and counter
     * referred to as initialisation vector (IV) and initialises cipher used
     * for decryption.
     *
     * @param key Session key in the form of a Baes64 encoded string
     * @param iv  Initialisation vector in the form of a Base64 encoded string
     */
    public SessionDecrypter(String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.sessionKey = new SessionKey(key);
        this.ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        this.cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);
    }

    public SessionDecrypter(SessionKey sessionKey, IvParameterSpec ivParameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.sessionKey = sessionKey;
        this.ivParameterSpec = ivParameterSpec;
        this.cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);
    }

    /**
     * The cipher text data to be decrypted is sent to the crypto_utils.SessionDecrypter via
     * an InputStream associated with the crypto_utils.SessionDecrypter. The output
     * from the crypto_utils.SessionDecrypter goes to a CipherInputStream.
     *
     * @param inputStream encrypted input stream
     * @return plain text input stream
     */
    public CipherInputStream openCipherInputStream(InputStream inputStream) {
        return new CipherInputStream(inputStream, cipher);
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
    public byte[] encodeKey() {
        return sessionKey.encodeKey().getBytes();
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
    public byte[] encodeIv() {
        return Base64.getEncoder().encodeToString(ivParameterSpec.getIV()).getBytes();
    }
}
