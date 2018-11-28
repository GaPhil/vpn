import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Created by GaPhil on 2018-11-28.
 * <p>
 * Performs encryption of a stream of data.
 */
public class SessionEncrypter {

    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    SessionKey sessionKey;
    IvParameterSpec ivParameterSpec;

    /**
     * Creates parameters needed for AES in CTR mode; namely key and
     * counter referred to as initialisation vector (IV).
     *
     * @param keyLength
     * @throws NoSuchAlgorithmException
     */
    public SessionEncrypter(Integer keyLength) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.sessionKey = new SessionKey(keyLength);
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);
        this.ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey());
    }

    /**
     * The plain text data to be encrypted is sent to the SessionEncrypter via
     * a CipherOutputStream associated with the SessionEncrypter. The output
     * from the SessionEncrypter goes to another OutputStream.
     *
     * @param outputStream
     * @return
     */
    CipherOutputStream openCipherOutputStream(OutputStream outputStream) {
        return new CipherOutputStream(outputStream, cipher);
    }

    /**
     * Returns SessionEncrypter's key
     *
     * @return
     */
    String encodeKey() {
        return sessionKey.encodeKey();
    }

    /**
     * Returns SessionEncrypter's initialisation vector (IV)
     * [counter used for AES in CTR more].
     *
     * @return
     */
    String encodeIV() {
        return Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
    }
}
