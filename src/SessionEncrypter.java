import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
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
    public SessionEncrypter(Integer keyLength) throws Exception {
        this.sessionKey = new SessionKey(keyLength);
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);
        this.ivParameterSpec = new IvParameterSpec(iv);
    }

    /**
     * Returns SessionEncrypter's key
     *
     * @return
     */
    String enccodeKey() {
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
