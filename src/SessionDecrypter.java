import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Created by GaPhil on 2018-11-28.
 * <p>
 * Performs decryption on a stream of data.
 */
public class SessionDecrypter {

    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    SessionKey sessionKey;
    IvParameterSpec ivParameterSpec;

    SessionDecrypter(String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        this.sessionKey = new SessionKey(key);
        this.ivParameterSpec = new IvParameterSpec(iv.getBytes());
//        this.ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        this.cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey());
    }


    CipherInputStream openCipherInputStream(InputStream inputStream) {
        return new CipherInputStream(inputStream, cipher);
    }

    /**
     * Returns SessionDecrypter's key
     *
     * @return
     */
    String encodeKey() {
        return sessionKey.encodeKey();
    }

    /**
     * Returns SessionDecrypter's initialisation vector (IV)
     * [counter used for AES in CTR more].
     *
     * @return
     */
    String encodeIV() {
        return Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
    }
}
