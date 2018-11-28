import java.io.*;
import javax.crypto.*;

/**
 * Created by GaPhil on 2018-11-28.
 */
public class TestSessionCrypto {
    static String PLAININPUT = "plaininput";
    static String PLAINOUTPUT = "plainoutput";
    static String CIPHER = "cipher";
    static Integer KEYLENGTH = 128;

    public static void main(String[] args) throws Exception {
        int b;

        // Create encrypter instance for a given key length
        SessionEncrypter sessionencrypter = new SessionEncrypter(KEYLENGTH);

        // Attach output file to encrypter, and open input file
        try (
                CipherOutputStream cryptoout = sessionencrypter.openCipherOutputStream(new FileOutputStream(CIPHER));
                FileInputStream plainin = new FileInputStream(PLAININPUT);
        ) {

            // Copy data byte by byte from plain input to crypto output via encrypter

            while ((b = plainin.read()) != -1) {
                cryptoout.write(b);
            }
        }

        // Now ciphertext is in cipher output file. Decrypt it back to plaintext.

        // Create decrypter instance using cipher parameters from encrypter
        SessionDecrypter sessiondecrypter = new SessionDecrypter(sessionencrypter.encodeKey(), sessionencrypter.encodeIV());

        // Attach input file to decrypter, and open output file
        try (
                CipherInputStream cryptoin = sessiondecrypter.openCipherInputStream(new FileInputStream(CIPHER));
                FileOutputStream plainout = new FileOutputStream(PLAINOUTPUT);
        ) {
            // Copy data byte by byte from cipher input to plain output via decrypter
            while ((b = cryptoin.read()) != -1) {
                plainout.write(b);
            }
        }

        System.out.format("Encryption and decryption done. Check that \"%s\" and \"%s\" are identical!\n", PLAININPUT, PLAINOUTPUT);
    }
}

