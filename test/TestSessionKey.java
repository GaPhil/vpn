import java.security.NoSuchAlgorithmException;

/**
 * Created by GaPhil on 2018-11-20.
 */
public class TestSessionKey {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        int[] keyLengths = {128, 192, 256};
        for (int keyLength : keyLengths) {
            SessionKey key1 = new SessionKey(keyLength);
            SessionKey key2 = new SessionKey(key1.encodeKey());
            if (key1.getSecretKey().equals(key2.getSecretKey())) {
                System.out.println(keyLength + " bit key:\t\tPass!");
                System.out.println("Base64 encoded Key:\t" + key1.encodeKey());
                System.out.println("Key algorithm:\t\t" + key1.getSecretKey().getAlgorithm() + "\n");
            } else {
                System.out.println(keyLength + " bit key: Fail!");
            }
        }
    }
}
