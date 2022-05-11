package caso3infracomp;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class SymmetricCipher {
    
    private final static String PADDING = "AES/ECB/PKCS5Padding";


    public static byte[] encrypt(byte[] data, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            System.out.println("Error encrypting data: " + e.getMessage());
            return null;
        }
    }

    public static byte[] decrypt(byte[] data, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(PADDING);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            System.out.println("Error decrypting data: " + e.getMessage());
            return null;
        }
    }
}