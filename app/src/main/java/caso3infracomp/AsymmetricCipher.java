package caso3infracomp;
import javax.crypto.*;
import java.security.Key;

public class AsymmetricCipher {

    public static byte[] encrypt(Key key, String algorithm, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedData = cipher.doFinal(data);

            return encryptedData;
    }
        catch (Exception e) {
            System.out.println("Error encrypting data: " + e.getMessage());
            return null;
        }
    }

    public static byte[] decrypt(Key key, String algorithm, byte[] data) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedData = cipher.doFinal(data);

            return decryptedData;
        }
        catch (Exception e) {
            System.out.println("Error decrypting data: " + e.getMessage());
            return null;
        }
    }
}