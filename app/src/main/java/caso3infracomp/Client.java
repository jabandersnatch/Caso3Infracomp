package caso3infracomp;

import java.io.*;

import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

public class Client implements Runnable {
    private static final String SERVER_PUBLIC_KEY_FILE = "app/src/main/resources/server_public.key";
    private static final String SERVER_IP = "localhost";
    private static final int SERVER_PORT = 3000;
    private static Socket socket;
    private static PrintWriter writer;
    private static BufferedReader reader;


    private static final String INICIO = "INICIO";
    private static final String ACK = "ACK";
    private static final String ERROR = "ERROR";
    private static final String TERMINAR = "TERMINAR";

    private static final String ALGORITHM = "AES";
    private static final String KEY_ALGORITHM = "RSA";

    private String name;

    public Client(String name) {
        this.name = name;
        try {
            socket = new Socket(SERVER_IP, SERVER_PORT);
            writer = new PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    
    public static String generateChallenge() {
        // creates a random number of 24 digits
        Random r = new Random();
        String challenge = "";
        for (int i = 0; i < 24; i++) {
            challenge += r.nextInt(10);
        }
        return challenge;
    }

    public static PublicKey getPublicKey() {
        try {
            FileReader fr = new FileReader(SERVER_PUBLIC_KEY_FILE);
            BufferedReader br = new BufferedReader(fr);
            String line = br.readLine();
            byte[] key = Base64.getDecoder().decode(line);
            br.close();
            return (PublicKey) KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(key));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static SecretKey generateSecretKey() {
        try {
            // generates a simmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();
            return secretKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void run() {
        try {
            Socket s = new Socket(SERVER_IP, SERVER_PORT);
            // Send hello to the server
            writer.println(INICIO);
            // Reads the response from the server
            String response = reader.readLine();
            System.out.println("Response: " + response);
            // Sends a challenge to the server
            String challenge = generateChallenge();

            writer.println(challenge);
            // recives the cipher challenge from the server
            String cipherChallenge = reader.readLine();

            // cipherChallenge to byte array
            byte[] cipherChallengeBytes = Util.str2byte(cipherChallenge);

            PublicKey publicKey = getPublicKey();

            // decrypt the challenge with the public key
            byte[] decryptedChallenge = AsymmetricCipher.decrypt(publicKey, KEY_ALGORITHM, cipherChallengeBytes);

            // byte array to string
            String decryptedChallengeString = Util.byte2str(decryptedChallenge);

            System.out.println("Decrypted challenge: " + decryptedChallengeString);

            // compare the challenge with the decrypted challenge
            if(!challenge.equals(decryptedChallengeString)){
                writer.println(ERROR);
                System.out.println("Error: challenge not equals");
                s.close();
                throw new Exception("Challenge not valid");
            }

            // generate a secret key
            SecretKey secretKey = generateSecretKey();

            System.out.println("Secret key: " + Util.byte2str(secretKey.getEncoded()));

            // cipher the secret key with the public key
            byte[] cipherSecretKey = AsymmetricCipher.encrypt(publicKey, KEY_ALGORITHM, secretKey.getEncoded());
            System.out.println("Cipher secret key: " + Util.byte2str(cipherSecretKey));
            // send the cipher secret key to the server
            writer.println(Util.byte2str(cipherSecretKey));

            // recive the ack from the server
            String ack = reader.readLine();
            if (!ack.equals(ACK)) {
                writer.println(ERROR);
                System.out.println("Error: ack not equals");
                s.close();
                throw new Exception("Ack not valid");
            }

            // send the name of the client ciphered with the secret key
            System.out.println("Name: " + this.name);
            byte[] cipherName = SymmetricCipher.encrypt(this.name.getBytes("UTF8"), secretKey);


            System.out.println("Cipher name: " + Util.byte2str(cipherName));
            writer.println(Util.byte2str(cipherName));

            // recive the ack from the server
            ack = reader.readLine();
            if (!ack.equals(ACK)) {
                writer.println(ERROR);
                System.out.println("Error: ack not equals");
                s.close();
                throw new Exception("Ack not valid");
            }
            System.out.println("Response: " + ack);

            // send the id of the package that the client wants to know its state
            String idPackage = "0";
            byte[] cipherIdPackage = SymmetricCipher.encrypt(idPackage.getBytes("UTF8"), secretKey);
            writer.println(Util.byte2str(cipherIdPackage));

            // recive the state of the package ciphered with the secret key
            String cipherState = reader.readLine();

            System.out.println("Cipher state: " + cipherState);

            byte [] bytesCryptedState = Util.str2byte(cipherState);



            // decrypt the state with the secret key
            byte[] bytesDecryptedState = SymmetricCipher.decrypt(bytesCryptedState, secretKey);

            // byte array to string
            String decryptedState = new String(bytesDecryptedState, "UTF8");

            System.out.println("Decrypted state: " + decryptedState);

            // send the ack to the server
            writer.println(ACK);

            // read the hmac digest from the server
            String hmacDigest = reader.readLine();

            System.out.println("Hmac digest: " + hmacDigest);

            // calculate the hmac digest of the secret key, the name and the id of the package

            Mac sha256 = Mac.getInstance("HmacSHA256");

            sha256.init(secretKey);

            byte[] hmacDigestBytes = sha256.doFinal((this.name+ idPackage).getBytes("UTF8"));

            String hmacDigestString = Util.byte2str(hmacDigestBytes);

            System.out.println("Hmac digest string: " + hmacDigestString);

            // compare the hmac digest with the hmac digest received from the server
            if(!hmacDigestString.equals(hmacDigest)){
                writer.println(ERROR);
                System.out.println("Error: hmac digest not equals");
                s.close();
                throw new Exception("Hmac digest not valid");
            }

            writer.println(TERMINAR);

            s.close();



            // byte array to string
            writer.close();
            
            s.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) {
        Client client = new Client("Juan M");
        client.run();
    
    }

    
}