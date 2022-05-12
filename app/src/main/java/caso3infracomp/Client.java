package caso3infracomp;

import java.io.*;

import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

public class Client implements Runnable {
    private static final String SERVER_PUBLIC_KEY_FILE = "app/src/main/resources/server_public.key";
    private static final String LOG_FILE_SYMMETRIC_TIME = "app/src/main/resources/log_symmetric_time.txt";
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
    private String packageId;

    public Client(String name, String packageId) {
        this.name = name;
        this.packageId = packageId;
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
            // Send hello to the server
            writer.println(INICIO);
            // Reads the response from the server
            String response = reader.readLine();
            if (!response.equals(ACK)) {
                System.out.println("Error: " + response);
                writer.println(ERROR);
                socket.close();
                throw new Exception("Error: " + response);
            }
            // Sends a challenge to the server
            String challenge = generateChallenge();

            writer.println(challenge);
            // recives the cipher challenge from the server
            String cipherChallenge = reader.readLine();

            // cipherChallenge to byte array
            byte[] cipherChallengeBytes = Util.str2byte(cipherChallenge);

            SecretKey secretKey = generateSecretKey();
            
            long startTime = System.nanoTime();
            byte[] cipherChallengeEncrypted = SymmetricCipher.encrypt(cipherChallengeBytes, secretKey);
            long endTime = System.nanoTime();
            Util.writeLog(LOG_FILE_SYMMETRIC_TIME, "Symmetric", endTime - startTime);


            PublicKey publicKey = getPublicKey();

            // decrypt the challenge with the public key
            byte[] decryptedChallenge = AsymmetricCipher.decrypt(publicKey, KEY_ALGORITHM, cipherChallengeBytes);

            // byte array to string
            String decryptedChallengeString = Util.byte2str(decryptedChallenge);

            // compare the challenge with the decrypted challenge
            if(!challenge.equals(decryptedChallengeString)){
                writer.println(ERROR);
                System.out.println("Error: challenge not equals");
                socket.close();
                throw new Exception("Challenge not valid");
            }

            // generate a secret key

            // cipher the secret key with the public key
            byte[] cipherSecretKey = AsymmetricCipher.encrypt(publicKey, KEY_ALGORITHM, secretKey.getEncoded());
            // send the cipher secret key to the server
            writer.println(Util.byte2str(cipherSecretKey));

            // recive the ack from the server
            String ack = reader.readLine();
            if (!ack.equals(ACK)) {
                writer.println(ERROR);
                System.out.println("Error: ack not equals");
                socket.close();
                throw new Exception("Ack not valid");
            }

            // send the name of the client ciphered with the secret key
            byte[] cipherName = SymmetricCipher.encrypt(this.name.getBytes("UTF8"), secretKey);

            writer.println(Util.byte2str(cipherName));

            // recive the ack from the server
            ack = reader.readLine();
            if (!ack.equals(ACK)) {
                writer.println(ERROR);
                System.out.println("Error: ack not equals");
                socket.close();
                throw new Exception("Ack not valid");
            }

            // send the id of the package that the client wants to know its state
            byte[] cipherIdPackage = SymmetricCipher.encrypt(this.packageId.getBytes("UTF8"), secretKey);
            writer.println(Util.byte2str(cipherIdPackage));

            // recive the state of the package ciphered with the secret key
            String cipherState = reader.readLine();

            if (cipherState.equals(ERROR)) {
                System.out.println("Error: package not found");
                writer.println(ERROR);
                socket.close();
                throw new Exception("Package not found");
            }

            byte [] bytesCryptedState = Util.str2byte(cipherState);

            // decrypt the state with the secret key
            byte[] bytesDecryptedState = SymmetricCipher.decrypt(bytesCryptedState, secretKey);

            // byte array to string
            String decryptedState = new String(bytesDecryptedState, "UTF8");

            // send the ack to the server
            writer.println(ACK);

            // read the hmac digest from the server
            String hmacDigest = reader.readLine();

            // calculate the hmac digest of the secret key, the name and the id of the package

            Mac sha256 = Mac.getInstance("HmacSHA256");

            sha256.init(secretKey);

            byte[] hmacDigestBytes = sha256.doFinal((this.name+ this.packageId).getBytes("UTF8"));

            String hmacDigestString = Util.byte2str(hmacDigestBytes);

            // compare the hmac digest with the hmac digest received from the server
            if(!hmacDigestString.equals(hmacDigest)){
                writer.println(ERROR);
                System.out.println("Error en la consulta");
                socket.close();
                throw new Exception("Hmac digest not valid");
            }

            System.out.println("State: " + decryptedState);

            writer.println(TERMINAR);

            socket.close();



            // byte array to string
            writer.close();
            
            socket.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
    
    public static synchronized ArrayList<String> poolNames() {
        ArrayList<String> names = new ArrayList<String>();
        names.add("Juan M");
        names.add("Jose C");
        names.add("Alejandro T");
        names.add("Carlos P");
        names.add("Sergio M");
        names.add("Joan S");
        names.add("Daniel A");
        names.add("Nicolas D");
        names.add("Juan Jose M");
        names.add("Esteban H");
        names.add("Mario C");
        names.add("Santiago M");
        names.add("Diego E");
        names.add("Andres M");
        names.add("Camilo K");
        names.add("Juan Carlos M");
        names.add("Nelly G");
        names.add("Maria B");
        names.add("Sandra A");
        names.add("Angelica B");
        names.add("Ana R");
        names.add("Sofia R");
        names.add("Juan Alejandro M");
        names.add("Samuel B");
        names.add("Carlos Mario M");
        names.add("Maya T");
        names.add("David T");
        names.add("Yei H");
        names.add("Zin Z");
        names.add("Yui M");
        names.add("Daniela C");

        return names;
    }

    public synchronized void setIdPakage(String idPackage) {
        this.packageId = idPackage;
    }
        
    public static void main(String[] args) {

        Random r = new Random();
        ArrayList<String> names = poolNames();
        String name = names.get(r.nextInt(names.size()));
        for (int i = 0; i < 32; i++) {
            Client client = new Client(name, Integer.toString(r.nextInt(31)));
            System.out.println("Name: " + name);
            System.out.println("Package: " + r.nextInt(32));
            client.run();
            client.setIdPakage(Integer.toString(r.nextInt(32)));
        }
    }

    
}