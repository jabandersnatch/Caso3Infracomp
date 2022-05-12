package caso3infracomp;

import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;

import java.security.*;

import javax.crypto.*;
// import SecretKeySpec;
import javax.crypto.spec.SecretKeySpec;
public class Server implements Runnable {

    public final static String PUBLIC_KEY_FILE = "app/src/main/resources/server_public.key";
    // Create a constant that saves the file path to the packages_info that is in the resources folder
    public final static String PACKAGES_STORAGE_FILE = Path.of(System.getProperty("user.dir"), "app","src", "main", "resources", "packages_info.csv").toString(); 
    public final static  int PORT = 3000; 
    public final static String HOST = "localhost"; 
    public final static String ALGORITHM = "AES"; 
    public final static String KEY_ALGORITHM = "RSA"; 
    public final static String TRANSFORMATION = "AES/ECB/PKCS5Padding"; 
    public final static int nChains = 13;

    public final static String INICIO = "INICIO";
    public final static String ACK = "ACK";
    public final static String ERROR = "ERROR";
    public final static String TERMINAR = "TERMINAR";
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static SecretKey secretKey;

    private Socket socketClient;
    private static BufferedReader reader;
    private static PrintWriter writer;

    private static ArrayList<Package> packages;   

    public Server(Socket socketClient){
        this.socketClient = socketClient;
        packages = new ArrayList<Package>();
        loadPackages();
        generateKeys();
        try {
            reader = new BufferedReader(new InputStreamReader(this.socketClient.getInputStream()));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static Package getPackage(int id)
    {
        for(Package p : packages)
        {
            if(p.idPackage() == id)
            {
                return p;
            }
        }
        return null;
    }

    public static boolean isNameOnPackageList(String name)
    {
        for(Package p : packages)
        {
            if(p.nameClient().equals(name))
            {
                return true;
            }
        }
        return false;
    }

    public static void loadPackages()
    {
        packages = new ArrayList<Package>();
        try {
            FileReader fr = new FileReader(PACKAGES_STORAGE_FILE);
            BufferedReader br = new BufferedReader(fr);
            String line;
            br.readLine();
            while((line = br.readLine()) != null)
            {
                // replace all spaces with none
                String[] parts = line.split(", ");
                Package p = new Package(Integer.parseInt(parts[0]), parts[1], Integer.parseInt(parts[2]));
                packages.add(p);
            }
            br.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void generateKeys()
    {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();
            publicKey = pair.getPublic();
            privateKey = pair.getPrivate();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        // Save public key to file
        try {
            FileWriter fw = new FileWriter(PUBLIC_KEY_FILE);
            writer = new PrintWriter(fw);
            writer.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            writer.close();
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Override
    public void run() {
        try {
            System.out.println("Server started");
            System.out.println("Client connected");
            // read the message from the client
            String message = reader.readLine();
            System.out.println("Message received: " + message);
            if (!message.equals(INICIO)) {
                System.out.println("Error: message not valid");
                socketClient.close();
                throw new Exception("Error: message not valid");}
            
            // send the message back to the client
            PrintWriter writer = new PrintWriter(socketClient.getOutputStream(), true);
            writer.println("ACK");
            // reads the challenge from the client
            String challenge = reader.readLine();
            // if the challenge length isn't equal to 24 the communication ends
            if(challenge.length() != 24)
            {
                writer.println("ERROR");
                writer.close();
                System.out.println("Client disconnected");
            }
            System.out.println("Challenge received: " + challenge);
            // transform the challenge to a byte array
            byte[] challengeBytes = Util.str2byte(challenge);

            // cipher the challenge with the private key
            byte[] cipherChallenge = AsymmetricCipher.encrypt(privateKey, KEY_ALGORITHM, challengeBytes);

            System.out.println("Cipher challenge: " + Util.byte2str(cipherChallenge));
            // send the cipher challenge to the client
            writer.println(Util.byte2str(cipherChallenge));

            // reads the symmetric key from the client and decrypt it with the private key
            String symmetricKey = reader.readLine();
            byte[] cipherSymmetricKey = Util.str2byte(symmetricKey);
            byte[] symmetricKeyBytes = AsymmetricCipher.decrypt(privateKey, KEY_ALGORITHM, cipherSymmetricKey);
            System.out.println("Symmetric key received: " + Util.byte2str(symmetricKeyBytes));

            // save the symmetric key to a variable
            secretKey = new SecretKeySpec(symmetricKeyBytes, 0, symmetricKeyBytes.length, ALGORITHM);

            System.out.println("Secret key generated: " + secretKey.getEncoded());
            // send the ACK to the client
            writer.println("ACK");

            // decrypt the message with the symmetric key
            String encryptedMessage = reader.readLine();
            System.out.println("Encrypted message received: " + encryptedMessage);
            byte[] cipherMessage = Util.str2byte(encryptedMessage);
            byte[] messageBytes = SymmetricCipher.decrypt(cipherMessage, secretKey);

            String name = new String(messageBytes, "UTF-8");
            System.out.println("Name received: " + name);

            // is the name on the list of packages?
            if(!isNameOnPackageList(name))
            {
                writer.println("ERROR");
                writer.close();
                System.out.println("Client disconnected");
                socketClient.close();
                throw new Exception("Client not found");
            }
            writer.println("ACK");

            // reads the ciphered message from the client tha contains the package id
            String cipherIdPackage = reader.readLine();
            System.out.println("Package id received: " + cipherIdPackage);
            byte[] bytesCipherIdPackage = Util.str2byte(cipherIdPackage);
            byte[] idPackageBytes = SymmetricCipher.decrypt(bytesCipherIdPackage, secretKey);

            String idPackage= new String(idPackageBytes, "UTF-8");

            System.out.println("Package id decrypted: " + idPackage);

            // get the package from the list
            Package p = getPackage(Integer.parseInt(idPackage));
            if (p == null || !p.nameClient().equals(name)) {
                System.out.println("Client "+p.nameClient()+" does not match package "+idPackage);
                System.out.println("The owner of the package is: " + p.nameClient());
                System.out.println("Client disconnected");
                writer.println("ERROR");
                writer.close();
            }

            // return the state of the package cipher with the symmetric key
            writer.println(Util.byte2str(SymmetricCipher.encrypt(p.getState().getBytes("UTF8"), secretKey)));

            // get the ACK from the client
            String ack = reader.readLine();
            System.out.println("ACK received: " + ack);
            if(!ack.equals("ACK"))
            {
                writer.println("ERROR");
                writer.close();
                System.out.println("Client disconnected");
                socketClient.close();
                throw new Exception("Client not found");
            }

            // send digest to the client with SHA-256
            Mac sha256 = Mac.getInstance("HmacSHA256");
            sha256.init(secretKey);
            byte[] digest = sha256.doFinal((name+idPackage).getBytes("UTF8"));
            writer.println(Util.byte2str(digest));

            // read the final response from the client
            String finalResponse = reader.readLine();
            System.out.println("Final response received: " + finalResponse);
            System.out.println("Client disconnected");
            writer.close();
            socketClient.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) {
        ServerSocket serverSocket;
        try {
            serverSocket = new ServerSocket(PORT);
            Socket socketClient = serverSocket.accept();
            new Server(socketClient).run();
            serverSocket.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}