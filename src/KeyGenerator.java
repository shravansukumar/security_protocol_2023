import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*; 
import java.security.interfaces.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.encoders.Base64;


public class KeyGenerator {

    private static String publicKeyFilePath = "MasterPublicKey.pem";
    private static String privateKeyFilePath = "MasterPrivateKey.pem";


    public void generateMasterKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keypair = generator.generateKeyPair();
        saveMasterKeyPair(keypair);
    }

    private void saveMasterKeyPair(KeyPair keypair) {
        ECPublicKey publicKey = (ECPublicKey) keypair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keypair.getPrivate();

        // We get the encoded keys in string for base 64
        String encodedPublicKeyString = Base64.toBase64String(publicKey.getEncoded());
        String encodedPrivateString = Base64.toBase64String(privateKey.getEncoded());

        // Format it to PEM content type
        String publicKeyPEMString = "-----BEGIN " + "PUBLIC KEY" + "-----\n" + encodedPublicKeyString + "\n-----END " + "PUBLIC KEY" + "-----";
        String privateKeyPEMString = "-----BEGIN " + "PRIVATE KEY" + "-----\n" + encodedPrivateString + "\n-----END " + "PRIVATE KEY" + "-----";
        
        // Getting the path to save the keys
        Path publicKeyPath = Paths.get(publicKeyFilePath);
        Path PrivateKeyPath = Paths.get(privateKeyFilePath);

        // Saving keys to the disk
        try {
            Files.write(publicKeyPath, publicKeyPEMString.getBytes());
            Files.write(PrivateKeyPath, privateKeyPEMString.getBytes());
        } catch (IOException exception) {
            System.out.println("Error in saving key to disk");
            System.out.println(exception.getMessage());
        }
    }

    public KeyPair retreiveMasterKeyPair() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

            // Read contents from PEM file
            byte [] publicKeyPEMContentsBytes = Files.readAllBytes(Paths.get(publicKeyFilePath));
            byte [] privateKeyPEMContentsBytes = Files.readAllBytes(Paths.get(privateKeyFilePath));

            // Convert bytes to string
            String publicKeyPEMString = new String(publicKeyPEMContentsBytes);
            String privateKeyPEMString = new String(privateKeyPEMContentsBytes);
            
            // Read the keys from the extracted string
            String publicKeyEncodedKey = publicKeyPEMString.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", ""); 
            
            String privateKeyEncodedKey = privateKeyPEMString.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");


            // Decode the String into base 64 bytes
            byte [] publicKeyDecoded = Base64.decode(publicKeyEncodedKey);
            byte [] privateKeyDecoded = Base64.decode(privateKeyEncodedKey);

            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyDecoded);
            ECPublicKey masterPublicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyDecoded);
            ECPrivateKey masterPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            KeyPair mastKeyPair = new KeyPair(masterPublicKey, masterPrivateKey);

            return mastKeyPair;

        // try {
        //     generateMasterKeyPair();
        // } catch (NoSuchAlgorithmException exception) {
        //     System.out.println("Used wrong algo for generating master key pair");
        //     System.out.println(exception.getMessage());
        //     System.exit(-2);
        // }

    }

    public KeyPair getKeyPairForCard() throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            KeyPair keypair = generator.generateKeyPair();
            return keypair;
    }

    public KeyPair getKeyPair() throws Exception, NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(256);
            KeyPair keypair = generator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey)keypair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey)keypair.getPrivate();
        return keypair;
    }


}
