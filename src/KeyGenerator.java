import java.security.*; 
import java.security.interfaces.*;


public class KeyGenerator {

    public KeyPair getKeyPair() throws Exception, NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(512);
            KeyPair keypair = generator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey)keypair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey)keypair.getPrivate();
            printStuff(publicKey);
            printStuff(privateKey);
        return keypair;
    }

    private void printStuff(Key key) {
        System.out.println(key);
    }
}
