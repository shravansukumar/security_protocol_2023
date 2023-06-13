import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.*;

public class TerminalMasterKeyCerts {
    // master terminal keypair
    public RSAPrivateKey masterPrivateKey;
    public RSAPublicKey masterPublicKey;

    // reload/POS terminal keypair
    public RSAPrivateKey terminalPrivateKey;
    public RSAPublicKey terminalPublicKey;

    private KeyGenerator keyGenerator;
    private SignAndVerify signAndVerify;

    private static TerminalMasterKeyCerts instance = null;

    private static byte INIT_TERMINAL = (byte)0x01;
    private static byte POS_RELOAD_TERMINAL = (byte) 0x02;

    byte [] certificate = new byte[1000];
    byte [] masterTag = new byte[256];
    byte [] otherDetails = new byte[2];
    byte [] terminalOtherDetails = new byte[2];
    byte [] terminalTag = new byte [256];
    byte [] masterValuesToBeSigned = new byte [256];
    byte [] terminalValuesToBeSigned = new byte [100];

    private TerminalMasterKeyCerts() {
        keyGenerator = new KeyGenerator();
        signAndVerify = new SignAndVerify();
        // master key pair and certs
        generateMasterKeyPairs();
        generateMasterCerts();
        // terminal key pair and certs
        generateTerminalKeyPairs();
        generateTerminalCerts();
        testVerify();
    }

    // This is for the master terminal
    private void generateMasterKeyPairs() {
        try {
            KeyPair keyPair = keyGenerator.getKeyPair();
            masterPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            masterPublicKey = (RSAPublicKey) keyPair.getPublic();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }

    // This is for the reload/POS terminal 
    /* :::DANGER ZONE:::
     * Please do not get confused between the master terminal keypairs/certs and the reload/POS key pair/certs.
     * They are different entities. We use the master terminal for signing the subsequent keys/certs.
     * I know, its confusing af!
     */
    private void generateTerminalKeyPairs() {
        try {
            KeyPair terminalKeyPair = keyGenerator.getKeyPair();
            terminalPrivateKey = (RSAPrivateKey) terminalKeyPair.getPrivate();
            terminalPublicKey = (RSAPublicKey) terminalKeyPair.getPublic();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }

    private void generateMasterCerts() {
        byte [] valuesToBeSigned = new byte[100];

        /*
         *  After careful delibration, me and ankit decided to that the master certificate would only have the master public key signed by the private key. 
         */
        // masterValuesToBeSigned[0] = (short)1;
        // masterValuesToBeSigned[1] = INIT_TERMINAL;

        /*
         * This following is commented for now. Idk why I was copying stuff into another array. The other details array I am not using it anywhere. Same for the terminal certs, I am removing it.
         */

        //System.arraycopy(valuesToBeSigned, 0, otherDetails, 0, 2);

         System.arraycopy(masterPublicKey.getPublicExponent().toByteArray(), 0, masterValuesToBeSigned, 0, masterPublicKey.getPublicExponent().toByteArray().length);
         System.arraycopy(masterPublicKey.getModulus().toByteArray(), 0, masterValuesToBeSigned, masterPublicKey.getPublicExponent().toByteArray().length, masterPublicKey.getModulus().toByteArray().length);
        try {
            masterTag = signAndVerify.sign(masterPrivateKey, masterValuesToBeSigned);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }

    private void generateTerminalCerts() {
        terminalValuesToBeSigned[0] = (short) 2;
        terminalValuesToBeSigned[1] = POS_RELOAD_TERMINAL;
        //System.arraycopy(terminalValuesToBeSigned, 0, terminalOtherDetails, 0, 2);
        System.arraycopy(terminalPublicKey.getPublicExponent().toByteArray(), 0, terminalValuesToBeSigned, 2, terminalPublicKey.getPublicExponent().toByteArray().length);
        System.arraycopy(terminalPublicKey.getModulus().toByteArray(), 0, terminalValuesToBeSigned, terminalPublicKey.getPublicExponent().toByteArray().length+2, terminalPublicKey.getModulus().toByteArray().length);
        try {
            System.out.println(masterPublicKey);
            terminalTag = signAndVerify.sign(masterPrivateKey, terminalValuesToBeSigned);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }

    private void testVerify() {
        signAndVerify.verify(masterPublicKey, terminalTag, terminalValuesToBeSigned);
    }

    public byte [] getTerminalPublicKeyExponent() {
        return terminalPublicKey.getPublicExponent().toByteArray();
    }

    public byte [] getTerminalPublicModulo() {
        return terminalPublicKey.getModulus().toByteArray();
    }

    public byte [] getTerminalMasterPublicKeyExponent() {
        return masterPublicKey.getPublicExponent().toByteArray();
    }

    public byte [] getTerminalMasterPublicKeyModulus() {
        return masterPublicKey.getModulus().toByteArray();
    }
    
    public static TerminalMasterKeyCerts getInstance() {
        if (instance == null) {
            instance = new TerminalMasterKeyCerts();
        }
        return instance;
    }
}
