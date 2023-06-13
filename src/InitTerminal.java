import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.*;

public class InitTerminal {
    public TerminalMasterKeyCerts terminalMasterKeyCerts = TerminalMasterKeyCerts.getInstance();
    private KeyGenerator keyGenerator = new KeyGenerator();
    private SignAndVerify signAndVerify = new SignAndVerify();
    private KeyPair cardKeyPair;
    public short cardNumber = (short) 12345;
    public short cardExpiry = (short) 1030;
    public short cardPIN = (short) 5678;
    byte [] cardCertificate = new byte[292];
    byte [] cardTag = new byte[300];
    byte [] cardNumberBytes = new byte [2];
    //byte [] cardPublicKey = new byte[162];
    byte [] cardDetails = new byte[256];

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;


    private static byte CARD = (byte)0x01;

    public void generateKeyPairForCard() {    
        try {
            cardKeyPair = keyGenerator.getKeyPair();
            publicKey = (RSAPublicKey) cardKeyPair.getPublic();
            privateKey = (RSAPrivateKey) cardKeyPair.getPrivate();            
        } catch (Exception exc) {
            System.out.println(exc.getMessage());
            System.exit(-1); 
        }
    }

    public void generateCardCerts() {
        byte [] valuesToBeSigned = new byte[256];
        valuesToBeSigned[0] = (byte)cardNumber;
        valuesToBeSigned[1] = (byte) cardExpiry;
        valuesToBeSigned[2] = CARD;
        System.arraycopy(valuesToBeSigned, 0, cardDetails, 0, valuesToBeSigned.length);
        System.arraycopy(publicKey.getEncoded(), 0, valuesToBeSigned, 3, publicKey.getEncoded().length);
        try {
            cardTag = signAndVerify.sign(terminalMasterKeyCerts.masterPrivateKey, valuesToBeSigned);
            
           // System.arraycopy(tag, 0, cardCertificate, 0, tag.length);
            //System.arraycopy(valuesToBeSigned, 0, cardCertificate, tag.length, 164);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }
    
    public byte [] getCardPublicKeyExponent() { 
        byte [] exponent = publicKey.getPublicExponent().toByteArray();
        return exponent;
    }

    public byte [] getCardPrivateKeyExponent() { 
        byte [] exponent = privateKey.getPrivateExponent().toByteArray();
        return exponent;
    }

    public byte [] getCardPublicKeyModulo() {
        byte [] modulo = publicKey.getModulus().toByteArray();
        return modulo;
    }

    public byte [] getCardPrivateKeyModulo() {
        byte [] modulo = privateKey.getModulus().toByteArray();
        return modulo;
    }

    public byte [] getBytesForShort(short value) {
        byte [] tempBytes = new byte[2];
        tempBytes[0] = (byte) (value & 0xff);
        tempBytes[1] = (byte) ((value >> 8) & 0xff);
        return tempBytes;
    }
}
