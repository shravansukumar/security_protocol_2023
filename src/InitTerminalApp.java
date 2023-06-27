
import com.licel.jcardsim.smartcardio.CardSimulator;

import javacard.framework.AID;
import javacard.framework.SystemException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import javax.smartcardio.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


public class InitTerminalApp {

    private CardSimulator simulator;
    public TerminalMasterKeyCerts terminalMasterKeyCerts;

    private CertificateBuilderPure certificateBuilderPure;
    private KeyGenerator keyGenerator;
    private byte [] masterCert;
    private byte [] cardCert;
    KeyPair mastKeyPair;
    KeyPair cardKeyPair;

    private State state = State.Init;

    private static final byte DUMMY = (byte) 0x52;
    
    // INIT Terminal stuff
    private static final byte INIT_MASTER_CERT = (byte) 0x23;

    final static byte[] pin = {'1', '2', '3', '4'}; 
    static final byte[] APPLET_AID = { (byte) 0x3B, (byte) 0x29,
        (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };

    public InitTerminalApp() {
        certificateBuilderPure = new CertificateBuilderPure();
        keyGenerator = new KeyGenerator();
    }


    // Function to prepare data for sending it to the card
    private void prepareAndtransmitDataToCard() {
        try {
         //   keyGenerator.generateMasterKeyPair();

            this.mastKeyPair = keyGenerator.retreiveMasterKeyPair();
            this.cardKeyPair = keyGenerator.getKeyPairForCard();

            ECPrivateKey masterPrivateKey = (ECPrivateKey) mastKeyPair.getPrivate();
            ECPublicKey masterPublicKey = (ECPublicKey) mastKeyPair.getPublic();

            this.masterCert = certificateBuilderPure.generateCertificate(masterPublicKey, masterPrivateKey, "12345", "MASTER");
         //   this.cardCert = certificateBuilderPure.generateCertificate((ECPublicKey)cardKeyPair.getPublic(), masterPrivateKey, "12345", "CARD");

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException |  InvalidKeyException | NoSuchProviderException | SignatureException | CertificateException | NullPointerException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }

    private void runInitTermainalApp() {
        prepareAndtransmitDataToCard();

        int offset = 0;
        int length = masterCert.length;
        int maxPayloadSize = 255;

        while (length > 0) {
            int chunkSize = Math.min(length, maxPayloadSize);
            byte [] tempArray = Arrays.copyOfRange(masterCert, offset, offset+chunkSize);
            // send stuff 
            prepareAndSendData(tempArray, INIT_MASTER_CERT);
            offset += chunkSize;
            length -= chunkSize;
        }
    }

    public static void main(String[] args) throws Exception {
        // First point of entry
        InitTerminalApp initTerminalApp = new InitTerminalApp();
       // POSTerminalApp  posTerminalApp = new POSTerminalApp();
        State state_test = State.Init;
        
        switch (state_test) {
            case Init:
            System.out.println("Entered init state");
            initTerminalApp.run();
            initTerminalApp.runInitTermainalApp(); 
            break;
            
            case POS:
            System.out.println("Entered POS state"); 
            //posTerminalApp.run();
            break;

            default:
            System.out.println("Entered default state");
            break;

        }
    }

    private void run() {
        System.out.println("***************** Entering run ****************");
        simulator = new CardSimulator();
        AID appletAID = new AID(APPLET_AID, (byte)0, (byte)7); //AIDUtil.create(APPLET_AID);
        try {
            simulator.installApplet(appletAID, CardApplet.class, pin, (short)0, (byte)0);
            simulator.selectApplet(appletAID);
        } catch (SystemException e) {
            e.printStackTrace();
        }
    }

    private void prepareAndSendData(byte [] data, byte commandType) {
        System.out.println("size of blocks: "+ data.length);
        CommandAPDU initCommand = new CommandAPDU(0, commandType, 0, 0, data);
        ResponseAPDU initResponse = transmit(initCommand);
        System.out.println(initResponse);

    }

    private ResponseAPDU transmit(CommandAPDU commandAPDU) {
        System.out.println("Terminal: Sending Command");
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
       // processDummyMessage(response);
        return response;
    }


    private void processDummyMessage(ResponseAPDU response) {
        byte [] responseData = response.getData();
        String repsString = new String(responseData);
        System.out.println(repsString);
    }
}

