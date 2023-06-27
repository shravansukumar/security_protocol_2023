import java.nio.charset.StandardCharsets;

import javax.print.attribute.standard.MediaSize.ISO;
import javax.smartcardio.CommandAPDU;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/*
 * Things to be persisted: balance, bruteForceCunter, PIN, state
 * Certificate: number, public key, expiry, cert_type: (card, terminal)
 * 
 */

public class CardApplet extends Applet {
    private static final byte DUMMY = (byte) 0x52;
    private static final byte INIT = (byte) 0x55;
    private byte[] test3;

    // Card details
    private short cardNumber;
    private short cardExpiry;
    private short cardPIN;
    private short bruteForceCounter;
    private short cardBalance;
    private byte cardState;
    private short randomNumber1;
    private Signature signature;

    private RandomData rng;
    private byte[] randomBuffer;

    OwnerPIN pin = new OwnerPIN((byte) 3, (byte) 6);

    // Variable for reciveding the buffer data

    private byte[] receivedData;

    // variables for reciving certificates
    private short totalLength = 312;
    private short offset = 0;

    // Card States
    private static final byte CARD_READY_TO_USE = (byte) 0x90;
    private static final byte CARD_BLOCKED = (byte) 0x91;

    private static byte POS_RELOAD_TERMINAL = (byte) 0x02;

    RSAPublicKey publicKey;
    RSAPrivateKey privateKey;
    RSAPublicKey terminaPublicKey;
    RSAPublicKey masterPublicKey;

    byte[] temporaryBuffer;
    byte[] cardTag;
    byte[] terminalMasterTag;
    byte[] terminalTag;
    byte[] terminalValuesToBeVerified;

    // Init terminal stuff
    private static final byte INIT_PUB_EXP = (byte) 0x10;
    private static final byte INIT_PUB_MOD = (byte) 0x11;
    private static final byte INIT_PRV_EXP = (byte) 0x12;
    private static final byte INIT_PRV_MOD = (byte) 0x13;
    private static final byte INIT_CARD_NUMBER = (byte) 0x14;
    private static final byte INIT_CARD_EXPIRY = (byte) 0x15;
    private static final byte INIT_CARD_TAG = (byte) 0x16;
    private static final byte INIT_MASTER_TERMINAL_TAG = (byte) 0x17;
    private static final byte INIT_CARD_PIN = (byte) 0x18;
    private static final byte INIT_MASTER_PUB_EXP = (byte) 0x80;
    private static final byte INIT_MASTER_PUB_MOD = (byte) 0x81;

    // Mutual Auth stuff
    private static final byte MUTUAL_AUTH_RN = (byte) 0x19;
    private static final byte MUTUAL_AUTH_TERMINAL_TAG = (byte) 0x20;
    private static final byte MUTUAL_AUTH_TERMINAL_PUBLIC_KEY_EXPONENT = (byte) 0x21;
    private static final byte MUTUAL_AUTH_TERMINAL_PUBLIC_KEY_MODULO = (byte) 0x22;
    private static final byte MUTUAL_AUTH_TERMINAL_CERT_VALUES = (byte) 0x24;

    // Init terminal stuff
    private static final byte INIT_MASTER_CERT = (byte) 0x23;

    protected CardApplet() {
        register();

        terminalValuesToBeVerified = JCSystem.makeTransientByteArray((short) 100, JCSystem.CLEAR_ON_DESELECT);
        temporaryBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        masterPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512,
                false);
        publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        terminaPublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512,
                false);
        cardTag = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        terminalMasterTag = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        terminalTag = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        receivedData = JCSystem.makeTransientByteArray((short) 312, JCSystem.CLEAR_ON_DESELECT);
        randomNumber1 = (short) 0;
        // Random number
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        randomBuffer = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        // Signature stuff
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws SystemException {
        new CardApplet();
    }

    @Override
    public boolean select() {
        // To choose this applet!
        return true;
    }

    @Override
    public void deselect() {
        // Do anything to clear stuff
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();
        short length = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0x00FF);

        try {
            switch (apduBuffer[ISO7816.OFFSET_INS]) {
                case DUMMY:
                    byte[] helloBack = "hello".getBytes();
                    apdu.setOutgoingAndSend((short) 0, (short) helloBack.length);
                    System.out.println("Hello from dummy message");
                    break;

                case INIT_MASTER_CERT:
                    short chunkLength = apdu.setIncomingAndReceive();
    
                    System.arraycopy(apduBuffer, ISO7816.OFFSET_CDATA, receivedData, offset, chunkLength);
                    offset += chunkLength;
                    if (offset >= totalLength) {
                        // All chunks have been received, process the complete data
                        // Reset the offset and totalLength for the next data transfer
                        offset = 0;
                        totalLength = 0;
                    }
                    System.out.println("Got the master cert");
                    break;

                case INIT_MASTER_PUB_EXP:
                    System.out.println("Got the master public exponent");
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    masterPublicKey.setExponent(temporaryBuffer, (short) 0, length);
                    break;

                case INIT_MASTER_PUB_MOD:
                    System.out.println("Got the master pubic modulus");
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    masterPublicKey.setModulus(temporaryBuffer, (short) 0, length);
                    break;

                case INIT_PUB_EXP:
                    System.out.println("Got the public exponent");
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    publicKey.setExponent(temporaryBuffer, (short) 0, length);
                    break;

                case INIT_PUB_MOD:
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    publicKey.setModulus(temporaryBuffer, (short) 0, length);
                    System.out.println("Got the public mod");
                    break;

                case INIT_PRV_EXP:
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    privateKey.setExponent(temporaryBuffer, (short) 0, length);
                    System.out.println("Got the priv exp");
                    break;

                case INIT_PRV_MOD:
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    privateKey.setModulus(temporaryBuffer, (short) 0, length);
                    System.out.println("Got the priv mod");
                    break;

                case INIT_CARD_NUMBER:
                    getCardNumber(apdu);
                    System.out.println(cardNumber);
                    System.out.println("Got the card number");
                    break;

                case INIT_CARD_EXPIRY:
                    getCardExpiry(apdu);
                    System.out.println(cardExpiry);
                    System.out.println("Got the card expiry");
                    break;

                case INIT_CARD_TAG:
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    Util.arrayCopy(temporaryBuffer, (short) 0, cardTag, (short) 0, length);
                    break;

                case INIT_MASTER_TERMINAL_TAG:
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    Util.arrayCopy(temporaryBuffer, (short) 0, terminalMasterTag, (short) 0, length);
                    break;

                case INIT_CARD_PIN:
                    // setCardPIN(apdu);
                    System.out.println("Got stuff for card pin");
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    pin.update(temporaryBuffer, (short) 0, (byte) length);
                    bruteForceCounter = (short) 0;
                    cardBalance = (short) 0;
                    cardState = CARD_READY_TO_USE;
                    break;

                case MUTUAL_AUTH_RN:
                    System.out.println("hello from mutual auth");
                    randomNumber1 = Util.makeShort(apduBuffer[ISO7816.OFFSET_CDATA + 1],
                            apduBuffer[ISO7816.OFFSET_CDATA]);
                    System.out.println(randomNumber1);
                    break;

                case MUTUAL_AUTH_TERMINAL_TAG:
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    Util.arrayCopy(temporaryBuffer, (short) 0, terminalTag, (short) 0, length);
                    break;

                case MUTUAL_AUTH_TERMINAL_PUBLIC_KEY_EXPONENT:
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    terminaPublicKey.setExponent(temporaryBuffer, (short) 0, length);
                    break;

                case MUTUAL_AUTH_TERMINAL_PUBLIC_KEY_MODULO:
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    terminaPublicKey.setModulus(temporaryBuffer, (short) 0, length);
                    // generateRandomNumber();
                    System.out.println(randomBuffer);
                    break;

                case MUTUAL_AUTH_TERMINAL_CERT_VALUES:
                    handleIncomingAPDU(apdu, temporaryBuffer, (short) 0, length);
                    Util.arrayCopy(temporaryBuffer, (short) 0, terminalValuesToBeVerified, (short) 0, length);
                    // Verify terminal tag
                    verifyTerminalCerts(terminalValuesToBeVerified, masterPublicKey);
                    break;

                default:
                    System.out.println(apduBuffer[ISO7816.OFFSET_INS]);
                    break;
            }
        } catch (ISOException expet) {
            System.out.println(expet.toString());
        }
    }

    private void handleIncomingAPDU(APDU apdu, byte[] destination, short offset, short length) {
        byte[] buffer = apdu.getBuffer();
        short readCount = apdu.setIncomingAndReceive();
        short i = 0;
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, destination, offset, length);
    }

    private void getCardNumber(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        cardNumber = Util.makeShort(buffer[ISO7816.OFFSET_CDATA + 1], buffer[ISO7816.OFFSET_CDATA]);
        // cardExpiry = (short) buffer[ISO7816.OFFSET_CDATA+1];
        // Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, cardNumber, (short) 0, (short)
        // 1);
    }

    private void getCardExpiry(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        cardExpiry = Util.makeShort(buffer[ISO7816.OFFSET_CDATA + 1], buffer[ISO7816.OFFSET_CDATA]);
        // cardExpiry = (short) buffer[ISO7816.OFFSET_CDATA+1];
        // Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, cardNumber, (short) 0, (short)
        // 1);
    }

    private void generateRandomNumber() {
        rng.generateData(randomBuffer, (short) 0, (short) 1);
    }

    private void verifyTerminalCerts(byte[] values, RSAPublicKey publicKey) {
        System.out.println(publicKey);
        signature.init(masterPublicKey, Signature.MODE_VERIFY);

        // signature.update(arg0, arg1, arg2);
        boolean isVerified = signature.verify(values, (short) 0, (short) values.length, terminalTag, (short) 0,
                (short) terminalTag.length);
        if (isVerified) {
            System.out.println("Signature verified");
            // Handle rn gen, signing and enc
            generateRandomNumber();

        } else {
            // Break exec chain..
            System.out.println("Signature NOT verified");
        }
    }

    private void handleIncomingBytesToShort(APDU apdu, short destination) {
        byte[] buffer = apdu.getBuffer();
        destination = Util.makeShort(buffer[ISO7816.OFFSET_CDATA + 1], buffer[ISO7816.OFFSET_CDATA]);
    }

    private void setCardPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        cardPIN = Util.makeShort(buffer[ISO7816.OFFSET_CDATA + 1], buffer[ISO7816.OFFSET_CDATA]);
    }

    private void readBuffer(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        if (byteRead != 5) {
            System.out.println("something");
        }
        short i = 0;
        byte[] testMessage;
        while (i < numBytes) {

        }

        byte[] message;
        // String newMsg = new String(message, StandardCharsets.UTF_8);

        // System.out.println("" + message);
    }

    private void readBuffer(APDU apdu, byte[] dest, short offset, short length) {
        byte[] buffer = apdu.getBuffer();
        short readCount = apdu.setIncomingAndReceive();
        short i = 0;
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, dest, offset, readCount);
        String random = new String(test3, StandardCharsets.UTF_8);
        // System.out.println(random);
        // apdu.setOutgoingAndSend((short) 999,(short) 3);
        // while (i <= length) {
        // i += readCount;
        // offset += readCount;
        // readCount = (short) apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        // Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, dest, offset, readCount);
        // }
        // String random2 = new String(test3, StandardCharsets.UTF_8);
        // System.out.println(random2);
    }
}
