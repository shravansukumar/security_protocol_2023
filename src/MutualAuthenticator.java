import java.util.Random;

public class MutualAuthenticator {

   private TerminalMasterKeyCerts terminalMasterKeyCerts = TerminalMasterKeyCerts.getInstance();
   
   public MutualAuthenticator() {

   }

   public short generateRandomNumber() {
    Random random = new Random();
    short rand = (short) random.nextInt(255);
    return rand;
   }
}
