import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;
import javacard.framework.SystemException;


public class POSTerminalApp {

  private CardSimulator simulator;
  static final byte[] APPLET_AID = { (byte) 0x3B, (byte) 0x29,
    (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };
  final static byte[] pin = {'1', '2', '3', '4'};

  void run() {
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

  void runApp()  {
    System.out.println("Do awesome stuff inside");
  }
}
