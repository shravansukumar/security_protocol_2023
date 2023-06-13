
public class Utils {
    public byte [] getBytesForShort(short value) {
        byte [] tempBytes = new byte[2];
        tempBytes[0] = (byte) (value & 0xff);
        tempBytes[1] = (byte) ((value >> 8) & 0xff);
        return tempBytes;
    }
}