package caso3infracomp;


public class Util {

    public static String byte2str(byte[] bytes) {
        String result = "";
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 0xFF);
            result += (hex.length() == 1 ? "0" : "") + hex;
        }
        return result;
    }

    public static byte[] str2byte(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(str.substring(i * 2, (i) * 2 + 2), 16);
        }
        return bytes;
    }

}
