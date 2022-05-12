package caso3infracomp;

import java.io.FileWriter;

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

    public static void writeLog(String logFileAsymmetrictTime, String string, long l) {
        try {
            FileWriter fw = new FileWriter(logFileAsymmetrictTime, true);
            // get the current date time in the format of yyyy-MM-dd HH:mm:ss
            String date = new java.util.Date().toString();
            // convert l to seconds 
            double seconds = (double) l / 1000000000;
            // show full decimal places
            String time = String.format("%.11f", seconds);
            // write the date and time to the log file
            fw.write(date + " " + string + " " + time + "\n");
            fw.close();
        } catch (Exception e) {
            System.out.println("Error writing to log file: " + e.getMessage());
        }
    }

}
