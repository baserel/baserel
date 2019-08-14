
package core;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

public class WriteNReadSpeedTest {

    public static JSONObject DATA = new JSONObject();

    public static void main(String[] args) throws Exception {

        long end;
        long start;

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

        for (int i = 0; i < 1000000; i++) {
            DATA.put("K" + i, "V" + i);
        }

        end = System.currentTimeMillis();

        System.out.println("Looping and putting took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        BufferedWriter bw = null;

        start = System.currentTimeMillis();

        try {
            //Specify the file name and path here
            File file = new File("junk.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(DATA.toString());

        } catch (IOException ioe) {
            ioe.printStackTrace();
        } finally {
            try {
                if (bw != null)
                    bw.close();
            } catch (Exception ex) {
                System.out.println("Error in closing the BufferedWriter" + ex);
            }
        }

        end = System.currentTimeMillis();

        System.out.println("Writting took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        StringBuilder contentBuilder = new StringBuilder();

        start = System.currentTimeMillis();

        try (Stream<String> stream = Files.lines(Paths.get("junk.txt"), StandardCharsets.UTF_8)) {
            stream.forEach(s -> contentBuilder.append(s));
        } catch (IOException e) {
            e.printStackTrace();
        }
        DATA = new JSONObject(contentBuilder.toString());

        end = System.currentTimeMillis();

        System.out.println("Reading took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

        JSONArray keys = DATA.names();

        for (int i = 0; i < keys.length(); ++i) {

            String key = keys.getString(i); // Here's your key
            DATA.put(key, "0");

        }

        end = System.currentTimeMillis();

        System.out.println("Iterating readed took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        bw = null;

        start = System.currentTimeMillis();

        try {
            //Specify the file name and path here
            File file = new File("junk_2.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(DATA.toString());

        } catch (IOException ioe) {
            ioe.printStackTrace();
        } finally {
            try {
                if (bw != null)
                    bw.close();
            } catch (Exception ex) {
                System.out.println("Error in closing the BufferedWriter" + ex);
            }
        }

        end = System.currentTimeMillis();

        System.out.println("Writting took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

    }

}
