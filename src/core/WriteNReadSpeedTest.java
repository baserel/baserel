
package core;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

public class WriteNReadSpeedTest {

    public static JSONObject DATAJ = new JSONObject();
    static ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>> DATA = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>>();
    public static String CryptoKey = "BhQCDT5bmQtZHg2A";

    public static void main(String[] args) throws Exception {

        int records = 100000;

        //TestJSON(500000);
        //TestHashMap(500000);
        //TestHashMap(10000);
        //TestHashMap(1000);
        TestHashMapJSON(records);
        TestHashMapJSON(records);

    }

    public static void TestJSON(int records) throws Exception {
        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        System.out.println("JSON test started.\n");

        long end;
        long start;

        start = System.currentTimeMillis();

        for (int i = 0; i < records; i++) {
            DATAJ.put("" + i, new JSONObject());
            DATAJ.getJSONObject("" + i).put("K1", "V" + i);
            DATAJ.getJSONObject("" + i).put("K2", "Y" + i);
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
            File file = new File("junk_json_1.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(DATAJ.toString());

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

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        StringBuilder contentBuilder = new StringBuilder();

        start = System.currentTimeMillis();

        try (Stream<String> stream = Files.lines(Paths.get("junk_json_1.txt"), StandardCharsets.UTF_8)) {
            stream.forEach(s -> contentBuilder.append(s));
        } catch (IOException e) {
            e.printStackTrace();
        }
        DATAJ = new JSONObject(contentBuilder.toString());

        end = System.currentTimeMillis();

        System.out.println("Reading took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

        JSONArray keys = DATAJ.names();

        for (int i = 0; i < keys.length(); ++i) {

            String key = keys.getString(i); // Here's your key
            DATAJ.getJSONObject(key).put("K1", "0");

        }

        end = System.currentTimeMillis();

        System.out.println("Iterating read took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        bw = null;

        start = System.currentTimeMillis();

        try {
            //Specify the file name and path here
            File file = new File("junk_json_2.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(DATAJ.toString());

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

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");

        start = System.currentTimeMillis();

        engine.put("data", DATAJ);

        try {

            engine.eval("for(var id in data){data[id] = {};}");

        } catch (ScriptException e) {
            //e.printStackTrace();

            System.out.println("Script error catched: " + e.getMessage());
        }

        end = System.currentTimeMillis();

        System.out.println("Scripting took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        bw = null;

        start = System.currentTimeMillis();

        try {
            //Specify the file name and path here
            File file = new File("junk_json_3.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(DATAJ.toString());

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

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        bw = null;

        start = System.currentTimeMillis();

        try {
            //Specify the file name and path here
            File file = new File("junk_json_4.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(engine.get("data").toString());

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

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        System.out.println("JSON test finished.\n");
    }

    public static void TestHashMap(int records) throws Exception {
        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        System.out.println("HashMap test started.\n");

        long end;
        long start;

        start = System.currentTimeMillis();

        DATA.put("test", new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>());
        DATA.get("test").put("test", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());

        for (int i = 0; i < records; i++) {
            DATA.get("test").get("test").put("" + i, new ConcurrentHashMap<>());
            DATA.get("test").get("test").get("" + i).put("K1", "V" + i);
            DATA.get("test").get("test").get("" + i).put("K2", "Y" + i);
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

//        try {
//            FileOutputStream fos = new FileOutputStream("junk_hashmap_1.txt", false);
//            ObjectOutputStream oos = new ObjectOutputStream(fos);
//            oos.writeObject(DATA);
//            oos.close();
//            fos.close();
//        } catch (IOException ioe) {
//            ioe.printStackTrace();
//        }

        ObjectOutputStream oos = new ObjectOutputStream(new DeflaterOutputStream(new FileOutputStream("junk_hashmap_1.txt")));
        oos.writeObject(DATA);
        oos.close();

        end = System.currentTimeMillis();

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        StringBuilder contentBuilder = new StringBuilder();

        DATA = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>>();

        start = System.currentTimeMillis();

//        try {
//
//            FileInputStream fis = new FileInputStream("junk_hashmap_1.txt");
//            ObjectInputStream ois = new ObjectInputStream(fis);
//
//            DATA = (ConcurrentHashMap) ois.readObject();
//
//            ois.close();
//
//        } catch (IOException ioe) {
//            ioe.printStackTrace();
//            return;
//        } catch (Exception e) {
//            e.printStackTrace();
//            throw new Exception("Error trying to restore the database.");
//        }

        ObjectInputStream ois = new ObjectInputStream(new InflaterInputStream(new FileInputStream("junk_hashmap_1.txt")));
        DATA = (ConcurrentHashMap) ois.readObject(); // cast is needed.
        ois.close();

        end = System.currentTimeMillis();

        System.out.println("Reading took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

        for (Map.Entry<String, ConcurrentHashMap<String, String>> entry : DATA.get("test").get("test").entrySet()) {
            entry.getValue().put("K1", "0");
        }

        end = System.currentTimeMillis();

        System.out.println("Iterating read took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

//        try {
//            FileOutputStream fos = new FileOutputStream("junk_hashmap_2.txt", false);
//            ObjectOutputStream oos = new ObjectOutputStream(fos);
//            oos.writeObject(DATA);
//            oos.close();
//            fos.close();
//        } catch (IOException ioe) {
//            ioe.printStackTrace();
//        }

        ObjectOutputStream oos2 = new ObjectOutputStream(new DeflaterOutputStream(new FileOutputStream("junk_hashmap_2.txt")));
        oos2.writeObject(DATA);
        oos2.close();

        end = System.currentTimeMillis();

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");

        start = System.currentTimeMillis();

        engine.put("data", DATA.get("test").get("test"));

        try {

            engine.eval("for(var id in data){data[id].K2 = 0;}");

        } catch (ScriptException e) {
            //e.printStackTrace();

            System.out.println("Script error catched: " + e.getMessage());
        }

        end = System.currentTimeMillis();

        System.out.println("Scripting took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

//        try {
//            FileOutputStream fos = new FileOutputStream("junk_hashmap_3.txt", false);
//            ObjectOutputStream oos = new ObjectOutputStream(fos);
//            oos.writeObject(DATA);
//            oos.close();
//            fos.close();
//        } catch (IOException ioe) {
//            ioe.printStackTrace();
//        }

        ObjectOutputStream oos3 = new ObjectOutputStream(new DeflaterOutputStream(new FileOutputStream("junk_hashmap_3.txt")));
        oos3.writeObject(DATA);
        oos3.close();

        end = System.currentTimeMillis();

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

        try {
            //Specify the file name and path here
            File file = new File("junk_hashmap_4.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(engine.get("data").toString());

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

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        System.out.println("HashMap test finished.\n");
    }

    public static void TestHashMapJSON(int records) throws Exception {
        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        System.out.println("HashMap test started.\n");

        long end;
        long start;

        start = System.currentTimeMillis();

        DATA.put("test", new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>());
        DATA.get("test").put("test", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());

        for (int i = 0; i < records; i++) {
            DATA.get("test").get("test").put("" + i, new ConcurrentHashMap<>());
            DATA.get("test").get("test").get("" + i).put("K1", "V" + i);
            DATA.get("test").get("test").get("" + i).put("K2", "Y" + i);
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
            File file = new File("junk_hashmapjson_1.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(new JSONObject(DATA).toString());

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

        try {
            CryptoUtils.encrypt(CryptoKey, new File("junk_hashmapjson_1.txt"), new File("junk_hashmapjson_1.encrypt.txt"));
        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }

        end = System.currentTimeMillis();

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        StringBuilder contentBuilder = new StringBuilder();

        DATA = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>>();

        start = System.currentTimeMillis();

        try {
            CryptoUtils.decrypt(CryptoKey, new File("junk_hashmapjson_1.encrypt.txt"), new File("junk_hashmapjson_1.decrypt.txt"));
        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }

        try (Stream<String> stream = Files.lines(Paths.get("junk_hashmapjson_1.decrypt.txt"), StandardCharsets.UTF_8)) {
            stream.forEach(s -> contentBuilder.append(s));
        } catch (IOException e) {
            e.printStackTrace();
        }

        JSONObject temp_json = new JSONObject(contentBuilder.toString());

        JSONArray keys = temp_json.names();

        for (int i = 0; i < keys.length(); ++i) {

            String key = keys.getString(i); // Here's your key

            DATA.put(key, new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>());

            JSONArray keys2 = temp_json.getJSONObject(key).names();

            for (int i2 = 0; i2 < keys2.length(); ++i2) {

                String key2 = keys2.getString(i2); // Here's your key

                DATA.get(key).put(key2, new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());

                JSONArray keys3 = temp_json.getJSONObject(key).getJSONObject(key2).names();

                for (int i3 = 0; i3 < keys3.length(); ++i3) {

                    String key3 = keys3.getString(i3); // Here's your key

                    DATA.get(key).get(key2).put(key3, new ConcurrentHashMap<String, String>());

                    JSONArray keys4 = temp_json.getJSONObject(key).getJSONObject(key2).getJSONObject(key3).names();

                    for (int i4 = 0; i4 < keys4.length(); ++i4) {

                        String key4 = keys4.getString(i4); // Here's your key

                        DATA.get(key).get(key2).get(key3).put(key4, temp_json.getJSONObject(key).getJSONObject(key2).getJSONObject(key3).get(key4).toString());

                    }

                }

            }

        }

        end = System.currentTimeMillis();

        System.out.println("Reading took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

        for (Map.Entry<String, ConcurrentHashMap<String, String>> entry : DATA.get("test").get("test").entrySet()) {
            entry.getValue().put("K1", "0");
        }

        end = System.currentTimeMillis();

        System.out.println("Iterating read took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

        try {
            //Specify the file name and path here
            File file = new File("junk_hashmapjson_2.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(new JSONObject(DATA).toString());

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

        try {
            CryptoUtils.encrypt(CryptoKey, new File("junk_hashmapjson_2.txt"), new File("junk_hashmapjson_2.encrypt.txt"));
        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }

        end = System.currentTimeMillis();

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");

        start = System.currentTimeMillis();

        engine.put("data", DATA.get("test").get("test"));

        try {

            engine.eval("for(var id in data){data[id].K2 = 0;}");

        } catch (ScriptException e) {
            //e.printStackTrace();

            System.out.println("Script error catched: " + e.getMessage());
        }

        end = System.currentTimeMillis();

        System.out.println("Scripting took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

        try {
            //Specify the file name and path here
            File file = new File("junk_hashmapjson_3.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(new JSONObject(DATA).toString());

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

        try {
            CryptoUtils.encrypt(CryptoKey, new File("junk_hashmapjson_3.txt"), new File("junk_hashmapjson_3.encrypt.txt"));
        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }

        end = System.currentTimeMillis();

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        start = System.currentTimeMillis();

        try {
            //Specify the file name and path here
            File file = new File("junk_hashmap_4.txt");

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!file.exists()) {
                file.createNewFile();
            }

            FileWriter fw = new FileWriter(file);
            bw = new BufferedWriter(fw);
            bw.write(engine.get("data").toString());

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

        try {
            CryptoUtils.encrypt(CryptoKey, new File("junk_hashmapjson_3.txt"), new File("junk_hashmapjson_3.encrypt.txt"));
        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }

        end = System.currentTimeMillis();

        System.out.println("Writing took " + (end - start) + " ms");

        ///////////////
        ///////////////
        ///////////////
        ///////////////
        ///////////////

        System.out.println("HashMap test finished.\n");
    }

}