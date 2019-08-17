package core;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.apache.commons.lang.StringUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpServer;

public class server {

    //  TODO Defining vars

    private static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1); // Initializing scheduler

    static boolean API_FIRST_RUN = true;
    static boolean API_GRACEFUL_SHUTDOWN = false;
    static boolean API_WRITTING_DATA = false;
    static boolean API_STARTED = false;
    static String API_CRYPTO_KEY = "h6Ka4p69Yp7t6CmW";
    static String API_OUTPUT_DATA_PATH = "bsrldb/data.bsrldb";
    static String API_OUTPUT_JUNK_PATH = "bsrldb/junk.bsrldb";
    static String API_CORE_KEY = "ntiqfki5h28HaVd2eycytwHZn4ooQmRmsU4tQx2y3g7aZCoE8CFbvEWT2omjDjj4"; // System Key to validate ADM commands
    static ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>> DATA = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>>();
    static JSONObject JDATA;
    static boolean API_EXPERIMENTAL = true; // Disable ADM API Auth and show additional information while an error
    static Map<String, String> API_MESSAGES = new HashMap<String, String>();
    static int API_OUTPUT_DATA_COUNTER = 0;
    static int API_OUTPUT_DATA_MAX_COUNTER = 10;
    /**
     * @param args
     */

    public static void main(String[] args) throws Exception {

        try {

            System.out.println("Starting server...");

            // setup the socket address
            InetSocketAddress address = new InetSocketAddress(8000);

            // initialise the HTTPS server
            //HttpsServer httpsServer = HttpsServer.create(address, 0);
            HttpServer httpsServer = HttpServer.create(address, 0);

            /*SSLContext sslContext = SSLContext.getInstance("TLS");

            // initialise the keystore
            char[] password = "password".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream("testkey.jks");
            ks.load(fis, password);

            // setup the key manager factory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password);

            // setup the trust manager factory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ks);

            // setup the HTTPS context and parameters
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {
                        // initialise the SSL context
                        SSLContext context = getSSLContext();
                        SSLEngine engine = context.createSSLEngine();
                        params.setNeedClientAuth(false);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        params.setProtocols(engine.getEnabledProtocols());

                        // Set the SSL parameters
                        SSLParameters sslParameters = context.getSupportedSSLParameters();
                        params.setSSLParameters(sslParameters);

                    } catch (Exception ex) {
                        System.out.println("Failed to create HTTPS port");
                    }
                }
            });*/
            // TODO Handlers contexts
            httpsServer.createContext("/test", new TestHandler());
            httpsServer.createContext("/adm", new AdmHandler());
            httpsServer.createContext("/put", new PutHandler());
            httpsServer.createContext("/get", new GetHandler());
            httpsServer.createContext("/del", new DelHandler());
            httpsServer.createContext("/cmd", new CmdHandler());
            httpsServer.setExecutor(null); // creates a default executor
            httpsServer.start();

            // TODO Preparing database
            System.out.println("Preparing database...");

            //Making Ser dir
            new File("bsrldb").mkdir();

            File f = new File(API_OUTPUT_DATA_PATH);
            if (f.isFile() && f.canRead()) {

//                try{
//
//                    FileInputStream fis = new FileInputStream(API_OUTPUT_DATA_PATH);
//                    ObjectInputStream ois = new ObjectInputStream(fis);
//
//                    DATA = (ConcurrentHashMap) ois.readObject();
//
//                    ois.close();
//
//                    API_FIRST_RUN = false;
//
//                } catch(IOException ioe)
//                {
//                    ioe.printStackTrace();
//                    return;
//                }catch(Exception e){
//                    e.printStackTrace();
//                    throw new Exception("Error trying to restore the database.");
//                }
                StringBuilder contentBuilder = new StringBuilder();

                try {
                    CryptoUtils.decrypt(API_CRYPTO_KEY, new File(API_OUTPUT_DATA_PATH), new File(API_OUTPUT_JUNK_PATH));
                } catch (CryptoException ex) {
                    System.out.println(ex.getMessage());
                    ex.printStackTrace();
                }

                try (Stream<String> stream = Files.lines(Paths.get(API_OUTPUT_JUNK_PATH), StandardCharsets.UTF_8)) {
                    stream.forEach(s -> contentBuilder.append(s));
                } catch (IOException e) {
                    e.printStackTrace();
                }

                JSONObject junk_json = new JSONObject(contentBuilder.toString());

                JSONArray keys = junk_json.names();

                for (int i = 0; i < keys.length(); ++i) {

                    String key = keys.getString(i); // Here's your key

                    DATA.put(key, new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>());

                    JSONArray keys2 = junk_json.getJSONObject(key).names();

                    if(keys2 != null){

                        for (int i2 = 0; i2 < keys2.length(); ++i2) {

                            String key2 = keys2.getString(i2); // Here's your key

                            DATA.get(key).put(key2, new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());

                            JSONArray keys3 = junk_json.getJSONObject(key).getJSONObject(key2).names();

                            if(keys3 != null){

                                for (int i3 = 0; i3 < keys3.length(); ++i3) {

                                    String key3 = keys3.getString(i3); // Here's your key

                                    DATA.get(key).get(key2).put(key3, new ConcurrentHashMap<String, String>());

                                    JSONArray keys4 = junk_json.getJSONObject(key).getJSONObject(key2).getJSONObject(key3).names();

                                    if(keys4 != null){

                                        for (int i4 = 0; i4 < keys4.length(); ++i4) {

                                            String key4 = keys4.getString(i4); // Here's your key

                                            DATA.get(key).get(key2).get(key3).put(key4, junk_json.getJSONObject(key).getJSONObject(key2).getJSONObject(key3).get(key4).toString());

                                        }
                                    }
                                }
                            }
                        }
                    }

                }

                API_FIRST_RUN = false;

            }

            new File(API_OUTPUT_JUNK_PATH).delete();

            API_STARTED = true;

            System.out.println("Server is runing");

        } catch (Exception exception) {
            System.out.println("Failed to create HTTPS server on port " + 8000 + " of localhost");
            exception.printStackTrace();

        }

        // TODO Defining errors

        API_MESSAGES.put("SUC100", "Done");
        API_MESSAGES.put("ERR100", "_auth is null");
        API_MESSAGES.put("ERR101", "_action is null");
        API_MESSAGES.put("ERR102", "_project is null");
        API_MESSAGES.put("ERR103", "Project must contain only alphanumeric characters");
        API_MESSAGES.put("ERR104", "Project does not exists");
        API_MESSAGES.put("ERR105", "Unknown action");
        API_MESSAGES.put("ERR106", "API Auth Validation failed");
        API_MESSAGES.put("ERR107", "_table is null");
        API_MESSAGES.put("ERR108", "Table already exists");
        API_MESSAGES.put("ERR109", "Table does not exists");
        API_MESSAGES.put("ERR110", "Unexpected URI");
        API_MESSAGES.put("ERR111", "Table record does not exists");
        API_MESSAGES.put("ERR112", "The parameters contain keys with non-alphanumeric characters");
        API_MESSAGES.put("ERR113", "Project Auth Validation failed");
        API_MESSAGES.put("ERR114", "_security is null");
        API_MESSAGES.put("ERR115", "Unexpected value");
        API_MESSAGES.put("ERR116", "Project already exists");
        API_MESSAGES.put("ERR117", "_experimental is null");
        API_MESSAGES.put("ERR118", "_name is null");
        API_MESSAGES.put("ERR119", "_email is null");
        API_MESSAGES.put("ERR120", "_pass is null");
        API_MESSAGES.put("ERR121", "_enabled is null");
        API_MESSAGES.put("ERR122", "_super is null");
        API_MESSAGES.put("ERR123", "Email already exists");
        API_MESSAGES.put("ERR124", "_pass must be at least 8 characters long");
        API_MESSAGES.put("ERR125", "_email is invalid");
        API_MESSAGES.put("ERR126", "User email does not exists");
        API_MESSAGES.put("ERR127", "This user cannot be deleted");
        API_MESSAGES.put("ERR128", "Table name must contain only alphanumeric characters");
        API_MESSAGES.put("ERR129", "You do not have the privileges to perform this action");
        API_MESSAGES.put("ERR130", "User fingerprint does not exists");
        API_MESSAGES.put("ERR131", "Some keys where not found on this table");
        API_MESSAGES.put("ERR132", "Super users cannot be deleted");
        API_MESSAGES.put("ERR133", "_fingerprint is invalid");
        API_MESSAGES.put("ERR134", "Privileges not found for this user");
        API_MESSAGES.put("ERR135", "Unexpected parameters");
        API_MESSAGES.put("ERR136", "Invalid sintax on where condition");
        API_MESSAGES.put("ERR137", "Access denied");
        API_MESSAGES.put("ERR138", "The parameters contain values with non-alphanumeric characters");
        API_MESSAGES.put("ERR139", "Some keys already exists on this table");
        API_MESSAGES.put("ERR140", "Some replacement keys already exists on this table");
        API_MESSAGES.put("ERR141", "_columns is null");
        API_MESSAGES.put("ERR142", "_new_column is null");
        API_MESSAGES.put("ERR143", "_alias is null");
        API_MESSAGES.put("ERR144", "Script does not exists");
        API_MESSAGES.put("ERR145", "_script is null");


        // TODO Pre-running

        ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>> temp_core = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>();
        ConcurrentHashMap<String, String> temp_map = new ConcurrentHashMap<String, String>();
        ConcurrentHashMap<String, String> temp_map2 = new ConcurrentHashMap<String, String>();

        if (API_FIRST_RUN) {
            temp_core.put("_projects", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_tables", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_users", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_privileges", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_project_privileges", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_user_privileges", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_project_tables", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_user_fingerprints", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_table_columns", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_columns", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_temp", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_scripts", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            temp_core.put("_project_scripts", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());

            DATA.put("_core", temp_core);

            temp_map = new ConcurrentHashMap<>();

            temp_map.put("name", "Master Developer");
            temp_map.put("email", "dev@baserel.com");
            temp_map.put("pass", MD5("12345678"));
            temp_map.put("enabled", "true");
            temp_map.put("super", "true");
            temp_map.put("fingerprint", randomString(32));

            temp_map2.put("email", "dev@baserel.com");

            DATA.get("_core").get("_users").put("dev@baserel.com", temp_map);
            DATA.get("_core").get("_user_fingerprints").put(temp_map.get("fingerprint"), temp_map2);
        }else{
            if(DATA.get("_core").get("_scripts") == null){
                DATA.get("_core").put("_scripts", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            }
            if(DATA.get("_core").get("_project_scripts") == null){
                DATA.get("_core").put("_project_scripts", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
            }
        }

        //TODO Runnable
        Runnable updateGame = new Runnable()
        {
            @Override
            public void run()
            {

                if(API_STARTED){
                    if(!API_GRACEFUL_SHUTDOWN){

                        API_OUTPUT_DATA_COUNTER++;

                        if(API_OUTPUT_DATA_COUNTER >= API_OUTPUT_DATA_MAX_COUNTER && !API_WRITTING_DATA)
                        {

                            API_WRITTING_DATA = true;
//
//                            try{
//                                FileOutputStream fos = new FileOutputStream(API_OUTPUT_DATA_PATH, false);
//                                ObjectOutputStream oos = new ObjectOutputStream(fos);
//                                oos.writeObject(DATA);
//                                oos.close();
//                                fos.close();
//                            }
//                            catch(IOException ioe)
//                            {
//                                ioe.printStackTrace();
//                            }

                            SaveToDisk();

                            API_OUTPUT_DATA_COUNTER = 0;
                            API_WRITTING_DATA = false;

                        }
                    }else if(!API_WRITTING_DATA){

                        SaveToDisk();

                        System.exit(0);

                    }
                }
            }
        };

        int initialDelay = 0;
        int delay = 1;

        scheduler.scheduleWithFixedDelay(updateGame, initialDelay, delay, TimeUnit.SECONDS);

    }

    // @@@@@
    // HANDLERS
    // @@@@@

    //TODO Starting defining handlers

    static class TestHandler implements HttpHandler { //TODO Handler

        public void handle(HttpExchange httpExchange) throws IOException {

            ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
            String response = "";

            engine.put("_id", "1");

            try {
                response = engine.eval("_id == 1").toString();
            } catch (ScriptException e) {
                //e.printStackTrace();
                response = "error";
            }

            server.writeResponse(httpExchange, response);

        }
    }

    static class PutHandler implements HttpHandler { //TODO Handler

        public void handle(HttpExchange httpExchange) throws IOException {

            JSONObject response = new JSONObject();

            String uri = httpExchange.getRequestURI().toString();

            String[] parts = uri.split("/");

            String project = parts[2];
            String table = parts[3];

            HashMap<String, String> parameters = getParametersJSON(httpExchange);

            System.out.println(parameters.toString());

            ConcurrentHashMap<String, String> temp_map = new ConcurrentHashMap<String, String>();

            if (httpExchange.getRequestHeaders().get("Authorization") == null) {
                try {

                    response.put("result", "ERR100");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", API_MESSAGES.get("ERR100"));
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else if (project == null || table == null || !StringUtils.isAlphanumeric(project)
                    || !StringUtils.isAlphanumeric(table)) {
                try {
                    response.put("result", "ERR110");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", API_MESSAGES.get("ERR110"));
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else if (DATA.get(project) == null) {
                try {

                    response.put("result", "ERR104");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", API_MESSAGES.get("ERR104"));
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else {

                String index = (parameters.get("_id") == null ? "" : parameters.get("_id"));

                parameters.remove("_id");

                if (!validateProjectAuth(httpExchange.getRequestHeaders().get("Authorization").toArray()[0].toString(), project)
                        && DATA.get("_core").get("_projects").get(project).get("security").equals("true")) {
                    try {
                        response.put("result", "ERR113");
                        response.put("text", "Access denied");

                        if (API_EXPERIMENTAL) {
                            response.put("info",
                                    "project Auth Validation failed: "+genProjectAuthExperimental(parameters, project));
                        }

                    } catch (JSONException e) {

                        e.printStackTrace();
                    }
                } else {

                    parameters.remove("_auth");

                    if (DATA.get(project).get(table) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR109"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        if (index.equals("")) {

                            if (!validateAPIMapKeys(parameters)) {

                                try {
                                    response.put("result", "ERR112");
                                    response.put("text", "Access denied");

                                    if (API_EXPERIMENTAL) {
                                        response.put("info", API_MESSAGES.get("ERR112"));
                                    }
                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }

                            } else {

                                temp_map = new ConcurrentHashMap<String, String>();

                                for (Entry<String, String> entry : parameters.entrySet()) {
                                    temp_map.put(entry.getKey(), entry.getValue());
                                }

                                index = DATA.get("_core").get("_tables").get(project + "_" + table).get("index");

                                DATA.get(project).get(table).put(index, temp_map);

                                DATA.get("_core").get("_tables").get(project + "_" + table).put("index",
                                        (Integer.parseInt(index) + 1) + "");

                                try {

                                    response.put("result", "SUC100");
                                    response.put("text", API_MESSAGES.get("SUC100"));
                                    response.put("_id", index);

                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }

                            }

                        } else {
                            if (DATA.get(project).get(table).get(index) == null) {
                                try {

                                    response.put("result", "ERR111");
                                    response.put("text", "Access denied");

                                    if (API_EXPERIMENTAL) {
                                        response.put("info", API_MESSAGES.get("ERR111"));
                                    }

                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }
                            } else {

                                if (!validateAPIMapKeys(parameters)) {

                                    try {
                                        response.put("result", "ERR112");
                                        response.put("text", "Access denied");

                                        if (API_EXPERIMENTAL) {
                                            response.put("info", API_MESSAGES.get("ERR112"));
                                        }
                                    } catch (JSONException e) {

                                        e.printStackTrace();
                                    }

                                } else {

                                    temp_map = DATA.get(project).get(table).get(index);

                                    for (Entry<String, String> entry : parameters.entrySet()) {
                                        temp_map.put(entry.getKey(), entry.getValue());
                                    }

                                    DATA.get(project).get(table).put(index, temp_map);

                                    try {

                                        response.put("result", "SUC100");
                                        response.put("text", API_MESSAGES.get("SUC100"));
                                        response.put("_id", index);

                                    } catch (JSONException e) {

                                        e.printStackTrace();
                                    }

                                }
                            }
                        }
                    }
                }
            }

            server.writeResponse(httpExchange, response.toString());
        }

    }

    static class GetHandler implements HttpHandler { //TODO Handler

        public void handle(HttpExchange httpExchange) throws IOException {

            JSONObject response = new JSONObject();

            String uri = httpExchange.getRequestURI().toString();

            String[] parts = uri.split("/");

            String project = parts[2];
            String table = parts[3];

            Map<String, String> parameters = getParametersJSON(httpExchange);

            if (httpExchange.getRequestHeaders().get("Authorization") == null) {
                try {

                    response.put("result", "ERR100");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", API_MESSAGES.get("ERR100"));
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else {
                if (project == null || table == null || !StringUtils.isAlphanumeric(project)
                        || !StringUtils.isAlphanumeric(table)) {
                    try {

                        response.put("result", "ERR110");
                        response.put("text", "Access denied");

                        if (API_EXPERIMENTAL) {
                            response.put("info", API_MESSAGES.get("ERR110"));
                        }

                    } catch (JSONException e) {

                        e.printStackTrace();
                    }
                } else {
                    if (DATA.get(project) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        String index = (parameters.get("_id") == null ? "" : parameters.get("_id"));

                        parameters.remove("_id");

                        if (!validateProjectAuth(httpExchange.getRequestHeaders().get("Authorization").toArray()[0].toString(), project)
                                && DATA.get("_core").get("_projects").get(project).get("security").equals("true")) {
                            try {
                                response.put("result", "ERR113");
                                response.put("text", "Access denied");

                                if (API_EXPERIMENTAL) {
                                    response.put("info", API_MESSAGES.get("ERR113"));
                                }

                            } catch (JSONException e) {

                                e.printStackTrace();
                            }
                        } else {

                            parameters.remove("_auth");

                            if (DATA.get(project).get(table) == null) {
                                try {

                                    response.put("result", "ERR109");
                                    response.put("text", "Access denied");

                                    if (API_EXPERIMENTAL) {
                                        response.put("info", API_MESSAGES.get("ERR109"));
                                    }

                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }
                            } else {

                                if (parameters.get("_where") == null) {
                                    response = new JSONObject(DATA.get(project).get(table));
                                } else {
                                    response = new JSONObject(
                                            filterTable(DATA.get(project).get(table), parameters.get("_where")));
                                }

                            }
                        }
                    }
                }
            }

            server.writeResponse(httpExchange, response.toString());
        }
    }

    static class DelHandler implements HttpHandler { //TODO Handler

        public void handle(HttpExchange httpExchange) throws IOException {

            JSONObject response = new JSONObject();

            String uri = httpExchange.getRequestURI().toString();

            String[] parts = uri.split("/");

            String project = parts[2];
            String table = parts[3];

            Map<String, String> parameters = getParametersJSON(httpExchange);

            if (httpExchange.getRequestHeaders().get("Authorization") == null) {
                try {

                    response.put("result", "ERR100");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", API_MESSAGES.get("ERR100"));
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else {
                if (project == null || table == null || !StringUtils.isAlphanumeric(project)
                        || !StringUtils.isAlphanumeric(table)) {
                    try {

                        response.put("result", "ERR110");
                        response.put("text", "Access denied");

                        if (API_EXPERIMENTAL) {
                            response.put("info", API_MESSAGES.get("ERR110"));
                        }

                    } catch (JSONException e) {

                        e.printStackTrace();
                    }
                } else {
                    if (DATA.get(project) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        String index = (parameters.get("_id") == null ? "" : parameters.get("_id"));

                        parameters.remove("_id");

                        if (!validateProjectAuth(httpExchange.getRequestHeaders().get("Authorization").toArray()[0].toString(), project)
                                && DATA.get("_core").get("_projects").get(project).get("security").equals("true")) {
                            try {
                                response.put("result", "ERR113");
                                response.put("text", "Access denied");

                                if (API_EXPERIMENTAL) {
                                    response.put("info", API_MESSAGES.get("ERR113"));
                                }

                            } catch (JSONException e) {

                                e.printStackTrace();
                            }
                        } else {

                            parameters.remove("_auth");

                            if (DATA.get(project).get(table) == null) {
                                try {

                                    response.put("result", "ERR109");
                                    response.put("text", "Access denied");

                                    if (API_EXPERIMENTAL) {
                                        response.put("info", API_MESSAGES.get("ERR109"));
                                    }

                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }
                            } else {

                                if (index != "") {

                                    DATA.get(project).get(table).remove(index);

                                    try {

                                        response.put("result", "SUC100");
                                        response.put("text", API_MESSAGES.get("SUC100"));

                                    } catch (JSONException e) {

                                        e.printStackTrace();
                                    }

                                } else if (parameters.size() == 0) {

                                    DATA.get(project).get(table).clear();

                                    try {

                                        response.put("result", "SUC100");
                                        response.put("text", API_MESSAGES.get("SUC100"));

                                    } catch (JSONException e) {

                                        e.printStackTrace();
                                    }

                                } else {

                                    if (filterAndDeletetable(DATA.get(project).get(table), parameters.get("_where"), project, table)) {
                                        try {

                                            response.put("result", "SUC100");
                                            response.put("text", API_MESSAGES.get("SUC100"));

                                        } catch (JSONException e) {

                                            e.printStackTrace();
                                        }
                                    }
                                    else
                                    {
                                        try {

                                            response.put("result", "ERR136");
                                            response.put("text", "Access denied");

                                            if (API_EXPERIMENTAL) {
                                                response.put("info", API_MESSAGES.get("ERR136"));
                                            }

                                        } catch (JSONException e) {

                                            e.printStackTrace();
                                        }
                                    }

                                }

                            }
                        }
                    }
                }
            }

            server.writeResponse(httpExchange, response.toString());
        }
    }

    static class AdmHandler implements HttpHandler { //TODO Handler

        public void handle(HttpExchange httpExchange) throws IOException {

            JSONObject response = new JSONObject();
            Map<String, String> parameters = getParametersJSON(httpExchange);

            ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>> temp_table = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>();
            ConcurrentHashMap<String, ConcurrentHashMap<String, String>> temp_keymap = new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>();
            ConcurrentHashMap<String, String> temp_map = new ConcurrentHashMap<String, String>();
            ConcurrentHashMap<String, String> temp_map2 = new ConcurrentHashMap<String, String>();

            System.out.println(parameters.toString());

            if (httpExchange.getRequestHeaders().get("Authorization") == null) {
                try {

                    response.put("result", "ERR100");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", API_MESSAGES.get("ERR100"));
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else if (!validateAPIAuth(httpExchange.getRequestHeaders().get("Authorization").toArray()[0].toString(), parameters) && !API_EXPERIMENTAL) {
                try {
                    response.put("result", "ERR106");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", API_MESSAGES.get("ERR106"));
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }

            } else if (parameters.get("_action") == null) {
                try {

                    response.put("result", "ERR101");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", API_MESSAGES.get("ERR101"));
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else {

                //TODO Starting defining actions

                if (parameters.get("_action").equals("create_user")) { //TODO command action


                    if (parameters.get("_name") == null) {

                        try {

                            response.put("result", "ERR118");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR118"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_pass") == null) {

                        try {

                            response.put("result", "ERR120");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR120"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_pass").length() < 8) {

                        try {

                            response.put("result", "ERR124");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR124"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_enalbed") == null) {

                        try {

                            response.put("result", "ERR121");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR121"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (!parameters.get("_enalbed").equals("true")
                            && !parameters.get("_enalbed").equals("false")) {

                        try {

                            response.put("result", "ERR115");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR115"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_super") == null) {
                        try {

                            response.put("result", "ERR122");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!parameters.get("_super").equals("true") && !parameters.get("_super").equals("false")) {
                        try {

                            response.put("result", "ERR115");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!isValidEmail(parameters.get("_email"))) {
                        try {

                            response.put("result", "ERR125");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) != null) {
                        try {

                            response.put("result", "ERR123");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        String fingerprint = randomString(32);

                        temp_map = new ConcurrentHashMap<String, String>();

                        temp_map.put("name", parameters.get("_name"));
                        temp_map.put("email", parameters.get("_email"));
                        temp_map.put("pass", MD5(parameters.get("_pass")));
                        temp_map.put("enabled", parameters.get("_enabled"));
                        temp_map.put("super", parameters.get("_super"));
                        temp_map.put("fingerprint", fingerprint);

                        DATA.get("_core").get("_users").put(parameters.get("_email"), temp_map);

                        temp_map = new ConcurrentHashMap<String, String>();

                        temp_map.put("email", parameters.get("_email"));

                        DATA.get("_core").get("_user_fingerprints").put(fingerprint, temp_map);

                        try {
                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));
                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }


                } else if (parameters.get("_action").equals("edit_user")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_pass") != null && parameters.get("_pass").length() < 8) {

                        try {

                            response.put("result", "ERR124");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR124"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_enalbed") != null && !parameters.get("_enalbed").equals("true")
                            && !parameters.get("_enalbed").equals("false")) {

                        try {

                            response.put("result", "ERR115");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR115"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_super") != null && !parameters.get("_super").equals("true")
                            && !parameters.get("_super").equals("false")) {
                        try {

                            response.put("result", "ERR115");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR115"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_nemail") != null && !isValidEmail(parameters.get("_nemail"))) {
                        try {

                            response.put("result", "ERR125");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR125"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_nemail") != null
                            && !parameters.get("_nemail").equals(parameters.get("_email"))
                            && DATA.get("_core").get("_users").get(parameters.get("_nemail")) != null) {
                        try {

                            response.put("result", "ERR123");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR123"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        temp_map = DATA.get("_core").get("_users").get(parameters.get("_email"));

                        if (parameters.get("_name") != null)
                            temp_map.put("name", parameters.get("_name"));

                        if (parameters.get("_nemail") != null)
                            temp_map.put("email", parameters.get("_nemail"));

                        if (parameters.get("_pass") != null)
                            temp_map.put("pass", MD5(parameters.get("_pass")));

                        if (parameters.get("_enabled") != null)
                            temp_map.put("enabled", parameters.get("_enabled"));

                        if (parameters.get("_super") != null)
                            temp_map.put("super", parameters.get("_super"));

                        DATA.get("_core").get("_users").put(parameters.get("_email"), temp_map);

                        try {
                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));
                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }


                } else if (parameters.get("_action").equals("get_user")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else {

                        response = new JSONObject(DATA.get("_core").get("_users").get(parameters.get("_email")));

                    }


                } else if (parameters.get("_action").equals("delete_user")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")).get("super").equals("true")) {

                        try {

                            response.put("result", "ERR132");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR132"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else {

                        DATA.get("_core").get("_user_fingerprints").remove(DATA.get("_core").get("_users").get(parameters.get("_email")).get("fingerprint"));
                        for (Entry<String, ConcurrentHashMap<String, String>> entry : DATA.get("_core").get("_project_privileges").entrySet()) {
                            if(entry.getValue().get(parameters.get("_email")) != null){
                                DATA.get("_core").get("_project_privileges").get(entry.getKey()).remove(parameters.get("_email"));
                            }
                        }
                        DATA.get("_core").get("_user_privileges").remove(parameters.get("_email"));
                        DATA.get("_core").get("_users").remove(parameters.get("_email"));

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }

                } else if (parameters.get("_action").equals("reset_user_fingerprint")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else {

                        String fingerprint = randomString(32);

                        DATA.get("_core").get("_users").get(parameters.get("_email")).put("fingerprint", fingerprint);

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }


                } else if (parameters.get("_action").equals("auth_user")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_pass") == null) {

                        try {

                            response.put("result", "ERR120");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR120"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (!DATA.get("_core").get("_users").get(parameters.get("_email")).get("pass").equals(parameters.get("_pass"))) {

                        try {

                            response.put("result", "ERR137");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR137"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else {

                        try {

                            response.put("email", parameters.get("_email"));
                            response.put("fingerprint", DATA.get("_core").get("_users").get(parameters.get("_email")).get("fingerprint"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }


                } else if (parameters.get("_action").equals("get_all_users")) { //TODO command action


                    response = new JSONObject(DATA.get("_core").get("_users"));


                } else if (parameters.get("_action").equals("set_privileges")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_fingerprint") == null) {
                        try {

                            response.put("result", "ERR133");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR107"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")) == null) {
                        try {

                            response.put("result", "ERR130");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR130"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_put") == null || (!parameters.get("_put").equals("true") && !parameters.get("_put").equals("false")) || parameters.get("_get") == null || (!parameters.get("_get").equals("true") && !parameters.get("_get").equals("false")) || parameters.get("_del") == null || (!parameters.get("_del").equals("true") && !parameters.get("_del").equals("false")) || parameters.get("_adm") == null || (!parameters.get("_adm").equals("true") && !parameters.get("_adm").equals("false")) || parameters.get("_cmd") == null || (!parameters.get("_cmd").equals("true") && !parameters.get("_cmd").equals("false"))) {
                        try {

                            response.put("result", "ERR135");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR135"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        if(DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")) == null)
                        {
                            DATA.get("_core").get("_user_privileges").put(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email"), new ConcurrentHashMap<String, String>());
                        }

                        if(DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).get(parameters.get("_project")) != null)
                        {
                            DATA.get("_core").get("_privileges").get(DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).get(parameters.get("_project"))).put("get", parameters.get("_get"));
                            DATA.get("_core").get("_privileges").get(DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).get(parameters.get("_project"))).put("put", parameters.get("_put"));
                            DATA.get("_core").get("_privileges").get(DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).get(parameters.get("_project"))).put("del", parameters.get("_del"));
                            DATA.get("_core").get("_privileges").get(DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).get(parameters.get("_project"))).put("adm", parameters.get("_adm"));
                            DATA.get("_core").get("_privileges").get(DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).get(parameters.get("_project"))).put("cmd", parameters.get("_cmd"));
                        }
                        else
                        {
                            String privileges_code = randomString(32);

                            temp_map = new ConcurrentHashMap<String, String>();

                            temp_map.put("email", DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email"));
                            temp_map.put("project", parameters.get("_project"));
                            temp_map.put("get", parameters.get("_get"));
                            temp_map.put("put", parameters.get("_put"));
                            temp_map.put("del", parameters.get("_del"));
                            temp_map.put("adm", parameters.get("_adm"));
                            temp_map.put("cmd", parameters.get("_cmd"));

                            DATA.get("_core").get("_privileges").put(privileges_code, temp_map);

                            DATA.get("_core").get("_project_privileges").put(parameters.get("_project"), new ConcurrentHashMap<String, String>());

                            DATA.get("_core").get("_project_privileges").get(parameters.get("_project")).put(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email"), parameters.get("_fingerprint"));

                            DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).put(parameters.get("_project"), privileges_code);
                        }

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }


                } else if (parameters.get("_action").equals("get_privileges")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_fingerprint") == null) {
                        try {

                            response.put("result", "ERR133");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR107"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")) == null) {
                        try {

                            response.put("result", "ERR130");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR130"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "any")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_project_privileges").get(parameters.get("_project")).get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")) == null) {
                        try {

                            response.put("result", "ERR134");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR134"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        response = new JSONObject(DATA.get("_core").get("_privileges").get(DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).get(parameters.get("_project"))));

                    }


                } else if (parameters.get("_action").equals("delete_privileges")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_fingerprint") == null) {
                        try {

                            response.put("result", "ERR133");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR107"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")) == null) {
                        try {

                            response.put("result", "ERR130");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR130"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_project_privileges").get(parameters.get("_project")).get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")) == null) {
                        try {

                            response.put("result", "ERR134");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR134"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        DATA.get("_core").get("_privileges").remove(DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).get(parameters.get("_project")));
                        DATA.get("_core").get("_user_privileges").get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")).remove(parameters.get("_project"));
                        DATA.get("_core").get("_project_privileges").get(parameters.get("_project")).remove(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email"));

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }


                } else if (parameters.get("_action").equals("create_project")) {  //TODO command action
                    if (parameters.get("_name") == null || parameters.get("_name") == "" || !StringUtils.isAlphanumeric(parameters.get("_name")) || parameters.get("_name").contains(" ")) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR118"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {
                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {
                        String project_code = randomString(32);
                        String privileges_code = randomString(32);

                        DATA.put(project_code, temp_table);

                        temp_map = new ConcurrentHashMap<String, String>();

                        temp_map.put("name", parameters.get("_name"));
                        temp_map.put("security", "true");
                        temp_map.put("color", "01579b");

                        DATA.get("_core").get("_projects").put(project_code, temp_map);

                        temp_map = new ConcurrentHashMap<String, String>();

                        temp_map.put("email", parameters.get("_email"));
                        temp_map.put("project", project_code);
                        temp_map.put("get", "true");
                        temp_map.put("put", "true");
                        temp_map.put("del", "true");
                        temp_map.put("adm", "true");
                        temp_map.put("cmd", "true");

                        DATA.get("_core").get("_privileges").put(privileges_code, temp_map);

                        temp_map = new ConcurrentHashMap<String, String>();

                        DATA.get("_core").get("_project_privileges").put(project_code,
                                new ConcurrentHashMap<String, String>());

                        DATA.get("_core").get("_project_privileges").get(project_code).put(parameters.get("_email"),
                                DATA.get("_core").get("_users").get(parameters.get("_email")).get("fingerprint"));

                        if(DATA.get("_core").get("_user_privileges").get(parameters.get("_email")) == null) {
                            DATA.get("_core").get("_user_privileges").put(parameters.get("_email"),
                                    new ConcurrentHashMap<String, String>());
                        }

                        DATA.get("_core").get("_user_privileges").get(parameters.get("_email")).put(project_code,
                                privileges_code);

                        try {

                            response.put("project", project_code);

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }


                } else if (parameters.get("_action").equals("get_project")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "any")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        temp_map = DATA.get("_core").get("_projects").get(parameters.get("_project"));
                        temp_map.put("tables_count", (DATA.get("_core").get("_project_tables").get(parameters.get("_project")) != null ? ""+DATA.get("_core").get("_project_tables").get(parameters.get("_project")).size() : "0"));

                        temp_map2 = DATA.get("_core").get("_privileges").get(DATA.get("_core").get("_user_privileges").get(parameters.get("_email")).get(parameters.get("_project")));

                        temp_map.put("perm_get", temp_map2.get("get"));
                        temp_map.put("perm_put", temp_map2.get("put"));
                        temp_map.put("perm_del", temp_map2.get("del"));
                        temp_map.put("perm_adm", temp_map2.get("adm"));
                        temp_map.put("perm_cmd", temp_map2.get("cmd"));

                        response = new JSONObject(temp_map);

                    }


                } else if (parameters.get("_action").equals("get_projects")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else {

                        if(DATA.get("_core").get("_user_privileges").get(parameters.get("_email")) != null) {
                            for (Entry<String, String> entry : DATA.get("_core").get("_user_privileges").get(parameters.get("_email")).entrySet()) {
                                temp_keymap.put(entry.getKey(), DATA.get("_core").get("_projects").get(entry.getKey()));
                                if (DATA.get("_core").get("_project_tables").get(entry.getKey()) != null)
                                    temp_keymap.get(entry.getKey()).put("tables_count", "" + DATA.get("_core").get("_project_tables").get(entry.getKey()).size());
                                else temp_keymap.get(entry.getKey()).put("tables_count", "0");
                            }
                        }

                        response = new JSONObject(temp_keymap);

                    }


                } else if (parameters.get("_action").equals("edit_project")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_color") == null || parameters.get("_color") == "" || parameters.get("_name") == null || parameters.get("_name") == "" || parameters.get("_security") == null || !StringUtils.isAlphanumeric(parameters.get("_name")) || parameters.get("_name").contains(" ") || (!parameters.get("_security").equals("true") && !parameters.get("_security").equals("false"))) {
                        try {

                            response.put("result", "ERR135");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR135"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        DATA.get("_core").get("_projects").get(parameters.get("_project")).put("name", parameters.get("_name"));
                        DATA.get("_core").get("_projects").get(parameters.get("_project")).put("security", parameters.get("_security"));
                        DATA.get("_core").get("_projects").get(parameters.get("_project")).put("color", parameters.get("_color"));

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }

                } else if (parameters.get("_action").equals("delete_project")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        DATA.get("_core").get("_projects").remove(parameters.get("_project"));

                        DATA.remove(parameters.get("_project"));

                        for (Entry<String, ConcurrentHashMap<String, String>> entry : DATA.get("_core").get("_privileges").entrySet()) {
                            if(entry.getValue().get("project").equals(parameters.get("_project"))) DATA.get("_core").get("_privileges").remove(entry.getKey());
                        }
                        for (Entry<String, String> entry : DATA.get("_core").get("_project_scripts").get(parameters.get("_project")).entrySet()) {
                            DATA.get("_core").get("_scripts").remove(entry.getKey());
                        }

                        DATA.get("_core").get("_project_scripts").remove(parameters.get("_project"));


                        DATA.get("_core").get("_user_privileges").get(parameters.get("_email")).remove(parameters.get("_project"));
                        DATA.get("_core").get("_project_privileges").remove(parameters.get("_project"));
                        DATA.get("_core").get("_tables").remove(parameters.get("_project"));

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }

                    // END DEFINING ACTIONS

                } else if (parameters.get("_action").equals("get_project_users")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        for (Entry<String, String> entry : DATA.get("_core").get("_project_privileges").get(parameters.get("_project")).entrySet()) {

                            temp_map2 = new ConcurrentHashMap<>(DATA.get("_core").get("_privileges").get(DATA.get("_core").get("_user_privileges").get(entry.getKey()).get(parameters.get("_project"))));

                            temp_map.put("email", entry.getKey());
                            temp_map.put("fingerprint", DATA.get("_core").get("_users").get(entry.getKey()).get("fingerprint"));
                            temp_map.put("perm_get", temp_map2.get("get"));
                            temp_map.put("perm_put", temp_map2.get("put"));
                            temp_map.put("perm_del", temp_map2.get("del"));
                            temp_map.put("perm_adm", temp_map2.get("adm"));
                            temp_map.put("perm_cmd", temp_map2.get("cmd"));

                            temp_keymap.put(entry.getKey(), temp_map);
                        }

                        response = new JSONObject(temp_keymap);

                    }

                } else if (parameters.get("_action").equals("create_table")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_name") == null || parameters.get("_name") == "" || !StringUtils.isAlphanumeric(parameters.get("_name")) || parameters.get("_name").contains(" ")) {
                        try {

                            response.put("result", "ERR118");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR118"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {


                        String table_code = randomString(32);

                        DATA.get(parameters.get("_project")).put(table_code, temp_keymap);

                        temp_map = new ConcurrentHashMap<String, String>();
                        temp_map.put("index", "1");
                        temp_map.put("name", parameters.get("_name"));
                        temp_map.put("columns_sort", "");


                        DATA.get("_core").get("_tables").put(parameters.get("_project") + "_" + table_code, temp_map);
                        DATA.get("_core").get("_table_columns").put(parameters.get("_project") + "_" + table_code, new ConcurrentHashMap<String, String>());

                        if (DATA.get("_core").get("_project_tables").get(parameters.get("_project")) == null) {
                            temp_map = new ConcurrentHashMap<String, String>();
                            DATA.get("_core").get("_project_tables").put(parameters.get("_project"), temp_map);
                        }

                        DATA.get("_core").get("_project_tables").get(parameters.get("_project")).put(table_code, table_code);

                        try {

                            response.put("table", table_code);

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }


                } else if (parameters.get("_action").equals("edit_table")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_name")) || parameters.get("_name") == null || parameters.get("_name") == "" || parameters.get("_table") == null || parameters.get("_name").contains(" ")) {
                        try {

                            response.put("result", "ERR135");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR135"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR109"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        DATA.get("_core").get("_tables").get(parameters.get("_project")+"_"+parameters.get("_table")).put("name", parameters.get("_name"));

                        if(parameters.get("_columns_sort") != null && parameters.get("_columns_sort") != "") {
                            DATA.get("_core").get("_tables").get(parameters.get("_project")+"_"+parameters.get("_table")).put("columns_sort", parameters.get("_columns_sort"));
                        }

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }

                } else if (parameters.get("_action").equals("delete_table")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_table") == null) {
                        try {

                            response.put("result", "ERR107");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR107"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR109"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        DATA.get("_core").get("_tables").remove(parameters.get("_project") + "_" + parameters.get("_table"));
                        DATA.get("_core").get("_project_tables").get(parameters.get("_project")).remove(parameters.get("_table"));
                        DATA.get(parameters.get("_project")).remove(parameters.get("_table"));

                        for (Entry<String, String> entry : DATA.get("_core").get("_table_columns").get(parameters.get("_project") + "_" + parameters.get("_table")).entrySet()) {

                            DATA.get("_core").get("_columns").remove(entry.getValue());

                        }

                        DATA.get("_core").get("_table_columns").remove(parameters.get("_project") + "_" + parameters.get("_table"));

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }


                } else if (parameters.get("_action").equals("get_table")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_table") == null) {

                        try {

                            response.put("result", "ERR107");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR107"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR109"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "any")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        temp_map = DATA.get("_core").get("_tables").get(parameters.get("_project") + "_" + parameters.get("_table"));

                        if(DATA.get(parameters.get("_project")).get(parameters.get("_table")) != null) temp_map.put("records_count", ""+DATA.get(parameters.get("_project")).get(parameters.get("_table")).size());
                        else temp_map.put("records_count", "0");

                        temp_map.put("columns_count", getColumnsCount(parameters.get("_project") + "_" + parameters.get("_table")));
                        temp_map.put("columns", getColumns(parameters.get("_project") + "_" + parameters.get("_table")));

                        response = new JSONObject(temp_map);

                    }


                } else if (parameters.get("_action").equals("get_tables")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "any")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        if(DATA.get("_core").get("_project_tables").get(parameters.get("_project")) != null){
                            for (Entry<String, String> entry : DATA.get("_core").get("_project_tables").get(parameters.get("_project")).entrySet()) {

                                temp_keymap.put(entry.getKey(), DATA.get("_core").get("_tables").get(parameters.get("_project") + "_" + entry.getKey()));

                                if (DATA.get(parameters.get("_project")).get(entry.getKey()) != null) {
                                    temp_keymap.get(entry.getKey()).put("records_count", "" + DATA.get(parameters.get("_project")).get(entry.getKey()).size());
                                } else {
                                    temp_keymap.get(entry.getKey()).put("records_count", "0");
                                }

                                temp_keymap.get(entry.getKey()).put("columns", getColumns(parameters.get("_project") + "_" + entry.getKey()));

                            }
                        }

                        response = new JSONObject(temp_keymap);

                    }


                } else if (parameters.get("_action").equals("add_table_columns")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_table") == null) {

                        try {

                            response.put("result", "ERR107");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR107"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR109"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_columns") == null) {
                        try {

                            response.put("result", "ERR141");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR141"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        boolean allKeysValid = true;

                        List<String> columns = Arrays.asList(parameters.get("_columns").split(","));

                        for (String column : columns) {
                            if (!StringUtils.isAlphanumeric(column) || column.contains(" ")) {

                                try {

                                    response.put("result", "ERR135");
                                    response.put("text", "Access denied");

                                    if (API_EXPERIMENTAL) {
                                        response.put("info", API_MESSAGES.get("ERR135"));
                                    }

                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }

                                allKeysValid = false;

                                break;

                            }
                        }

                        if(allKeysValid){
                            for (String column : columns) {
                                if(DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).get(column) == null){

                                    String column_key = randomString(16);

                                    DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).put(column, column_key);

                                    temp_map = new ConcurrentHashMap<>();

                                    temp_map.put("key", column);
                                    temp_map.put("alias", column.substring(0, 1).toUpperCase() + column.substring(1));
                                    temp_map.put("input", "string");
                                    temp_map.put("format", "plain");

                                    DATA.get("_core").get("_columns").put(column_key, temp_map);

                                }
                            }
                        }

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }


                } else if (parameters.get("_action").equals("edit_table_column")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_table") == null) {

                        try {

                            response.put("result", "ERR107");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR107"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR109"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_column") == null) {
                        try {

                            response.put("result", "ERR141");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR141"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_alias") == null || parameters.get("_alias") == "") {
                        try {

                            response.put("result", "ERR143");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR143"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_new_column") == null) {
                        try {

                            response.put("result", "ERR142");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR142"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_new_column")) || parameters.get("_new_column").contains(" ")) {
                        try {

                            response.put("result", "ERR135");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR135"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if(DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).get(parameters.get("_column")) == null) {
                        try {

                            response.put("result", "ERR131");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR131"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if(DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).get(parameters.get("_new_column")) != null && !parameters.get("_new_column").equals(parameters.get("_column"))) {
                        try {

                            response.put("result", "ERR140");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR140"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }else{

                        if(parameters.get("_new_column").equals(parameters.get("_column"))){
                            DATA.get("_core").get("_columns").get(DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).get(parameters.get("_column"))).put("alias", parameters.get("_alias"));
                        }else{
                            DATA.get("_core").get("_columns").get(DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).get(parameters.get("_column"))).put("key", parameters.get("_new_column"));
                            DATA.get("_core").get("_columns").get(DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).get(parameters.get("_column"))).put("alias", parameters.get("_alias"));
                            DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).put(parameters.get("_new_column"), DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).get(parameters.get("_column")));
                            DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).remove(parameters.get("_column"));

                            for (Entry<String, ConcurrentHashMap<String, String>> entry : DATA.get(parameters.get("_project")).get(parameters.get("_table")).entrySet()) {

                                Map<String, String> data_replace_map = entry.getValue();

                                data_replace_map.put(parameters.get("_new_column"), data_replace_map.get(parameters.get("_column")));
                                data_replace_map.remove(parameters.get("_column"));

                            }
                        }

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }


                } else  if (parameters.get("_action").equals("delete_table_column")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_table") == null) {

                        try {

                            response.put("result", "ERR107");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR107"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR109"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_column") == null) {
                        try {

                            response.put("result", "ERR141");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR141"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if(DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).get(parameters.get("_column")) == null) {
                        try {

                            response.put("result", "ERR131");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR131"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }else{

                        DATA.get("_core").get("_columns").remove(DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).get(parameters.get("_column")));
                        DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).remove(parameters.get("_column"));

                        for (Entry<String, ConcurrentHashMap<String, String>> entry : DATA.get(parameters.get("_project")).get(parameters.get("_table")).entrySet()) {

                            Map<String, String> data_replace_map = entry.getValue();

                            data_replace_map.remove(parameters.get("_column"));

                        }

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }


                } else if (parameters.get("_action").equals("get_table_columns")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_table") == null) {

                        try {

                            response.put("result", "ERR107");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR107"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR109"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "any")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        if(DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")) != null){
                            for (Entry<String, String> entry : DATA.get("_core").get("_table_columns").get(parameters.get("_project")+"_"+parameters.get("_table")).entrySet()) {

                                temp_keymap.put(entry.getKey(), DATA.get("_core").get("_columns").get(entry.getValue()));

                            }
                        }

                        response = new JSONObject(temp_keymap);

                    }


                } else if (parameters.get("_action").equals("set_api_experimental")) { //TODO command action


                    if (parameters.get("_experimental") == null) {

                        try {

                            response.put("result", "ERR117");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR117"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (!parameters.get("_experimental").equals("false") && !parameters.get("_experimental").equals("true")) {

                        try {

                            response.put("result", "ERR115");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR115"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else {

                        if(parameters.get("_experimental").equals("false"))
                        {
                            API_EXPERIMENTAL = false;
                        }

                        if(parameters.get("_experimental").equals("true"))
                        {
                            API_EXPERIMENTAL = true;
                        }

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }

                } else if (parameters.get("_action").equals("api_graceful_shutdown")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else {

                        API_GRACEFUL_SHUTDOWN = true;

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }

                } else if (parameters.get("_action").equals("create_script")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_name") == null || parameters.get("_name") == "" || !StringUtils.isAlphanumeric(parameters.get("_name")) || parameters.get("_name").contains(" ")) {
                        try {

                            response.put("result", "ERR118");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR118"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "cmd")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        String script_code = randomString(32);

                        temp_map = new ConcurrentHashMap<String, String>();
                        temp_map.put("name", parameters.get("_name"));
                        temp_map.put("script", "");
                        temp_map.put("request", "");


                        DATA.get("_core").get("_scripts").put(script_code, temp_map);

                        if (DATA.get("_core").get("_project_scripts").get(parameters.get("_project")) == null) {
                            temp_map = new ConcurrentHashMap<String, String>();
                            DATA.get("_core").get("_project_scripts").put(parameters.get("_project"), temp_map);
                        }

                        DATA.get("_core").get("_project_scripts").get(parameters.get("_project")).put(script_code, script_code);

                        try {

                            response.put("script", script_code);

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }


                } else if (parameters.get("_action").equals("edit_script")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if ((!StringUtils.isAlphanumeric(parameters.get("_name")) || parameters.get("_name") == "" || parameters.get("_name").contains(" ")) && (parameters.get("_name") != null || parameters.get("_script") == null)) {
                        try {

                            response.put("result", "ERR135");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR135"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_scripts").get(parameters.get("_script")) == null) {
                        try {

                            response.put("result", "ERR144");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR144"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "cmd")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        if(parameters.get("_name") != null) {
                            DATA.get("_core").get("_scripts").get(parameters.get("_script")).put("name", parameters.get("_name"));
                        }

                        if(parameters.get("_script_str") != null) {
                            DATA.get("_core").get("_scripts").get(parameters.get("_script")).put("script", parameters.get("_script_str"));
                        }
                        if(parameters.get("_script_request") != null) {
                            DATA.get("_core").get("_scripts").get(parameters.get("_script")).put("request", parameters.get("_script_request"));
                        }

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }

                } else if (parameters.get("_action").equals("delete_script")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_script") == null) {
                        try {

                            response.put("result", "ERR145");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR145"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_scripts").get(parameters.get("_script")) == null) {
                        try {

                            response.put("result", "ERR144");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR144"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "cmd")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        DATA.get("_core").get("_scripts").remove(parameters.get("_script"));
                        DATA.get("_core").get("_project_scripts").get(parameters.get("_project")).remove(parameters.get("_script"));

                        try {

                            response.put("result", "SUC100");
                            response.put("text", API_MESSAGES.get("SUC100"));

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }


                } else if (parameters.get("_action").equals("get_script")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_script") == null) {

                        try {

                            response.put("result", "ERR145");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR145"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_scripts").get(parameters.get("_script")) == null) {
                        try {

                            response.put("result", "ERR144");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR144"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "cmd")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        DATA.get("_core").get("_scripts").get(parameters.get("_script")).putIfAbsent("request", "");

                        temp_map = DATA.get("_core").get("_scripts").get(parameters.get("_script"));

                        response = new JSONObject(temp_map);

                    }


                } else if (parameters.get("_action").equals("get_scripts")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR119"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR126"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR102"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR103"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "cmd")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR129"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        if(DATA.get("_core").get("_project_scripts").get(parameters.get("_project")) != null){
                            for (Entry<String, String> entry : DATA.get("_core").get("_project_scripts").get(parameters.get("_project")).entrySet()) {

                                temp_map.put(entry.getKey(), DATA.get("_core").get("_scripts").get(entry.getKey()).get("name"));

                            }
                        }

                        response = new JSONObject(temp_map);

                    }


                } else { //TODO End of command actions
                    try {

                        response.put("result", "ERR105");
                        response.put("text", "Access denied");

                        if (API_EXPERIMENTAL) {
                            response.put("info", "Unkown action");
                        }

                    } catch (JSONException e) {

                        e.printStackTrace();
                    }
                }

            }

            server.writeResponse(httpExchange, response.toString());

        }
    }

    static class CmdHandler implements HttpHandler { //TODO Handler

        public void handle(HttpExchange httpExchange) throws IOException {

            ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");

            JSONObject response = new JSONObject();

            String response_str = "";

            String uri = httpExchange.getRequestURI().toString();

            String[] parts = uri.split("/");

            String project = parts[2];
            String script = parts[3];

            JSONObject parameters = getParametersJSONObject(httpExchange);

            if (httpExchange.getRequestHeaders().get("Authorization") == null) {
                try {

                    response.put("result", "ERR100");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", API_MESSAGES.get("ERR100"));
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else {
                if (project == null || script == null || !StringUtils.isAlphanumeric(project)
                        || !StringUtils.isAlphanumeric(script)) {
                    try {

                        response.put("result", "ERR110");
                        response.put("text", "Access denied");

                        if (API_EXPERIMENTAL) {
                            response.put("info", API_MESSAGES.get("ERR110"));
                        }

                    } catch (JSONException e) {

                        e.printStackTrace();
                    }
                } else {
                    if (DATA.get(project) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR104"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_scripts").get(script) == null) {
                        try {

                            response.put("result", "ERR144");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR144"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!validateProjectAuth(httpExchange.getRequestHeaders().get("Authorization").toArray()[0].toString(), project)
                            && DATA.get("_core").get("_projects").get(project).get("security").equals("true")) {
                        try {
                            response.put("result", "ERR113");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", API_MESSAGES.get("ERR113"));
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        JSONObject getObject = new JSONObject();
                        ConcurrentHashMap<String,String> tablesObject = new ConcurrentHashMap<String,String>();
                        ConcurrentHashMap<String,String> scriptsObject = new ConcurrentHashMap<String,String>();
                        ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>> putObject = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>();

                        if(DATA.get("_core").get("_project_tables").get(project) != null){
                            for (Entry<String, String> entry : DATA.get("_core").get("_project_tables").get(project).entrySet()) {

                                putObject.put(DATA.get("_core").get("_tables").get(project + "_" + entry.getKey()).get("name"), DATA.get(project).get(entry.getKey()));
                                tablesObject.put(DATA.get("_core").get("_tables").get(project + "_" + entry.getKey()).get("name"), project + "_" + entry.getKey());

                                try {

                                    getObject.put(DATA.get("_core").get("_tables").get(project + "_" + entry.getKey()).get("name"), DATA.get(project).get(entry.getKey()));

                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }

                            }
                        }

                        if(DATA.get("_core").get("_project_scripts").get(project) != null){
                            for (Entry<String, String> entry : DATA.get("_core").get("_project_scripts").get(project).entrySet()) {

                                scriptsObject.put(DATA.get("_core").get("_scripts").get(entry.getKey()).get("name"), entry.getKey());

                            }
                        }

                        engine.put("_get", getObject);
                        engine.put("_set", putObject);
                        engine.put("_req", parameters);
                        engine.put("_tables", new JSONObject(tablesObject));
                        engine.put("_scripts", new JSONObject(scriptsObject));

                        Boolean error = false;

                        System.out.println("CMD: "+uri);

                        try {

                            System.out.println("Script runned");

                            engine.eval("var Data = Java.type('java.util.concurrent.ConcurrentHashMap');");
                            engine.eval("var _data = Java.type('core.server.helpers');");
                            engine.eval("var _script = Java.type('core.server.scripts');");
                            engine.eval("_get = JSON.parse(_get);");
                            engine.eval("_req = JSON.parse(_req);");
                            engine.eval("_tables = JSON.parse(_tables);");
                            engine.eval("_scripts = JSON.parse(_scripts);");
                            engine.eval("strfy = JSON.stringify;");
                            engine.eval("insert = _data.insert;");
                            engine.eval("send = _scripts.send;");

                            engine.eval(DATA.get("_core").get("_scripts").get(script).get("script"));

                            if(engine.get("_res") != null) response_str = toJson(engine.get("_res").toString());

                        } catch (ScriptException e) {
                            //e.printStackTrace();
                            error = true;

                            System.out.println("Script error catched: "+ e.getMessage());
                        }

                        if(error){

                            try {

                                response.put("result", "ERR200");
                                response.put("text", "Scripting error");

                            } catch (JSONException e) {

                                e.printStackTrace();
                            }

                        }

                    }
                }
            }

            if(response_str.equals("")){
                response_str = response.toString();
            }

            server.writeResponse(httpExchange, response_str);
        }
    }

    // @@@@@
    // HELPER METHODS
    // @@@@@


    private static void SaveToDisk(){

        BufferedWriter bw = null;

        File junk_file = new File(API_OUTPUT_JUNK_PATH);

        try {

            /* This logic will make sure that the file
             * gets created if it is not present at the
             * specified location*/
            if (!junk_file.exists()) {
                junk_file.createNewFile();
            }

            FileWriter fw = new FileWriter(junk_file);
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
            CryptoUtils.encrypt(API_CRYPTO_KEY, junk_file, new File(API_OUTPUT_DATA_PATH));
        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }

        junk_file.delete();

    }

    private static String toJson(String s) {
        String r = "";
        try {
            r = new JSONObject(s).toString();
        } catch (JSONException ex) {
            // edited, to include @Arthur's comment
            // e.g. in case JSONArray is valid as well...
            r = "{\"result\":\"ERR201\", \"text\":\"Response parsing error\"}";
        }

        return r;
    }

    public static boolean isJSONValid(String test) {
        try {
            new JSONObject(test);
        } catch (JSONException ex) {
            // edited, to include @Arthur's comment
            // e.g. in case JSONArray is valid as well...
            try {
                new JSONArray(test);
            } catch (JSONException ex1) {
                return false;
            }
        }
        return true;
    }

    public static boolean hasColumns(String tablecode, Map<String, String> t_map){

        boolean ret = false;

        Map<String, String> map = new HashMap<>(t_map);

        map.remove("_action");
        map.remove("_project");
        map.remove("_table");
        map.remove("_email");

        for (Entry<String, String> entry : map.entrySet()) {

            if(DATA.get("_core").get("_table_columns").get(tablecode).get(entry.getKey()) != null){
                ret = true;
                break;
            }

        }

        return ret;

    }

    public static boolean hasColumnsFromValues(String tablecode, Map<String, String> map){

        boolean ret = true;

        map = new ConcurrentHashMap<>(map);


        map.remove("_action");
        map.remove("_project");
        map.remove("_table");
        map.remove("_email");

        for (Entry<String, String> entry : map.entrySet()) {

            if(DATA.get("_core").get("_table_columns").get(tablecode).get(entry.getValue()) == null){
                ret = false;
                break;
            }

        }

        return ret;

    }
    public static String getColumns(String tablecode){

        String ret = "";

        for (Entry<String, String> entry : DATA.get("_core").get("_table_columns").get(tablecode).entrySet()) {

            if(!ret.equals("")){
                ret = ret+",";
            }

            ret = ret+entry.getKey();

        }

        return ret;

    }
    public static String getColumnsCount(String tablecode){

        int ret = 0;

        for (Entry<String, String> entry : DATA.get("_core").get("_table_columns").get(tablecode).entrySet()) {

            ret++;

        }

        return ret+"";

    }

    public static boolean hasPriviliges(String email, String projectcode, String privilege) {

        boolean access = true;
        String priviliegecode;

        if (DATA.get("_core").get("_user_privileges").get(email).get(projectcode) != null) {

            priviliegecode = DATA.get("_core").get("_user_privileges").get(email).get(projectcode);

            if(privilege.equals("any")){
                access = true;
            }else if(DATA.get("_core").get("_privileges").get(priviliegecode).get(privilege) == null){
                access = false;
            }else if (DATA.get("_core").get("_privileges").get(priviliegecode).get(privilege).equals("true")) {
                access = true;
            } else {
                access = false;
            }

        } else {
            access = false;
        }

        return access;

    }

    public static boolean isValidEmail(String emailAddress) {
        return emailAddress.contains(" ") == false && emailAddress.matches(".+@.+\\.[a-z]+");
    }

    public static ConcurrentHashMap<String, ConcurrentHashMap<String, String>> filterTable(
            ConcurrentHashMap<String, ConcurrentHashMap<String, String>> map, String where) {

        ConcurrentHashMap<String, ConcurrentHashMap<String, String>> result = new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>();

        boolean success = true;

        for (Entry<String, ConcurrentHashMap<String, String>> entry : map.entrySet()) {

            ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");

            engine.put("_id", entry.getKey());

            for (Entry<String, String> se : entry.getValue().entrySet()) {
                engine.put(se.getKey(), se.getValue());
            }

            try {

                if(engine.eval(where).toString().equals("true")) result.put(entry.getKey(), entry.getValue());

            } catch (ScriptException e) {
                //e.printStackTrace();
                success = false;
                break;
            }

        }

        if (success)
            return result;
        else
            return new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>();
    }

    public static boolean filterAndDeletetable(
            ConcurrentHashMap<String, ConcurrentHashMap<String, String>> map, String where, String project, String table) {

        ConcurrentHashMap<String, ConcurrentHashMap<String, String>> result = new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>();

        boolean success = true;

        for (Entry<String, ConcurrentHashMap<String, String>> entry : map.entrySet()) {

            ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");

            engine.put("_id", entry.getKey());

            for (Entry<String, String> se : entry.getValue().entrySet()) {
                engine.put(se.getKey(), se.getValue());
            }

            try {

                if(engine.eval(where).toString().equals("true")) DATA.get(project).get(table).remove(entry.getKey());

            } catch (ScriptException e) {
                //e.printStackTrace();
                success = false;
                break;
            }

        }

        return success;
    }

    public static boolean validateAPIMapKeys(Map<String, String> map) {

        boolean auth = true;

        for (Entry<String, String> entry : map.entrySet()) {
            if (!isAlphanumeric(entry.getKey()) || entry.getKey().contains(" ")) {
                auth = false;
                break;
            }
        }

        return auth;

    }

    public static boolean validateAPIMapValues(Map<String, String> map) {

        boolean auth = true;

        for (Entry<String, String> entry : map.entrySet()) {
            if (!isAlphanumeric(entry.getValue())) {
                auth = false;
                break;
            }
        }

        return auth;

    }

    public static boolean validateAPIAuth(String CLIENT_HASH, Map<String, String> map) {

        boolean auth = true;

        String SERVER_HASH;

        SERVER_HASH = genAPIAuth(map);

        if (!CLIENT_HASH.equals(SERVER_HASH)) {
            auth = false;
        }

        return auth;

    }

    public static boolean validateProjectAuth(String CLIENT_HASH, String project) {

        boolean auth = false;

        String SERVER_HASH;

        for (Entry<String, String> entry : DATA.get("_core").get("_project_privileges").get(project).entrySet()) {
            SERVER_HASH = entry.getValue();
            if (CLIENT_HASH.equals(SERVER_HASH)) {
                auth = true;
                break;
            }
        }

        return auth;

    }

    public static String genAPIAuth(Map<String, String> map) {

        String SERVER_HASH = "";
        String MAP_COCAT = "";



        MAP_COCAT = concMapValues(map);
        SERVER_HASH = MD5(MAP_COCAT + API_CORE_KEY);

        return SERVER_HASH;

    }

    public static String genAPIAuth2(Map<String, String> map) {

        String SERVER_HASH = "";
        String MAP_COCAT = "";



        MAP_COCAT = concMapValues(map);
        SERVER_HASH = MAP_COCAT + API_CORE_KEY;

        return SERVER_HASH;

    }

    public static String genProjectAuth(Map<String, String> map, String project) {

        String SERVER_HASH = "";
        String MAP_COCAT = "";



        MAP_COCAT = concMapValues(map);
        SERVER_HASH = MD5(MAP_COCAT + DATA.get("_core").get("_projects").get(project).get("key"));

        return SERVER_HASH;

    }

    public static String genProjectAuthExperimental(Map<String, String> map, String project) {

        String SERVER_HASH = "";
        String MAP_COCAT = "";



        MAP_COCAT = concMapValues(map);
        SERVER_HASH = MAP_COCAT + DATA.get("_core").get("_projects").get(project).get("key");

        return SERVER_HASH;

    }

    public static boolean isDouble(String str) {
        try {
            Double.parseDouble(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    // @@@@@
    // GENERIC METHODS
    // @@@@@

    public static String concMapValues(Map<String, String> map) {
        String cocat = "";

        Set<String> keySet = map.keySet();
        ArrayList<String> list = new ArrayList<String>(keySet);
        Collections.sort(list);

        for (int i = 0; i < list.size(); i++) {
            cocat += map.get(list.get(i));
        }

        return cocat;
    }

    public static String MD5(String md5) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] array = md.digest(md5.getBytes());
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < array.length; ++i) {
                sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
        }
        return null;
    }

    public static void writeResponse(HttpExchange httpExchange, String response) throws IOException {
        Headers h = httpExchange.getResponseHeaders();
        h.set("Access-Control-Allow-Origin", "*");
        httpExchange.sendResponseHeaders(200, response.length());
        OutputStream os = httpExchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    static HashMap<String, String> getParametersJSON(HttpExchange httpExchange) {
        HashMap<String, String> parameters = new HashMap<>();
        InputStream inputStream = httpExchange.getRequestBody();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[2048];
        int read = 0;

        try {
            while ((read = inputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, read);
            }

            JSONObject jsonObject;

            try{
                jsonObject = new JSONObject(byteArrayOutputStream.toString());
            }catch(Exception xx){
                jsonObject = new JSONObject();
            }

            try
            {

                Iterator<?> keys = jsonObject.keys();

                while (keys.hasNext())
                {
                    String key = (String) keys.next();
                    String value = jsonObject.getString(key);
                    parameters.put(key, value);

                }


            }
            catch (Exception xx)
            {
                xx.toString();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return parameters;
    }
    static JSONObject getParametersJSONObject(HttpExchange httpExchange) {
        JSONObject parameters = new JSONObject();
        InputStream inputStream = httpExchange.getRequestBody();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[2048];
        int read = 0;

        try {
            while ((read = inputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, read);
            }

            JSONObject jsonObject;

            try{
                jsonObject = new JSONObject(byteArrayOutputStream.toString());
            }catch(Exception xx){
                jsonObject = new JSONObject();
            }

            parameters = jsonObject;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return parameters;
    }

    static HashMap<String, String> getParameters(HttpExchange httpExchange) {
        HashMap<String, String> parameters = new HashMap<>();
        InputStream inputStream = httpExchange.getRequestBody();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[2048];
        int read = 0;

        try {
            while ((read = inputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, read);
            }
            String[] keyValuePairs = byteArrayOutputStream.toString().split("&");
            for (String keyValuePair : keyValuePairs) {
                String[] keyValue = keyValuePair.split("=");
                if (keyValue.length != 2) {
                    continue;
                }
                parameters.put(URLDecoder.decode(keyValue[0], "UTF-8"), URLDecoder.decode(keyValue[1], "UTF-8"));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return parameters;
    }

    public static Map<String, String> queryToMap(String query) {
        Map<String, String> result = new HashMap<String, String>();
        for (String param : query.split("&")) {
            String pair[] = param.split("=");
            if (pair.length > 1) {
                result.put(pair[0], pair[1]);
            } else {
                result.put(pair[0], "");
            }
        }
        return result;
    }

    public static Map<String, String> mapArrayToMapStr(Map<String, String[]> map) {
        Map<String, String> result = new HashMap<String, String>();
        for (Map.Entry<String, String[]> entry : map.entrySet()) {
            result.put(entry.getKey(), Arrays.toString(entry.getValue()));
        }
        return result;
    }

    static final String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static SecureRandom rnd = new SecureRandom();

    public static String randomString(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(AB.charAt(rnd.nextInt(AB.length())));
        }
        return sb.toString();
    }

    public static String[] strArrAdd(String[] arr, String str) {
        String[] newArr = new String[arr.length + 1];

        for (int i = 0; i < newArr.length; i++) {
            if (i == arr.length) {
                newArr[i] = str;
            } else {
                newArr[i] = arr[i];
            }
        }

        return newArr;
    }

    public static String[] strArrRem(String[] arr, String str) {
        String[] newArr;

        List<String> list = new ArrayList<String>(Arrays.asList(arr));
        list.remove(str);
        newArr = list.toArray(new String[0]);

        return newArr;
    }

    static String get_SHA_512(String toHash, String salt) {
        MessageDigest md = null;
        byte[] hash = null;
        try {
            md = MessageDigest.getInstance("SHA-512");
            hash = md.digest(toHash.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return convertToHex(hash);
    }

    static String convertToHex(byte[] raw) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < raw.length; i++) {
            sb.append(Integer.toString((raw[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    public static double eval(final String str) {
        return new Object() {
            int pos = -1, ch;

            void nextChar() {
                ch = (++pos < str.length()) ? str.charAt(pos) : -1;
            }

            boolean eat(int charToEat) {
                while (ch == ' ') {
                    nextChar();
                }
                if (ch == charToEat) {
                    nextChar();
                    return true;
                }
                return false;
            }

            double parse() {
                nextChar();
                double x = parseExpression();
                if (pos < str.length()) {
                    throw new RuntimeException("Unexpected: " + (char) ch);
                }
                return x;
            }

            // Grammar:
            // expression = term | expression `+` term | expression `-` term
            // term = factor | term `*` factor | term `/` factor
            // factor = `+` factor | `-` factor | `(` expression `)`
            // | number | functionName factor | factor `^` factor
            double parseExpression() {
                double x = parseTerm();
                for (; ; ) {
                    if (eat('+')) {
                        x += parseTerm(); // addition
                    } else if (eat('-')) {
                        x -= parseTerm(); // subtraction
                    } else {
                        return x;
                    }
                }
            }

            double parseTerm() {
                double x = parseFactor();
                for (; ; ) {
                    if (eat('*')) {
                        x *= parseFactor(); // multiplication
                    } else if (eat('/')) {
                        x /= parseFactor(); // division
                    } else {
                        return x;
                    }
                }
            }

            double parseFactor() {
                if (eat('+')) {
                    return parseFactor(); // unary plus
                }
                if (eat('-')) {
                    return -parseFactor(); // unary minus
                }
                double x;
                int startPos = this.pos;
                if (eat('(')) { // parentheses
                    x = parseExpression();
                    eat(')');
                } else if ((ch >= '0' && ch <= '9') || ch == '.') { // numbers
                    while ((ch >= '0' && ch <= '9') || ch == '.') {
                        nextChar();
                    }
                    x = Double.parseDouble(str.substring(startPos, this.pos));
                } else if (ch >= 'a' && ch <= 'z') { // functions
                    while (ch >= 'a' && ch <= 'z') {
                        nextChar();
                    }
                    String func = str.substring(startPos, this.pos);
                    x = parseFactor();
                    if (func.equals("sqrt")) {
                        x = Math.sqrt(x);
                    } else if (func.equals("sin")) {
                        x = Math.sin(Math.toRadians(x));
                    } else if (func.equals("cos")) {
                        x = Math.cos(Math.toRadians(x));
                    } else if (func.equals("tan")) {
                        x = Math.tan(Math.toRadians(x));
                    } else {
                        throw new RuntimeException("Unknown function: " + func);
                    }
                } else {
                    throw new RuntimeException("Unexpected: " + (char) ch);
                }

                if (eat('^')) {
                    x = Math.pow(x, parseFactor()); // exponentiation
                }
                return x;
            }
        }.parse();
    }

    public static List<String> MergeUniqueKeys(List<String> Keys, List<String> Map) {
        List<String> MapCopy = new ArrayList<>(Map);
        MapCopy.removeAll(Keys);
        Keys.addAll(MapCopy);
        return Keys;
    }

    public static List<String> MultiMergeUniqueKeys(List<String> Keys, HashMap<String, HashMap<String, String>> Map) {
        List<String> innerMap = new ArrayList<>();
        List<String> MainKeys = new ArrayList<>(Map.keySet());
        for (String innerKey : MainKeys) {
            innerMap = new ArrayList<>(Map.get(innerKey).keySet());
            innerMap.removeAll(Keys);
            Keys.addAll(innerMap);
        }
        return Keys;
    }

    public static int Random(int min, int max) {
        return ThreadLocalRandom.current().nextInt(min, max);
    }

    public static double RandomDouble(int rangeMin, int rangeMax) {
        Random r = new Random();
        return rangeMin + (rangeMax - rangeMin) * r.nextDouble();
    }
    public static boolean isAlphanumeric(String str) {
        for (int i=0; i<str.length(); i++) {
            char c = str.charAt(i);
            if (c < 0x30 || (c >= 0x3a && c <= 0x40) || (c > 0x5a && c <= 0x60) || c > 0x7a)
                return false;
        }
        return true;
    }

    public static class helpers{ //TODO helper class
        public static Map<String, String> insert(String project_table, ConcurrentHashMap<String, String> map){

            String project = project_table.split("_")[0];
            String table = project_table.split("_")[1];
            String index = "0";
            Map<String, String> response = new HashMap<String, String>();

            ConcurrentHashMap<String, String> temp_map = new ConcurrentHashMap<String, String>();

            for (Entry<String, String> entry : map.entrySet()) {
                if(DATA.get("_core").get("_table_columns").get(project_table).get(entry.getKey()) != null){
                    temp_map.put(entry.getKey(), entry.getValue());
                }
            }

            index = DATA.get("_core").get("_tables").get(project + "_" + table).get("index");

            DATA.get(project).get(table).put(index, temp_map);

            DATA.get("_core").get("_tables").get(project + "_" + table).put("index",
                    (Integer.parseInt(index) + 1) + "");

            response.put("index", index);

            return response;
        }
    }

    public static class scripts{ //TODO scripts class
        public static void send(String script, String request){
            new Thread(() -> {
                ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");

                engine.put("_req", request);

                if(DATA.get("_core").get("_scripts").get(script) != null){
                    try{
                        engine.eval("_req = JSON.parse(_req)");
                        engine.eval(DATA.get("_core").get("_scripts").get(script).get("script"));
                    }catch(ScriptException e){

                    }
                }

            }).start();
        }
    }

    private static String readLineByLineJava8(String filePath)
    {
        StringBuilder contentBuilder = new StringBuilder();
        try (Stream<String> stream = Files.lines( Paths.get(filePath), StandardCharsets.UTF_8))
        {
            stream.forEach(s -> contentBuilder.append(s));
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        return contentBuilder.toString();
    }

    private static String serialize(Serializable o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    private static Object deserialize(String s) throws IOException,
            ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data));
        Object o = ois.readObject();
        ois.close();
        return o;
    }

}