package core;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.lang.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

public class server {

    private static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1); // Initializing scheduler

    static boolean API_FIRST_RUN = true;
    static String API_CORE_KEY = "ntiqfki5h28HaVd2eycytwHZn4ooQmRmsU4tQx2y3g7aZCoE8CFbvEWT2omjDjj4"; // System Key to validate ADM commands
    static ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>> DATA = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>>();
    static boolean API_EXPERIMENTAL = true; // Disable ADM API Auth and show additional information while an error

    /**
     * @param args
     */

    public static void main(String[] args) throws Exception {

        try {

            System.out.println("Starting server...");

            // setup the socket address
            InetSocketAddress address = new InetSocketAddress(8000);

            // initialise the HTTPS server
            HttpsServer httpsServer = HttpsServer.create(address, 0);
            SSLContext sslContext = SSLContext.getInstance("TLS");

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
            });
            // TODO Handlers contexts
            httpsServer.createContext("/adm", new AdmHandler());
            httpsServer.createContext("/put", new PutHandler());
            httpsServer.createContext("/get", new GetHandler());
            httpsServer.createContext("/del", new DelHandler());
            httpsServer.setExecutor(null); // creates a default executor
            httpsServer.start();

            System.out.println("Server is runing");

        } catch (Exception exception) {
            System.out.println("Failed to create HTTPS server on port " + 8000 + " of localhost");
            exception.printStackTrace();

        }

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

            DATA.put("_core", temp_core);

            temp_map = new ConcurrentHashMap<>();

            temp_map.put("name", "Master Developer");
            temp_map.put("email", "dev@baserel.com");
            temp_map.put("pass", MD5("12345678"));
            temp_map.put("verified", "true");
            temp_map.put("super", "true");
            temp_map.put("fingerprint", randomString(32));

            temp_map2.put("email", "dev@baserel.com");

            DATA.get("_core").get("_users").put("dev@baserel.com", temp_map);
            DATA.get("_core").get("_user_fingerprints").put(temp_map.get("fingerprint"), temp_map2);
        }

        // Runnable
        Runnable updateGame = new Runnable() {
            @Override
            public void run() {

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

    static class PutHandler implements HttpHandler { //TODO Handler

        public void handle(HttpExchange httpExchange) throws IOException {

            JSONObject response = new JSONObject();

            String uri = httpExchange.getRequestURI().toString();

            String[] parts = uri.split("/");

            String datamap = parts[2];
            String continent = parts[3];

            HashMap<String, String> parameters = getParameters(httpExchange);

            ConcurrentHashMap<String, String> temp_map = new ConcurrentHashMap<String, String>();

            if (parameters.get("_auth") == null) {
                try {

                    response.put("result", "ERR100");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", "_auth is null");
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else if (datamap == null || continent == null || !StringUtils.isAlphanumeric(datamap)
                    || !StringUtils.isAlphanumeric(continent)) {
                try {
                    response.put("result", "ERR110");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", "Unexpected URI");
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else if (DATA.get(datamap) == null) {
                try {

                    response.put("result", "ERR104");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", "project does not exists");
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else {

                String index = (parameters.get("_id") == null ? "" : parameters.get("_id"));

                parameters.remove("_id");

                if (!validateDatamapAuth(parameters, datamap)
                        && DATA.get("_core").get("_projects").get(datamap).get("security").equals("true")) {
                    try {
                        response.put("result", "ERR113");
                        response.put("text", "Access denied");

                        if (API_EXPERIMENTAL) {
                            response.put("info",
                                    "Datamap Auth Validation failed " + genDatamapAuth2(parameters, datamap));
                        }

                    } catch (JSONException e) {

                        e.printStackTrace();
                    }
                } else {

                    parameters.remove("_auth");

                    if (DATA.get(datamap).get(continent) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "table does not exists");
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
                                        response.put("info",
                                                "The parameters contains keys with non-alphanumeric characters");
                                    }
                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }

                            } else {

                                temp_map = new ConcurrentHashMap<String, String>();

                                for (Entry<String, String> entry : parameters.entrySet()) {
                                    temp_map.put(entry.getKey(), entry.getValue());
                                }

                                index = DATA.get("_core").get("_tables").get(datamap + "_" + continent).get("index");

                                DATA.get(datamap).get(continent).put(index, temp_map);

                                DATA.get("_core").get("_tables").get(datamap + "_" + continent).put("index",
                                        (Integer.parseInt(index) + 1) + "");

                                try {

                                    response.put("result", "SUC100");
                                    response.put("text", "Done");

                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }

                            }

                        } else {
                            if (DATA.get(datamap).get(continent).get(index) == null) {
                                try {

                                    response.put("result", "ERR111");
                                    response.put("text", "Access denied");

                                    if (API_EXPERIMENTAL) {
                                        response.put("info", "Table record id does not exists");
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
                                            response.put("info",
                                                    "The parameters contains keys with non-alphanumeric characters");
                                        }
                                    } catch (JSONException e) {

                                        e.printStackTrace();
                                    }

                                } else {

                                    temp_map = DATA.get(datamap).get(continent).get(index);

                                    for (Entry<String, String> entry : parameters.entrySet()) {
                                        temp_map.put(entry.getKey(), entry.getValue());
                                    }

                                    DATA.get(datamap).get(continent).put(index, temp_map);

                                    try {

                                        response.put("result", "SUC100");
                                        response.put("text", "Done");
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

            String datamap = parts[2];
            String continent = parts[3];

            Map<String, String> parameters = getParameters(httpExchange);

            if (parameters.get("_auth") == null) {
                try {

                    response.put("result", "ERR100");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", "_auth is null");
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else {
                if (datamap == null || continent == null || !StringUtils.isAlphanumeric(datamap)
                        || !StringUtils.isAlphanumeric(continent)) {
                    try {

                        response.put("result", "ERR110");
                        response.put("text", "Access denied");

                        if (API_EXPERIMENTAL) {
                            response.put("info", "Unexpected URI");
                        }

                    } catch (JSONException e) {

                        e.printStackTrace();
                    }
                } else {
                    if (DATA.get(datamap) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        String index = (parameters.get("_id") == null ? "" : parameters.get("_id"));

                        parameters.remove("_id");

                        if (!validateDatamapAuth(parameters, datamap)
                                && DATA.get("_core").get("_projects").get(datamap).get("security").equals("true")) {
                            try {
                                response.put("result", "ERR113");
                                response.put("text", "Access denied");

                                if (API_EXPERIMENTAL) {
                                    response.put("info", "Project Auth Validation failed");
                                }

                            } catch (JSONException e) {

                                e.printStackTrace();
                            }
                        } else {

                            parameters.remove("_auth");

                            if (DATA.get(datamap).get(continent) == null) {
                                try {

                                    response.put("result", "ERR109");
                                    response.put("text", "Access denied");

                                    if (API_EXPERIMENTAL) {
                                        response.put("info", "table does not exists");
                                    }

                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }
                            } else {

                                if (index != "") {
                                    response = new JSONObject(DATA.get(datamap).get(continent).get(index));
                                } else if (parameters.size() == 0) {
                                    response = new JSONObject(DATA.get(datamap).get(continent));
                                } else {
                                    response = new JSONObject(
                                            filterContinent(DATA.get(datamap).get(continent), parameters));
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

            String datamap = parts[2];
            String continent = parts[3];

            Map<String, String> parameters = getParameters(httpExchange);

            if (parameters.get("_auth") == null) {
                try {

                    response.put("result", "ERR100");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", "_auth is null");
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else {
                if (datamap == null || continent == null || !StringUtils.isAlphanumeric(datamap)
                        || !StringUtils.isAlphanumeric(continent)) {
                    try {

                        response.put("result", "ERR110");
                        response.put("text", "Access denied");

                        if (API_EXPERIMENTAL) {
                            response.put("info", "Unexpected URI");
                        }

                    } catch (JSONException e) {

                        e.printStackTrace();
                    }
                } else {
                    if (DATA.get(datamap) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        String index = (parameters.get("_id") == null ? "" : parameters.get("_id"));

                        parameters.remove("_id");

                        if (!validateDatamapAuth(parameters, datamap)
                                && DATA.get("_core").get("_projects").get(datamap).get("security").equals("true")) {
                            try {
                                response.put("result", "ERR113");
                                response.put("text", "Access denied");

                                if (API_EXPERIMENTAL) {
                                    response.put("info", "Project Auth Validation failed");
                                }

                            } catch (JSONException e) {

                                e.printStackTrace();
                            }
                        } else {

                            parameters.remove("_auth");

                            if (DATA.get(datamap).get(continent) == null) {
                                try {

                                    response.put("result", "ERR109");
                                    response.put("text", "Access denied");

                                    if (API_EXPERIMENTAL) {
                                        response.put("info", "table does not exists");
                                    }

                                } catch (JSONException e) {

                                    e.printStackTrace();
                                }
                            } else {

                                if (index != "") {

                                    DATA.get(datamap).get(continent).remove(index);

                                    try {

                                        response.put("result", "SUC100");
                                        response.put("text", "Done");

                                    } catch (JSONException e) {

                                        e.printStackTrace();
                                    }

                                } else if (parameters.size() == 0) {

                                    DATA.get(datamap).get(continent).clear();

                                    try {

                                        response.put("result", "SUC100");
                                        response.put("text", "Done");

                                    } catch (JSONException e) {

                                        e.printStackTrace();
                                    }

                                } else {

                                    filterAndDeleteContinent(datamap, continent, parameters);

                                    try {

                                        response.put("result", "SUC100");
                                        response.put("text", "Done");

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

    static class AdmHandler implements HttpHandler { //TODO Handler

        public void handle(HttpExchange httpExchange) throws IOException {

            JSONObject response = new JSONObject();
            Map<String, String> parameters = getParameters(httpExchange);

            ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>> temp_table = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>();
            ConcurrentHashMap<String, ConcurrentHashMap<String, String>> temp_keymap = new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>();
            ConcurrentHashMap<String, String> temp_map = new ConcurrentHashMap<String, String>();
            ConcurrentHashMap<String, String> temp_map2 = new ConcurrentHashMap<String, String>();

            if (parameters.get("_auth") == null) {
                try {

                    response.put("result", "ERR100");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", "_auth is null");
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }
            } else if (!validateAPIAuth(parameters) && !API_EXPERIMENTAL) {
                try {
                    response.put("result", "ERR106");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", "API Auth Validation failed ");
                    }

                } catch (JSONException e) {

                    e.printStackTrace();
                }

            } else if (parameters.get("_action") == null) {
                try {

                    response.put("result", "ERR101");
                    response.put("text", "Access denied");

                    if (API_EXPERIMENTAL) {
                        response.put("info", "_action is null");
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
                                response.put("info", "_name is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_pass") == null) {

                        try {

                            response.put("result", "ERR120");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_pass is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_pass").length() < 8) {

                        try {

                            response.put("result", "ERR124");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_pass must be at least 8 characters long");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_verified") == null) {

                        try {

                            response.put("result", "ERR121");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_verified is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (!parameters.get("_verified").equals("true")
                            && !parameters.get("_verified").equals("false")) {

                        try {

                            response.put("result", "ERR115");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                // response.put("info", "_verified is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_super") == null) {
                        try {

                            response.put("result", "ERR122");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                // response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!parameters.get("_super").equals("true") && !parameters.get("_super").equals("false")) {
                        try {

                            response.put("result", "ERR115");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                // response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!isValidEmail(parameters.get("_email"))) {
                        try {

                            response.put("result", "ERR125");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                // response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) != null) {
                        try {

                            response.put("result", "ERR123");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                // response.put("info", "project does not exists");
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
                        temp_map.put("verified", parameters.get("_verified"));
                        temp_map.put("super", parameters.get("_super"));
                        temp_map.put("fingerprint", fingerprint);

                        DATA.get("_core").get("_users").put(parameters.get("_email"), temp_map);

                        temp_map = new ConcurrentHashMap<String, String>();

                        temp_map.put("email", parameters.get("_email"));

                        DATA.get("_core").get("_user_fingerprints").put(fingerprint, temp_map);

                        try {
                            response.put("result", "SUC100");
                            response.put("text", "Done");
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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_pass") != null && parameters.get("_pass").length() < 8) {

                        try {

                            response.put("result", "ERR124");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_pass must be at least 8 characters long");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_verified") != null && !parameters.get("_verified").equals("true")
                            && !parameters.get("_verified").equals("false")) {

                        try {

                            response.put("result", "ERR115");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                // response.put("info", "_verified is null");
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
                                // response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_nemail") != null && !isValidEmail(parameters.get("_nemail"))) {
                        try {

                            response.put("result", "ERR125");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                // response.put("info", "project does not exists");
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
                                // response.put("info", "project does not exists");
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

                        if (parameters.get("_verified") != null)
                            temp_map.put("verified", parameters.get("_verified"));

                        if (parameters.get("_super") != null)
                            temp_map.put("super", parameters.get("_super"));

                        DATA.get("_core").get("_users").put(parameters.get("_email"), temp_map);

                        try {
                            response.put("result", "SUC100");
                            response.put("text", "Done");
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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User does not exists");
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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")).get("super").equals("true")) {

                        try {

                            response.put("result", "ERR132");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "Super users cannot be deleted");
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
                            response.put("text", "Done");

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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else {

                        String fingerprint = randomString(32);

                        DATA.get("_core").get("_users").get(parameters.get("_email")).put("fingerprint", fingerprint);

                        try {

                            response.put("result", "SUC100");
                            response.put("text", "Done");

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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_project is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_fingerprint") == null) {
                        try {

                            response.put("result", "ERR133");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_table is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")) == null) {
                        try {

                            response.put("result", "ERR130");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User fingerprint does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project must contain only alphanumeric characters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "You do not have the privileges to perform this action");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_put") == null || (!parameters.get("_put").equals("true") && !parameters.get("_put").equals("false")) || parameters.get("_get") == null || (!parameters.get("_get").equals("true") && !parameters.get("_get").equals("false")) || parameters.get("_del") == null || (!parameters.get("_del").equals("true") && !parameters.get("_del").equals("false")) || parameters.get("_adm") == null || (!parameters.get("_adm").equals("true") && !parameters.get("_adm").equals("false")) || parameters.get("_cmd") == null || (!parameters.get("_cmd").equals("true") && !parameters.get("_cmd").equals("false"))) {
                        try {

                            response.put("result", "ERR135");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "Unexpected parameters");
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
                            response.put("text", "Done");

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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_project is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_fingerprint") == null) {
                        try {

                            response.put("result", "ERR133");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_table is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")) == null) {
                        try {

                            response.put("result", "ERR130");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User fingerprint does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project must contain only alphanumeric characters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "any")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "You do not have the privileges to perform this action");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_project_privileges").get(parameters.get("_project")).get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")) == null) {
                        try {

                            response.put("result", "ERR134");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "Privileges not found for this user");
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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_project is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_fingerprint") == null) {
                        try {

                            response.put("result", "ERR133");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_table is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")) == null) {
                        try {

                            response.put("result", "ERR130");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User fingerprint does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project must contain only alphanumeric characters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "You do not have the privileges to perform this action");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get("_core").get("_project_privileges").get(parameters.get("_project")).get(DATA.get("_core").get("_user_fingerprints").get(parameters.get("_fingerprint")).get("email")) == null) {
                        try {

                            response.put("result", "ERR134");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "Privileges not found for this user");
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
                            response.put("text", "Done");

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }


                } else if (parameters.get("_action").equals("create_project")) {  //TODO command action
                    if (parameters.get("_name") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_name is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {
                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
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
                        temp_map.put("security", "false");

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

                            response.put("result", "SUC100");
                            response.put("text", "Done");
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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_project is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project must contain only alphanumeric characters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "any")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "You do not have the privileges to perform this action");
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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_project is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project must contain only alphanumeric characters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_name") == null || parameters.get("_security") == null || (!parameters.get("_security").equals("true") && !parameters.get("_security").equals("false"))) {
                        try {

                            response.put("result", "ERR135");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "Unexpected parameters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "You do not have the privileges to perform this action");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        DATA.get("_core").get("_projects").get(parameters.get("_project")).put("name", parameters.get("_name"));
                        DATA.get("_core").get("_projects").get(parameters.get("_project")).put("security", parameters.get("_security"));

                        try {

                            response.put("result", "SUC100");
                            response.put("text", "Done");

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }

                    // END DEFINING ACTIONS

                } else if (parameters.get("_action").equals("delete_project")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_project is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project must contain only alphanumeric characters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "You do not have the privileges to perform this action");
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


                        DATA.get("_core").get("_user_privileges").get(parameters.get("_email")).remove(parameters.get("_project"));
                        DATA.get("_core").get("_project_privileges").remove(parameters.get("_project"));
                        DATA.get("_core").get("_tables").remove(parameters.get("_project"));

                        try {

                            response.put("result", "SUC100");
                            response.put("text", "Done");

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    }

                    // END DEFINING ACTIONS

                } else if (parameters.get("_action").equals("create_table")) { //TODO command action


                    if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_project is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_name") == null) {
                        try {

                            response.put("result", "ERR118");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_name is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project must contain only alphanumeric characters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "You do not have the privileges to perform this action");
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


                        DATA.get("_core").get("_tables").put(parameters.get("_project") + "_" + table_code, temp_map);

                        if (DATA.get("_core").get("_project_tables").get(parameters.get("_project")) == null) {
                            temp_map = new ConcurrentHashMap<String, String>();
                            DATA.get("_core").get("_project_tables").put(parameters.get("_project"), temp_map);
                        }

                        DATA.get("_core").get("_project_tables").get(parameters.get("_project")).put(table_code, table_code);

                        try {

                            response.put("result", "SUC100");
                            response.put("text", "Done");
                            response.put("table", table_code);

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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_project is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (parameters.get("_table") == null) {
                        try {

                            response.put("result", "ERR107");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_table is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project must contain only alphanumeric characters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "table does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "adm")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "You do not have the privileges to perform this action");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        DATA.get("_core").get("_tables").remove(parameters.get("_project") + "_" + parameters.get("_table"));
                        DATA.get("_core").get("_project_tables").get(parameters.get("_project")).remove(parameters.get("_table"));
                        DATA.get(parameters.get("_project")).remove(parameters.get("_table"));

                        try {

                            response.put("result", "SUC100");
                            response.put("text", "Done");

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
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_project") == null) {

                        try {

                            response.put("result", "ERR102");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_project is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_table") == null) {

                        try {

                            response.put("result", "ERR107");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_table is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get(parameters.get("_project")) == null) {
                        try {

                            response.put("result", "ERR104");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
                        try {

                            response.put("result", "ERR103");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "project must contain only alphanumeric characters");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
                        try {

                            response.put("result", "ERR109");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "table does not exists");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else if (!server.hasPriviliges(parameters.get("_email"), parameters.get("_project"), "any")) {
                        try {

                            response.put("result", "ERR129");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "You do not have the privileges to perform this action");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }
                    } else {

                        temp_map = DATA.get("_core").get("_tables").get(parameters.get("_project") + "_" + parameters.get("_table"));

                        if(DATA.get(parameters.get("_project")).get(parameters.get("_table")) != null) temp_map.put("records_count", ""+DATA.get(parameters.get("_project")).get(parameters.get("_table")).size());
                        else temp_map.put("records_count", "0");

                        response = new JSONObject(temp_map);

                    }


                } else if (parameters.get("_action").equals("set_api_experimental")) { //TODO command action


                    if (parameters.get("_experimental") == null) {

                        try {

                            response.put("result", "ERR117");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_experimental is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (!parameters.get("_experimental").equals("false") && !parameters.get("_experimental").equals("true")) {

                        try {

                            response.put("result", "ERR115");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "Unexpected value");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (parameters.get("_email") == null) {

                        try {

                            response.put("result", "ERR119");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "_email is null");
                            }

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    } else if (DATA.get("_core").get("_users").get(parameters.get("_email")) == null) {

                        try {

                            response.put("result", "ERR126");
                            response.put("text", "Access denied");

                            if (API_EXPERIMENTAL) {
                                response.put("info", "User email does not exists");
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
                            response.put("text", "Done");

                        } catch (JSONException e) {

                            e.printStackTrace();
                        }

                    }

                } else {
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

    // @@@@@
    // HELPER METHODS
    // @@@@@

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

    public static ConcurrentHashMap<String, ConcurrentHashMap<String, String>> filterContinent(
            ConcurrentHashMap<String, ConcurrentHashMap<String, String>> map, Map<String, String> params) {

        ConcurrentHashMap<String, ConcurrentHashMap<String, String>> result = new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>();
        boolean success = true;

        for (Entry<String, ConcurrentHashMap<String, String>> entry : map.entrySet()) {

            for (Entry<String, String> c_entry : params.entrySet()) {
                if (entry.getValue().get(c_entry.getKey()) != null) {

                    if (c_entry.getValue().substring(0, 1).equals("!")) {
                        if (!entry.getValue().get(c_entry.getKey()).equals(c_entry.getValue().substring(1))) {
                            result.put(entry.getKey(), entry.getValue());
                        }
                    } else if (c_entry.getValue().substring(0, 2).equals(">=")) {
                        if (isDouble(entry.getValue().get(c_entry.getKey()))
                                && isDouble(c_entry.getValue().substring(2))) {

                            if (Double.parseDouble(entry.getValue().get(c_entry.getKey())) >= Float
                                    .parseFloat(c_entry.getValue().substring(2))) {

                                result.put(entry.getKey(), entry.getValue());

                            }

                        } else {
                            success = false;
                        }
                    } else if (c_entry.getValue().substring(0, 2).equals("<=")) {
                        if (isDouble(entry.getValue().get(c_entry.getKey()))
                                && isDouble(c_entry.getValue().substring(2))) {

                            if (Double.parseDouble(entry.getValue().get(c_entry.getKey())) <= Float
                                    .parseFloat(c_entry.getValue().substring(2))) {

                                result.put(entry.getKey(), entry.getValue());

                            }

                        } else {
                            success = false;
                        }
                    } else if (c_entry.getValue().substring(0, 1).equals(">")) {
                        if (isDouble(entry.getValue().get(c_entry.getKey()))
                                && isDouble(c_entry.getValue().substring(1))) {

                            if (Double.parseDouble(entry.getValue().get(c_entry.getKey())) > Float
                                    .parseFloat(c_entry.getValue().substring(1))) {

                                result.put(entry.getKey(), entry.getValue());

                            }

                        } else {
                            success = false;
                        }
                    } else if (c_entry.getValue().substring(0, 1).equals("<")) {
                        if (isDouble(entry.getValue().get(c_entry.getKey()))
                                && isDouble(c_entry.getValue().substring(1))) {

                            if (Double.parseDouble(entry.getValue().get(c_entry.getKey())) < Float
                                    .parseFloat(c_entry.getValue().substring(1))) {

                                result.put(entry.getKey(), entry.getValue());

                            }

                        } else {
                            success = false;
                        }
                    } else {

                        if (entry.getValue().get(c_entry.getKey()).equals(c_entry.getValue())) {
                            result.put(entry.getKey(), entry.getValue());
                        }
                    }

                }

            }

        }

        if (success)
            return result;
        else
            return new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>();
    }

    public static void filterAndDeleteContinent(String datamap, String continent, Map<String, String> params) {

        for (Entry<String, ConcurrentHashMap<String, String>> entry : DATA.get(datamap).get(continent).entrySet()) {

            for (Entry<String, String> c_entry : params.entrySet()) {
                if (entry.getValue().get(c_entry.getKey()) != null) {

                    if (c_entry.getValue().substring(0, 1).equals("!")) {
                        if (!entry.getValue().get(c_entry.getKey()).equals(c_entry.getValue().substring(1))) {
                            DATA.get(datamap).get(continent).remove(entry.getKey());
                        }
                    } else if (c_entry.getValue().substring(0, 2).equals(">=")) {
                        if (isDouble(entry.getValue().get(c_entry.getKey()))
                                && isDouble(c_entry.getValue().substring(2))) {

                            if (Double.parseDouble(entry.getValue().get(c_entry.getKey())) >= Float
                                    .parseFloat(c_entry.getValue().substring(2))) {

                                DATA.get(datamap).get(continent).remove(entry.getKey());

                            }

                        }
                    } else if (c_entry.getValue().substring(0, 2).equals("<=")) {
                        if (isDouble(entry.getValue().get(c_entry.getKey()))
                                && isDouble(c_entry.getValue().substring(2))) {

                            if (Double.parseDouble(entry.getValue().get(c_entry.getKey())) <= Float
                                    .parseFloat(c_entry.getValue().substring(2))) {

                                DATA.get(datamap).get(continent).remove(entry.getKey());

                            }

                        }
                    } else if (c_entry.getValue().substring(0, 1).equals(">")) {
                        if (isDouble(entry.getValue().get(c_entry.getKey()))
                                && isDouble(c_entry.getValue().substring(1))) {

                            if (Double.parseDouble(entry.getValue().get(c_entry.getKey())) > Float
                                    .parseFloat(c_entry.getValue().substring(1))) {

                                DATA.get(datamap).get(continent).remove(entry.getKey());

                            }

                        }
                    } else if (c_entry.getValue().substring(0, 1).equals("<")) {
                        if (isDouble(entry.getValue().get(c_entry.getKey()))
                                && isDouble(c_entry.getValue().substring(1))) {

                            if (Double.parseDouble(entry.getValue().get(c_entry.getKey())) < Float
                                    .parseFloat(c_entry.getValue().substring(1))) {

                                DATA.get(datamap).get(continent).remove(entry.getKey());

                            }

                        }
                    } else {

                        if (entry.getValue().get(c_entry.getKey()).equals(c_entry.getValue())) {
                            DATA.get(datamap).get(continent).remove(entry.getKey());
                        }
                    }

                }

            }

        }
    }

    public static boolean validateAPIMapKeys(Map<String, String> map) {

        boolean auth = true;

        for (Entry<String, String> entry : map.entrySet()) {
            if (!StringUtils.isAlphanumeric(entry.getKey())) {
                auth = false;
                break;
            }
        }

        return auth;

    }

    public static boolean validateAPIAuth(Map<String, String> map) {

        boolean auth = true;

        String CLIENT_HASH;
        String SERVER_HASH;

        CLIENT_HASH = map.get("_auth");
        SERVER_HASH = genAPIAuth(map);

        if (!CLIENT_HASH.equals(SERVER_HASH)) {
            auth = false;
        }

        return auth;

    }

    public static boolean validateDatamapAuth(Map<String, String> map, String datamap) {

        boolean auth = true;

        String CLIENT_HASH;
        String SERVER_HASH;

        CLIENT_HASH = map.get("_auth");
        SERVER_HASH = genDatamapAuth(map, datamap);

        if (!CLIENT_HASH.equals(SERVER_HASH)) {
            auth = false;
        }

        return auth;

    }

    public static String genAPIAuth(Map<String, String> map) {

        String SERVER_HASH = "";
        String MAP_COCAT = "";

        map.remove("_auth");

        MAP_COCAT = concMapValues(map);
        SERVER_HASH = MD5(MAP_COCAT + API_CORE_KEY);

        return SERVER_HASH;

    }

    public static String genAPIAuth2(Map<String, String> map) {

        String SERVER_HASH = "";
        String MAP_COCAT = "";

        map.remove("_auth");

        MAP_COCAT = concMapValues(map);
        SERVER_HASH = MAP_COCAT + API_CORE_KEY;

        return SERVER_HASH;

    }

    public static String genDatamapAuth(Map<String, String> map, String datamap) {

        String SERVER_HASH = "";
        String MAP_COCAT = "";

        map.remove("_auth");

        MAP_COCAT = concMapValues(map);
        SERVER_HASH = MD5(MAP_COCAT + DATA.get("_core").get("_projects").get(datamap).get("key"));

        return SERVER_HASH;

    }

    public static String genDatamapAuth2(Map<String, String> map, String datamap) {

        String SERVER_HASH = "";
        String MAP_COCAT = "";

        map.remove("_auth");

        MAP_COCAT = concMapValues(map);
        SERVER_HASH = MAP_COCAT + DATA.get("_core").get("_projects").get(datamap).get("key");

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

}