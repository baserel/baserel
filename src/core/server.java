package core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
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

import org.apache.commons.lang.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class server {

	public static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1); // Initializing scheduler

	static boolean API_FIRST_RUN = true;
	static String API_CORE_KEY = "ntiqfki5h28HaVd2eycytwHZn4ooQmRmsU4tQx2y3g7aZCoE8CFbvEWT2omjDjj4"; // System Key to
																										// validate ADM
																										// commands
	static ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>> DATA = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>>();
	static boolean API_EXPERIMENTAL = true; // Disable ADM API Auth and show additional information while an error

	public static void main(String[] args) throws Exception {

		System.out.println("Starting server...");

		HttpServer server = HttpServer.create(new InetSocketAddress(8181), 0); // Creating server

		server.createContext("/test", new InfoHandler()); // Test Handler
		server.createContext("/adm", new AdmHandler());
		server.createContext("/put", new PutHandler());
		server.createContext("/get", new GetHandler());
		server.createContext("/del", new DelHandler());

		server.setExecutor(null); // creates a default executor
		server.start();

		System.out.println("The server is running: 1.3.14");

		String ip;
		boolean first = true;
		// long unixTime = System.currentTimeMillis() / 1000L;

		System.out.println("Getting adress...");

		try {
			Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
			while (interfaces.hasMoreElements()) {
				NetworkInterface iface = interfaces.nextElement();
				// filters out 127.0.0.1 and inactive interfaces
				if (iface.isLoopback() || !iface.isUp()) {
					continue;
				}

				Enumeration<InetAddress> addresses = iface.getInetAddresses();
				while (addresses.hasMoreElements()) {
					InetAddress addr = addresses.nextElement();
					ip = addr.getHostAddress();
					if (first) {
						System.out.println("Connection address: " + ip);
						first = false;
					}
				}
			}
		} catch (SocketException e) {
			throw new RuntimeException(e);
		}

		// PreRunning
		ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>> temp_core = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>();
		ConcurrentHashMap<String, String> temp_map = new ConcurrentHashMap<String, String>();

		if (API_FIRST_RUN) {
			temp_core.put("_projects", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
			temp_core.put("_tables", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
			temp_core.put("_users", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
			temp_core.put("_privileges", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());
			temp_core.put("_projects_privileges", new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>());

			DATA.put("_core", temp_core);

			temp_map = new ConcurrentHashMap<String, String>();

			temp_map.put("name", "Master Developer");
			temp_map.put("email", "dev@baserel.com");
			temp_map.put("pass", "12345678");
			temp_map.put("verified", "true");
			temp_map.put("super", "true");
			temp_map.put("fingerprint", randomString(32));

			DATA.get("_core").get("_users").put("dev@baserel.com", temp_map);
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

	// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	// HANDLERS
	// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

	static class InfoHandler implements HttpHandler {

		public void handle(HttpExchange httpExchange) throws IOException {
			String response = httpExchange.getRequestURI().toString();

			server.writeResponse(httpExchange, response.toString());
		}
	}

	static class PutHandler implements HttpHandler {

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
					// TODO Auto-generated catch block
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
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else if (DATA.get(datamap) == null) {
				try {

					response.put("result", "ERR104");
					response.put("text", "Access denied");

					if (API_EXPERIMENTAL) {
						response.put("info", "Project name does not exists");
					}

				} catch (JSONException e) {
					// TODO Auto-generated catch block
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
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} else {

					parameters.remove("_auth");

					if (DATA.get(datamap).get(continent) == null) {
						try {

							response.put("result", "ERR109");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Table name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
									// TODO Auto-generated catch block
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
									// TODO Auto-generated catch block
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
									// TODO Auto-generated catch block
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
										// TODO Auto-generated catch block
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
										// TODO Auto-generated catch block
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

	static class GetHandler implements HttpHandler {

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
					// TODO Auto-generated catch block
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
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} else {
					if (DATA.get(datamap) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						} else {

							parameters.remove("_auth");

							if (DATA.get(datamap).get(continent) == null) {
								try {

									response.put("result", "ERR109");
									response.put("text", "Access denied");

									if (API_EXPERIMENTAL) {
										response.put("info", "Table name does not exists");
									}

								} catch (JSONException e) {
									// TODO Auto-generated catch block
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

	static class DelHandler implements HttpHandler {

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
					// TODO Auto-generated catch block
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
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} else {
					if (DATA.get(datamap) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						} else {

							parameters.remove("_auth");

							if (DATA.get(datamap).get(continent) == null) {
								try {

									response.put("result", "ERR109");
									response.put("text", "Access denied");

									if (API_EXPERIMENTAL) {
										response.put("info", "Table name does not exists");
									}

								} catch (JSONException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							} else {

								if (index != "") {

									DATA.get(datamap).get(continent).remove(index);

									try {

										response.put("result", "SUC100");
										response.put("text", "Done");

									} catch (JSONException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									}

								} else if (parameters.size() == 0) {

									DATA.get(datamap).get(continent).clear();

									try {

										response.put("result", "SUC100");
										response.put("text", "Done");

									} catch (JSONException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									}

								} else {

									filterAndDeleteContinent(datamap, continent, parameters);

									try {

										response.put("result", "SUC100");
										response.put("text", "Done");

									} catch (JSONException e) {
										// TODO Auto-generated catch block
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

	static class AdmHandler implements HttpHandler {

		public void handle(HttpExchange httpExchange) throws IOException {

			JSONObject response = new JSONObject();
			Map<String, String> parameters = getParameters(httpExchange);

			ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>> temp_table = new ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>>();
			ConcurrentHashMap<String, ConcurrentHashMap<String, String>> temp_keymap = new ConcurrentHashMap<String, ConcurrentHashMap<String, String>>();
			ConcurrentHashMap<String, String> temp_map = new ConcurrentHashMap<String, String>();

			if (parameters.get("_auth") == null) {
				try {

					response.put("result", "ERR100");
					response.put("text", "Access denied");

					if (API_EXPERIMENTAL) {
						response.put("info", "_auth is null");
					}

				} catch (JSONException e) {
					// TODO Auto-generated catch block
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
					// TODO Auto-generated catch block
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
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else {

				// Start Defining actions

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				if (parameters.get("_action").equals("create_project")) { // create_project command
					if (parameters.get("_project") == null) {

						try {

							response.put("result", "ERR102");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_project is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
						try {

							response.put("result", "ERR103");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name must contain only alphanumeric characters");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (DATA.get("_core").get("_users").get(parameters.get("_email")) != null) {
						try {

							response.put("result", "ERR116");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name already exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {

						DATA.put(parameters.get("_project"), temp_table);

						temp_map = new ConcurrentHashMap<String, String>();

						temp_map.put("name", parameters.get("_name"));
						temp_map.put("security", "false");

						String project_code = randomString(32);
						String privileges_code = randomString(32);

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

						DATA.get("_core").get("_projects_privileges").put(project_code,
								new ConcurrentHashMap<String, String>());

						DATA.get("_core").get("_projects_privileges").get(project_code).put(parameters.get("_email"),
								DATA.get("_core").get("_users").get(parameters.get("_email")).get("fingerprint"));

						try {

							response.put("result", "SUC100");
							response.put("text", "Done");

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("reset_project_key")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_project") == null) {

						try {

							response.put("result", "ERR102");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_project is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (DATA.get(parameters.get("_project")) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {

						DATA.get("_core").get("_projects").get(parameters.get("_project")).put("key", randomString(36));

						try {

							response.put("result", "SUC100");
							response.put("text", "Done");

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("create_user")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_name") == null) {

						try {

							response.put("result", "ERR118");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_name is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (parameters.get("_super") == null) {
						try {

							response.put("result", "ERR122");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								// response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (!parameters.get("_super").equals("true") && !parameters.get("_super").equals("false")) {
						try {

							response.put("result", "ERR115");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								// response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (!isValidEmail(parameters.get("_email"))) {
						try {

							response.put("result", "ERR125");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								// response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (DATA.get("_core").get("_users").get(parameters.get("_email")) != null) {
						try {

							response.put("result", "ERR123");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								// response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {

						temp_map = new ConcurrentHashMap<String, String>();

						temp_map.put("name", parameters.get("_name"));
						temp_map.put("email", parameters.get("_email"));
						temp_map.put("pass", parameters.get("_pass"));
						temp_map.put("verified", parameters.get("_verified"));
						temp_map.put("super", parameters.get("_super"));
						temp_map.put("fingerprint", randomString(32));

						DATA.get("_core").get("_users").put(parameters.get("_email"), temp_map);

						try {
							response.put("result", "SUC100");
							response.put("text", "Done");
						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("edit_user")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_email") == null) {

						try {

							response.put("result", "ERR119");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_email is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (parameters.get("_super") != null && !parameters.get("_super").equals("true")
							&& !parameters.get("_super").equals("false")) {
						try {

							response.put("result", "ERR115");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								// response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (parameters.get("_nemail") != null && !isValidEmail(parameters.get("_nemail"))) {
						try {

							response.put("result", "ERR125");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								// response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (parameters.get("_nemail") != null
							&& !parameters.get("_nemail").equals(parameters.get("_email"))
							&& DATA.get("_core").get("_users").get(parameters.get("_nemail")) != null) {
						try {

							response.put("result", "ERR123");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								// response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {

						temp_map = DATA.get("_core").get("_users").get(parameters.get("_email"));

						if (parameters.get("_name") != null)
							temp_map.put("name", parameters.get("_name"));

						if (parameters.get("_nemail") != null)
							temp_map.put("email", parameters.get("_nemail"));

						if (parameters.get("_pass") != null)
							temp_map.put("pass", parameters.get("_pass"));

						if (parameters.get("_verified") != null)
							temp_map.put("verified", parameters.get("_verified"));

						if (parameters.get("_super") != null)
							temp_map.put("super", parameters.get("_super"));

						DATA.get("_core").get("_users").put(parameters.get("_email"), temp_map);

						try {
							response.put("result", "SUC100");
							response.put("text", "Done");
						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("get_user")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_email") == null) {

						try {

							response.put("result", "ERR119");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_email is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (DATA.get("_core").get("_users").get(parameters.get("_email")).get("super")
							.equals("true")) {

						try {

							response.put("result", "ERR127");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "This user cannot be deleted");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else {

						response = new JSONObject(DATA.get("_core").get("_users").get(parameters.get("_email")));

					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("delete_user")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_email") == null) {

						try {

							response.put("result", "ERR119");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_email is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else {

						DATA.get("_core").get("_users").remove(parameters.get("_email"));

						try {

							response.put("result", "SUC100");
							response.put("text", "Done");

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("get_all_users")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					response = new JSONObject(DATA.get("_core").get("_users"));

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("create_project_table")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_project") == null) {

						try {

							response.put("result", "ERR102");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_project is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (DATA.get(parameters.get("_project")) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) != null) {
						try {

							response.put("result", "ERR108");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Table name already exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
						try {

							response.put("result", "ERR103");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name must contain only alphanumeric characters");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {

						DATA.get(parameters.get("_project")).put(parameters.get("_table"), temp_keymap);

						temp_map = new ConcurrentHashMap<String, String>();
						temp_map.put("index", "1");

						DATA.get("_core").get("_tables")
								.put(parameters.get("_project") + "_" + parameters.get("_table"), temp_map);

						try {

							response.put("result", "SUC100");
							response.put("text", "Done");

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("delete_project_table")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_project") == null) {

						try {

							response.put("result", "ERR102");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_project is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (DATA.get(parameters.get("_project")) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
						try {

							response.put("result", "ERR103");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name must contain only alphanumeric characters");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
						try {

							response.put("result", "ERR109");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Table name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {

						DATA.get("_core").get("_tables")
								.remove(parameters.get("_project") + "_" + parameters.get("_table"));
						DATA.get(parameters.get("_project")).remove(parameters.get("_table"));

						try {

							response.put("result", "SUC100");
							response.put("text", "Done");

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("get_project_info")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_project") == null) {

						try {

							response.put("result", "ERR102");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_project is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (DATA.get(parameters.get("_project")) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
						try {

							response.put("result", "ERR103");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name must contain only alphanumeric characters");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {

						temp_map = DATA.get("_core").get("_projects").get(parameters.get("_project"));

						response = new JSONObject(temp_map);
					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("get_table_info")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_project") == null) {

						try {

							response.put("result", "ERR102");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_project is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
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
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (DATA.get(parameters.get("_project")) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
						try {

							response.put("result", "ERR103");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name must contain only alphanumeric characters");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (DATA.get(parameters.get("_project")).get(parameters.get("_table")) == null) {
						try {

							response.put("result", "ERR109");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Table name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {

						temp_map = DATA.get("_core").get("_tables")
								.get(parameters.get("_project") + "_" + parameters.get("_table"));

						response = new JSONObject(temp_map);

					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("get_project_tables")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_project") == null) {

						try {

							response.put("result", "ERR102");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_project is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (DATA.get(parameters.get("_project")) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
						try {

							response.put("result", "ERR103");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name must contain only alphanumeric characters");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {
						try {
							response.put("continents", getContinentList(DATA.get(parameters.get("_project"))));
						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("set_project_security")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_project") == null) {

						try {

							response.put("result", "ERR102");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_project is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (parameters.get("_security") == null) {

						try {

							response.put("result", "ERR114");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_security is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (!parameters.get("_security").equals("true")
							&& !parameters.get("_security").equals("false")) {

						try {

							response.put("result", "ERR115");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Unexpected value");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (DATA.get(parameters.get("_project")) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
						try {

							response.put("result", "ERR103");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name must contain only alphanumeric characters");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {
						DATA.get("_core").get("_projects").get(parameters.get("_project")).put("security",
								parameters.get("_security"));

						try {

							response.put("result", "SUC100");
							response.put("text", "Done");

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}

//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
				} else if (parameters.get("_action").equals("delete_project")) {
//				@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

					if (parameters.get("_project") == null) {

						try {

							response.put("result", "ERR102");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "_project is null");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					} else if (DATA.get(parameters.get("_project")) == null) {
						try {

							response.put("result", "ERR104");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name does not exists");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else if (!StringUtils.isAlphanumeric(parameters.get("_project"))) {
						try {

							response.put("result", "ERR103");
							response.put("text", "Access denied");

							if (API_EXPERIMENTAL) {
								response.put("info", "Project name must contain only alphanumeric characters");
							}

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					} else {
						DATA.get("_core").get("_projects").remove(parameters.get("_project"));
						DATA.remove(parameters.get("_project"));

						try {

							response.put("result", "SUC100");
							response.put("text", "Done");

						} catch (JSONException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}

					// END DEFINING ACTIONS

				} else {
					try {

						response.put("result", "ERR105");
						response.put("text", "Access denied");

						if (API_EXPERIMENTAL) {
							response.put("info", "Unkown action");
						}

					} catch (JSONException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}

			}

			server.writeResponse(httpExchange, response.toString());

		}
	}

	// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	// HELPER METHODS
	// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

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

	public static String[] getContinentList(
			ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>> datamap) {

		String[] continents = new String[0];

		for (Entry<String, ConcurrentHashMap<String, ConcurrentHashMap<String, String>>> entry : datamap.entrySet()) {
			continents = strArrAdd(continents, entry.getKey());
		}

		return continents;

	}

	public static boolean isDouble(String str) {
		try {
			Double.parseDouble(str);
			return true;
		} catch (NumberFormatException e) {
			return false;
		}
	}

	// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	// GENERIC METHODS
	// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

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
				for (;;) {
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
				for (;;) {
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
