/*
 Copyright 2021  Simon Farrow <simon.farrow1@nhs.net>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */
package uk.nhs.digital.mait.jwttools;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.UUID;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.internal.LinkedTreeMap;
import java.net.URLEncoder;
import uk.nhs.digital.mait.jwttools.AuthorisationGenerator.JWT_Algorithm;

/**
 * Utilities to support authentication using oauth2
 * @author simonfarrow
 */
public class OauthUtils {

    private final static boolean DEBUG = false;
    private static HttpClient client;
    private static Gson gson;

    // environment variable names in endpoint config file
    private static final String OAUTH_SERVER_ENDPOINT_CONFIG = "oauth_server";
    private static final String OAUTH_SECRET_ENDPOINT_CONFIG = "oauth_secret";
    private static final String OAUTH_REDIRECT_ENDPOINT_CONFIG = "oauth_redirect";
    private static final String OAUTH_APIKEY_ENDPOINT_CONFIG = "oauth_apikey";

    private static final String OAUTH_JWT_TEMPLATE_ENDPOINT_CONFIG = "oauth_jwt_template";
    private static final String OAUTH_PRIVATE_KEY_ENDPOINT_CONFIG = "oauth_private_key";
    private static final String OAUTH_KID_ENDPOINT_CONFIG = "oauth_kid";

    private static final String URLENCODED_CONTENT_TYPE = "application/x-www-form-urlencoded";
    private static final String LOCATION_HEADER = "Location";

    //  json attribute names 
    private static final String ACCESS_TOKEN_ATT = "access_token";
    private static final String EXPIRES_IN_ATT = "expires_in";
    private static final String WHEN_ATT = "when";

    private static final String TOKEN_FILE_SUFFIX = "_token.json";

    // see https://www.rfc-editor.org/rfc/rfc7591.html
    enum GrantType {
        authorization_code,
        implicit,
        password,
        client_credentials,
        refresh_token,
        jwt_bearer,
        saml2_bearer
    }

    enum ResponseType {
        code,
        token
    }
    
    // not to be instantiated
    private OauthUtils() {};

    /**
     * unpack url context path parameters into a hashmap
     *
     * @param url
     * @return hashmap of kay  value pairs
     */
    private static HashMap parseCPParameters(String url) {
        String line = url.replaceFirst("^.*\\?", "");
        String[] parameters = line.split("\\&");
        HashMap<String, String> hm = new HashMap();
        if (parameters.length > 1) {
            for (int i = 0; i < parameters.length; i++) {
                String parameter[] = parameters[i].split("=");
                if (parameter.length == 2) {
                    hm.put(parameter[0], parameter[1]);
                }
            }
        }
        return hm;
    }

    /**
     * parse an endpoint config file containing environment variable settings
     * These are the autotest sh ell script endpoint config files which
     * set environment variables
     * @param endPointConfigFile
     * @return HashMap of config file attribute value pairs
     * @throws IOException
     */
    private static HashMap<String, String> parseEndpointConfig(String endPointConfigFile) throws IOException {
        HashMap<String, String> endpointConfig = new HashMap<>();
        File configFile = new File(endPointConfigFile);
        if (!configFile.exists()) {
            throw new IOException("Endpoint config file " + endPointConfigFile + " does not exist");
        }
        String configFileText = Files.readString(Paths.get(endPointConfigFile));
        BufferedReader br = new BufferedReader(new StringReader(configFileText));
        String line;
        while ((line = br.readLine()) != null) {
            if (!line.matches("^\\s*#")) {
                String[] elements = line.split("=");
                if (elements.length == 2) {
                    endpointConfig.put(elements[0].trim(), elements[1].trim());
                }
            }
        }
        return endpointConfig;
    }

    /**
     * return an oauth2 access token using the client credentials grant type
     * public overload method
     * @param endPointConfigFile
     * @return oauth access token
     * @throws URISyntaxException
     * @throws IOException
     * @throws InterruptedException
     * @throws Exception
     */
    public static String oauthGetAccessToken_ClientCredentials(String endPointConfigFile) throws URISyntaxException, IOException, InterruptedException, Exception {
        return oauthGetAccessToken(endPointConfigFile, GrantType.client_credentials);
    }

    /**
     * return an oauth2 access token using the authorization code grant type
     * public overload method
     * @param endPointConfigFile String
     * @return oauth access token
     * @throws URISyntaxException
     * @throws IOException
     * @throws InterruptedException
     */
    
    public static String oauthGetAccessToken_AuthorizationCode(String endPointConfigFile) throws URISyntaxException, IOException, InterruptedException, Exception {
        return oauthGetAccessToken(endPointConfigFile, GrantType.authorization_code);
    }

    /**
     * return an oauth2 access token
     * This method is private with two public overloads named for supported oauth2 grant types
     * @param endPointConfigFile String
     * @return oauth access token
     * @throws URISyntaxException
     * @throws IOException
     * @throws InterruptedException
     */
    private static String oauthGetAccessToken(String endPointConfigFile, GrantType grantType) throws URISyntaxException, IOException, InterruptedException, Exception {

        // these files are typically appened with .sh so remove that if present to derive the endpoint name
        String endPointName = endPointConfigFile.replaceFirst("\\.sh", "");
        HashMap<String, String> endpointConfig = parseEndpointConfig(endPointConfigFile);

        // check for common settings
        checkSettings(endpointConfig, new String[]{OAUTH_APIKEY_ENDPOINT_CONFIG, OAUTH_SERVER_ENDPOINT_CONFIG});

        gson = new GsonBuilder().setPrettyPrinting().create();
        client = HttpClient.newHttpClient();
        
        LinkedTreeMap treeMap = null;
        File tokenFile = new File(endPointName + TOKEN_FILE_SUFFIX);
        if (tokenFile.exists()) {
            String json = Files.readString(Paths.get(tokenFile.getAbsolutePath()));
            treeMap = (LinkedTreeMap) gson.fromJson(json, Object.class);

            Long when = Long.parseLong((String) treeMap.get(WHEN_ATT));
            Long expires_in = Long.parseLong((String) treeMap.get(EXPIRES_IN_ATT));
            String access_token = (String) treeMap.get(ACCESS_TOKEN_ATT);

            // token has not expired so re use it
            if ((Instant.now().getEpochSecond() - when) < expires_in) {
                return "Bearer " + access_token;
            }
        }

        // either the token has expired or this is the first time through so do the interaction with the oauth server
        String tokenJson = null;
        switch (grantType) {
            case authorization_code:
                tokenJson = doAuthorizationCode(endpointConfig);
                break;
            case client_credentials:
                tokenJson = doClientCredentials(endpointConfig);
                break;
            default:
                throw new IllegalArgumentException("Unhandled oath2 grant type "+grantType);
        }

        // parse the returned json
        treeMap = (LinkedTreeMap) gson.fromJson(tokenJson, Object.class);
        String accessToken = (String) treeMap.get(ACCESS_TOKEN_ATT);
        if (accessToken == null) {
            throw new IllegalArgumentException("Protocol error missing access token element in json token response");
        }

        if (DEBUG) {
            Iterator iter = treeMap.keySet().iterator();
            while (iter.hasNext()) {
                String key1 = (String) iter.next();
                System.out.println(key1 + "=" + treeMap.get(key1));
            }
        }

        // when did we get this response?
        Long when = Instant.now().getEpochSecond();
        // add to the json object prior to serialsing to the json file so we can calculate if the token has expired next time we open the file
        try ( FileWriter fw = new FileWriter(tokenFile.getAbsolutePath())) {
            treeMap.put(WHEN_ATT, when.toString());
            fw.write(gson.toJson(treeMap));
        }

        return "Bearer " + accessToken;
    }

    /**
     * handles the authorization code grant type
     * return an oauth2 access token 
     * This interacts with a webpage performing the authentication
     * @param endpointConfig
     * @return oauth2 access token
     * @throws Exception
     */
    private static String doAuthorizationCode(HashMap<String, String> endpointConfig) throws Exception {
        String state = UUID.randomUUID().toString();

        // we know these exist
        String aPIKey = endpointConfig.get(OAUTH_APIKEY_ENDPOINT_CONFIG);
        String ep = endpointConfig.get(OAUTH_SERVER_ENDPOINT_CONFIG);
        
        // only required for this grant type
        checkSettings(endpointConfig, new String[]{OAUTH_REDIRECT_ENDPOINT_CONFIG, OAUTH_SECRET_ENDPOINT_CONFIG});

        String redirect = endpointConfig.get(OAUTH_REDIRECT_ENDPOINT_CONFIG);
        redirect = URLEncoder.encode(redirect, java.nio.charset.StandardCharsets.UTF_8.toString());
        String secret = endpointConfig.get(OAUTH_SECRET_ENDPOINT_CONFIG);

        // Call 1 authorization
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://" + ep + "/oauth2/authorize?"
                        + "response_type=" + ResponseType.code.name()
                        + "&client_id=" + aPIKey
                        + "&redirect_uri=" + redirect
                        + "&state=" + state))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        // response should be a 302 redirect
        if (response.statusCode() != 302) {
            throw new Exception("Protocol error call 1 expecting 302 redirect");
        }
        String location = response.headers().firstValue(LOCATION_HEADER).get();
        if (location == null) {
            throw new Exception("Protocol error call 1 missing location header");
        }

        HashMap parameters = parseCPParameters(location);
        String state1 = (String) parameters.get("state");
        if (state1 == null) {
            throw new Exception("Protocol error call 1 missing state parameter in location header");
        }

        // call 2 simulate selecting a method from the web page
        request = HttpRequest.newBuilder()
                .uri(URI.create(location))
                .setHeader("Content-type", URLENCODED_CONTENT_TYPE)
                .setHeader("Origin", "https://" + ep)
                .POST(HttpRequest.BodyPublishers.ofString("state=" + state1 + "&auth_method=" + "N3_SMARTCARD"))
                .build();

        response = client.send(request, HttpResponse.BodyHandlers.ofString());
        // response should be a 302 redirect
        if (response.statusCode() != 302) {
            throw new Exception("Protocol error call 2 expecting 302 redirect");
        }
        location = response.headers().firstValue(LOCATION_HEADER).get();
        if (location == null) {
            throw new Exception("Protocol error call 2 missing location header");
        }

        // call 3 get the authorization code
        request = HttpRequest.newBuilder()
                .uri(URI.create(location))
                .build();
        response = client.send(request, HttpResponse.BodyHandlers.ofString());
        // response should be a 302 redirect
        if (response.statusCode() != 302) {
            throw new Exception("Protocol error call 3 expecting 302 redirect");
        }
        location = response.headers().firstValue(LOCATION_HEADER).get();
        if (location == null) {
            throw new Exception("Protocol error call 3 missing location header");
        }

        parameters = parseCPParameters(location);
        String code = (String) parameters.get("code");
        if (code == null) {
            throw new Exception("Protocol error call 3 missing code parameter in location header");
        }

        // call 4 get the token
        request = HttpRequest.newBuilder()
                .uri(URI.create("https://" + ep + "/oauth2/token"))
                .setHeader("Content-type", URLENCODED_CONTENT_TYPE)
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=" + GrantType.authorization_code.name()
                        + "&client_id=" + aPIKey
                        + "&client_secret=" + secret
                        + "&redirect_uri=" + redirect
                        + "&code=" + code))
                .build();
        response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new Exception("Protocol error call 4 expecting 200 ok");
        }
        return response.body();
    }

    /**
     * handles the client credentials grant type
     * creates a RS512 signed JWT and receives an access token in return
     * @param endpointConfig
     * @return oauth2 access token
     * @throws Exception 
     */
    private static String doClientCredentials(HashMap<String, String> endpointConfig) throws Exception {
        // we know these exist
        String aPIKey = endpointConfig.get(OAUTH_APIKEY_ENDPOINT_CONFIG);
        String ep = endpointConfig.get(OAUTH_SERVER_ENDPOINT_CONFIG);

        // only required for this grant type
        String[] requiredSettings = new String[]{OAUTH_PRIVATE_KEY_ENDPOINT_CONFIG, OAUTH_JWT_TEMPLATE_ENDPOINT_CONFIG};
        checkSettings(endpointConfig, requiredSettings);
        for (String configItem : requiredSettings){
            File file = new File(endpointConfig.get(configItem));
            if (!file.exists()) {
                throw new IllegalArgumentException("File " + file.getAbsolutePath() + " referenced by config item "+ configItem + " does not exist");
            }
        }
        String privateKeyFile = endpointConfig.get(OAUTH_PRIVATE_KEY_ENDPOINT_CONFIG);
        String jwtTemplateFile = endpointConfig.get(OAUTH_JWT_TEMPLATE_ENDPOINT_CONFIG);
        String kid = endpointConfig.get(OAUTH_KID_ENDPOINT_CONFIG);
        if (kid == null){
            throw new IllegalArgumentException("No value supplied for required endpoint config item: " + OAUTH_KID_ENDPOINT_CONFIG);
        }
        
        AuthorisationGenerator authorisationGenerator = new AuthorisationGenerator(jwtTemplateFile);
        String jwt = authorisationGenerator.getAuthorisationString(kid,
                "https://" + ep + "/oauth2/token,__API_KEY__|" + aPIKey,
                privateKeyFile,
                true,
                JWT_Algorithm.RS512,
                1);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://" + ep + "/oauth2/token"))
                .setHeader("Content-type", URLENCODED_CONTENT_TYPE)
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=" + GrantType.client_credentials.name()
                        + "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                        + "&client_assertion=" + jwt))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
           throw new Exception("Protocol error client credentials call expecting 200 ok received "+response.statusCode() +" " + response.body());
        }
        return response.body();
    }
    
    /**
     * if a required setting is not present in the config file throw an exception
     * @param endpointConfig
     * @param requiredSettings 
     */
    private static void checkSettings(HashMap<String,String> endpointConfig, String[] requiredSettings) {      
        for (String setting : requiredSettings) {
            if (endpointConfig.get(setting) == null) {
                throw new IllegalArgumentException("No value supplied for required endpoint config item: " + setting);
            }
        }
   }
}
