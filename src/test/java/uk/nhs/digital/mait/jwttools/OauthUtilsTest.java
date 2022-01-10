/*
 Copyright 2017  Simon Farrow <simon.farrow1@hscic.gov.uk>

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

import java.io.File;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author simonfarrow
 */
public class OauthUtilsTest {

    private File tokenFile;

    public OauthUtilsTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        tokenFile = new File("src/test/resources/NHS0001_token.json");
        if (tokenFile.exists()) {
            tokenFile.delete();
        }
    }

    @After
    public void tearDown() {
        if (tokenFile.exists()) {
            tokenFile.delete();
        }
    }

    /**
     * Test of oathGetAccessToken method, of class OauthUtils.
     */
    @Test
    public void testOauthGetAccessToken_AuthorizationCode() throws Exception {
        System.out.println("oauthGetAccessToken_AuthorizationCode");
        String endPointConfigFile = "src/test/resources/NHS0001.sh";
        String result = OauthUtils.oauthGetAccessToken_AuthorizationCode(endPointConfigFile);
        assertTrue(result.trim().length() > 0);

        assertTrue(tokenFile.exists());

        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://sandbox.api.service.nhs.uk/hello-world/hello/user"))
                .setHeader("Authorization", result)
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
        assertEquals(200,response.statusCode());
    }

    /**
     * Test of oauthGetAccessToken_ClientCredentials method, of class OauthUtils.
     * we'll get a 403 here since the test data doesn't contain a registered public key 
     */
    @Test(expected=Exception.class)
    public void testOauthGetAccessToken_ClientCredentials() throws Exception {
        System.out.println("oauthGetAccessToken_ClientCredentials");
        String endPointConfigFile = "src/test/resources/NHS0001.sh";
        String expResult = "";
        String result = OauthUtils.oauthGetAccessToken_ClientCredentials(endPointConfigFile);
        assertEquals(expResult, result);
    }

}
