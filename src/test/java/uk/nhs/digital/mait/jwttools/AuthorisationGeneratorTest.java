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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Base64;
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
public class AuthorisationGeneratorTest {

    private AuthorisationGenerator instance;

    private static String practitionerID;
    private static String nhsNumber;
    private static String secret;
    private static String templateFile;

    public AuthorisationGeneratorTest() {
    }

    @BeforeClass
    public static void setUpClass() {
        practitionerID = "pid";
        nhsNumber = "9999999999";
        secret = "secret";
        templateFile = "src/main/resources/uk/nhs/digital/mait/jwttools/jwt_template.txt";
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() throws Exception {
        instance = new AuthorisationGenerator();
    }

    @After
    public void tearDown() {
    }

    private boolean checkJWT(String jwt) {
        return checkJWT(jwt, true);
    }

    private boolean checkJWT(String jwt, boolean urlEncoding) {
        Base64.Decoder decoder = urlEncoding ? Base64.getUrlDecoder() : Base64.getDecoder();
        if (jwt.matches("^[^.]+\\.[^.]+\\.[^.]+$")) {
            String[] parts = jwt.split("\\.");
            if (parts.length == 3) {
                int i = 0;
                for (String part : parts) {
                    parts[i++] = new String(decoder.decode(part));
                }
                return true;
            }
        } else if (jwt.matches("^[^.]+\\.[^.]+\\.$")) {
            String[] parts = jwt.split("\\.");
            if (parts.length == 2) {
                int i = 0;
                for (String part : parts) {
                    parts[i++] = new String(decoder.decode(part));
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Test of AuthorisationGenerator method, of class AuthorisationGenerator.
     *
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.UnsupportedEncodingException
     * @throws java.security.InvalidKeyException
     */
    @Test
    public void testAuthorisationGenerator() throws Exception {
        System.out.println("AuthorisationGenerator");
        instance = new AuthorisationGenerator(templateFile);
        String result = instance.getAuthorisationString(practitionerID, nhsNumber, secret);
        System.out.println(result);
        assertTrue(checkJWT(result));
    }

    /**
     * Test of getAuthorisationString method, of class AuthorisationGenerator.
     *
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.UnsupportedEncodingException
     * @throws java.security.InvalidKeyException
     */
    @Test
    public void testGetAuthorisationString() throws Exception {
        System.out.println("getAuthorisationString");
        String result = instance.getAuthorisationString(practitionerID, nhsNumber, secret);
        System.out.println(result);
        assertTrue(checkJWT(result));
    }

    /**
     * Test of getAuthorisationStringNoSmartcard method, of class
     * AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetAuthorisationStringNoSmartcard() throws Exception {
        System.out.println("getAuthorisationStringNoSmartcard");
        String result = instance.getAuthorisationStringNoSmartcard(practitionerID, nhsNumber, secret);
        System.out.println(result);
        assertTrue(checkJWT(result));
    }

    /**
     * Test of main method, of class AuthorisationGenerator. There is code here
     * to trap stdout from main
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testMain() throws Exception {
        System.out.println("main");
        PrintStream oldOut = System.out;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        String[] args = new String[]{templateFile, practitionerID, nhsNumber, secret};
        System.setOut(new PrintStream(bos));
        AuthorisationGenerator.main(args);

        String result = bos.toString();
        System.setOut(oldOut);
        System.out.println(result);

        bos.reset();

        System.setOut(new PrintStream(bos));
        args = new String[]{templateFile, practitionerID, nhsNumber, secret, "true", "true", "1"};
        AuthorisationGenerator.main(args);

        result = bos.toString();
        System.setOut(oldOut);
        System.out.println(result);
    }

    /**
     * Test of getJWT method, of class AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    //@Test
    public void testGetJWT() throws Exception {
        System.out.println("getJWT");
        for (Boolean useURLEncoding : new Boolean[]{true, false}) {
            String result = AuthorisationGenerator.getJWT(templateFile, practitionerID, nhsNumber, secret, useURLEncoding.toString());
            assertTrue(result.length() > 0);
            assertTrue(result.startsWith("ewogI"));
            assertTrue(checkJWT(result, useURLEncoding));
        }
    }

    /**
     * Test of getAuthorisationString method, of class AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetAuthorisationString_4args() throws Exception {
        System.out.println("getAuthorisationString_4args");
        boolean useBase64URL = false;
        String result = instance.getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, true);
        // This might "fail" if the b64 did not by chance require to include these chars
        assertTrue(result.contains("=") || result.contains("+") || result.contains("/"));
        assertTrue(checkJWT(result, useBase64URL));

        useBase64URL = true;
        result = instance.getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, true);
        assertTrue(!result.contains("=") && !result.contains("+") && !result.contains("/"));
        assertTrue(checkJWT(result, useBase64URL));

        result = instance.getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, false);
        assertTrue(!result.contains("=") && !result.contains("+") && !result.contains("/"));
        assertTrue(checkJWT(result, useBase64URL));
    }

    /**
     * Test of getAuthorisationString method, of class AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetAuthorisationString_3args() throws Exception {
        System.out.println("getAuthorisationString_3args");
        String result = instance.getAuthorisationString(practitionerID, nhsNumber, secret);
        assertTrue(checkJWT(result));
    }

    /**
     * Test of getAuthorisationStringNoSmartcard method, of class
     * AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetAuthorisationStringNoSmartcard_4args() throws Exception {
        System.out.println("getAuthorisationStringNoSmartcard_4args");
        boolean useBase64URL = false;
        String result = instance.getAuthorisationStringNoSmartcard(practitionerID, nhsNumber, secret, useBase64URL);
        // This might "fail" if the b64 did not by chance require to include these chars
        assertTrue(result.contains("=") || result.contains("+") || result.contains("/"));
        assertTrue(checkJWT(result, useBase64URL));

        useBase64URL = true;
        result = instance.getAuthorisationStringNoSmartcard(practitionerID, nhsNumber, secret, useBase64URL);
        assertTrue(!result.contains("=") && !result.contains("+") && !result.contains("/"));
        assertTrue(checkJWT(result, useBase64URL));
    }

    /**
     * Test of getAuthorisationStringNoSmartcard method, of class
     * AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetAuthorisationStringNoSmartcard_3args() throws Exception {
        System.out.println("getAuthorisationStringNoSmartcard_3args");
        String result = instance.getAuthorisationStringNoSmartcard(practitionerID, nhsNumber, secret);
        assertTrue(checkJWT(result));
    }

    /**
     * Test of getAuthorisationString method, of class AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetAuthorisationString_5args() throws Exception {
        System.out.println("getAuthorisationString_5args");
        boolean useBase64URL = true;
        boolean addSignature = false;
        int expResult = 2;
        String strResult = instance.getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, addSignature);
        long result = strResult.chars().filter(ch -> ch == '.').count();
        assertEquals(expResult, result);

        assertTrue(!strResult.contains("=") && !strResult.contains("+") && !strResult.contains("/"));
        assertTrue(checkJWT(strResult, useBase64URL));

        addSignature = true;
        expResult = 2;
        strResult = instance.getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, addSignature);
        result = strResult.chars().filter(ch -> ch == '.').count();
        assertEquals(expResult, result);

        assertTrue(!strResult.contains("=") && !strResult.contains("+") && !strResult.contains("/"));
        assertTrue(checkJWT(strResult, useBase64URL));
    }

    /**
     * Test of getAuthorisationString method, of class AuthorisationGenerator.
     * this has an extra integer parameter - payloadCount
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetAuthorisationString_6args() throws Exception {
        System.out.println("getAuthorisationString_6args");
        boolean useBase64URL = true;
        boolean addSignature = false;

        // extra test cases for NRLS
        // header, two payloads no signature
        int payloadCount = 2;
        int expResult = 3;
        String result = instance.getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, addSignature, payloadCount);
        assertEquals(expResult, result.chars().filter(ch -> ch == '.').count());

        expResult = 4;
        String parts[] = result.split("\\.");
        assertEquals(expResult, parts.length);
        assertEquals("", parts[2]); // no signature
        assertEquals(parts[1], parts[3]);

        // header, two payloads with signature
        addSignature = true;
        expResult = 3;
        result = instance.getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, addSignature, payloadCount);
        assertEquals(expResult, result.chars().filter(ch -> ch == '.').count());

        expResult = 4;
        parts = result.split("\\.");
        assertEquals(expResult, parts.length);
        assertNotEquals("", parts[0]); // header
        assertNotEquals("", parts[2]); // signature
        assertEquals(parts[1], parts[3]); // check appended payload = original payload

        // edge cases ?
        // no payload
        payloadCount = 0;

        // no payload, no signature 
        addSignature = false;
        expResult = 1;
        result = instance.getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, addSignature, payloadCount);
        assertEquals(expResult, result.chars().filter(ch -> ch == '.').count());

        expResult = 1;
        parts = result.split("\\.");
        assertEquals(expResult, parts.length);
        assertNotEquals("", parts[0]); // header
        System.out.println(new String(Base64.getUrlDecoder().decode(parts[0])));

        // no payload, with signature 
        addSignature = true;
        expResult = 1;
        result = instance.getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, addSignature, payloadCount);
        assertEquals(expResult, result.chars().filter(ch -> ch == '.').count());

        expResult = 2;
        parts = result.split("\\.");
        assertEquals(expResult, parts.length);
        System.out.println(new String(Base64.getUrlDecoder().decode(parts[0])));
        assertNotEquals("", parts[0]); // header
        assertNotEquals("", parts[1]); // signature
    }

    /**
     * Test of getJWT method, of class AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetJWT_5args() throws Exception {
        System.out.println("getJWT_5args");
        String useBase64URLStr = "true";
        int expResult = 2;
        String result = AuthorisationGenerator.getJWT(templateFile, practitionerID, nhsNumber, secret, useBase64URLStr);
        assertEquals(expResult, result.chars().filter(ch -> ch == '.').count());
        String parts[] = result.split("\\.");
        assertTrue(parts[2].length() > 0);
    }

    /**
     * Test of getJWT method, of class AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetJWT_6args() throws Exception {
        System.out.println("getJWT_6args");
        String useBase64URLStr = "true";
        String addSignatureStr = "true";
        int expResult = 2;
        String result = AuthorisationGenerator.getJWT(templateFile, practitionerID, nhsNumber, secret, useBase64URLStr, addSignatureStr);
        assertEquals(expResult, result.chars().filter(ch -> ch == '.').count());
        String parts[] = result.split("\\.");
        assertTrue(parts.length == 3);
        assertTrue(parts[2].length() > 0);

        addSignatureStr = "false";
        expResult = 2;
        result = AuthorisationGenerator.getJWT(templateFile, practitionerID, nhsNumber, secret, useBase64URLStr, addSignatureStr);
        assertEquals(expResult, result.chars().filter(ch -> ch == '.').count());
        parts = result.split("\\.");
        assertTrue(parts.length == 2);
    }

    /**
     * Test of getJWT method, of class AuthorisationGenerator.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testGetJWT_7args() throws Exception {
        System.out.println("getJWT_7args");
        String useBase64URLStr = "true";
        String addSignatureStr = "true";
        String payloadCountStr = "1";
        int expResult = 2;
        String result = AuthorisationGenerator.getJWT(templateFile, practitionerID, nhsNumber, secret, useBase64URLStr, addSignatureStr, payloadCountStr);
        assertEquals(expResult, result.chars().filter(ch -> ch == '.').count());
        String parts[] = result.split("\\.");
        assertTrue(parts.length == 3);
        assertTrue(parts[2].length() > 0);

        payloadCountStr = "2";
        expResult = 3;
        result = AuthorisationGenerator.getJWT(templateFile, practitionerID, nhsNumber, secret, useBase64URLStr, addSignatureStr, payloadCountStr);
        assertEquals(expResult, result.chars().filter(ch -> ch == '.').count());
        parts = result.split("\\.");
        assertTrue(parts.length == 4);
        assertEquals(parts[1], parts[3]);
    }

    @Test
    public void testRS512Sign() throws Exception {
        System.out.println("RS512Sign");
        String signature = instance.getRS512Signature("src/test/resources/test.pem", "abc123");
        assertTrue(signature.length()>0);
    }

    @Test  (expected = IOException.class)
    public void testRS512SignNoFile() throws Exception {
        System.out.println("RS512SignNoFile");
        String signature = instance.getRS512Signature("src/test/resources/test.pemxxx", "abc123");
        assertTrue(signature.length()>0);
    }
    
    /**
     * Test of verifyRS512Signature method, of class AuthorisationGenerator.
     */
    @Test
    public void testVerifyRS512Signature() throws Exception {
        System.out.println("verifyRS512Signature");
        String key = "src/test/resources/test.pubkey";
        String data = "abc123";
        byte[] sigBytes = Base64.getDecoder().decode(instance.getRS512Signature("src/test/resources/test.pem", data));
        boolean expResult = true;
        boolean result = instance.verifyRS512Signature(key, data, sigBytes);
        assertEquals(expResult, result);
    }

    /**
     * Test of verifyRS512SignatureNoFile method, of class AuthorisationGenerator.
     */
    @Test (expected = IOException.class)
    public void testVerifyRS512SignatureNoFile() throws Exception {
        System.out.println("verifyRS512SignatureNo0File");
        String key = "src/test/resources/test.pubkeyxxx";
        String data = "abc123";
        byte[] sigBytes = Base64.getDecoder().decode(instance.getRS512Signature("src/test/resources/test.pem", data));
        boolean expResult = true;
        boolean result = instance.verifyRS512Signature(key, data, sigBytes);
        assertEquals(expResult, result);
    }
}
