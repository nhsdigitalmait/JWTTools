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
// rev 10 Full alignment of all interfaces with the extra payloadCount int parameter
// rev 9 Added extra parameter payloadCount to Enable support for extra test conditions - 0..n payloads, default is now to use base64 *url* encoding
// rev 8 Amended usage text
// rev 7 USE_PADDING set to off applies to b64 url; encoding only b64 is always padding on
// added add signature boolean
// rev 6 Now optionally URL encodes Base64 not plain base64
// rev 5 Allows invocation as an executable jar via main
// rev 3 added an extra constructor taking a template filename
// rev 1 amended smartcard template to add missing id
// rev 1 added non smartcard method
package uk.nhs.digital.mait.jwttools;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * supports creation of jwt tokens using template substitution. Suitable for use
 * in JMeter Also invocable as a java executable
 *
 * @author simonfarrow
 */
public class AuthorisationGenerator {

    private String payloadTemplate = null;
    private String payloadTemplateNoSmartcard = null;
    private boolean useBase64URL = false;

    public final static String HEADER_NONE = "{\n"
            + "  \"alg\": \"none\",\n"
            + "  \"typ\": \"JWT\"\n"
            + "}";

    private final static String HEADER_HS256 = "{\n"
            + "  \"alg\": \"HS256\",\n"
            + "  \"typ\": \"JWT\"\n"
            + "}";

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String USAGE = "usage: java -jar JWTTools.jar <path to message template file> <practitionerid> <nhs number> <hmac key> [<urlencode> [<addsignature> [<payloadCount>]]]";
    private static final String VERSION_STRING = "JWTTools Subversion $Rev: 10 $";
    // Was modified for NRLS testing which seems to demand base 64 encoding with padding
    // padding now back to the more correct false for now as per spec
    // nb pure b64 is always padding on anyway
    private static final boolean USE_PADDING = false;

    /**
     * eg for use from curl etc
     *
     * @param args allows invocation from main templateFile practitionerID nhsNo
     * secret [&lt;urlencode&gt; [ &lt;addSignature&gt; [&lt;payloadCount&gt;]]]
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {
        switch (args.length) {
            case 0:
                System.out.println(VERSION_STRING);
                System.out.println(USAGE);
                break;
            case 4:
                System.out.println(getJWT(args[0], args[1], args[2], args[3], "true"));
                break;
            case 5:
                System.out.println(getJWT(args[0], args[1], args[2], args[3], args[4]));
                break;
            case 6:
                System.out.println(getJWT(args[0], args[1], args[2], args[3], args[4], args[5], "1"));
                break;
            case 7:
                System.out.println(getJWT(args[0], args[1], args[2], args[3], args[4], args[5], args[6]));
                break;
            default:
                System.err.println(USAGE);
        }
    }

    /**
     * Public constructor
     *
     * @param filename template filename
     * @throws java.lang.Exception
     */
    public AuthorisationGenerator(String filename) throws Exception {
        // read the templates
        payloadTemplate = readFile2String(filename);
    }

    /**
     * Public constructor
     *
     * @throws java.lang.Exception
     */
    public AuthorisationGenerator() throws Exception {
        // read the templates
        payloadTemplate = readFileFromJar("jwt_template.txt");
        payloadTemplateNoSmartcard = readFileFromJar("jwt_template_no_smartcard.txt");
    }

    /**
     *
     * @param payload
     * @param practitionerID this is a fhir resource id guid
     * @param nhsNumber 10 digit new style nhs number
     * @return substituted payload
     */
    private String commonSubstitutions(String payload, String practitionerID, String nhsNumber) {
        payload = payload.replaceAll("__PRACTITIONER_ID__", practitionerID);
        payload = payload.replaceAll("__NHS_NUMBER__", nhsNumber);
        // This is the unix epoch
        long now = new Date().getTime() / 1000;
        payload = payload.replaceAll("__CURRENT_UTC__", "" + now);
        return payload.replaceAll("__CURRENT_UTC_PLUS_5_MIN__", "" + (now + (5 * 60)));
    }

    /**
     * return the fully populated two/three/four part authorisation string main
     * method call with full set of parameters extra parameters for test
     * mangling purposes
     *
     * @param practitionerID this is a fhir resource id guid
     * @param nhsNumber 10 digit new style nhs number
     * @param secret hmac secret string
     * @param useBase64URL use base 64 url encoding rather than pure base64
     * @param addSignature whether to add the third part of the JWT
     * @param payloadCount
     * @return the full string to be used in the http header
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     */
    public String getAuthorisationString(String practitionerID, String nhsNumber, String secret, boolean useBase64URL, boolean addSignature, int payloadCount)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        boolean addHeader = true; // this should always be true but just in case we need the flexibility..

        this.useBase64URL = useBase64URL;
        // do the substitutions
        String payload = commonSubstitutions(payloadTemplate, practitionerID, nhsNumber);

        StringBuilder sbHeaderPlusPayload = new StringBuilder();
        if (addHeader) {
            if (addSignature) {
                sbHeaderPlusPayload.append(toBase64(HEADER_HS256));
            } else {
                sbHeaderPlusPayload.append(toBase64(HEADER_NONE));
            }
            sbHeaderPlusPayload.append(".");
        }

        if (payloadCount > 0) {
            sbHeaderPlusPayload.append(toBase64(payload)).append(".");
        }

        if (addHeader && addSignature) {
            sbHeaderPlusPayload.append(getHmac(secret, sbHeaderPlusPayload.toString()));
        }

        // append some more payloads at the end if required
        for (int i = 1; i < payloadCount; i++) {
            sbHeaderPlusPayload.append(".").append(toBase64(payload));
        }
        return sbHeaderPlusPayload.toString();
    }

    /**
     * return the fully populated two/three part authorisation string main
     * method call with addHedaer defaulting true and payloadCount defaulting 1
     *
     * @param practitionerID this is a fhir resource id guid
     * @param nhsNumber 10 digit new style nhs number
     * @param secret hmac secret string
     * @param useBase64URL use base 64 url encoding rather than pure base64
     * @param addSignature whether to add the third part of the JWT
     * @return the full string to be used in the http header
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @throws Exception
     */
    public String getAuthorisationString(String practitionerID, String nhsNumber, String secret, boolean useBase64URL, boolean addSignature) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, Exception {
        return getAuthorisationString(practitionerID, nhsNumber, secret, useBase64URL, addSignature, 1);
    }

    /**
     * overload with defaulting use base64urlencoding true, addSignature true
     *
     * @param practitionerID
     * @param nhsNumber
     * @param secret
     * @return the full string to be used in the http header
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @throws Exception
     */
    public String getAuthorisationString(String practitionerID, String nhsNumber, String secret) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, Exception {
        // final two boolean parameters are use base 64 url encoding and add signature
        return getAuthorisationString(practitionerID, nhsNumber, secret, true, true);
    }

    /**
     * return the fully populated three part authorisation string
     *
     * @param practitionerID this is a fhir resource id guid
     * @param nhsNumber 10 digit new style nhs number
     * @param secret hmac secret string
     * @param useBase64URL
     * @return the full string to be used in the http header
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @deprecated Use more general form getAuthorisationString where template
     * is supplied in constructor
     */
    public String getAuthorisationStringNoSmartcard(String practitionerID, String nhsNumber, String secret, boolean useBase64URL) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        this.useBase64URL = useBase64URL;
        // do the substitutions
        String payload = commonSubstitutions(payloadTemplateNoSmartcard, practitionerID, nhsNumber);
        String headerPlusPayload = toBase64(HEADER_HS256) + "." + toBase64(payload);
        return headerPlusPayload + "." + getHmac(secret, headerPlusPayload);
    }

    /**
     * overload for default using Base64URL Encoding
     *
     * @param practitionerID
     * @param nhsNumber
     * @param secret HMac secret key
     * @return the full string to be used in the http header
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @deprecated Use more general form getAuthorisationString where template
     * is supplied in constructor
     */
    public String getAuthorisationStringNoSmartcard(String practitionerID, String nhsNumber, String secret) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        return getAuthorisationStringNoSmartcard(practitionerID, nhsNumber, secret, true);
    }

    /**
     * return the hmac SHA256 hash encoding
     *
     * @param key String secret key
     * @param data String data to be hashed
     * @return base 64 representation of the hmac hash encoding
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     */
    private String getHmac(String key, String data) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), HMAC_ALGORITHM);
        hmac.init(secret_key);
        return toBase64(hmac.doFinal(data.getBytes("UTF-8")));
    }

    /**
     * take a file name as a local resource within the jar
     *
     * @param filename
     * @return String containing cr/lf delimited lines
     * @throws Exception
     */
    private String readFileFromJar(String filename)
            throws Exception {
        StringBuilder sb;
        try (InputStream is = getClass().getResourceAsStream(filename)) {
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            sb = new StringBuilder();
            String line = null;
            while ((line = br.readLine()) != null) {
                sb.append(line);
                sb.append("\r\n");
            }
        }
        return sb.toString();
    }

    private String readFile2String(String filename) throws IOException {
        Path path = Paths.get(filename);
        byte[] bytes = Files.readAllBytes(path);
        return new String(bytes);
    }

    /**
     *
     * @param byte array
     * @return base64 encoded string
     */
    private String toBase64(byte[] bytes) throws UnsupportedEncodingException {
        return (useBase64URL ? (USE_PADDING ? Base64.getUrlEncoder() : Base64.getUrlEncoder().withoutPadding()) : Base64.getEncoder()).encodeToString(bytes);
    }

    /**
     * make the base64URL encoding remove = padding and do a couple of global
     * replaces
     *
     * @param String s
     * @return base64URL encoded string
     */
    private String toBase64(String s) throws UnsupportedEncodingException {
        return toBase64(s.getBytes("UTF-8"));
    }

    /**
     * allows static linked invocation for invocation from main for use with eg
     * curl shell scripts
     * defaults addSIgnature to true and payloadCount to 1
     * @param templateFile
     * @param practitionerID
     * @param nhsNo
     * @param secret
     * @param useBase64URLStr "true" or "false"
     * @return base 64 encoded JWT string
     * @throws Exception
     */
    public static String getJWT(String templateFile, String practitionerID, String nhsNo, String secret, String useBase64URLStr) throws Exception {
        AuthorisationGenerator authorisationGenerator = new AuthorisationGenerator(templateFile);
        Boolean useBase64Url = Boolean.valueOf(useBase64URLStr);
        if (!useBase64Url) {
            System.err.println("WARNING: JWTTools is not using base64 url encoding");
        } else if (USE_PADDING) {
            System.err.println("WARNING: JWTTools is using base64 url encoding WITH padding");
        }
        // last param true => add signature
        return authorisationGenerator.getAuthorisationString(practitionerID, nhsNo, secret, useBase64Url, true);
    }

    /**
     * allows static linked invocation for invocation from main for use with eg
     * curl shell scripts
     * adds addSignature and defaults payloadCount to 1
     * @param templateFile
     * @param practitionerID
     * @param nhsNo
     * @param secret
     * @param useBase64URLStr "true" or "false"
     * @param addSignatureStr "true" or "false"
     * @return base 64 encoded JWT string
     * @throws Exception
     */
    public static String getJWT(String templateFile, String practitionerID, String nhsNo, String secret, String useBase64URLStr, String addSignatureStr) throws Exception {
        AuthorisationGenerator authorisationGenerator = new AuthorisationGenerator(templateFile);
        Boolean useBase64Url = Boolean.valueOf(useBase64URLStr);
        Boolean addSignature = Boolean.valueOf(addSignatureStr);
        if (!useBase64Url) {
            System.err.println("WARNING: JWTTools is not using base64 url encoding");
        } else if (USE_PADDING) {
            System.err.println("WARNING: JWTTools is using base64 url encoding WITH padding");
        }
        return authorisationGenerator.getAuthorisationString(practitionerID, nhsNo, secret, useBase64Url, addSignature, 1);
    }
    
    
    /**
     * allows static linked invocation for invocation from main for use with eg
     * curl shell scripts
     *
     * @param templateFile
     * @param practitionerID
     * @param nhsNo
     * @param secret
     * @param useBase64URLStr "true" or "false"
     * @param addSignatureStr "true" or "false"
     * @param payloadCountStr integer
     * @return base 64 encoded JWT string
     * @throws Exception
     */
    public static String getJWT(String templateFile, String practitionerID, String nhsNo, String secret, String useBase64URLStr, String addSignatureStr, String payloadCountStr) throws Exception {
        AuthorisationGenerator authorisationGenerator = new AuthorisationGenerator(templateFile);
        Boolean useBase64Url = Boolean.valueOf(useBase64URLStr);
        Boolean addSignature = Boolean.valueOf(addSignatureStr);
        int payloadCount = Integer.parseInt(payloadCountStr);
        if (!useBase64Url) {
            System.err.println("WARNING: JWTTools is not using base64 url encoding");
        } else if (USE_PADDING) {
            System.err.println("WARNING: JWTTools is using base64 url encoding WITH padding");
        }
        return authorisationGenerator.getAuthorisationString(practitionerID, nhsNo, secret, useBase64Url, addSignature, payloadCount);
    }
}
