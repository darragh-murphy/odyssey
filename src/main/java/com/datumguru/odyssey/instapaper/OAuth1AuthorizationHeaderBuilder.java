package com.datumguru.odyssey.instapaper;

/**
 * Copyright (c) 2019, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
/*
 * Copyright (c) 2019-2021, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Daniel DeGroff
 */
public class OAuth1AuthorizationHeaderBuilder {
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    // https://tools.ietf.org/html/rfc3986#section-2.3
    private static final Set<Character> UnreservedChars = new HashSet<>(Arrays.asList(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
            'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
            'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            '-', '_', '.', '~'));

    public String consumerSecret;
    public String method;
    public String parameterString;
    public String queryParameters = "";
    public Map<String, String> queryParametersMap = new LinkedHashMap<>();
    public Map<String, String> parameters = new LinkedHashMap<>();
    public String signature;
    public String signatureBaseString;
    public String signingKey;
    public String tokenSecret;
    public String url;

    /***
     * Replaces any character not specifically unreserved to an equivalent percent
     * sequence.
     *
     * @param s the string to encode
     * @return and encoded string
     */
    public static String encodeURIComponent(String s) {
        StringBuilder o = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            if (isSafe(b)) {
                o.append((char) b);
            } else {
                o.append('%');
                o.append(HEX[((b & 0xF0) >> 4)]);
                o.append(HEX[((b & 0x0F))]);
            }
        }
        return o.toString();
    }

    private static boolean isSafe(byte b) {
        return UnreservedChars.contains((char) b);
    }

    public String build() {
        // For testing purposes, only add the timestamp if it has not yet been added
        if (!parameters.containsKey("oauth_timestamp")) {
            parameters.put("oauth_timestamp", "" + Instant.now().getEpochSecond());
        }

        // Boiler plate parameters
        parameters.put("oauth_nonce", nonceGenerator());
        parameters.put("oauth_signature_method", "HMAC-SHA1");
        parameters.put("oauth_version", "1.0");

        Map<String, String> parametersCopy = new LinkedHashMap<>(parameters);
        parametersCopy.putAll(queryParametersMap);

        // Build the parameter string after sorting the keys in lexicographic order per
        // the OAuth v1 spec.
        parameterString = parametersCopy.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> encodeURIComponent(e.getKey()) + "=" + encodeURIComponent(e.getValue()))
                .collect(Collectors.joining("&"));

        // Build the signature base string
        signatureBaseString = method.toUpperCase() + "&" + encodeURIComponent(url) + "&"
                + encodeURIComponent(parameterString);

        // If the signing key was not provided, build it by encoding the consumer secret
        // + the token secret
        if (signingKey == null) {
            signingKey = encodeURIComponent(consumerSecret) + "&"
                    + (tokenSecret == null ? "" : encodeURIComponent(tokenSecret));
        }

        // Sign the Signature Base String
        signature = generateSignature(signingKey, signatureBaseString);

        // Add the signature to be included in the header
        parameters.put("oauth_signature", signature);

        // Build the authorization header value using the order in which the parameters
        // were added
        return "OAuth " + parameters.entrySet().stream()
                .map(e -> encodeURIComponent(e.getKey()) + "=\"" + encodeURIComponent(e.getValue()) + "\"")
                .collect(Collectors.joining(", "));
    }

    public String generateSignature(String secret, String message) {
        try {
            byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(bytes, "HmacSHA1"));
            byte[] result = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(result);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Set the Consumer Secret
     *
     * @param consumerSecret the Consumer Secret
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withConsumerSecret(String consumerSecret) {
        this.consumerSecret = consumerSecret;
        return this;
    }

    /**
     * Set the requested HTTP method
     *
     * @param method the HTTP method you are requesting
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withMethod(String method) {
        this.method = method;
        return this;
    }

    /**
     * Add a parameter to the be included when building the signature.
     *
     * @param name  the parameter name
     * @param value the parameter value
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withParameter(String name, String value) {
        parameters.put(name, value);
        return this;
    }

    public OAuth1AuthorizationHeaderBuilder withURLQueryParameter(String queryParameters) {
        if (queryParameters == null || queryParameters.isEmpty()) {
            this.queryParameters = "";
        } else {
            String[] kvp = queryParameters.split("=");
            this.queryParametersMap.put(kvp[0], kvp[1]);
            this.queryParameters += "&" + queryParameters;
        }
        return this;
    }

    /**
     * Set the OAuth Token Secret
     *
     * @param tokenSecret the OAuth Token Secret
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
        return this;
    }

    /**
     * Set the requested URL in the builder.
     *
     * @param url the URL you are requesting
     * @return this
     */
    public OAuth1AuthorizationHeaderBuilder withURL(String url) {

        if (url.contains("?")) {
            handleQueryParam(url);
        } else {
            this.url = url;
        }
        return this;
    }

    /**
     * If url contains queryParam , extract them from the this.url data member
     * and assign the, to the this.queryParameters data member <br/>
     * <p>
     * For ex: <br/>
     * URL:
     * <i>https://lp-agentmngworkspace-qa.dev.lprnd.net/manager_workspace/api/account/le61691980/agent_view?version=v1</i>
     * will lead to : <br/>
     * url =
     * <b>https://lp-agentmngworkspace-qa.dev.lprnd.net/manager_workspace/api/account/le61691980/agent_view</b>
     * <br/>
     * queryParameters = <b>&version=v1</b> <br/>
     *
     * @param url
     */
    private void handleQueryParam(String url) {
        if (url.contains("?")) {
            String queryParam = url.substring(url.indexOf("?"));
            if (queryParam.length() > 1) {
                queryParam = queryParam.substring(1);

                String[] paramTokens = queryParam.split("&");
                if (paramTokens != null) {
                    for (String paramToken : paramTokens) {
                        String[] paramNameAndValue = paramToken.split("=");
                        if (paramNameAndValue != null) {
                            this.withURLQueryParameter(paramToken);
                        }
                    }
                }
            }
            this.url = url.substring(0, url.indexOf("?"));

        }
    }

    public static String nonceGenerator() {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < 15; i++) {
            stringBuilder.append(secureRandom.nextInt(10));
        }
        String randomNumber = stringBuilder.toString();
        return DigestUtils.md5Hex(randomNumber);
    }

}
