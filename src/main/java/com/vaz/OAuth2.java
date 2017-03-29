package com.vaz;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

import java.security.Key;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


public class OAuth2 {

    RestTemplate restTemplate = new RestTemplate();


    public String generateJsonWebToken(final String clientId, final String secret, final String audience)
            throws JoseException {
        JwtClaims claims = new JwtClaims();
        claims.setIssuedAt(NumericDate.now());
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setSubject(clientId);
        claims.setIssuer(clientId);
        claims.setAudience(audience);
        claims.setGeneratedJwtId();

        try {
            Key key = new HmacKey(secret.getBytes("UTF-8"));
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toJson());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
            jws.setKey(key);
            jws.setDoKeyValidation(false);
            return jws.getCompactSerialization();
        } catch (Exception e) {
            throw new JoseException("JWT Generation failed", e);
        }
    }

    public void obtainOAuth2Token(final String clientId, final String secret, final String audience) throws JoseException {
        String jWTtoken = generateJsonWebToken(clientId, secret, audience);
        final String path = "https://id.corp.aol.com/identity/oauth2/access_token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        Map<String, Object> urlParams = new HashMap<>();
        urlParams.put("grant_type", "client_credentials");
        urlParams.put("scope", "one");
        urlParams.put("realm", "aolcorporate/aolexternals");
        urlParams.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        urlParams.put("client_assertion", jWTtoken);
        restTemplate.postForObject(path, urlParams, String.class);

    }
}
