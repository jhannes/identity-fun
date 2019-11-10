package com.johannesbrodwall.identity.idporten;

import com.johannesbrodwall.identity.config.Configuration;
import com.johannesbrodwall.identity.util.BearerToken;
import org.jsonbuddy.JsonArray;
import org.jsonbuddy.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

class IdPortenAccessTokenFactory {

    private static final Logger logger = LoggerFactory.getLogger(IdPortenApiClient.class);

    private Configuration idPortenConfig;
    private URL oidcEndpoint;

    public IdPortenAccessTokenFactory(Configuration idPortenConfig, URL oidcEndpoint) {
        this.idPortenConfig = idPortenConfig;
        this.oidcEndpoint = oidcEndpoint;
    }

    public BearerToken requestAccessToken(String issuer, String scopes) throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(new FileInputStream(idPortenConfig.getRequiredProperty("keystore.file")), idPortenConfig.getRequiredProperty("keystore.password").toCharArray());
        String alias = Collections.list(keyStore.aliases()).get(0);
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, idPortenConfig.getRequiredProperty("keystore.password").toCharArray());
        return requestAccessToken(oidcEndpoint, issuer, certificate, privateKey, scopes);
    }

    private BearerToken requestAccessToken(URL oidcEndpoint, String issuer, X509Certificate certificate, PrivateKey privateKey, String scopes) throws GeneralSecurityException, IOException {
        JsonObject jwtHeader = new JsonObject()
                .put("alg", "RS256")
                .put("x5c", new JsonArray().add(Base64.getEncoder().encodeToString(certificate.getEncoded())));
        JsonObject jwtPayload = new JsonObject()
                .put("aud", oidcEndpoint.toString())
                .put("iss", issuer)
                .put("jti", UUID.randomUUID().toString())
                .put("scope", scopes)
                .put("iat", System.currentTimeMillis() / 1000)
                .put("exp", System.currentTimeMillis() / 1000 + 2*60);
        logger.debug("Signing JWT with payload: {}", jwtPayload.toJson());
        String organizationJwt = createSignedJwt(jwtHeader, jwtPayload, privateKey);
        logger.debug("Requesting access token for JWT: {}", organizationJwt);

        URL tokenEndpoint = new URL(oidcEndpoint, "token");
        String payload =
                "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8)
                        + "&assertion=" + organizationJwt;
        logger.debug("\n{} {}\n{}", "POST", tokenEndpoint, payload);
        HttpURLConnection conn = (HttpURLConnection) tokenEndpoint.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        try (OutputStream outputStream = conn.getOutputStream()) {
            outputStream.write(payload.getBytes());
        }
        JsonObject response = JsonObject.parse(conn);
        logger.debug("POST {} response {}", tokenEndpoint, response);
        logger.debug("access_token={}", response.requiredString("access_token"));

        return new BearerToken(response.requiredString("access_token"));
    }

    private static String createSignedJwt(JsonObject jwtHeader, JsonObject jwtPayload, PrivateKey privateKey) throws GeneralSecurityException {
        Base64.Encoder base64Encoder = Base64.getUrlEncoder();
        String jwtContent =
                base64Encoder.encodeToString(jwtHeader.toJson().getBytes())
                        + "."
                        + base64Encoder.encodeToString(jwtPayload.toJson().getBytes());
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(jwtContent.getBytes());
        return jwtContent + "." + base64Encoder.encodeToString(signature.sign());
    }
}
