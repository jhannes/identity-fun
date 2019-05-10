package com.johannesbrodwall.identity.idporten;

import com.johannesbrodwall.identity.util.BearerToken;
import org.jsonbuddy.JsonArray;
import org.jsonbuddy.JsonNode;
import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonHttpException;
import org.jsonbuddy.parse.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Demonstrates the use of a certificate to generate a client-generated JWT, exchanging it
 * for an API JTW and using this JWT as a bearer token to make API calls. Will try to ensure
 * that exactly one client exists with the client_name "javabin_openid_demo"
 * <p>
 *     Uses a <code>idporten.properties</code> file with the following values:
 * </p>
 * <pre>
 * keystore.file=&lt;path to the authentication pkcs12 keystore file&gt;
 * keystore.password=&lt;password for the keystore file&gt;
 * issuer=&lt;the client_id issues by ID-porten&gt;
 * idporten.oidc_endpoint=&lt;normally https://oidc.difi.no/idporten-oidc-provider/ or https://oidc-ver2.difi.no/idporten-oidc-provider/&gt;
 * idporten.integrasjon_endpoint=&lt;normally https://integrasjon.difi.no or https://integrasjon-ver2.difi.no&gt;
 * </pre>
 */
public class IdPortenApiClient {

    private static final Logger logger = LoggerFactory.getLogger(IdPortenApiClient.class);

    private final BearerToken accessToken;

    public IdPortenApiClient(URL oidcEndpoint, String issuer, X509Certificate certificate, PrivateKey privateKey) throws GeneralSecurityException, IOException {
        this.accessToken = requestAccessToken(oidcEndpoint, issuer, certificate, privateKey);
    }

    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        properties.load(new FileReader("idporten.properties"));

        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(new FileInputStream(properties.getProperty("keystore.file")), properties.getProperty("keystore.password").toCharArray());
        String alias = Collections.list(keyStore.aliases()).get(0);
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, properties.getProperty("keystore.password").toCharArray());

        String issuer = properties.getProperty("issuer");

        URL oidcEndpoint = new URL(properties.getProperty("idporten.oidc_endpoint"));

        IdPortenApiClient idPortenApiClient = new IdPortenApiClient(oidcEndpoint, issuer, certificate, privateKey);

        URL apiEndpoint = new URL(properties.getProperty("idporten.integrasjon_endpoint"));

        List<String> clientIds = idPortenApiClient.parseToJsonArray(new URL(apiEndpoint, "/clients"))
                .objectStream()
                .filter(o -> o.requiredString("client_name").equals("javabin_openid_demo"))
                .sorted(Comparator.comparing((JsonObject o) -> ZonedDateTime.parse(o.requiredString("created"))).reversed())
                .map(o -> o.requiredString("client_id"))
                .collect(Collectors.toList());
        logger.info("First client id {}", clientIds.stream().findFirst());
        logger.info("Client_ids {}", clientIds.stream().skip(1).collect(Collectors.toList()));

        clientIds.stream().findFirst().ifPresentOrElse(
                clientId -> idPortenApiClient.updateClient(apiEndpoint, clientId),
                () -> idPortenApiClient.createClient(apiEndpoint));
        clientIds.stream().skip(1)
                .forEach(clientId -> idPortenApiClient.deleteClient(apiEndpoint, clientId));
        idPortenApiClient.listClients(apiEndpoint);
    }

    private void deleteClient(URL apiEndpoint, String clientId) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(apiEndpoint, "clients/" + clientId).openConnection();
            conn.setRequestMethod("DELETE");
            accessToken.authorize(conn);
            logger.debug("DELETE {}", new URL(apiEndpoint, "clients/" + clientId));
            verifySuccess(conn);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void createClient(URL apiEndpoint) {

    }

    private void updateClient(URL apiEndpoint, String clientId) {
        JsonObject clientObject = new JsonObject()
                .put("client_name", "javabin_openid_demo")
                .put("client_id", "javabin_openid_demo")
                .put("description", "javabin_openid_demo")
                .put("scopes", new JsonArray().add("openid").add("profile"))
                .put("redirect_uris", Arrays.asList(
                        "http://localhost:8080/id/idporten/oauth2callback",
                        "http://localhost:8080/idporten/oauth2callback",
                        "https://javabin-openid-demo.azurewebsites.net/id/idporten/oauth2callback"))
                .put("post_logout_uris", Arrays.asList(
                        "https://javabin-openid-demo.azurewebsites.net/id/idporten/logout"))
                .put("authorization_lifetime", 0)
                .put("access_token_lifetime", 0)
                .put("refresh_token_lifetime", 0)
                .put("client_type", "CONFIDENTIAL")
                .put("token_reference", "OPAQUE")
                .put("refresh_token_usage", "ONETIME")
                .put("frontchannel_logout_session_required", false)
                .put("force_pkce", false)
                .put("client_uri", "")
                ;
        try {
            URL url = new URL(apiEndpoint, "clients/" + clientId);
            JsonNode result = postJson(clientObject, url, "PUT");
            logger.info("PUT {} Response: {}", url, result);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void listClients(URL apiEndpoint) throws IOException {
        URL url = new URL(apiEndpoint, "/clients");
        JsonArray response = parseToJsonArray(url);
        logger.info("GET {} Response: {}", url, response.toIndentedJson("  "));
    }


    private static BearerToken requestAccessToken(URL oidcEndpoint, String issuer, X509Certificate certificate, PrivateKey privateKey) throws GeneralSecurityException, IOException {
        JsonObject jwtHeader = new JsonObject()
                .put("alg", "RS256")
                .put("x5c", new JsonArray().add(Base64.getEncoder().encodeToString(certificate.getEncoded())));
        JsonObject jwtPayload = new JsonObject()
                .put("aud", oidcEndpoint.toString())
                .put("iss", issuer)
                .put("jti", UUID.randomUUID().toString())
                .put("scope", "idporten:dcr.read idporten:dcr.modify idporten:dcr.write")
                .put("iat", System.currentTimeMillis() / 1000)
                .put("exp", System.currentTimeMillis() / 1000 + 2*60);
        String organizationJwt = createSignedJwt(jwtHeader, jwtPayload, privateKey);

        URL tokenEndpoint = new URL(oidcEndpoint, "token");
        String payload =
                "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", "utf8")
                + "&assertion=" + organizationJwt;
        HttpURLConnection conn = (HttpURLConnection) tokenEndpoint.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        try (OutputStream outputStream = conn.getOutputStream()) {
            outputStream.write(payload.getBytes());
        }
        JsonObject response = JsonParser.parseToObject(conn);
        logger.debug("POST {} response {}", tokenEndpoint, response);

        return new BearerToken(response.requiredString("access_token"));
    }

    private static String createSignedJwt(JsonObject jwtHeader, JsonObject jwtPayload, PrivateKey privateKey) throws GeneralSecurityException {
        String organizationJwt = base64(jwtHeader) + "." + base64(jwtPayload);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(organizationJwt.getBytes());
        return organizationJwt + "." + Base64.getUrlEncoder().encodeToString(signature.sign());
    }

    private static String base64(JsonObject jsonObject) {
        return Base64.getUrlEncoder().encodeToString(jsonObject.toJson().getBytes());
    }

    private JsonNode postJson(JsonObject object, URL url, String method) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        accessToken.authorize(conn);
        conn.setRequestMethod(method);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        try (OutputStream outputStream = conn.getOutputStream()) {
            outputStream.write(object.toJson().getBytes());
        }
        verifySuccess(conn);
        try (InputStream input = conn.getInputStream()) {
            return JsonParser.parse(input);
        }
    }

    private JsonArray parseToJsonArray(URL url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        accessToken.authorize(connection);
        return parseToJsonArray(connection);
    }

    private JsonArray parseToJsonArray(HttpURLConnection connection) throws IOException {
        verifySuccess(connection);
        try (InputStream input = connection.getInputStream()) {
            return JsonParser.parseToArray(input);
        }
    }

    private void verifySuccess(HttpURLConnection connection) throws IOException {
        if (connection.getResponseCode() >= 400) {
            throw new JsonHttpException(connection);
        }
    }
}
