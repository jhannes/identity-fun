package com.johannesbrodwall.identity.idporten;

import com.johannesbrodwall.identity.Configuration;
import com.johannesbrodwall.identity.util.BearerToken;
import org.jsonbuddy.JsonArray;
import org.jsonbuddy.JsonNode;
import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonHttpException;
import org.jsonbuddy.parse.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.Optional;
import java.util.UUID;

/**
 * Client for use of the <a href="https://integrasjon-ver2.difi.no/swagger-ui.html">Self-service API</a> for ID-porten.
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
    private URL apiEndpoint;

    public IdPortenApiClient(URL apiEndpoint, BearerToken accessToken) {
        this.apiEndpoint = apiEndpoint;
        this.accessToken = accessToken;
    }

    public static void main(String[] args) throws Exception {
        Configuration idPortenConfig = new Configuration(new File("idporten.properties"));
        Configuration oauth2Config = new Configuration(new File("oauth2-providers.properties"));

        URL apiEndpoint = new URL(idPortenConfig.getRequiredProperty("idporten.integrasjon_endpoint"));

        URL oidcEndpoint = new URL(oauth2Config.getProperty("id_porten.issuer_uri").orElse("https://oidc-ver2.difi.no/idporten-oidc-provider") + "/");
        BearerToken accessToken = requestAccessToken(idPortenConfig, oidcEndpoint);

        IdPortenApiClient idPortenApiClient = new IdPortenApiClient(apiEndpoint, accessToken);

        String clientName = System.getProperty("idporten.client_name");
        if (clientName == null) {
            System.err.println("Please run with -Didporten.client_name=<client_name>");
            System.exit(1);
        }

        System.out.println("Please enter command: [list [<client_name>]|create|findClient|show|update|deleteDuplicates|help]");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String input = reader.readLine().trim();

        String[] parts = input.split(" ");
        String command = parts[0];
        if (command.equalsIgnoreCase("list")) {
            JsonArray clients = idPortenApiClient.listClients(parts.length > 1 ? Optional.of(parts[1]) : Optional.empty());
            logger.info("Clients: {}", clients.toIndentedJson("  "));
        } else if (command.equals("show")) {
            String clientId = oauth2Config.getRequiredProperty("idporten.client_id");
            JsonObject clientObject = idPortenApiClient.getClient(clientId);
            logger.info("show client {} Response: {}", clientId, clientObject.toIndentedJson("  "));
        } else if (command.equals("deleteDuplicates")) {
            idPortenApiClient.deleteDuplicates(clientName);
        } else if (command.equals("update")) {
            String clientId = oauth2Config.getRequiredProperty("idporten.client_id");
            String redirectUri = oauth2Config.getRequiredProperty("idporten.redirect_uri");
            String postLogoutUri = redirectUri.replace("/oauth2callback", "/logout");
            idPortenApiClient.updateClientUris(clientId, redirectUri, postLogoutUri);
        } else if (command.equals("DELETE")) {
            String clientId = oauth2Config.getRequiredProperty("idporten.client_id");
            idPortenApiClient.deleteClient(clientId);
        } else if (command.equals("findClient")) {
            JsonArray clients = idPortenApiClient.listClients(Optional.of(clientName));
            if (clients.size() != 1) {
                throw new RuntimeException("Could not determine client_id for client_name=" + clientName + ": " + clients);
            }
            JsonObject client = clients.requiredObject(0);
            String clientId = client.requiredString("client_id");
            System.out.println("idporten.client_id=" + clientId);
            if (oauth2Config.getProperty("idporten.client_secret").isEmpty()) {
                idPortenApiClient.createSecret(clientId);
            }
        } else if (command.equals("create")) {
            JsonArray clients = idPortenApiClient.listClients(Optional.of(clientName));
            if (!clients.isEmpty()) {
                throw new RuntimeException("Client already exists for client_name=" + clientName + ": " + clients);
            }
            String redirectUri = oauth2Config.getRequiredProperty("idporten.redirect_uri");
            String postLogoutUri = redirectUri.replace("/oauth2callback", "/logout");

            JsonObject clientObject = newClient(clientName, redirectUri, postLogoutUri);
            JsonObject client = idPortenApiClient.createClient(clientObject);
            logger.info("Clients: {}", idPortenApiClient.listClients(Optional.of(clientName)).toIndentedJson("  "));
            System.out.println("idporten.client_id=" + client.requiredString("client_id"));
        } else {
            System.err.println("Illegal command [" + input + "]");
        }
    }

    private static JsonObject newClient(String clientName, String redirectUri, String postLogoutUri) {
        return new JsonObject()
                        .put("client_name", clientName)
                        .put("description", clientName)
                        .put("scopes", new JsonArray().add("openid").add("profile"))
                        .put("redirect_uris", new JsonArray().add(redirectUri))
                        .put("post_logout_uris", new JsonArray().add(postLogoutUri))
                        .put("client_type", "PUBLIC")
                        .put("token_reference", "OPAQUE")
                        .put("refresh_token_usage", "ONETIME")
                        .put("frontchannel_logout_session_required", false)
                        .put("force_pkce", false)
                        .put("grant_types", new JsonArray().add("authorization_code"))
                        .put("token_endpoint_auth_method", "client_secret_post")
                        .put("client_uri", "");
    }

    private void createSecret(String clientId) throws IOException {
        URL url = new URL(apiEndpoint, "clients/" + clientId + "/secret");
        try {
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            accessToken.authorize(conn);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            JsonObject secret = JsonParser.parseToObject(conn);
            logger.info("POST {} Response: {}", url, secret.toIndentedJson("  "));
            System.out.println("idporten.client_secret=" + secret.requiredString("client_secret"));
        } catch (JsonHttpException e) {
            logger.error("POST {} Error: {}{}", url, e.getErrorContent(), e.getJsonError(), e);
            throw e;
        }

    }

    private JsonObject createClient(JsonObject clientObject) throws IOException {
        URL url = new URL(apiEndpoint, "clients/");
        try {
            JsonNode result = postJson(clientObject, url, "POST");
            logger.info("POST {} Response: {}", url, result);
            return (JsonObject)result;
        } catch (JsonHttpException e) {
            logger.error("PUT {} Error: {}{}", url, e.getErrorContent(), e.getJsonError(), e);
            throw e;
        }
    }

    private void deleteDuplicates(String clientName) throws IOException {
        parseToJsonArray(new URL(apiEndpoint, "/clients"))
                .objectStream()
                .filter(o -> o.requiredString("client_name").equals(clientName))
                .sorted(Comparator.comparing((JsonObject o) -> ZonedDateTime.parse(o.requiredString("created"))).reversed())
                .skip(1)
                .forEach(client -> deleteClient(client.requiredString("client_id")));
    }

    private void updateClientUris(String clientId, String redirectUri, String postLogoutUri) throws IOException {
        JsonObject clientObject = getClient(clientId);
        boolean updateRequired = false;
        JsonArray redirectUris = clientObject.requiredArray("redirect_uris");
        if (!redirectUris.strings().contains(redirectUri)) {
            redirectUris.add(redirectUri);
            clientObject.put("redirect_uris", redirectUris);
            updateRequired = true;
        }

        JsonArray postLogoutUris = clientObject.arrayValue("post_logout_redirect_uris").orElse(new JsonArray());
        System.out.println(postLogoutUris);
        if (!postLogoutUris.strings().contains(postLogoutUri)) {
            clientObject.put("post_logout_redirect_uris", postLogoutUris);
            updateRequired = true;
        }

        if (updateRequired) {
            clientObject.remove("client_orgno");
            URL url = new URL(apiEndpoint, "clients/" + clientId);
            try {
                JsonNode result = postJson(clientObject, url, "PUT");
                logger.info("PUT {} Response: {}", url, result.toIndentedJson("  "));
            } catch (JsonHttpException e) {
                logger.error("PUT {} Error: {}{}", url, e.getErrorContent(), e.getJsonError(), e);
            }
        } else {
            logger.info("No update needed: {}", clientObject.toIndentedJson("  "));
        }
    }

    private static BearerToken requestAccessToken(Configuration idPortenConfig, URL oidcEndpoint) throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("pkcs12");
        keyStore.load(new FileInputStream(idPortenConfig.getRequiredProperty("keystore.file")), idPortenConfig.getRequiredProperty("keystore.password").toCharArray());
        String alias = Collections.list(keyStore.aliases()).get(0);
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, idPortenConfig.getRequiredProperty("keystore.password").toCharArray());
        return requestAccessToken(oidcEndpoint, idPortenConfig.getRequiredProperty("issuer"), certificate, privateKey);
    }

    private JsonObject getClient(String clientId) throws IOException {
        URL url = new URL(apiEndpoint, "/clients/");
        return parseToJsonArray(url).objectStream()
                .filter(o -> o.requiredString("client_id").equals(clientId))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Could not find client " + clientId));
    }

    private void deleteClient(String clientId) {
        logger.info("Deleting " + clientId);
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

    private JsonArray listClients(Optional<String> clientNameFilter) throws IOException {
        URL url = new URL(apiEndpoint, "/clients");
        JsonArray clients = new JsonArray();
        parseToJsonArray(url)
                .objectStream()
                .filter(o -> clientNameFilter.map(n -> o.requiredString("client_name").equals(n)).orElse(true))
                .forEach(clients::add);
        return clients;
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
                "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8)
                + "&assertion=" + organizationJwt;
        HttpURLConnection conn = (HttpURLConnection) tokenEndpoint.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        try (OutputStream outputStream = conn.getOutputStream()) {
            outputStream.write(payload.getBytes());
        }
        JsonObject response = JsonParser.parseToObject(conn);
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
