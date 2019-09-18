package com.johannesbrodwall.identity.idporten;

import com.johannesbrodwall.identity.Configuration;
import com.johannesbrodwall.identity.util.BearerToken;
import org.actioncontroller.client.ApiClientProxy;
import org.actioncontroller.client.HttpURLConnectionApiClient;
import org.jsonbuddy.JsonArray;
import org.jsonbuddy.JsonNode;
import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonHttpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.Comparator;
import java.util.Optional;

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
        final IdPortenAccessTokenFactory idPortenAccessTokenFactory = new IdPortenAccessTokenFactory(idPortenConfig, oidcEndpoint);
        BearerToken accessToken = idPortenAccessTokenFactory.requestAccessToken(
                idPortenConfig.getRequiredProperty("issuer"),
                "idporten:dcr.read idporten:dcr.modify idporten:dcr.write"
        );

        IdPortenApiClient idPortenApiClient = new IdPortenApiClient(apiEndpoint, accessToken);

        String clientName = System.getProperty("idporten.client_name");
        if (clientName == null) {
            System.err.println("Please run with -Didporten.client_name=<client_name>");
            System.exit(1);
        }

        System.out.println("Please enter command: [list [<client_name>]|create|findClient|show|update|deleteDuplicates|help|scopes]");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String input = reader.readLine().trim();

        String[] parts = input.split(" ");
        String command = parts[0];
        if (command.equalsIgnoreCase("list")) {
            JsonArray clients = idPortenApiClient.listClients(parts.length > 1 ? Optional.of(parts[1]) : Optional.empty());
            JsonArray output = new JsonArray();
            clients.objectStream()
                    .map(o -> new JsonObject().put("client_id", o.requiredString("client_id")).put("client_name", o.requiredString("client_name")).put("scopes", o.requiredArray("scopes")))
                    .forEach(output::add);
            logger.info("Clients: {}",  clients.toIndentedJson("  "));
        } else if (command.equals("scopes")) {
            JsonArray scopes = idPortenApiClient.listScopes();
            logger.info("Scopes: {}", scopes.toIndentedJson("  "));
        } else if (command.equals("show")) {
            String clientId = oauth2Config.getRequiredProperty("idporten.client_id");
            JsonObject clientObject = idPortenApiClient.getClient(clientId);
            logger.info("show client {} Response: {}", clientId, clientObject.toIndentedJson("  "));
        } else if (command.equals("deleteDuplicates")) {
            idPortenApiClient.deleteDuplicates(clientName);
        } else if (command.equals("update")) {
            String clientId = oauth2Config.getRequiredProperty("idporten.client_id");
            String redirectUri = getRedirectUri(oauth2Config);
            String postLogoutUri = oauth2Config.getProperty("idporten.post_logout_redirect_uri").orElse(redirectUri.replace("/oauth2callback", "/logout"));
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
            if (oauth2Config.getProperty("idporten.client_secret").isEmpty()) {
                JsonObject secret = idPortenApiClient.createSecret(clientId);
                System.out.println("idporten.client_id=" + clientId);
                System.out.println("idporten.client_secret=" + secret.requiredString("client_secret"));
            } else {
                System.out.println("idporten.client_id=" + clientId);
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

    private JsonArray listScopes() throws IOException {
        return JsonArray.parse(connect("GET", "/scopes?inactive=true"));
    }

    private static String getRedirectUri(Configuration oauth2Config) {
        if (System.getProperty("idporten.redirect_uri") != null) {
            return System.getProperty("idporten.redirect_uri");
        }
        return oauth2Config.getRequiredProperty("idporten.redirect_uri");
    }

    private JsonArray listClients(Optional<String> clientNameFilter) throws IOException {
        IdPortenClientsApi client = ApiClientProxy.create(IdPortenClientsApi.class, new HttpURLConnectionApiClient(apiEndpoint.toString()) {
            @Override
            protected HttpURLConnection openConnection(URL url) throws IOException {
                HttpURLConnection httpURLConnection = super.openConnection(url);
                accessToken.authorize(httpURLConnection);
                return httpURLConnection;
            }
        });
        JsonArray clients = new JsonArray();
        client.list(Optional.empty())
                .objectStream()
                .filter(o -> clientNameFilter.map(n -> o.requiredString("client_name").equals(n)).orElse(true))
                .forEach(clients::add);
        return clients;
    }

    private JsonObject getClient(String clientId) throws IOException {
        HttpURLConnection connection = connect("GET", "/clients/");
        return JsonArray.parse(connection).objectStream()
                .filter(o -> o.requiredString("client_id").equals(clientId))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Could not find client " + clientId));
    }

    private JsonObject createClient(JsonObject clientObject) throws IOException {
        try {
            HttpURLConnection conn = connect("POST", "clients/");
            write(conn, clientObject);
            JsonObject result = JsonObject.parse(conn);
            logger.info("POST {} Response: {}", "clients/", result);
            return result;
        } catch (JsonHttpException e) {
            logger.error("PUT {} Error: {}{}", "clients/", e.getErrorContent(), e.getJsonError(), e);
            throw e;
        }
    }

    private static JsonObject newClient(String clientName, String redirectUri, String postLogoutUri) {
        return new JsonObject()
                .put("client_name", clientName)
                .put("description", "Delete after JavaZone 2019")
                .put("scopes", new JsonArray().add("openid").add("profile"))
                .put("redirect_uris", new JsonArray().add(redirectUri))
                .put("post_logout_redirect_uris", new JsonArray().add(postLogoutUri))
                .put("frontchannel_logout_uri", postLogoutUri)
                .put("client_type", "PUBLIC")
                .put("token_reference", "OPAQUE")
                .put("refresh_token_usage", "ONETIME")
                .put("frontchannel_logout_session_required", false)
                .put("force_pkce", false)
                .put("grant_types", new JsonArray().add("authorization_code"))
                .put("token_endpoint_auth_method", "client_secret_post")
                .put("client_uri", "");
    }

    private JsonObject createSecret(String clientId) throws IOException {
        String path = "clients/" + clientId + "/secret";
        try {
            HttpURLConnection conn = connect("POST", path);
            JsonObject secret = JsonObject.parse(conn);
            logger.info("POST {} Response: {}", path, secret.toIndentedJson("  "));
            return secret;
        } catch (JsonHttpException e) {
            logger.error("POST {} Error: {}{}", path, e.getErrorContent(), e.getJsonError(), e);
            throw e;
        }
    }

    private void deleteDuplicates(String clientName) throws IOException {
        HttpURLConnection connection = connect("GET", "/clients");
        JsonArray.parse(connection)
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
            postLogoutUris.add(postLogoutUri);
            clientObject.put("post_logout_redirect_uris", postLogoutUris);
            updateRequired = true;
        }
        if (!clientObject.stringValue("frontchannel_logout_uri").orElse("").equals(postLogoutUri)) {
            clientObject.put("frontchannel_logout_uri", postLogoutUri);
            updateRequired = true;
        }

        if (updateRequired) {
            clientObject.remove("client_orgno");
            try {
                HttpURLConnection conn = connect("PUT", "clients/" + clientId);
                write(conn, clientObject);
                JsonNode result = JsonObject.parse(conn);
                logger.info("PUT {} Response: {}", "clients/" + clientId, result.toIndentedJson("  "));
            } catch (JsonHttpException e) {
                logger.error("PUT {} Error: {}{}", "clients/" + clientId, e.getErrorContent(), e.getJsonError(), e);
            }
        } else {
            logger.info("No update needed: {}", clientObject.toIndentedJson("  "));
        }
    }

    private void deleteClient(String clientId) {
        logger.info("Deleting " + clientId);
        try {
            HttpURLConnection conn = connect("DELETE", "clients/" + clientId);
            logger.debug("DELETE {}", new URL(apiEndpoint, "clients/" + clientId));
            JsonHttpException.verifyResponseCode(conn);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void write(HttpURLConnection conn, JsonNode json) throws IOException {
        logger.debug("Payload: {}", json);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        try (OutputStream outputStream = conn.getOutputStream()) {
            outputStream.write(json.toJson().getBytes());
        }
    }

    private HttpURLConnection connect(String method, String path) throws IOException {
        URL url = new URL(apiEndpoint, path);
        logger.debug("\n{} {}\n{}", method, url, accessToken);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        accessToken.authorize(conn);
        conn.setRequestMethod(method);
        return conn;
    }

}
