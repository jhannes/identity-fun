package com.johannesbrodwall.identity;

import com.johannesbrodwall.identity.config.Oauth2Configuration;
import com.johannesbrodwall.identity.util.BearerToken;
import com.johannesbrodwall.identity.util.HttpAuthorization;
import org.actioncontroller.ContentBody;
import org.actioncontroller.Get;
import org.actioncontroller.QueryString;
import org.actioncontroller.RequestParam;
import org.actioncontroller.SendRedirect;
import org.actioncontroller.ServletUrl;
import org.actioncontroller.SessionParameter;
import org.jsonbuddy.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

public abstract class Oauth2Controller {

    private static Logger logger = LoggerFactory.getLogger(Oauth2Controller.class);

    protected final String providerName;

    protected abstract Oauth2Configuration getOauth2Configuration() throws IOException, HttpConfigurationException;

    protected abstract JsonObject fetchUserProfile(BearerToken accessToken) throws IOException;

    protected abstract String getApiUrl(BearerToken accessToken) throws MalformedURLException;

    public Oauth2Controller(String providerName) {
        this.providerName = providerName;
    }

    @Get("/authenticate")
    @ContentBody(contentType = "text/html")
    public String authenticate(
            @RequestParam("domain_hint") Optional<String> domainHint,
            @ServletUrl String servletUrl,
            @SessionParameter("state") Consumer<String> setLoginState
    ) throws IOException {
        String state = UUID.randomUUID().toString();
        setLoginState.accept(state);
        String authenticationUrl = getAuthenticationUrl(domainHint, servletUrl, state);
        return "<!DOCTYPE html>\n"
                + "<html>"
                + "<head>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
                + "</head>"
                + "<body>"
                + "<h2>Step 1: Redirect to authorization endpoint</h2>"
                + "<div><a href='" + authenticationUrl + "'>authenticate at " + authenticationUrl + "</a></div>"
                + "<div>"
                + "Normally your app would redirect directly to the following URL: <br />"
                + "<code>"
                + authenticationUrl.replaceAll("[?&]", "<br />&nbsp;&nbsp;&nbsp;&nbsp;$0")
                + "</code>"
                + "</div></body></html>";
    }

    @Get("/oauth2callback?code")
    @ContentBody(contentType = "text/html")
    public String oauth2callback(
            @RequestParam("code") String code,
            @RequestParam("state") String state,
            @ServletUrl String servletUrl,
            @SessionParameter("state") String loginState,
            @ServletUrl String servletPath
    ) throws IOException {
        if (loginState.equals(state)) {
            logger.debug("Login state matches callback state: {}", state);
        } else {
            logger.warn("Login state DOES NOT match callback state: {} != {}", loginState, state);
        }

        String payload = fetchPayload(code, servletUrl, "xxxxxxx");
        URL tokenEndpoint = getOauth2Configuration().getTokenEndpoint();
        return "<!DOCTYPE html>\n"
                + "<html>"
                + "<head>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
                + "</head>"
                + "<body>"
                + "<h2>Step 2: Client received callback with code</h2>"
                + "<div><a href='" + servletPath + "/token?" + payload + "'>fetch token with POST to " + tokenEndpoint + "</a></div>"
                + "<div>"
                + "Normally your app would directly perform a POST to <code>" + tokenEndpoint + "</code> with this payload:<br />"
                + "<code>&nbsp;&nbsp;&nbsp;&nbsp;"
                + payload.replaceAll("[?&]", "<br />&nbsp;&nbsp;&nbsp;&nbsp;$0")
                + "</code>"
                + "</div></body></html>";
    }

    @Get("/oauth2callback?error")
    @ContentBody
    public String oauth2callback(
            @RequestParam("error") String error,
            @RequestParam("error_description") Optional<String> errorDescription
    ) {
        return "<!DOCTYPE html>\n"
                + "<html>"
                + "<head>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
                + "</head>"
                + "<body>"
                + "<h2>Step 2b: Client received callback with error!</h2>"
                + "<div>Error: <code>" + error + "</code></div>"
                + errorDescription.map(e -> "<div>Error description: <code>" + e + "</code></div>").orElse("")
                + "<div><a href='/'>Front page</a></div>"
                + "</body>"
                + "</html>";
    }

    @Get("/token")
    @ContentBody(contentType = "text/html")
    public String getToken(
            @ServletUrl String servletUrl,
            @QueryString String payload,
            @SessionParameter("token_response") Consumer<JsonObject> setTokenResponse,
            @ServletUrl String servletPath
    ) throws IOException {
        payload = payload.replace("xxxxxxx", URLEncoder.encode(getOauth2Configuration().getClientSecret(), StandardCharsets.UTF_8.toString()));

        JsonObject jsonObject = fetchToken(payload);
        setTokenResponse.accept(jsonObject);

        return "<!DOCTYPE html>\n"
                + "<html>"
                + "<head>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
                + "</head>"
                + "<body>"
                + "<h2>Step 3: Process token</h2>"
                + "<div>This was the response from " + getOauth2Configuration().getTokenEndpoint() + "</div>"
                + "<pre>" + jsonObject.toIndentedJson("  ") + "</pre>"
                + jsonObject.stringValue("id_token")
                    .map(idToken -> "<button onclick='navigator.clipboard.writeText(\"" + idToken + "\").then(console.log)'>Copy id_token to clipboard</button>")
                    .orElse("")
                + "<div>Normally you application will directly use the token to establish an application session</div>"
                + "<div><a href='" + servletPath + "/session'>Create session</a></div>"
                + "<div><a href='/'>Front page</a></div>"
                + "</body>"
                + "</html>";
    }

    @Get("/session")
    @SendRedirect
    public String setupSession(
            @ServletUrl String servletUrl,
            @SessionParameter("token_response") JsonObject tokenResponse,
            @SessionParameter(createIfMissing = true) UserSession userSession
    ) throws IOException {
        BearerToken accessToken = new BearerToken(tokenResponse.requiredString("access_token"));

        UserSession.Oauth2ProviderSession session = new UserSession.Oauth2ProviderSession(providerName);
        session.setIssuer(getOauth2Configuration().getAuthorizationEndpoint().getAuthority());
        session.setAccessToken(tokenResponse.requiredString("access_token"));
        session.setUserinfo(fetchUserProfile(accessToken));
        session.setApiUrl(getApiUrl(accessToken));

        userSession.addSession(session);

        return "/";
    }

    private String getAuthenticationUrl(Optional<String> domainHint, String servletUrl, String state) throws IOException {
        Oauth2Configuration config = getOauth2Configuration();
        return new URLBuilder(config.getAuthorizationEndpoint())
                .query("client_id", config.getClientId())
                .query("state", state)
                .query("redirect_uri", getRedirectUri(servletUrl))
                .query("response_type", "code")
                .query("scope", config.getScopesString())
                .query("domain_hint", domainHint)
                .toString();
    }

    private String fetchPayload(String code, String servletUrl, String clientSecret) throws IOException {
        return "client_id=" + getOauth2Configuration().getClientId()
                + "&" + "client_secret=" + clientSecret
                + "&" + "redirect_uri=" + getRedirectUri(servletUrl)
                + "&" + "code=" + code
                + "&" + "grant_type=" + "authorization_code";
    }

    private JsonObject fetchToken(String payload) throws IOException {
        logger.debug("Fetching token from POST {} with payload: {}", getOauth2Configuration().getTokenEndpoint(), payload);
        HttpURLConnection connection = (HttpURLConnection) getOauth2Configuration().getTokenEndpoint().openConnection();
        connection.setDoOutput(true);
        try (OutputStream outputStream = connection.getOutputStream()) {
            outputStream.write(payload.getBytes());
        }
        JsonObject jsonObject = JsonObject.parse(connection);
        logger.debug("Token response: {}", jsonObject);
        return jsonObject;
    }

    private String getRedirectUri(@ServletUrl String servletUrl) throws IOException {
        return getOauth2Configuration().getRedirectUri(getDefaultRedirectUri(servletUrl));
    }

    private String getDefaultRedirectUri(String servletUrl) {
        return servletUrl + "/oauth2callback";
    }

    protected JsonObject jsonParserParseToObject(URL endpoint, HttpAuthorization authorization) throws IOException {
        logger.debug("Fetching from {}", endpoint);
        HttpURLConnection connection = (HttpURLConnection) endpoint.openConnection();
        authorization.authorize(connection);
        JsonObject response = JsonObject.parse(connection);
        logger.debug("Response: {}", response);
        return response;
    }
}
