package com.johannesbrodwall.identity;

import com.johannesbrodwall.identity.config.Configuration;
import com.johannesbrodwall.identity.config.Oauth2ClientConfiguration;
import com.johannesbrodwall.identity.config.Oauth2Configuration;
import com.johannesbrodwall.identity.config.Oauth2ConfigurationException;
import com.johannesbrodwall.identity.config.OpenidConfiguration;
import com.johannesbrodwall.identity.util.HttpAuthorization;
import org.actioncontroller.ContentBody;
import org.actioncontroller.ExceptionUtil;
import org.actioncontroller.Get;
import org.actioncontroller.QueryString;
import org.actioncontroller.RequestParam;
import org.actioncontroller.SendRedirect;
import org.actioncontroller.ServletUrl;
import org.actioncontroller.SessionParameter;
import org.jsonbuddy.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

public class OpenIdConnectController {

    private static final Logger logger = LoggerFactory.getLogger(OpenIdConnectController.class);

    private final String providerName;
    private final String discoveryUrl;
    private final Optional<String> consoleUrl;

    public OpenIdConnectController(String providerName, String discoveryUrl, String consoleUrl) {
        this.providerName = providerName;
        this.discoveryUrl = discoveryUrl;
        this.consoleUrl = Optional.ofNullable(consoleUrl);
    }

    //@Get("/authenticate")
    @SendRedirect
    public String authenticateWithRedirect(
            @RequestParam("domain_hint") Optional<String> domainHint,
            @ServletUrl String servletUrl,
            @SessionParameter("state") Consumer<String> setLoginState
    ) {
        String state = UUID.randomUUID().toString();
        setLoginState.accept(state);
        return getAuthorizationUrl(domainHint, servletUrl, state);
    }

    @Get("/authenticate")
    @ContentBody(contentType = "text/html")
    public String authenticate(
            @RequestParam("domain_hint") Optional<String> domainHint,
            @ServletUrl String servletUrl,
            @SessionParameter("state") Consumer<String> setLoginState
    ) {
        String state = UUID.randomUUID().toString();
        setLoginState.accept(state);
        String authenticationUrl = getAuthorizationUrl(domainHint, servletUrl, state);
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

    //@Get("/oauth2callback?code")
    @SendRedirect
    public String oauth2callbackWithRedirect(
            @RequestParam("code") String code,
            @RequestParam("state") String state,
            @ServletUrl String servletUrl,
            @SessionParameter("state") String loginState,
            @SessionParameter(createIfMissing = true) UserSession userSession
    ) throws IOException {
        if (loginState.equals(state)) {
            logger.debug("Login state matches callback state: {}", state);
        } else {
            logger.warn("Login state DOES NOT match callback state: {} != {}", loginState, state);
        }

        String payload = "client_id=" + getConfiguration(servletUrl).getClientId()
                + "&" + "client_secret=" + URLEncoder.encode(getConfiguration(servletUrl).getClientSecret(), StandardCharsets.UTF_8.toString())
                + "&" + "redirect_uri=" + getConfiguration(servletUrl).getRedirectUri(getDefaultRedirectUri(servletUrl))
                + "&" + "code=" + code
                + "&" + "grant_type=" + "authorization_code";
        JsonObject tokenResponse = fetchToken(servletUrl, payload);

        userSession.addSession(createSession(tokenResponse, getIssuerConfig(servletUrl), getConfiguration(servletUrl)));

        return "/";
    }

    @Get("/oauth2callback?code")
    @ContentBody(contentType = "text/html")
    public String oauth2callback(
            @RequestParam("code") String code,
            @RequestParam("state") String state,
            @ServletUrl String servletUrl,
            @SessionParameter("state") String loginState,
            @ServletUrl String servletPath
    ) {
        if (loginState.equals(state)) {
            logger.debug("Login state matches callback state: {}", state);
        } else {
            logger.warn("Login state DOES NOT match callback state: {} != {}", loginState, state);
        }

        Oauth2Configuration config = getConfiguration(servletUrl);
        String payload = "client_id=" + config.getClientId()
                + "&" + "client_secret=" + "xxxxxxx"
                + "&" + "redirect_uri=" + config.getRedirectUri(getDefaultRedirectUri(servletUrl))
                + "&" + "code=" + code
                + "&" + "grant_type=" + "authorization_code";
        URL tokenEndpoint = config.getTokenEndpoint();
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
        payload = payload.replace("xxxxxxx", URLEncoder.encode(getConfiguration(servletUrl).getClientSecret(), StandardCharsets.UTF_8.toString()));

        JsonObject jsonObject = fetchToken(servletUrl, payload);
        setTokenResponse.accept(jsonObject);

        return "<!DOCTYPE html>\n"
                + "<html>"
                + "<head>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
                + "</head>"
                + "<body>"
                + "<h2>Step 3: Process token</h2>"
                + "<div>This was the response from " + getConfiguration(servletUrl).getTokenEndpoint() + "</div>"
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
        OpenidConfiguration issuerConfig = getIssuerConfig(servletUrl);
        Oauth2Configuration config = getConfiguration(servletUrl);

        logger.debug("Access token: {} expires {}",
                tokenResponse.requiredString("access_token"),
                tokenResponse.stringValue("expires_on").orElse(""));

        userSession.addSession(createSession(tokenResponse, issuerConfig, config));

        return "/";
    }

    @Get("/refresh")
    public void refreshAccessToken(
            @ServletUrl String servletUrl,
            @SessionParameter(createIfMissing = true) UserSession session
    ) throws IOException {
        Oauth2Configuration config = getConfiguration(servletUrl);
        String clientId = config.getClientId();
        String redirectUri = config.getRedirectUri(getDefaultRedirectUri(servletUrl));
        String clientSecret = config.getClientSecret();
        URL tokenEndpoint = config.getTokenEndpoint();

        UserSession.IdProviderSession idProviderSession = session.getIdProviderSessions().stream()
                .filter(s -> s.getProviderName().equals(providerName))
                .findAny().orElseThrow(() -> new IllegalArgumentException("Can't refresh non-existing session"));

        String payload = "client_id=" + clientId
                + "&" + "client_secret=" + clientSecret
                + "&" + "redirect_uri=" + redirectUri
                + "&" + "refresh_token=" + idProviderSession.getRefreshToken()
                + "&" + "grant_type=" + "refresh_token";
        HttpURLConnection connection = (HttpURLConnection) tokenEndpoint.openConnection();
        connection.setDoOutput(true);
        connection.setDoInput(true);
        try (OutputStream outputStream = connection.getOutputStream()) {
            outputStream.write(payload.getBytes());
        }
        JsonObject jsonObject = JsonObject.parse(connection);
        logger.debug("Refreshed session: {}", jsonObject);

        idProviderSession.setAccessToken(jsonObject.requiredString("access_token"));
    }

    @Get("/verify")
    @ContentBody(contentType = "text/html")
    public String verifyIdToken(
            @ServletUrl String servletUrl,
            @RequestParam("id_token") String idTokenString
    ) throws IOException {
        OpenidConfiguration issuerConfig = getIssuerConfig(servletUrl);
        JwtToken idTokenJwt = new JwtToken(idTokenString, false);
        try {
            idTokenJwt.safeVerifySignature();
        } catch (Exception e) {
            return "Signature failed: " + e;
        }
        try {
            idTokenJwt.verifyTimeValidity(Instant.now());
        } catch (Exception e) {
            return "Token time validity check failed: " + e;
        }

        if (!isMatchingIssuer(idTokenJwt, issuerConfig.getIssuer())) {
            return "Invalid issuer (was " + idTokenJwt.iss() + ", but wanted " + issuerConfig.getIssuer() + ")";
        }

        return "Token valid";
    }

    @Get("/logout")
    public void logoutSession(
            @SessionParameter(createIfMissing = true) UserSession session
    ) {
        session.removeSession(providerName);
    }

    private boolean isMatchingIssuer(JwtToken jwt, String issuer) {
        if (issuer.contains("{tenantid}")) {
            issuer = issuer.replaceAll("\\{tenantid}", jwt.getPayload().requiredString("tid"));
        }
        return issuer.equals(jwt.iss());
    }

    private String getAuthorizationUrl(@RequestParam("domain_hint") Optional<String> domainHint, @ServletUrl String servletUrl, String state) {
        Oauth2Configuration config = getConfiguration(servletUrl);
        return new URLBuilder(config.getAuthorizationEndpoint())
                .query("client_id", config.getClientId())
                .query("state", state)
                .query("redirect_uri", config.getRedirectUri(getDefaultRedirectUri(servletUrl)))
                .query("response_type", "code")
                .query("scope", config.getScopesString())
                .query("domain_hint", domainHint)
                .toString();
    }


    private UserSession.OpenIdConnectSession createSession(JsonObject tokenResponse, OpenidConfiguration issuerConfig, Oauth2Configuration config) throws IOException {
        String clientId = config.getClientId();
        String idToken = tokenResponse.requiredString("id_token");
        logger.debug("Decoding session from JWT: {}", idToken);
        JwtToken idTokenJwt = new JwtToken(idToken, true);
        logger.debug("Validated token with iss={} sub={} aud={}", idTokenJwt.iss(), idTokenJwt.sub(), idTokenJwt.aud());
        if (!clientId.equals(idTokenJwt.aud())) {
            logger.warn("Token was not intended for us! {} != {}", clientId, idTokenJwt.aud());
        }
        if (!issuerConfig.getIssuer().equals(idTokenJwt.iss())) {
            logger.warn("Token was not issued by expected OpenID provider! {} != {}", issuerConfig.getIssuer(), idTokenJwt.iss());
        }

        UserSession.OpenIdConnectSession session = new UserSession.OpenIdConnectSession(providerName);
        session.setAccessToken(tokenResponse.requiredString("access_token"));
        session.setRefreshToken(tokenResponse.stringValue("refresh_token"));
        session.setIdToken(idTokenJwt);
        session.setEndSessionEndpoint(config.getEndSessionEndpoint());
        session.setUserinfo(jsonParserParseToObject(issuerConfig.getUserinfoEndpoint(), session.getAccessBearerToken()));
        return session;
    }

    private JsonObject fetchToken(String servletUrl, String payload) throws IOException {
        logger.debug("Fetching token from POST {} with payload: {}", getConfiguration(servletUrl).getTokenEndpoint(), payload);
        HttpURLConnection connection = (HttpURLConnection) getConfiguration(servletUrl).getTokenEndpoint().openConnection();
        connection.setDoOutput(true);
        try (OutputStream outputStream = connection.getOutputStream()) {
            outputStream.write(payload.getBytes());
        }
        JsonObject jsonObject = JsonObject.parse(connection);
        logger.debug("Token response: {}", jsonObject);
        return jsonObject;
    }

    private Oauth2Configuration getConfiguration(String servletUrl) {
        try {
            Configuration configuration = new Configuration(new File("oauth2-providers.properties"));
            return new Oauth2Configuration(
                    getIssuerConfig(servletUrl),
                    new Oauth2ClientConfiguration(providerName, configuration)
            );
        } catch (Oauth2ConfigurationException e) {
            throw new HttpConfigurationException(providerName, consoleUrl, getDefaultRedirectUri(servletUrl), e);
        } catch (IOException e) {
            throw ExceptionUtil.softenException(e);
        }
    }

    private OpenidConfiguration getIssuerConfig(String servletUrl) {
        try {
            Configuration configuration = new Configuration(new File("oauth2-providers.properties"));
            String openIdIssuerUrl = Optional.ofNullable(this.discoveryUrl)
                    .orElseGet(() -> configuration.getRequiredProperty(providerName + ".issuer_uri"));
            return new OpenidConfiguration(openIdIssuerUrl);
        } catch (Oauth2ConfigurationException e) {
            throw new HttpConfigurationException(providerName, consoleUrl, getDefaultRedirectUri(servletUrl), e);
        } catch (IOException e) {
            throw ExceptionUtil.softenException(e);
        }
    }

    private JsonObject jsonParserParseToObject(URL endpoint, HttpAuthorization authorization) throws IOException {
        logger.debug("Fetching from {}", endpoint);
        HttpURLConnection connection = (HttpURLConnection) endpoint.openConnection();
        authorization.authorize(connection);
        JsonObject response = JsonObject.parse(connection);
        logger.debug("Response: {}", response);
        return response;
    }

    private String getDefaultRedirectUri(String servletUrl) {
        return servletUrl + "/oauth2callback";
    }

}
