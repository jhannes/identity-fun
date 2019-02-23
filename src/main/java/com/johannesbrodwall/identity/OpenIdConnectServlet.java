package com.johannesbrodwall.identity;

import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.UUID;

public class OpenIdConnectServlet extends HttpServlet {

    private static Logger logger = LoggerFactory.getLogger(OpenIdConnectServlet.class);

    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;

    private final String authorizationEndpoint;
    private final String tokenEndpoint;
    private String grantType = "authorization_code";
    private String responseType = "code";
    private String scope;
    private String openIdIssuerUrl;

    public OpenIdConnectServlet(String openIdIssuerUrl, Oauth2ClientConfiguration clientConfiguration) throws IOException {
        this.openIdIssuerUrl = openIdIssuerUrl;
        logger.debug("Loading openid-configuration from {}", openIdIssuerUrl + "/.well-known/openid-configuration");
        OpenidConfiguration configuration = new OpenidConfiguration(openIdIssuerUrl);
        this.authorizationEndpoint = configuration.getAuthorizationEndpoint();
        this.tokenEndpoint = configuration.getTokenEndpoint();
        this.scope = configuration.getScopesString();

        this.clientId = clientConfiguration.getClientId();
        this.clientSecret = clientConfiguration.getClientSecret();
        this.redirectUri = clientConfiguration.getRedirectUri();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String[] pathParts = req.getPathInfo().split("/");

        if (pathParts.length < 2) {
            resp.sendError(404);
            return;
        }

        try (MDC.MDCCloseable ignored = MDC.putCloseable("provider", openIdIssuerUrl)) {
            String action = pathParts[1];
            if (action.equals("authenticate")) {
                authenticate(req, resp);
            } else if (action.equals("oauth2callback")) {
                oauth2callback(req, resp);
            } else if (action.equals("token")) {
                getToken(req, resp);
            } else if (action.equals("session")) {
                setupSession(req, resp);
            } else {
                resp.sendError(404);
            }
        }
    }

    private void authenticate(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String loginState = UUID.randomUUID().toString();
        req.getSession().setAttribute("loginState", loginState);

        String domainHint = req.getParameter("domain_hint");

        URL authenticationRequest = new URL(authorizationEndpoint + "?"
                + "client_id=" + clientId + "&"
                + "redirect_uri=" + redirectUri + "&"
                + "response_type=" + responseType + "&"
                + "scope=" + scope + "&"
                + "state=" + loginState
                + (domainHint != null ? "&domain_hint=" + domainHint : "")
        );

        logger.debug("Generating authentication request: {}", authenticationRequest);

        resp.setContentType("text/html");
        resp.getWriter().write("<html>" +
                "<h2>Step 1: Redirect to authorization endpoint</h2>" +
                "<div><a href='" + authenticationRequest + "'>authenticate at " + authorizationEndpoint + "</a></div>" +
                "<div>" +
                "Normally your app would redirect directly to the following URL: <br />" +
                "<code>" +
                authenticationRequest.toString().replaceAll("[?&]", "<br />&nbsp;&nbsp;&nbsp;&nbsp;$0") +
                "</code>" +
                "</div></html>");
    }

    private void oauth2callback(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String code = req.getParameter("code");
        String state = req.getParameter("state");
        String scope = req.getParameter("scope");

        logger.debug("oauth2callback code {}", code);
        logger.debug("oauth2callback with response {}: {}", Collections.list(req.getParameterNames()), req.getQueryString());

        String loginState = (String) req.getSession().getAttribute("loginState");
        if (loginState == null) {
            logger.warn("Callback received without having called authorize first!");
        } else if (loginState.equals(state)) {
            logger.debug("Login state matches callback state: {}", state);
        } else {
            logger.warn("Login state DOES NOT match callback state: {} != {}", loginState, state);
        }

        String payload = "client_id=" + clientId
                + "&" + "client_secret=" + "xxxxxxx"
                + "&" + "redirect_uri=" + redirectUri
                + "&" + "code=" + code
                + "&" + "grant_type=" + grantType;

        resp.setContentType("text/html");

        resp.getWriter().write("<html>" +
                "<h2>Step 2: Client received callback with code</h2>" +
                "<div><a href='" + req.getServletPath() + "/token?" + payload + "'>fetch token with POST to " + tokenEndpoint + "</a></div>" +
                "<div>" +
                "Normally your app would directly perform a POST to <code>" + tokenEndpoint + "</code> with this payload:<br />" +
                "<code>&nbsp;&nbsp;&nbsp;&nbsp;" +
                payload.replaceAll("[?&]", "<br />&nbsp;&nbsp;&nbsp;&nbsp;$0") +
                "</code>" +
                "</div></html>");
    }

    private void getToken(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String payload = req.getQueryString();
        payload = payload.replace("xxxxxxx", URLEncoder.encode(clientSecret, StandardCharsets.UTF_8.toString()));

        logger.debug("Fetching token from POST {} with payload: {}", tokenEndpoint, payload);

        HttpURLConnection connection = (HttpURLConnection) new URL(tokenEndpoint).openConnection();
        connection.setDoOutput(true);
        connection.setDoInput(true);
        try (OutputStream outputStream = connection.getOutputStream()) {
            outputStream.write(payload.getBytes());
        }

        String response;
        if (connection.getResponseCode() < 400) {
            response = toString(connection.getInputStream());
        } else {
            response = toString(connection.getErrorStream());
        }

        req.getSession().setAttribute("token_response", response);
        resp.setContentType("text/html");
        resp.getWriter().write("<html>"
                + "<h2>Token received</h2>"
                + "<div>This was the response from " + tokenEndpoint + "</div>"
                + "<pre>" + response + "</pre>"
                + (connection.getResponseCode() < 400
                    ?   "<div>Normally you application will directly use the token to establish an application session</div>"
                        + "<div><a href='" + req.getServletPath() + "/session'>Create session</a></div>"
                    : "")
                + "<div><a href='/'>Front page</a></div>"
                + "</html>");
    }

    private void setupSession(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        JsonObject tokenResponse = JsonParser.parseToObject((String) req.getSession().getAttribute("token_response"));
        logger.debug("Decoding session from JWT: {}", tokenResponse.requiredString("id_token"));
        UserSession.OpenIdConnectSession session = new UserSession.OpenIdConnectSession(tokenResponse);
        JwtToken idToken = session.getIdToken();
        logger.debug("Validated token with iss={} sub={} aud={}",
                idToken.iss(), idToken.sub(), idToken.aud());
        if (!clientId.equals(idToken.aud())) {
            logger.warn("Token was not intended for us! {} != {}", clientId, idToken.aud());
        }
        if (!openIdIssuerUrl.equals(idToken.iss())) {
            logger.warn("Token was not issued by expected OpenID provider! {} != {}", openIdIssuerUrl, idToken.iss());
        }

        UserSession.getFromSession(req).addSession(idToken.iss(), session);
        resp.sendRedirect("/");
    }

    private String toString(InputStream inputStream) throws IOException {
        StringBuilder responseBuffer = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            int c;
            while ((c = reader.read()) != -1) {
                responseBuffer.append((char) c);
            }
        }
        return responseBuffer.toString();
    }
}
