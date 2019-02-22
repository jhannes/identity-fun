package com.johannesbrodwall.identity;

import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.UUID;

public class Oauth2Servlet extends HttpServlet {

    private static Logger logger = LoggerFactory.getLogger(Oauth2Servlet.class);

    private String clientId;
    private String clientSecret;
    private String redirectUri;

    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String grantType = "authorization_code";
    private String responseType = "code";
    private String scope;

    public Oauth2Servlet(String authorizationEndpoint, String tokenEndpoint, String scope) {
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.scope = scope;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String[] pathParts = req.getPathInfo().split("/");

        if (pathParts.length < 2) {
            resp.sendError(404);
            return;
        }

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

    private void setupSession(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        JsonObject tokenResponse = JsonParser.parseToObject((String) req.getSession().getAttribute("token_response"));

        String accessToken = tokenResponse.requiredString("access_token");

        JsonObject profile = JsonParser.parseToObject(
                new URL("https://slack.com/api/users.profile.get?token=" + accessToken)
        );
        JsonObject conversations = JsonParser.parseToObject(
                new URL("https://slack.com/api/conversations.list?token=" + accessToken)
        );

        UserSession.getFromSession(req)
                .addProfile("https://slack.com", accessToken, new JsonObject()
                    .put("user.profile.get", profile)
                    .put("user.conversations", conversations));

        resp.sendRedirect("/");
    }

    private void getToken(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String payload = req.getQueryString();
        payload = payload.replace("xxxxxxx", clientSecret);
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
                + "<h1>Token response</h1>"
                + "<pre>" + response + "</pre>"
                + "<div><a href='" + req.getServletPath() + "/session'>Create session</a></div>"
                + "<div><a href='/'>Front page</a></div>"
                + "</html>");
    }

    private void oauth2callback(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        logger.debug("oauth2callback with response: {}", req.getQueryString());
        logger.debug("oauth2callback parameters {}", Collections.list(req.getParameterNames()));

        String code = req.getParameter("code");
        String state = req.getParameter("state");
        String scope = req.getParameter("scope");

        String payload = "client_id=" + clientId
                + "&" + "client_secret=" + "xxxxxxx"
                + "&" + "redirect_uri=" + redirectUri
                + "&" + "code=" + code
                + "&" + "grant_type=" + grantType;

        resp.setContentType("text/html");
        resp.getWriter().write("<a href='" + req.getServletPath() + "/token?" + payload + "'>POST to " + tokenEndpoint + " " + payload + "</a>");
    }

    private void authenticate(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String loginState = UUID.randomUUID().toString();
        req.getSession().setAttribute("loginState", loginState);

        URL authenticationRequest = new URL(authorizationEndpoint + "?"
                + "client_id=" + clientId + "&"
                + "redirect_uri=" + redirectUri + "&"
                + "response_type=" + responseType + "&"
                + "scope=" + scope + "&"
                + "state=" + loginState);

        resp.setContentType("text/html");
        resp.getWriter().write("<a href='" + authenticationRequest + "'>" + authenticationRequest + "</a>");
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

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }
}
