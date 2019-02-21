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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.UUID;

public class IdentityServlet extends HttpServlet {

    private static Logger logger = LoggerFactory.getLogger(IdentityServlet.class);

    private String clientId = "716142064442-mj5uo5olbrqdau8qu5gl47emdmb50uil.apps.googleusercontent.com";
    private String clientSecret = "W5CEYkxFQ7jy9m2N9gYFr-fz";
    private String redirectUri = "http://localhost:8080/id/google/oauth2callback";

    private String openidConfigurationUrl;
    private String authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    private String tokenEndpoint = "https://oauth2.googleapis.com/token";
    private String grantType = "authorization_code";
    private String responseType = "code";
    private String scope = "openid+profile+email";

    public IdentityServlet(String openidConfigurationUrl) {
        this.openidConfigurationUrl = openidConfigurationUrl;
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
            String loginState = UUID.randomUUID().toString();
            URL authenticationRequest = generateAuthenticationRequest(loginState);
            req.getSession().setAttribute("loginState", loginState);

            resp.setContentType("text/html");
            resp.getWriter().write("<a href='" + authenticationRequest + "'>" + authenticationRequest + "</a>");
        } else if (action.equals("oauth2callback")) {
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

        } else if (action.equals("token")) {
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
        } else if (action.equals("session")) {
            JsonObject tokenResponse = JsonParser.parseToObject((String) req.getSession().getAttribute("token_response"));

            UserSession session = UserSession.getFromSession(req);
            session.addTokenResponse(openidConfigurationUrl, tokenResponse);

            resp.sendRedirect("/");
        } else {
            resp.sendError(404);
        }
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

    private URL generateAuthenticationRequest(String loginState) throws MalformedURLException {
        return new URL(authorizationEndpoint + "?"
                + "client_id=" + clientId + "&"
                + "redirect_uri=" + redirectUri + "&"
                + "response_type=" + responseType + "&"
                + "scope=" + scope + "&"
                + "state=" + loginState);
    }
}
