package com.johannesbrodwall.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.UUID;

public class IdentityServlet extends HttpServlet {

    private static Logger logger = LoggerFactory.getLogger(IdentityServlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String[] pathParts = req.getPathInfo().split("/");

        if (pathParts.length < 3) {
            resp.sendError(404);
            return;
        }

        String provider = pathParts[1];
        String action = pathParts[2];

        if (action.equals("authenticate")) {
            String loginState = UUID.randomUUID().toString();
            URL authenticationRequest = generateAuthenticationRequest(loginState);
            req.getSession().setAttribute("loginState", loginState);

            resp.setContentType("text/html");
            resp.getWriter().write("<a href='" + authenticationRequest + "'>" + authenticationRequest + "</a>");
        } else if (action.equals("oauth2callback")) {
            logger.debug("oauth2callback with response: {}", req.getQueryString());
            logger.debug("oauth2callback parameters {}", Collections.list(req.getParameterNames()));

            String openidConfigurationUrl = "https://accounts.google.com/.well-known/openid-configuration";

            String clientId = "716142064442-mj5uo5olbrqdau8qu5gl47emdmb50uil.apps.googleusercontent.com";
            String clientSecret = "W5CEYkxFQ7jy9m2N9gYFr-fz";

            String tokenEndpoint = "https://accounts.google.com/o/oauth2/v2/token";
            String redirectUri = "http://localhost:8080/id/google/oauth2callback";

            String code = req.getParameter("code");

            String state = req.getParameter("state");

            String scope = req.getParameter("scope");


            String grantType = "authorization_code";
            String payload = "client_id=" + clientId
                    + "&" + "client_secret=" + "xxxxxxx"
                    + "&" + "redirect_uri=" + redirectUri
                    + "&" + "code=" + code
                    + "&" + "grant_type=" + grantType;

            resp.setContentType("text/html");

            resp.getWriter().write("<a href='/id/" + provider + "/token?" + payload + "'>POST to " + tokenEndpoint + " " + payload + "</a>");

        } else if (action.equals("token")) {
            URL tokenEndpoint = new URL("https://oauth2.googleapis.com/token");
            String clientSecret = "W5CEYkxFQ7jy9m2N9gYFr-fz";

            String payload = req.getQueryString();
            payload = payload.replace("xxxxxxx", clientSecret);
            HttpURLConnection connection = (HttpURLConnection) tokenEndpoint.openConnection();
            connection.setDoOutput(true);
            connection.setDoInput(true);

            try (OutputStream outputStream = connection.getOutputStream()) {
                outputStream.write(payload.getBytes());
            }


            StringBuilder response = new StringBuilder();
            if (connection.getResponseCode() < 400) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                    int c;
                    while ((c = reader.read()) != -1) {
                        response.append((char) c);
                    }
                }
            } else {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()))) {
                    int c;
                    while ((c = reader.read()) != -1) {
                        response.append((char) c);
                    }
                }
            }

            req.getSession().setAttribute("token_response", response.toString());
            resp.setContentType("text/html");
            resp.getWriter().write("<html>"
                            + "<h1>Token response</h1>"
                            + "<pre>" + response.toString() + "</pre>"
                            + "<div><a href='/id/" + provider + "/session'>Create session</a></div>"
                            + "<div><a href='/'>Front page</a></div>"
                            + "</html>");
        } else if (action.equals("session")) {
            String tokenResponse = (String) req.getSession().getAttribute("token_response");
            resp.sendRedirect("/");
        } else {
            resp.sendError(404);
        }
    }

    private URL generateAuthenticationRequest(String loginState) throws MalformedURLException {
        String openidConfigurationUrl = "https://accounts.google.com/.well-known/openid-configuration";

        String clientId = "716142064442-mj5uo5olbrqdau8qu5gl47emdmb50uil.apps.googleusercontent.com";
        String clientSecret = "W5CEYkxFQ7jy9m2N9gYFr-fz";

        String authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";

        String redirectUri = "http://localhost:8080/id/google/oauth2callback";
        String responseType = "code";
        String scope = "openid+profile+email";

        return new URL(authorizationEndpoint + "?"
                + "client_id=" + clientId + "&"
                + "redirect_uri=" + redirectUri + "&"
                + "response_type=" + responseType + "&"
                + "scope=" + scope + "&"
                + "state=" + loginState);
    }
}
