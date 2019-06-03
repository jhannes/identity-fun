package com.johannesbrodwall.identity;

import org.jsonbuddy.JsonObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Properties;

public class ConfigurationServlet extends HttpServlet {
    private Properties properties;

    public ConfigurationServlet(Properties properties) {
        this.properties = properties;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (req.getPathInfo() == null) {
            resp.sendError(404);
        } else if (req.getPathInfo().equals("/idProviders")) {
            resp.setContentType("text/javascript");

            JsonObject config = new JsonObject()
                    .put("google", openIdConnectProvider("google", "https://accounts.google.com"))
                    .put("microsoft", openIdConnectProvider("azure", "https://login.microsoftonline.com/common"))
                    .put("mssingle", openIdConnectProvider("mssingle", properties.getProperty("mssingle.issuer_uri")))
                    .put("idporten", openIdConnectProvider("idporten", properties.getProperty("idporten.issuer_uri")));

            resp.getWriter().println("const idProviderConfigurations = " + config + ";");
        } else {
            resp.sendError(404);
        }
    }

    private JsonObject openIdConnectProvider(final String idProvider, String openIdIssuerUrl) throws IOException {
        OpenidConfiguration configuration = new OpenidConfiguration(openIdIssuerUrl);
        return new JsonObject()
                .put("title", Optional.ofNullable(properties.getProperty(idProvider + ".title"))
                        .orElse("Login with " + idProvider))
                .put("token_endpoint", configuration.getTokenEndpoint().toString())
                .put("authorization_endpoint", configuration.getAuthorizationEndpoint().toString())
                .put("client_id", properties.getProperty(idProvider + ".client_id"))
                .put("scope", Optional.ofNullable(properties.getProperty(idProvider + ".scope"))
                        .orElse("openid profile"));
    }
}
