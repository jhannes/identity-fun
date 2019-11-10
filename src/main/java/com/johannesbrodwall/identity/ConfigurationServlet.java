package com.johannesbrodwall.identity;

import com.johannesbrodwall.identity.config.Configuration;
import com.johannesbrodwall.identity.config.Oauth2ConfigurationException;
import com.johannesbrodwall.identity.config.OpenidConfiguration;
import org.jsonbuddy.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

public class ConfigurationServlet extends HttpServlet {
    private static Logger logger = LoggerFactory.getLogger(Configuration.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            Configuration configuration = new Configuration(new File("oauth2-public-providers.properties"));
            if (req.getPathInfo() == null) {
                resp.sendError(404);
            } else if (req.getPathInfo().equals("/idProviders")) {
                resp.setContentType("text/javascript");

                JsonObject config = new JsonObject()
                        .put("google", getOpenIdProvider(configuration, "google", "https://accounts.google.com"))
                        .put("microsoft", getOpenIdProvider(configuration, "azure", "https://login.microsoftonline.com/common"))
                        .put("mssingle", getOpenIdProvider(configuration, "mssingle", configuration.getRequiredProperty("mssingle.issuer_uri")))
                        .put("idporten", getOpenIdProvider(configuration, "idporten", configuration.getProperty("idporten.issuer_uri").orElse("https://oidc-ver2.difi.no/idporten-oidc-provider")));

                resp.getWriter().println("const idProviderConfigurations = " + config + ";");
            } else {
                resp.sendError(404);
            }
        } catch (Oauth2ConfigurationException e) {
            logger.warn("Configuration problem", e);
            resp.getWriter().println("Configuration problems " + e);
        }
    }

    private JsonObject getOpenIdProvider(Configuration configuration, String mssingle, String requiredProperty) throws IOException {
        return openIdConnectProvider(mssingle, requiredProperty, configuration);
    }

    private JsonObject openIdConnectProvider(String idProvider, String openIdIssuerUrl, Configuration properties) throws IOException {
        OpenidConfiguration configuration = new OpenidConfiguration(openIdIssuerUrl);
        return new JsonObject()
                .put("title", properties.getProperty(idProvider + ".title").orElse("Login with " + idProvider))
                .put("token_endpoint", configuration.getTokenEndpoint().toString())
                .put("authorization_endpoint", configuration.getAuthorizationEndpoint().toString())
                .put("client_id", properties.getProperty(idProvider + ".client_id"))
                .put("scope", properties.getProperty(idProvider + ".scope").orElse("openid profile"));
    }
}
