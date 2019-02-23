package com.johannesbrodwall.identity;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.webapp.WebAppContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

public class IdentityServer {

    private static Logger logger = LoggerFactory.getLogger(IdentityServer.class);

    private Server server = new Server();


    public static void main(String[] args) throws Exception {
        new IdentityServer().start();
    }

    private void start() throws Exception {
        setupServer();
        server.start();
        logger.warn("Started {}", server.getURI());
    }

    private void setupServer() throws IOException {
        server.addConnector(createConnector());
        server.setHandler(createWebAppContext());
    }

    private ServerConnector createConnector() {
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(8080);
        connector.setHost("localhost");
        return connector;
    }

    private WebAppContext createWebAppContext() throws IOException {
        WebAppContext webAppContext = new WebAppContext();
        webAppContext.setContextPath("/");
        webAppContext.setBaseResource(Resource.newClassPathResource("/webapp-identity"));
        webAppContext.getInitParams().put("org.eclipse.jetty.servlet.Default.useFileMappedBuffer", "false");

        addOpenIdConnectServlet(webAppContext, "/id/google/*", "google", "https://accounts.google.com");
        addOpenIdConnectServlet(webAppContext, "/id/microsoft/*", "azure", "https://login.microsoftonline.com/common");
        addOpenIdConnectServlet(webAppContext, "/idporten/*", "idporten", "https://oidc-ver1.difi.no/idporten-oidc-provider");
        webAppContext.addServlet(new ServletHolder(createSlackIdProviderServlet()), "/id/slack/*");
        webAppContext.addServlet(new ServletHolder(new UserServlet()), "/user");


        return webAppContext;
    }

    private void addOpenIdConnectServlet(WebAppContext webAppContext, String pathSpec, String providerName, String openIdIssuerUrl) throws IOException {
        OpenIdConnectServlet servlet = new OpenIdConnectServlet(openIdIssuerUrl, getOauth2ClientConfiguration(providerName));
        webAppContext.addServlet(new ServletHolder(servlet), pathSpec);
    }

    private Oauth2Servlet createSlackIdProviderServlet() throws IOException {
        // Setup https://api.slack.com/apps
        String authorizationEndpoint = "https://javaBin-test.slack.com/oauth/authorize";
        String tokenEndpoint = "https://slack.com/api/oauth.access";
        String scope = "identity.basic";
        return new Oauth2Servlet(authorizationEndpoint, tokenEndpoint, scope, getOauth2ClientConfiguration("slack"));
    }

    private Oauth2ClientConfiguration getOauth2ClientConfiguration(String providerName) throws IOException {
        Properties properties = new Properties();

        try (FileReader reader = new FileReader("oauth2-providers.properties")) {
            properties.load(reader);
        }

        Oauth2ClientConfiguration configuration = new Oauth2ClientConfiguration(providerName);
        configuration.setClientId(properties.getProperty(providerName + ".client_id"));
        configuration.setClientSecret(properties.getProperty(providerName + ".client_secret"));
        configuration.setRedirectUri(properties.getProperty(providerName + ".redirect_uri"));
        return configuration;
    }


}
