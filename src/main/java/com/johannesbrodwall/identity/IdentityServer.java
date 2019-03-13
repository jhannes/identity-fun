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
import java.util.Optional;
import java.util.Properties;

public class IdentityServer {

    private static Logger logger = LoggerFactory.getLogger(IdentityServer.class);

    private Server server = new Server();
    private Properties properties = new Properties();


    public static void main(String[] args) throws Exception {
        new IdentityServer().start();
    }

    private void start() throws Exception {
        setupServer();
        server.start();
        logger.warn("Started {}", server.getURI());
    }

    private void setupServer() throws IOException {
        try (FileReader reader = new FileReader("oauth2-providers.properties")) {
            properties.load(reader);
        }

        server.addLifeCycleListener(Server.STOP_ON_FAILURE);
        server.addConnector(createConnector());
        server.setHandler(createWebAppContext());
    }

    private ServerConnector createConnector() {
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(Optional.ofNullable(System.getenv("HTTP_PLATFORM_PORT"))
                .map(Integer::parseInt)
                .orElse(8080));
        connector.setHost("localhost");
        return connector;
    }

    private WebAppContext createWebAppContext() throws IOException {
        WebAppContext webAppContext = new WebAppContext();
        webAppContext.setContextPath("/");
        webAppContext.setBaseResource(Resource.newClassPathResource("/webapp-identity"));
        webAppContext.getInitParams().put("org.eclipse.jetty.servlet.Default.useFileMappedBuffer", "false");

        // TODO: Johannes: Provide URLs for where to set up these kinds of applications
        // TODO Create your Google application in https://console.developers.google.com/apis/credentials
        //  put `google.client_id`, `google.client_secret` and `google.redirect_uri` into `oauth2-providers.properties`
        addOpenIdConnectServlet(webAppContext, "/id/google/*", "google", "https://accounts.google.com");
        // TODO Create your Microsoft application in https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade
        //  Put the `azure.client_id`, `azure.client_secret` and `azure.redirect_uri` into `oauth2-providers.properties`
        addOpenIdConnectServlet(webAppContext, "/id/microsoft/*", "azure", "https://login.microsoftonline.com/common");
        // TODO Ask Johannes for crentials for a test application
        addOpenIdConnectServlet(webAppContext, "/idporten/*", "idporten", "https://oidc-ver1.difi.no/idporten-oidc-provider");

        // TODO Create your Slack app at https://api.slack.com/apps
        //  Put slack.client_id` and `slack.client_secret` in `oauth2-providers.properties`
        //  Select "OAuth & Permissions" in the menu and add your Redirect URL here. Put `slack.redirect_id` in `oauth2-providers.properties`
        //  Put `slack.authorization_endpoint=https://<team>.slack.com/oauth/authorize` in `oauth2-providers.properties`
        //  Put `slack.token_endpoint=https://slack.com/api/oauth.access` in `oauth2-providers.properties`
        String authorizationEndpoint = properties.getProperty("slack.authorization_endpoint");
        String tokenEndpoint = properties.getProperty("slack.token_endpoint");
        String scope = "groups:read";
        webAppContext.addServlet(new ServletHolder(new Oauth2Servlet(authorizationEndpoint, tokenEndpoint, scope, getOauth2ClientConfiguration("slack"))), "/id/slack/*");

        webAppContext.addServlet(new ServletHolder(new UserServlet()), "/user");

        return webAppContext;
    }

    private void addOpenIdConnectServlet(WebAppContext webAppContext, String pathSpec, String providerName, String openIdIssuerUrl) throws IOException {
        OpenIdConnectServlet servlet = new OpenIdConnectServlet(openIdIssuerUrl, getOauth2ClientConfiguration(providerName));
        webAppContext.addServlet(new ServletHolder(servlet), pathSpec);
    }

    private Oauth2ClientConfiguration getOauth2ClientConfiguration(String providerName) throws IOException {
        Oauth2ClientConfiguration configuration = new Oauth2ClientConfiguration(providerName);
        configuration.setClientId(properties.getProperty(providerName + ".client_id"));
        configuration.setClientSecret(properties.getProperty(providerName + ".client_secret"));
        configuration.setRedirectUri(properties.getProperty(providerName + ".redirect_uri"));
        return configuration;
    }


}
