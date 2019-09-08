package com.johannesbrodwall.identity;

import org.logevents.extend.servlets.LogEventsServlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

public class IdentityServletListener implements ServletContextListener {
    private Properties properties = new Properties();
    private Properties publicClientProperties = new Properties();

    private static Map<String, String> issuerUrls = Map.of(
            "google", "https://accounts.google.com",
            "azure", "https://login.microsoftonline.com/common",
            "idporten", "https://oidc-ver2.difi.no/idporten-oidc-provider"
    );

    private static Map<String, String> consoleUrls = Map.of(
            "google", "https://console.developers.google.com/apis/credentials",
            "idporten", "https://integrasjon-ver2.difi.no/swagger-ui.html",
            "azure", "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
            "mssingle", "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"
    );

    @Override
    public void contextInitialized(ServletContextEvent event) {
        try {
            ServletContext context = event.getServletContext();
            context.addServlet("logs", new LogEventsServlet()).addMapping("/logs/*");

            try (FileReader reader = new FileReader("oauth2-public-providers.properties")) {
                publicClientProperties.load(reader);
            }

            addOpenIdConnectServlet(context, "google");
            addOpenIdConnectServlet(context, "azure");
            addOpenIdConnectServlet(context, "mssingle");
            addOpenIdConnectServlet(context, "idporten");

            context.addServlet("slack", createSlackIdProviderServlet()).addMapping("/id/slack/*");

            context.addServlet("user", new UserServlet()).addMapping("/user");
            context.addServlet("config", new ConfigurationServlet(publicClientProperties)).addMapping("/config/*");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void addOpenIdConnectServlet(ServletContext context, String providerName) {
        OpenIdConnectServlet servlet = new OpenIdConnectServlet(providerName, issuerUrls.get(providerName), consoleUrls.get(providerName));
        context.addServlet(providerName, servlet).addMapping("/id/" + providerName + "/*");
    }

    // Setup https://api.slack.com/apps
    private Oauth2Servlet createSlackIdProviderServlet() {
        return new SlackOauth2Servlet();
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {

    }
}
