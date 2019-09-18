package com.johannesbrodwall.identity;

import org.logevents.extend.servlets.LogEventsServlet;

import javax.servlet.DispatcherType;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.EnumSet;
import java.util.Map;

public class IdentityWebApp implements ServletContextListener {

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
        ServletContext context = event.getServletContext();
        context.addServlet("logs", new LogEventsServlet()).addMapping("/logs/*");

        addOpenIdConnectServlet(context, "google");
        addOpenIdConnectServlet(context, "azure");
        addOpenIdConnectServlet(context, "mssingle");
        addOpenIdConnectServlet(context, "idporten");

        context.addServlet("slack", new SlackOauth2Servlet("slack")).addMapping("/id/slack/*");

        context.addServlet("user", new UserServlet()).addMapping("/user");
        context.addServlet("config", new ConfigurationServlet()).addMapping("/config/*");

        context.addFilter("redirectToHttps", new EnsureHttpsFilter())
                .addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), true, "/*");

        context.addFilter("loggingContext", new LoggingContextFilter())
                .addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), true, "/*");
    }

    private void addOpenIdConnectServlet(ServletContext context, String providerName) {
        OpenIdConnectServlet servlet = new OpenIdConnectServlet(providerName, issuerUrls.get(providerName), consoleUrls.get(providerName));
        context.addServlet(providerName, servlet).addMapping("/id/" + providerName + "/*");
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {

    }
}
