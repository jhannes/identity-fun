package com.johannesbrodwall.identity;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.webapp.WebAppContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

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

        webAppContext.addServlet(new ServletHolder(createGoogleIdProviderServlet()), "/id/google/*");
        webAppContext.addServlet(new ServletHolder(createAzureIdProviderServlet()), "/id/microsoft/*");
        webAppContext.addServlet(new ServletHolder(new UserServlet()), "/user");


        return webAppContext;
    }

    private IdentityServlet createAzureIdProviderServlet() throws IOException {
        IdentityServlet servlet = new IdentityServlet("https://login.microsoftonline.com/common");
        return servlet;
    }

    private IdentityServlet createGoogleIdProviderServlet() throws IOException {
        IdentityServlet servlet = new IdentityServlet("https://accounts.google.com");
        servlet.setClientId("716142064442-mj5uo5olbrqdau8qu5gl47emdmb50uil.apps.googleusercontent.com");
        servlet.setClientSecret("W5CEYkxFQ7jy9m2N9gYFr-fz");
        servlet.setRedirectUri("http://localhost:8080/id/google/oauth2callback");
        return servlet;
    }
}
