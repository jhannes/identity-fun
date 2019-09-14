package com.johannesbrodwall.identity;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.webapp.WebAppContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Optional;

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
        server.setRequestLog(new LogEventsRequestLog());
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

        URL webAppResource = getClass().getResource("/webapp-identity");
        File webAppSource = new File(webAppResource.getPath().replaceAll("/target/classes/", "/src/main/resources/"));
        if (webAppSource.isDirectory()) {
            webAppContext.setBaseResource(Resource.newResource(webAppSource));
            webAppContext.getInitParams().put("org.eclipse.jetty.servlet.Default.useFileMappedBuffer", "false");
        } else {
            webAppContext.setBaseResource(Resource.newResource(webAppResource));
        }

        webAppContext.addEventListener(new IdentityWebApp());
        return webAppContext;
    }

}
