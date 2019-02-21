package com.johannesbrodwall.identity;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.webapp.WebAppContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IdentityServer {

    private static Logger logger = LoggerFactory.getLogger(IdentityServer.class);

    private Server server = new Server(8080);


    public static void main(String[] args) throws Exception {
        new IdentityServer().start();
    }

    private void start() throws Exception {
        setupServer();
        server.start();
        logger.warn("Started {}", server.getURI());
    }

    private void setupServer() {
        server.setHandler(createWebAppContext());
    }

    private WebAppContext createWebAppContext() {
        WebAppContext webAppContext = new WebAppContext();
        webAppContext.setContextPath("/");
        webAppContext.setBaseResource(Resource.newClassPathResource("/webapp-identity"));
        return webAppContext;
    }
}
