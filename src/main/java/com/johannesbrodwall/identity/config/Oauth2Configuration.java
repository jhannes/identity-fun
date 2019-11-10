package com.johannesbrodwall.identity.config;

import java.net.URL;
import java.util.Optional;

public class Oauth2Configuration {
    private final Oauth2IssuerConfiguration issuerConfig;
    private final Oauth2ClientConfiguration clientConfig;

    public Oauth2Configuration(Oauth2IssuerConfiguration issuerConfig, Oauth2ClientConfiguration clientConfig) {
        this.issuerConfig = issuerConfig;
        this.clientConfig = clientConfig;
    }

    public URL getAuthorizationEndpoint() {
        return issuerConfig.getAuthorizationEndpoint();
    }

    public String getScopesString() {
        return issuerConfig.getScopesString();
    }

    public Optional<URL> getEndSessionEndpoint() {
        return issuerConfig.getEndSessionEndpoint();
    }

    public URL getTokenEndpoint() {
        return issuerConfig.getTokenEndpoint();
    }

    public String getClientId() {
        return clientConfig.getClientId();
    }

    public String getRedirectUri(String defaultValue) {
        return clientConfig.getRedirectUri(defaultValue);
    }

    public String getClientSecret() {
        return clientConfig.getClientSecret();
    }
}
