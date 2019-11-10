package com.johannesbrodwall.identity.config;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;

public interface Oauth2IssuerConfiguration {
    URL getAuthorizationEndpoint();

    String getScopesString();

    Optional<URL> getEndSessionEndpoint();

    URL getTokenEndpoint();

    default URL toURL(String url) {
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }


}
