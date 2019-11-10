package com.johannesbrodwall.identity.config;

public class Oauth2ClientConfiguration {
    private String clientId;
    private String clientSecret;
    private String providerName;
    private final Configuration configuration;

    public Oauth2ClientConfiguration(String providerName, Configuration configuration) {
        this.providerName = providerName;
        this.configuration = configuration;
        setClientId(configuration.getRequiredProperty(providerName + ".client_id"));
        setClientSecret(configuration.getRequiredProperty(providerName + ".client_secret"));
    }

    public void setClientId(String clientId) {
        this.clientId = verifyNotNull("clientId", clientId);
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = verifyNotNull("clientSecret", clientSecret);
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getRedirectUri(String defaultValue) {
        return configuration.getProperty(providerName + ".redirect_uri").orElse(defaultValue);
    }

    private String verifyNotNull(String propertyName, String value) {
        if (value == null) {
            throw new IllegalArgumentException("Missing " + propertyName + " for provider " + providerName);
        }
        return value;
    }

}
