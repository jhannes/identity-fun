package com.johannesbrodwall.identity;

import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonParser;

import java.io.IOException;
import java.net.URL;
import java.util.List;

public class OpenidConfiguration {

    private JsonObject configuration;

    public OpenidConfiguration(String openIdIssuerUrl) throws IOException {
        configuration = JsonParser.parseToObject(new URL(openIdIssuerUrl + "/.well-known/openid-configuration"));
    }

    public String getAuthorizationEndpoint() {
        return configuration.requiredString("authorization_endpoint");
    }

    public String getTokenEndpoint() {
        return configuration.requiredString("token_endpoint");
    }

    public String getScopesString() {
        return String.join("+", getScopes());
    }

    private List<String> getScopes() {
        return configuration.requiredArray("scopes_supported").strings();
    }
}
