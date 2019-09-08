package com.johannesbrodwall.identity;

import org.jsonbuddy.JsonObject;
import org.jsonbuddy.parse.JsonParser;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Optional;

public class OpenidConfiguration implements Oauth2IssuerConfiguration {

    private JsonObject configuration;

    public OpenidConfiguration(String openIdIssuerUrl) throws IOException {
        configuration = JsonParser.parseToObject(new URL(openIdIssuerUrl + "/.well-known/openid-configuration"));
    }

    @Override
    public URL getAuthorizationEndpoint() {
        return toURL(configuration.requiredString("authorization_endpoint"));
    }

    @Override
    public URL getTokenEndpoint() {
        return toURL(configuration.requiredString("token_endpoint"));
    }

    @Override
    public String getScopesString() {
        return String.join("+", getScopes());
    }

    private List<String> getScopes() {
        return configuration.requiredArray("scopes_supported").strings();
    }

    @Override
    public Optional<URL> getEndSessionEndpoint() {
        return configuration.stringValue("end_session_endpoint").map(this::toURL);
    }

    public String getIssuer() {
        return configuration.requiredString("issuer");
    }

    public URL getUserinfoEndpoint() {
        return toURL(configuration.requiredString("userinfo_endpoint"));
    }
}
