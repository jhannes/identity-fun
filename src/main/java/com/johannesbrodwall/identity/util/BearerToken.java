package com.johannesbrodwall.identity.util;

import java.net.HttpURLConnection;

public class BearerToken implements HttpAuthorization {
    private String value;

    public BearerToken(String bearerToken) {
        this.value = bearerToken;
    }

    @Override
    public void authorize(HttpURLConnection connection) {
        connection.setRequestProperty("Authorization", getValue());
    }

    public String getValue() {
        return "Bearer " + value;
    }

    @Override
    public String toString() {
        return "Authorization: " + getValue();
    }
}
