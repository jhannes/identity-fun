package com.johannesbrodwall.identity.util;

import java.net.HttpURLConnection;

public class BearerToken implements HttpAuthorization {
    private String value;

    public BearerToken(String bearerToken) {
        this.value = bearerToken;
    }

    @Override
    public void authorize(HttpURLConnection connection) {
        connection.setRequestProperty("Authorization", getHeaderValue());
    }

    public String getHeaderValue() {
        return "Bearer " + value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "Authorization: " + getHeaderValue();
    }
}
