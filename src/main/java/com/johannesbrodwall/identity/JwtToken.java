package com.johannesbrodwall.identity;

import org.jsonbuddy.JsonNode;
import org.jsonbuddy.parse.JsonParser;

public class JwtToken {
    private final JsonNode payload;
    private final JsonNode header;
    private String token;

    public JwtToken(String token) {
        this.token = token;
        String[] tokenParts = token.split("\\.");
        this.header = JsonParser.parseFromBase64encodedString(tokenParts[0]);
        this.payload = JsonParser.parseFromBase64encodedString(tokenParts[1]);
    }

    public JsonNode getPayload() {
        return payload;
    }

    public JsonNode getHeader() {
        return header;
    }
}
