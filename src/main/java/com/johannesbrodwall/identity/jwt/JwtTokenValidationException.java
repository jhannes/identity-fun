package com.johannesbrodwall.identity.jwt;

public class JwtTokenValidationException extends RuntimeException {
    public JwtTokenValidationException(String message) {
        super(message);
    }

    public JwtTokenValidationException(String message, Exception e) {
        super(message, e);
    }
}
