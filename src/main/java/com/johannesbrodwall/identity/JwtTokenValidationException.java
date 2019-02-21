package com.johannesbrodwall.identity;

public class JwtTokenValidationException extends RuntimeException {
    public JwtTokenValidationException(String message) {
        super(message);
    }

    public JwtTokenValidationException(String message, Exception e) {
        super(message, e);
    }
}
