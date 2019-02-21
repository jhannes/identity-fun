package com.johannesbrodwall.identity;

import org.jsonbuddy.JsonObject;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class UserSession {

    private Map<String, IdProviderSession> idProviderSessions = new HashMap<>();

    public Map<String, IdProviderSession> getIdProviderSessions() {
        return idProviderSessions;
    }

    public static UserSession getFromSession(HttpServletRequest req) {
        UserSession session = (UserSession) req.getSession().getAttribute(UserSession.class.getName());
        if (session == null) {
            req.getSession().invalidate();
            session = new UserSession();
            req.getSession(true).setAttribute(UserSession.class.getName(), session);
        }
        return session;
    }

    public void addTokenResponse(String provider, JsonObject tokenResponse) {
        idProviderSessions.put(provider, new IdProviderSession(tokenResponse));
    }

    public static class IdProviderSession {
        private final String accessToken;
        private final Optional<String> refreshToken;
        private final JwtToken idToken;

        public IdProviderSession(JsonObject tokenResponse) {
            this.accessToken = tokenResponse.requiredString("access_token");
            this.refreshToken = tokenResponse.stringValue("refresh_token");
            this.idToken = new JwtToken(tokenResponse.requiredString("id_token"));
        }

        public Optional<String> getRefreshToken() {
            return refreshToken;
        }

        public JwtToken getIdToken() {
            return idToken;
        }

        public String getAccessToken() {
            return accessToken;
        }
    }
}
