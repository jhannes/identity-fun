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

    public void addTokenResponse(JsonObject tokenResponse) {
        OpenIdConnectSession session = new OpenIdConnectSession(tokenResponse);
        idProviderSessions.put(session.getIdToken().iss(), session);
    }

    public void addProfile(String provider, String accessToken, JsonObject profile) {
        idProviderSessions.put(provider, new Oauth2ProviderSession(accessToken, profile));
    }

    public interface IdProviderSession {

    }

    public static class OpenIdConnectSession implements IdProviderSession {
        private final String accessToken;
        private final Optional<String> refreshToken;
        private final JwtToken idToken;

        public OpenIdConnectSession(JsonObject tokenResponse) {
            this.accessToken = tokenResponse.requiredString("access_token");
            this.refreshToken = tokenResponse.stringValue("refresh_token");
            this.idToken = new JwtToken(tokenResponse.requiredString("id_token"), true);
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

    public class Oauth2ProviderSession implements IdProviderSession {
        private final String accessToken;
        private final JsonObject profile;

        public Oauth2ProviderSession(String accessToken, JsonObject profile) {
            this.accessToken = accessToken;
            this.profile = profile;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public JsonObject getProfile() {
            return profile;
        }
    }
}
