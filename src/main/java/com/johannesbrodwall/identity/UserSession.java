package com.johannesbrodwall.identity;

import com.johannesbrodwall.identity.util.BearerToken;
import org.jsonbuddy.JsonObject;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@SuppressWarnings("unused")
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

    public void addSession(String idProvider, IdProviderSession session) {
        idProviderSessions.put(idProvider, session);
    }

    public interface IdProviderSession {

        BearerToken getAccessToken();

        JsonObject getUserinfo();
    }

    public static class OpenIdConnectSession implements IdProviderSession {
        private final BearerToken accessToken;
        private JsonObject userinfo;
        private final Optional<String> refreshToken;
        private final JwtToken idToken;

        public OpenIdConnectSession(BearerToken accessToken, JsonObject userinfo, Optional<String> refreshToken, JwtToken idToken) {
            this.accessToken = accessToken;
            this.userinfo = userinfo;
            this.refreshToken = refreshToken;
            this.idToken = idToken;
        }

        @Override
        public JsonObject getUserinfo() {
            return userinfo;
        }

        public Optional<String> getRefreshToken() {
            return refreshToken;
        }

        public JwtToken getIdToken() {
            return idToken;
        }

        @Override
        public BearerToken getAccessToken() {
            return accessToken;
        }
    }

    public static class Oauth2ProviderSession implements IdProviderSession {
        private final BearerToken accessToken;
        private final JsonObject userinfo;

        public Oauth2ProviderSession(BearerToken accessToken, JsonObject userinfo) {
            this.accessToken = accessToken;
            this.userinfo = userinfo;
        }

        @Override
        public BearerToken getAccessToken() {
            return accessToken;
        }

        @Override
        public JsonObject getUserinfo() {
            return userinfo;
        }
    }
}
