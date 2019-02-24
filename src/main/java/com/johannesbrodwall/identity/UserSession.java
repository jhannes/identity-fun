package com.johannesbrodwall.identity;

import com.johannesbrodwall.identity.util.BearerToken;
import org.jsonbuddy.JsonObject;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@SuppressWarnings("unused")
public class UserSession {

    private List<IdProviderSession> idProviderSessions = new ArrayList<>();

    public List<IdProviderSession> getIdProviderSessions() {
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

    public void addSession(IdProviderSession session) {
        idProviderSessions.add(session);
    }

    public interface IdProviderSession {

        String getControlUrl();

        String getIssuer();

        String getAccessToken();

        void setAccessToken(String accessToken);

        String getRefreshToken();

        JsonObject getUserinfo();
    }

    public static class OpenIdConnectSession implements IdProviderSession {
        private final String controlUrl;
        private final String issuer;
        private BearerToken accessToken;
        private JsonObject userinfo;
        private final Optional<String> refreshToken;
        private final JwtToken idToken;

        public OpenIdConnectSession(String controlUrl, BearerToken accessToken, JsonObject userinfo, Optional<String> refreshToken, JwtToken idToken) {
            this.controlUrl = controlUrl;
            this.issuer = idToken.iss();
            this.accessToken = accessToken;
            this.userinfo = userinfo;
            this.refreshToken = refreshToken;
            this.idToken = idToken;
        }

        @Override
        public String getControlUrl() {
            return controlUrl;
        }

        @Override
        public String getIssuer() {
            return issuer;
        }

        @Override
        public JsonObject getUserinfo() {
            return userinfo;
        }

        @Override
        public String getRefreshToken() {
            return refreshToken.orElse(null);
        }

        public JwtToken getIdToken() {
            return idToken;
        }

        @Override
        public String getAccessToken() {
            return accessToken.toString();
        }

        @Override
        public void setAccessToken(String accessToken) {
            this.accessToken = new BearerToken(accessToken);
        }
    }

    public static class Oauth2ProviderSession implements IdProviderSession {
        private final String controlUrl;
        private BearerToken accessToken;
        private final String issuer;
        private final JsonObject userinfo;

        public Oauth2ProviderSession(String controlUrl, String issuer, BearerToken accessToken, JsonObject userinfo) {
            this.controlUrl = controlUrl;
            this.issuer = issuer;
            this.accessToken = accessToken;
            this.userinfo = userinfo;
        }

        @Override
        public String getControlUrl() {
            return controlUrl;
        }

        @Override
        public String getIssuer() {
            return issuer;
        }

        @Override
        public String getRefreshToken() {
            return null;
        }

        @Override
        public String getAccessToken() {
            return accessToken.toString();
        }

        @Override
        public void setAccessToken(String accessToken) {
            this.accessToken = new BearerToken(accessToken);
        }

        @Override
        public JsonObject getUserinfo() {
            return userinfo;
        }
    }
}
