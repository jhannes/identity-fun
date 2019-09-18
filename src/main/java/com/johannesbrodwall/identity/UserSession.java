package com.johannesbrodwall.identity;

import com.johannesbrodwall.identity.util.BearerToken;
import com.johannesbrodwall.identity.util.HttpAuthorization;
import org.jsonbuddy.JsonObject;

import javax.servlet.http.HttpServletRequest;
import java.net.URL;
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

    public void removeSession(String providerName) {
        idProviderSessions.removeIf(idProviderSession -> idProviderSession.getProviderName().equals(providerName));
    }

    public interface IdProviderSession {

        String getIssuer();

        String getAccessToken();

        void setAccessToken(String accessToken);

        String getRefreshToken();

        JsonObject getUserinfo();

        String getProviderName();
    }

    public static class OpenIdConnectSession implements IdProviderSession {
        private String controlUrl;
        private BearerToken accessToken;
        private JsonObject userinfo;
        private Optional<String> refreshToken;
        private Optional<URL> endSessionEndpoint;
        private String providerName;

        public OpenIdConnectSession(String providerName) {
            this.providerName = providerName;
        }

        @Override
        public String getProviderName() {
            return providerName;
        }

        public void setAccessToken(BearerToken accessToken) {
            this.accessToken = accessToken;
        }

        public void setUserinfo(JsonObject userinfo) {
            this.userinfo = userinfo;
        }

        public void setRefreshToken(Optional<String> refreshToken) {
            this.refreshToken = refreshToken;
        }

        public void setIdToken(JwtToken idToken) {
            this.idToken = idToken;
        }

        private JwtToken idToken;

        @Override
        public String getIssuer() {
            return getIdToken().iss();
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

        public HttpAuthorization getAccessBearerToken() {
            return accessToken;
        }

        public String getEndSessionEndpoint() {
            return endSessionEndpoint.map(URL::toString).orElse(null);
        }

        public void setEndSessionEndpoint(Optional<URL> endSessionEndpoint) {
            this.endSessionEndpoint = endSessionEndpoint;
        }
    }

    public static class Oauth2ProviderSession implements IdProviderSession {
        private BearerToken accessToken;
        private String issuer;
        private JsonObject userinfo;
        private final String providerName;

        public Oauth2ProviderSession(String providerName) {
            this.providerName = providerName;
        }

        @Override
        public String getProviderName() {
            return providerName;
        }

        @Override
        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
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

        public void setUserinfo(JsonObject userinfo) {
            this.userinfo = userinfo;
        }
    }
}
