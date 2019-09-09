package com.johannesbrodwall.identity;

import com.johannesbrodwall.identity.util.BearerToken;
import org.jsonbuddy.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Optional;

public class SlackOauth2Servlet extends Oauth2Servlet {

    private static Logger logger = LoggerFactory.getLogger(SlackOauth2Servlet.class);

    public SlackOauth2Servlet(String providerName) {
        super(providerName);
    }

    @Override
    protected Optional<String> getConsoleUrl() {
        return Optional.of("https://api.slack.com/apps");
    }

    @Override
    protected Oauth2Configuration getOauth2Configuration() throws IOException {
        Configuration configuration = new Configuration(new File("oauth2-providers.properties"));
        return new Oauth2Configuration(
                new SlackIssuerConfig(configuration),
                new Oauth2ClientConfiguration(providerName, configuration)
        );
    }

    @Override
    protected JsonObject fetchUserProfile(BearerToken accessToken) throws IOException {
        URL slackApiUrl = new URL("https://slack.com/api/");

        URL userProfileEndpoint = null;
        logger.debug("Fetching user info from : {}", userProfileEndpoint);
        JsonObject profile = jsonParserParseToObject(userProfileEndpoint, accessToken).requiredObject("profile");
        logger.debug("Fetching user conversations from : {}", new URL(slackApiUrl,"conversations.list?types=private_channel,public_channel"));
        JsonObject conversations = jsonParserParseToObject(
                new URL(slackApiUrl,"conversations.list?types=private_channel,public_channel"),
                accessToken
        );
        profile.put("user.conversations", conversations);
        return profile;
    }

    private static class SlackIssuerConfig implements Oauth2IssuerConfiguration {
        private Configuration configuration;

        public SlackIssuerConfig(Configuration configuration) {
            this.configuration = configuration;
        }

        @Override
        public URL getAuthorizationEndpoint() {
            return toURL(configuration.getRequiredProperty("slack.authorization_endpoint"));
        }

        @Override
        public String getScopesString() {
            return "groups:read+channels:read+users.profile:read";
        }

        @Override
        public URL getTokenEndpoint() {
            return toURL("https://slack.com/api/oauth.access");
        }

        @Override
        public Optional<URL> getEndSessionEndpoint() {
            return Optional.empty();
        }
    }
}
