package com.johannesbrodwall.identity;

import com.johannesbrodwall.identity.util.BearerToken;
import org.jsonbuddy.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;

public class SlackOauth2Servlet extends Oauth2Servlet {
    public static final String TOKEN_ENDPOINT = "https://slack.com/api/oauth.access";
    public static final String SCOPE = "groups:read+channels:read+users.profile:read";

    private static Logger logger = LoggerFactory.getLogger(SlackOauth2Servlet.class);

    public SlackOauth2Servlet(String authorizationEndpoint, Oauth2ClientConfiguration oauth2ClientConfiguration) {
        super(authorizationEndpoint, TOKEN_ENDPOINT, SCOPE, oauth2ClientConfiguration);
    }

    @Override
    protected JsonObject fetchUserProfile(BearerToken accessToken) throws IOException {
        URL slackApiUrl = new URL("https://slack.com/api/");

        logger.debug("Fetching user info from : {}", new URL(slackApiUrl, "users.profile.get"));
        JsonObject profile = jsonParserParseToObject(new URL(slackApiUrl, "users.profile.get"), accessToken).requiredObject("profile");
        logger.debug("Fetching user conversations from : {}", new URL(slackApiUrl,"conversations.list?types=private_channel,public_channel"));
        JsonObject conversations = jsonParserParseToObject(
                new URL(slackApiUrl,"conversations.list?types=private_channel,public_channel"),
                accessToken
        );
        profile.put("user.conversations", conversations);
        return profile;
    }

}
