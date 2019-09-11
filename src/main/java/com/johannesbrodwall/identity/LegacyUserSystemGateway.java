package com.johannesbrodwall.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class LegacyUserSystemGateway {
    private static final Logger logger = LoggerFactory.getLogger(LegacyUserSystemGateway.class);
    public void updateUser(User user) {
        logger.debug("Writing to server {}", user);
        Map<String, String> transformedUser = transform(user);
        logger.debug("Sending data to server {}", transformedUser);
        sendData(transformedUser);
        logger.debug("Done");
    }

    Map<String, String> transform(User user) {
        HashMap<String, String> values = new HashMap<>();
        values.put("id", user.getId().toString());
        values.put("username", user.getUsername());
        values.put("role", user.getRole().getRole());
        if (!user.getUsername().matches("\\d+")) {
            logger.warn("Illegal username {}", user.getUsername());
        }
        return values;
    }


    private void sendData(Map<String, String> transformedUser) {

    }

}
