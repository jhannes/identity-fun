package com.johannesbrodwall.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.MarkerFactory;

import java.util.List;

public class UserAccountSyncWorker extends Thread {

    private static final Logger logger = LoggerFactory.getLogger(UserAccountSyncWorker.class);

    private UserRepository userRepository = new UserRepository();

    private LegacyUserSystemGateway destination = new LegacyUserSystemGateway();

    public UserAccountSyncWorker() {
        setName(getClass().getSimpleName());
        setDaemon(true);
    }

    @Override
    public void run() {
        logger.info("Starting");
        try {
            while (!Thread.interrupted()) {
                logger.info("Running sync");
                List<User> users = userRepository.fetchUserRoles();
                for (User user : users) {
                    try (MDC.MDCCloseable ignore = MDC.putCloseable("id", String.valueOf(user.getId()))) {
                        destination.updateUser(user);
                    } catch (Exception e) {
                        logger.error(MarkerFactory.getMarker("WORKER"), "Failed to sync {}", user, e);
                    }
                }
                Thread.sleep(30000);
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
