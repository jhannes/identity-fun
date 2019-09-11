package com.johannesbrodwall.identity;

import org.junit.Rule;
import org.junit.Test;
import org.logevents.extend.junit.ExpectedLogEventsRule;
import org.slf4j.event.Level;

import java.util.Map;

import static org.junit.Assert.*;

public class LegacyUserSystemGatewayTest {

    @Rule
    public ExpectedLogEventsRule expectedLogEventsRule = new ExpectedLogEventsRule(Level.WARN);

    @Test
    public void shouldTransformUser() {
        expectedLogEventsRule.expectPattern(LegacyUserSystemGateway.class, Level.WARN, "Illegal username {}");
        LegacyUserSystemGateway gateway = new LegacyUserSystemGateway();
        Map<String, String> values = gateway.transform(new User("test", new UserRole("admin")));
        assertEquals("test", values.get("username"));
    }

}
