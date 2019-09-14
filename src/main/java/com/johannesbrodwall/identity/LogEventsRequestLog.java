package com.johannesbrodwall.identity;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Optional;

public class LogEventsRequestLog implements RequestLog {
    private Marker HTTP = MarkerFactory.getMarker("HTTP");
    private Logger logger = LoggerFactory.getLogger("HTTP");

    @Override
    public void log(Request req, Response resp) {
        String addr = Optional.ofNullable(req.getHeader("X-Forwarded")).orElse(req.getRemoteHost());
        String user = getAuthentication(req);
        String method = req.getMethod();
        String originalUri = req.getOriginalURI();
        String protocol = req.getProtocol();
        int statusCode = resp.getStatus();
        String bytesWritten = String.format("%04d", resp.getHttpChannel().getBytesWritten());

        try(
            MDC.MDCCloseable ignored = MDC.putCloseable("clientIP", addr);
            MDC.MDCCloseable ignored2 = MDC.putCloseable("user", user)
        ) {
            logger.info(HTTP, "clientIp={} user={} \"{} {} {} status={} bytes={}",
                    addr, user, method, originalUri, protocol, statusCode, bytesWritten);
        }
    }

    private String getAuthentication(Request req) {
        return req.getRemoteUser();
    }
}
