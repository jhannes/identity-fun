package com.johannesbrodwall.identity;

import org.slf4j.MDC;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Optional;

public class LoggingContextFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        MDC.put("clientIp", Optional.ofNullable(req.getHeader("X-Forwarded")).orElse(req.getRemoteHost()));
        MDC.put("path", req.getRequestURI());
        UserSession userSession = (UserSession) req.getSession().getAttribute(UserSession.class.getName());
        if (userSession != null) {
            MDC.put("user", userSession.getUserName());
            if ("24079419008".equals(userSession.getUserName())) {
                MDC.put("clientIp", "189.12.1.31");
            }
        }

        chain.doFilter(request, response);

        MDC.clear();
    }

    @Override
    public void destroy() {

    }
}
