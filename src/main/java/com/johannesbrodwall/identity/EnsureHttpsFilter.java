package com.johannesbrodwall.identity;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class EnsureHttpsFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        String scheme = Optional.ofNullable(req.getHeader("X-Forwarded-Proto")).orElse(req.getScheme());
        String host = Optional.ofNullable(req.getHeader("X-Forwarded-Host")).orElse(req.getHeader("Host"));

        if (scheme.equals("https") || host.equals("localhost") || host.startsWith("localhost:")) {
            chain.doFilter(request, response);
        } else {
            resp.sendRedirect("https://" + host + req.getRequestURI()
                    + (req.getQueryString() != null ? "?" + req.getQueryString() : "")
            );
        }
    }

    @Override
    public void destroy() {

    }
}
